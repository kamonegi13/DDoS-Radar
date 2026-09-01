"""Writing the fetch record to L1 (§1-6). The only writer of these tables.

Three records, three different reasons:

  * **`fetch_log`, always.** A fetch that produced no observation and a
    fetch that never happened look identical in an observation ledger. The
    log is what tells them apart, and it carries the feed death cause
    (§1-7) so a source that has been serving an HTML error page for six
    weeks is a query rather than a discovery.
  * **`llm_call`, mandatory on the LLM path.** S5-VERIF-022 requires parity
    to replay recorded responses by `prompt_sha256` and forbids calling a
    model. E-08 measured what happens without it: the legacy annotation
    path records only `prompt_version`, so those conclusions cannot be
    replayed at all. If this layer does not write the record, L3 has
    nothing to read — the table is created in WP-2.5 and filled in WP-2.7.
  * **`fetch_body`, opt-in and short-lived.** Keeping 60 days of every body
    for 34 adapters is a capacity decision outside S3's estimate that
    nobody has approved; `body_sha256` proves identity without it.
"""
from __future__ import annotations

import hashlib
from typing import Iterable, Mapping, Optional

from v3.fetch.breaker import BreakerState
from v3.fetch.state import AdapterState
from v3.kernel.errors import DomainError


def prompt_digest(prompt: str) -> str:
    """S5-VERIF-022's replay key."""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


# ── fetch_log ───────────────────────────────────────────────────────────

def record_fetch(store, adapter_id: str, *, requested_at: float,
                 url_sha256: str, outcome: str,
                 http_status: Optional[int] = None,
                 latency_ms: Optional[float] = None,
                 body_sha256: Optional[str] = None,
                 breaker_state: str = "CLOSED", detail: str = "",
                 connection=None) -> None:
    """Append one fetch record.

    `connection` is the ledger's established seam: passing the caller's
    open transaction makes this write part of that unit rather than a
    separately-committed statement. One adapter cycle writes a fetch_log
    row, possibly a body, its observations and its schedule state — and a
    crash between them must not leave the log claiming a fetch whose
    outcome was never recorded.
    """
    with store._maybe_transaction(connection) as conn:
        conn.execute(
            "INSERT INTO fetch_log (adapter_id, requested_at, url_sha256, "
            "http_status, latency_ms, outcome, body_sha256, breaker_state, "
            "detail) VALUES (?,?,?,?,?,?,?,?,?)",
            (adapter_id, requested_at, url_sha256, http_status, latency_ms,
             outcome, body_sha256, breaker_state, detail))


def fetch_log_for(store, adapter_id: str, *, limit: int = 100) -> list[dict]:
    rows = store._read_connection().execute(
        "SELECT * FROM fetch_log WHERE adapter_id = ? "
        "ORDER BY requested_at DESC, id DESC LIMIT ?",
        (adapter_id, limit)).fetchall()
    return [dict(row) for row in rows]


def liveness(store, *, since: float = 0.0) -> Mapping[str, str]:
    """adapter -> most recent outcome. The feed liveness ledger (§1-7).

    D1 §4 records JP_MOFA at 404/WAF, CN_MFA returning HTML, RU_MFA
    geo-blocked and KCNA intermittently empty — knowledge that currently
    exists only as comments. Here it is a query over recorded facts.
    """
    rows = store._read_connection().execute(
        "SELECT adapter_id, outcome FROM fetch_log AS f WHERE requested_at "
        ">= ? AND requested_at = (SELECT MAX(requested_at) FROM fetch_log "
        "WHERE adapter_id = f.adapter_id) GROUP BY adapter_id",
        (since,)).fetchall()
    return {row["adapter_id"]: row["outcome"] for row in rows}


# ── llm_call (S5-VERIF-022) ─────────────────────────────────────────────

def record_llm_call(store, adapter_id: str, *, prompt: str, response: str,
                    model_id: str, temperature: float,
                    called_at: float, connection=None) -> str:
    """Record an LLM exchange completely, or refuse to record it at all.

    Every field is required because every field is required to replay.
    A partial row would satisfy the schema and then fail S5-VERIF-022's
    reconstruction months later, at which point the exchange is gone —
    so the refusal happens here, where it is still fixable.
    """
    for name, value in (("prompt", prompt), ("response", response),
                        ("model_id", model_id)):
        if not isinstance(value, str) or not value.strip():
            raise DomainError(
                f"llm_call {name} is required and must be non-empty: "
                f"S5-VERIF-022 replays a recorded response by prompt_sha256, "
                f"and a row missing {name} cannot be replayed — its "
                f"conclusion type would have to be excluded from parity")
    if isinstance(temperature, bool) or not isinstance(
            temperature, (int, float)):
        raise DomainError(
            f"llm_call temperature must be a number, got "
            f"{type(temperature).__name__}; it is part of what makes a "
            f"replay faithful")
    digest = prompt_digest(prompt)
    with store._maybe_transaction(connection) as conn:
        conn.execute(
            "INSERT INTO llm_call (adapter_id, called_at, prompt, "
            "prompt_sha256, response, model_id, temperature) "
            "VALUES (?,?,?,?,?,?,?)",
            (adapter_id, called_at, prompt, digest, response, model_id,
             float(temperature)))
    return digest


def recorded_response(store, prompt: str) -> Optional[dict]:
    """The recorded exchange for a prompt, for replay. None if absent.

    None is the signal S5-VERIF-022 acts on: the conclusion type is then
    excluded from parity and the exclusion stated, rather than a model
    being called to fill the gap.
    """
    row = store._read_connection().execute(
        "SELECT * FROM llm_call WHERE prompt_sha256 = ? "
        "ORDER BY called_at DESC LIMIT 1", (prompt_digest(prompt),)).fetchone()
    return dict(row) if row else None


# ── fetch_body (opt-in) ─────────────────────────────────────────────────

def record_body(store, adapter_id: str, *, body: bytes,
                recorded_at: float, connection=None) -> str:
    """Store a raw body, keyed by its own hash. Idempotent."""
    digest = hashlib.sha256(body).hexdigest()
    with store._maybe_transaction(connection) as conn:
        conn.execute(
            "INSERT INTO fetch_body (body_sha256, adapter_id, recorded_at, "
            "body) VALUES (?,?,?,?) ON CONFLICT (body_sha256) DO NOTHING",
            (digest, adapter_id, recorded_at, body))
    return digest


def stored_body(store, body_sha256: str) -> Optional[bytes]:
    row = store._read_connection().execute(
        "SELECT body FROM fetch_body WHERE body_sha256 = ?",
        (body_sha256,)).fetchone()
    return bytes(row["body"]) if row else None


# ── fetch_schedule (per-adapter state) ──────────────────────────────────

def load_states(store) -> dict:
    """Every adapter's persisted state, keyed by adapter id."""
    rows = store._read_connection().execute(
        "SELECT * FROM fetch_schedule").fetchall()
    states = {}
    for row in rows:
        states[row["adapter_id"]] = AdapterState(
            adapter_id=row["adapter_id"],
            last_run_at=row["last_run_at"],
            last_outcome=row["last_outcome"],
            breaker=BreakerState(
                state=row["breaker_state"],
                fail_count=row["breaker_fail_count"],
                opened_at=row["breaker_opened_at"],
                recovery_delay_sec=row["breaker_recovery_delay_sec"]))
    return states


def save_state(store, state: AdapterState, *, updated_at: float,
               connection=None) -> None:
    """Upsert one adapter's state. The one table updated in place."""
    if not isinstance(state, AdapterState):
        raise DomainError(
            f"save_state takes an AdapterState, got {type(state).__name__}")
    with store._maybe_transaction(connection) as conn:
        conn.execute(
            "INSERT INTO fetch_schedule (adapter_id, last_run_at, "
            "last_outcome, breaker_state, breaker_fail_count, "
            "breaker_opened_at, breaker_recovery_delay_sec, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?) "
            "ON CONFLICT (adapter_id) DO UPDATE SET last_run_at=excluded."
            "last_run_at, last_outcome=excluded.last_outcome, "
            "breaker_state=excluded.breaker_state, "
            "breaker_fail_count=excluded.breaker_fail_count, "
            "breaker_opened_at=excluded.breaker_opened_at, "
            "breaker_recovery_delay_sec=excluded."
            "breaker_recovery_delay_sec, "
            "updated_at=excluded.updated_at",
            (state.adapter_id, state.last_run_at, state.last_outcome,
             state.breaker.state, state.breaker.fail_count,
             state.breaker.opened_at, state.breaker.recovery_delay_sec,
             updated_at))


def save_states(store, states: Iterable[AdapterState], *,
                updated_at: float, connection=None) -> int:
    written = 0
    for state in states:
        save_state(store, state, updated_at=updated_at, connection=connection)
        written += 1
    return written


__all__ = ["record_fetch", "fetch_log_for", "liveness", "record_llm_call",
           "recorded_response", "prompt_digest", "record_body", "stored_body",
           "load_states", "save_state", "save_states"]
