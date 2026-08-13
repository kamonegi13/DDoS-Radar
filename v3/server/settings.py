"""The deployment facts, and the ONE place their names are written down.

These are not thresholds. A threshold is a number a formula compares
against, it carries a unit, and it resolves through `Threshold` — P6 O-18
and the G-15 record settle that. Which file the ledger is, which port to
bind, which scenarios to watch: those are composition, decided before any
formula exists, and routing them through the configuration registry would
put deployment identity behind a dial an analyst can turn at runtime.

So they are read from the environment, once, through
`v3/runtime/secrets.py::from_environment` — the single licensed reader —
for exactly the names listed here. What this file CAN read is therefore
derivable from `KEY_IDS` rather than from a search of the source, which is
the same property `required_key_ids` gives the credential side.

Three of the values are refused rather than defaulted:

    ledger path   no default at all. `LedgerStore` refuses one for the
                  reason a default is dangerous (two processes disagreeing
                  about which database is real); this layer refuses to
                  invent one for the same reason, and additionally refuses
                  any path that names a v1 file (R4, `isolation.py`).
    port          defaulted away from v1's 8000, and 8000 itself refused.
    scenarios     defaulted to "every enabled scenario in the geography",
                  which is derived from deployment data rather than listed
                  here, and refused if it names one the geography lacks.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional

from v3.auth import session as SESSION
from v3.kernel.errors import DomainError
from v3.runtime import geo as GEO
from v3.runtime import secrets as SECRETS
from v3.runtime.loop import DEFAULT_INTERVAL_SEC
from v3.server import isolation

#: WHICH file the v3 ledger is. Required — see the module docstring.
LEDGER_PATH_KEY = "NOROSHI_V3_LEDGER_PATH"
#: WHERE the deployment geography is read from. Defaults to the repo copy.
GEO_PATH_KEY = "NOROSHI_V3_GEO_PATH"
HOST_KEY = "NOROSHI_V3_HOST"
PORT_KEY = "NOROSHI_V3_PORT"
#: Comma-separated scenario ids. Empty means every enabled scenario.
SCENARIOS_KEY = "NOROSHI_V3_SCENARIOS"
INTERVAL_KEY = "NOROSHI_V3_TICK_INTERVAL_SEC"
COOKIE_SECURE_KEY = "NOROSHI_V3_COOKIE_SECURE"

# ── the model (WP-2.7's stage) ──────────────────────────────────────────
#
# These four are v1's OWN names, without the `NOROSHI_V3_` prefix, and
# that is deliberate — it is the only decision on this page that copies a
# legacy spelling.
#
# The shadow container already receives them: `docker-compose.yml`'s
# `v3_shadow` service declares `env_file: config.env`, which is where
# v1's live values live (measured 2026-08-13: `LLM_HOST=
# http://host.docker.internal:11434`, `LLM_MODEL=gemma4:26b`). Reading the
# same names is what makes the shadow ask the SAME model as production —
# and S5-VERIF-022 compares recorded answers, so a shadow quietly running
# a different model would produce a parity gap with no cause anyone could
# find. A `NOROSHI_V3_LLM_MODEL` alias would have been a second value to
# keep in step, which is the drift this project has now measured four
# times.
#
# What the shadow does NOT inherit is unchanged: v1's secrets are blanked
# by the compose service, and these four are operational configuration of
# exactly the class the shadow already shares (the adapter credentials).
LLM_ENABLED_KEY = "LLM_ENABLED"
LLM_HOST_KEY = "LLM_HOST"
LLM_MODEL_KEY = "LLM_MODEL"
LLM_TIMEOUT_KEY = "LLM_TIMEOUT"

# ── the sweep scope (C-lite) ────────────────────────────────────────────
#
# v1's OWN name again, for the LLM keys' reason: the shadow inherits
# `config.env` through `docker-compose.yml`, so reading the same name is
# what makes the shadow sweep the same theatre production sweeps. A
# `NOROSHI_V3_` alias would be a second value to keep in step, and the two
# drifting is how the shadow comes to be measuring a different world than
# the system it is being compared against.
#
# It is composition and NOT a threshold, which is why it belongs here and
# not in the configuration registry: it decides which countries are
# fetched for, before any formula exists. Production classifies it the
# same way — `restart_required=True`, `apply_timing=TIMING_RESTART_REQUIRED`
# (`radar/config.py:745-747`).
DEFAULT_FOCUSED_SCENARIO_KEY = "DEFAULT_FOCUSED_SCENARIO"
# There is deliberately NO key for the sequence chain's owner. WP-4.4
# registered one (§7-2 #115) and the owner ruling struck it out: production
# picks a dual-core scenario's owner by live spike, so a configured
# constant picks the same country forever — the very failure the original
# ruling forbade, with an operator's name on it. The owner is measured per
# tick in `v3/runtime/chain.py`.

#: 8300 rather than 8000. Distance from v1's port is the point.
DEFAULT_PORT = 8300
#: Loopback by default. A shadow deployment that binds every interface on
#: first run is a shadow deployment somebody else can read.
DEFAULT_HOST = "127.0.0.1"

#: v1 parity, `config.env.example:329-342`. The HOST default is the one
#: the CONTAINER can reach — `localhost` inside a container is the
#: container, and the example file's `http://localhost:11434` is written
#: for a host-side run. The live `config.env` uses
#: `http://host.docker.internal:11434`, which is what the shadow inherits
#: and what this default matches so a missing variable does not silently
#: point the shadow at itself.
DEFAULT_LLM_HOST = "http://host.docker.internal:11434"
#: `config.env.example:339`. The live deployment overrides it
#: (`gemma4:26b`); the repo-visible default is the repo-visible value,
#: because a default copied from an untracked file is a default nobody can
#: review.
DEFAULT_LLM_MODEL = "llama3.2:3b"
#: `radar/config.py:675` / `config.env.example:342`. One attempt, no
#: retry — see `v3/runtime/llm_stage.LlmEgress`.
DEFAULT_LLM_TIMEOUT_SEC = 30.0
#: ON by default, unlike `config.env.example:329`. The example ships the
#: flag off so a first run does not depend on a daemon nobody installed;
#: a v3 deployment that reaches this code has the stage wired, and a
#: silently-off extraction path is the state C12 was filed against. An
#: operator who wants it off sets the variable, and the disclosure says
#: which layer answered.
DEFAULT_LLM_ENABLED = True

#: `radar/config.py:743` — the same default, and the same reason: "compute
#: / API-quota budget. Running every sensor on every scenario every cycle
#: would saturate upstreams." Only the BOOT default; a C1 focus command
#: moves the sweep at runtime (`v3/commands/state.py::focus_state`).
DEFAULT_FOCUSED_SCENARIO = "taiwan_contingency"

#: Every environment name this deployment honours. Includes the two auth
#: key ids, which live in `v3/auth/session.py` because the surface that
#: uses them owns their names — listed here so the start-up disclosure can
#: print the whole set from one place.
KEY_IDS: tuple[str, ...] = (
    LEDGER_PATH_KEY, GEO_PATH_KEY, HOST_KEY, PORT_KEY, SCENARIOS_KEY,
    INTERVAL_KEY, COOKIE_SECURE_KEY,
    LLM_ENABLED_KEY, LLM_HOST_KEY, LLM_MODEL_KEY, LLM_TIMEOUT_KEY,
    DEFAULT_FOCUSED_SCENARIO_KEY,
    SESSION.SIGNING_KEY_ID, SESSION.BOOTSTRAP_KEY_ID,
)

_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})


def _flag(raw: str, key: str, fallback: bool) -> bool:
    text = str(raw).strip().lower()
    if not text:
        return fallback
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise DomainError(
        f"{key}={raw!r} is neither true nor false. A misspelt flag that "
        f"silently took its default is how a `Secure` cookie attribute "
        f"comes to be off in production.")



@dataclass(frozen=True, slots=True)
class ServerSettings:
    """One shadow deployment, as a value.

    Validated at construction rather than at use: a deployment whose port
    collides with v1's should fail before the ledger file is created, not
    after the first tick has written to it.
    """

    ledger_path: str
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    geo_path: str = str(GEO.DEFAULT_PATH)
    scenario_ids: tuple[str, ...] = ()
    #: Which scenario's participants the per-country sensors sweep when no
    #: analyst has focused one. Checked against the geography — and against
    #: `scenario_ids` — at composition, not here: this layer has not read
    #: the deployment data yet.
    default_focused_scenario: str = DEFAULT_FOCUSED_SCENARIO
    interval_sec: float = DEFAULT_INTERVAL_SEC
    cookie_secure: bool = True
    llm_enabled: bool = DEFAULT_LLM_ENABLED
    llm_host: str = DEFAULT_LLM_HOST
    llm_model: str = DEFAULT_LLM_MODEL
    llm_timeout_sec: float = DEFAULT_LLM_TIMEOUT_SEC

    def __post_init__(self) -> None:
        object.__setattr__(self, "ledger_path",
                           isolation.assert_isolated_ledger(self.ledger_path))
        object.__setattr__(self, "port", isolation.assert_isolated_port(
            self.port))
        if not str(self.host).strip():
            raise DomainError("host must be a non-empty address")
        if float(self.interval_sec) <= 0:
            raise DomainError(
                f"interval_sec must be positive, got {self.interval_sec}: a "
                f"non-positive interval is a busy loop holding the ledger's "
                f"write lock")
        object.__setattr__(self, "interval_sec", float(self.interval_sec))
        if self.llm_enabled:
            # Refused rather than defaulted, the way the ledger path is: an
            # empty host would make every tick's probe fail with a reason
            # ("unreachable") that names the wrong cause, and an empty
            # model id cannot be replayed by (S5-VERIF-022).
            for name in ("llm_host", "llm_model"):
                if not str(getattr(self, name) or "").strip():
                    raise DomainError(
                        f"{name} must be set while the LLM stage is "
                        f"enabled; an empty one makes every tick report an "
                        f"unreachable model instead of a missing setting")
        if float(self.llm_timeout_sec) <= 0:
            raise DomainError(
                f"llm_timeout_sec must be positive, got "
                f"{self.llm_timeout_sec}: a request without a timeout holds "
                f"the tick open for as long as the model wants")
        object.__setattr__(self, "llm_timeout_sec", float(self.llm_timeout_sec))
        object.__setattr__(self, "llm_host", str(self.llm_host).strip())
        object.__setattr__(self, "llm_model", str(self.llm_model).strip())
        object.__setattr__(self, "scenario_ids",
                           tuple(dict.fromkeys(
                               str(item).strip()
                               for item in self.scenario_ids
                               if str(item).strip())))
        focused = str(self.default_focused_scenario or "").strip()
        if not focused:
            raise DomainError(
                f"{DEFAULT_FOCUSED_SCENARIO_KEY} must name a scenario. An "
                f"empty one leaves the per-country sensors with no sweep "
                f"scope at all, and a cycle that expands nothing reports a "
                f"completed sweep of nowhere")
        object.__setattr__(self, "default_focused_scenario", focused)

    @property
    def ledger_name(self) -> str:
        """The basename. What the API may disclose; the path is not served."""
        import pathlib
        return pathlib.Path(self.ledger_path).name

    def as_dict(self) -> dict:
        """The operator's view. Includes the path — this is the CLI's."""
        return {"ledger_path": self.ledger_path, "host": self.host,
                "port": self.port, "geo_path": self.geo_path,
                "scenario_ids": list(self.scenario_ids),
                "default_focused_scenario": self.default_focused_scenario,
                "interval_sec": self.interval_sec,
                "cookie_secure": self.cookie_secure,
                "llm_enabled": self.llm_enabled,
                "llm_host": self.llm_host,
                "llm_model": self.llm_model,
                "llm_timeout_sec": self.llm_timeout_sec}


def from_environment(source: Optional[Mapping[str, str]] = None
                     ) -> ServerSettings:
    """Build the settings from a snapshot, or from the process environment.

    `source` is an explicit mapping for tests and for a composition root
    that already took ONE snapshot for the whole deployment; `None` means
    "read exactly `KEY_IDS`", which is the production path and goes
    through the single licensed reader.
    """
    material = dict(SECRETS.from_environment(KEY_IDS)) if source is None \
        else dict(source)
    ledger_path = str(material.get(LEDGER_PATH_KEY, "")).strip()
    if not ledger_path:
        raise DomainError(
            f"{LEDGER_PATH_KEY} is not set. The v3 ledger is a separate "
            f"SQLite file from v1's (R4: the old system stays authoritative "
            f"until parity passes), and this layer will not invent a path — "
            f"a default is how two processes come to disagree about which "
            f"database is real. Set it to a file OUTSIDE "
            f"radar/persistence/, e.g. /app/v3data/noroshi_v3.db")
    scenarios = tuple(item.strip() for item
                      in str(material.get(SCENARIOS_KEY, "")).split(",")
                      if item.strip())
    return ServerSettings(
        ledger_path=ledger_path,
        host=str(material.get(HOST_KEY, "") or DEFAULT_HOST).strip(),
        port=int(str(material.get(PORT_KEY, "") or DEFAULT_PORT)),
        geo_path=str(material.get(GEO_PATH_KEY, "")
                     or str(GEO.DEFAULT_PATH)).strip(),
        scenario_ids=scenarios,
        default_focused_scenario=str(
            material.get(DEFAULT_FOCUSED_SCENARIO_KEY, "")
            or DEFAULT_FOCUSED_SCENARIO).strip(),
        interval_sec=float(str(material.get(INTERVAL_KEY, "")
                               or DEFAULT_INTERVAL_SEC)),
        cookie_secure=_flag(material.get(COOKIE_SECURE_KEY, ""),
                            COOKIE_SECURE_KEY, True),
        llm_enabled=_flag(material.get(LLM_ENABLED_KEY, ""),
                          LLM_ENABLED_KEY, DEFAULT_LLM_ENABLED),
        llm_host=str(material.get(LLM_HOST_KEY, "")
                     or DEFAULT_LLM_HOST).strip(),
        llm_model=str(material.get(LLM_MODEL_KEY, "")
                      or DEFAULT_LLM_MODEL).strip(),
        llm_timeout_sec=float(str(material.get(LLM_TIMEOUT_KEY, "")
                                  or DEFAULT_LLM_TIMEOUT_SEC)))


def describe() -> tuple[dict, ...]:
    """Every honoured variable and what it decides. For `--check`."""
    return (
        {"key": LEDGER_PATH_KEY, "required": True,
         "note": "v3 台帳の SQLite ファイル。v1 のファイル名・"
                 "radar/persistence/ 配下は拒否される"},
        {"key": GEO_PATH_KEY, "required": False,
         "note": f"配備地理。既定 {GEO.DEFAULT_PATH}"},
        {"key": HOST_KEY, "required": False,
         "note": f"束縛アドレス。既定 {DEFAULT_HOST}"},
        {"key": PORT_KEY, "required": False,
         "note": f"束縛ポート。既定 {DEFAULT_PORT}。"
                 f"v1 の {isolation.V1_PORT} は拒否される"},
        {"key": SCENARIOS_KEY, "required": False,
         "note": "カンマ区切りのシナリオ ID。空なら地理の有効シナリオ全件"},
        {"key": DEFAULT_FOCUSED_SCENARIO_KEY, "required": False,
         "note": f"focus 未設定時に per-country センサーが掃引する"
                 f"シナリオ。既定 {DEFAULT_FOCUSED_SCENARIO}（v1 同値・"
                 f"同名）。記事系 5 センサーは常に全シナリオ参加国の和集合を"
                 f"受け取る。地理に無い ID / 監視対象外の ID は合成時に拒否"},
        {"key": LLM_ENABLED_KEY, "required": False,
         "note": f"LLM 抽出ステージの有無。既定 {DEFAULT_LLM_ENABLED}。"
                 f"false なら記事は awaiting のまま残り、tick 報告の "
                 f"llm.reason が llm_disabled になる（沈黙しない）"},
        {"key": LLM_HOST_KEY, "required": False,
         "note": f"Ollama の endpoint。既定 {DEFAULT_LLM_HOST}。"
                 f"v1 と同じ変数名を読むため、shadow は config.env の値を"
                 f"そのまま継承する"},
        {"key": LLM_MODEL_KEY, "required": False,
         "note": f"model id。既定 {DEFAULT_LLM_MODEL}。"
                 f"S5-VERIF-022 は prompt と model の両方で replay する"},
        {"key": LLM_TIMEOUT_KEY, "required": False,
         "note": f"1 交換の読み取り上限（秒）。既定 "
                 f"{DEFAULT_LLM_TIMEOUT_SEC}（v1 同値）。再試行は無し"},
        {"key": INTERVAL_KEY, "required": False,
         "note": f"ティック間隔（秒）。既定 {DEFAULT_INTERVAL_SEC}"},
        {"key": COOKIE_SECURE_KEY, "required": False,
         "note": "refresh cookie の Secure 属性。既定 true。"
                 "http で動かす検証時のみ false"},
        {"key": SESSION.SIGNING_KEY_ID, "required": False,
         "note": "署名鍵。無ければ auth ルート全件が 503。v3 は生成しない"},
        {"key": SESSION.BOOTSTRAP_KEY_ID, "required": False,
         "note": "利用者 0 件のときだけ使う初期管理者パスワード"},
    )


__all__ = ["ServerSettings", "from_environment", "describe", "KEY_IDS",
           "LEDGER_PATH_KEY", "GEO_PATH_KEY", "HOST_KEY", "PORT_KEY",
           "SCENARIOS_KEY", "INTERVAL_KEY", "COOKIE_SECURE_KEY",
           "DEFAULT_FOCUSED_SCENARIO_KEY", "DEFAULT_FOCUSED_SCENARIO",
           "DEFAULT_PORT", "DEFAULT_HOST"]
