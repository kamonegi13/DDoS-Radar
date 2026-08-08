"""The folds. Effective state IS the command log, not a copy beside it.

This module is the whole answer to G-15. There, an analyst changed a
value; an override row and an audit row were written; the UI showed the
new value; and nothing read it. The audit rows were honest — 95 of 98
registered keys simply bypassed the resolution chain, so the record
described a change that had no effect.

The remedy is not a better audit row. It is that there is no second copy
of the state to disagree with the record: `focus_state`, `labels_for` and
`ground_truth_for` are folds over `command_record`, and the API's read
projections call these same functions. A change that is not in the log is
not in the state, and a row in the log is in the state by construction.

Two consequences worth naming:

* **Replay is free.** Every fold takes `until`, so "what was focused at
  T" is this same function bounded at T — P7's derivation principle 4
  (replay and live are one projection) applied to the write side.
* **Effect verification is possible.** `v3.api.write.WriteContext.commit`
  re-runs the fold after appending and refuses if the state did not move
  to what the command claimed. A write nothing reads fails loudly here
  instead of returning 200.

Every value produced is plain JSON (dicts with string keys, lists,
strings, numbers, None). It has to be: the stored `after` is compared for
equality against a freshly folded value, and a type that does not survive
`json.dumps`/`loads` would compare unequal to itself forever.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from v3.calibration.ground_truth import RULE_ORDER
from v3.kernel.errors import DomainError

# ── the closed action vocabulary ────────────────────────────────────────
FOCUS_SET = "focus.set"
CONCLUSION_LABEL = "conclusion.label"
GROUND_TRUTH_ASSERT = "ground_truth.assert"
CONFIG_OVERRIDE = "config.override"
CONFIG_CLEAR = "config.clear"

TARGET_SCENARIO = "scenario"
TARGET_CONCLUSION = "conclusion"
TARGET_CONFIG = "config"

#: An analyst's label uses THE calibration vocabulary, imported rather
#: than re-spelled. There is deliberately no fifth "unclear" value: the
#: four cells are what the recall metric is computed from, and a label
#: outside them would either be dropped silently by the consumer or widen
#: the confusion matrix by a value nothing knows how to score. An analyst
#: who cannot place a conclusion in a cell does not label it — three
#: calibration disasters were all label contamination, and forcing a
#: judgement is how contamination starts.
ANALYST_LABELS: frozenset = frozenset(RULE_ORDER)


def latest_after(ledger, action: str, *, target_id: Optional[str] = None,
                 until: Optional[float] = None, empty=None):
    """THE fold, and there is only one of it.

    Every `apply_*` below is a pure function of `(before, payload)` that
    returns the complete new state, and `before` is always this function's
    result — so the state after N commands is the last command's `after`,
    and the fold is a lookup rather than a replay.

    That equivalence is not an optimisation, it is the invariant:
    `tests/test_api_write_seam.py` re-derives the state by replaying every
    row through its `apply` and asserts it matches this. If the two ever
    disagree, a row was written by something other than `commit()`.
    """
    rows = ledger.command_records(action=action, target_id=target_id,
                                  until=until)
    return rows[-1]["after"] if rows else empty


# ── C1: focus ───────────────────────────────────────────────────────────
def focus_state(ledger, *, until: Optional[float] = None) -> Optional[str]:
    """The focused scenario, or None if focus has never been set.

    GLOBAL, not per-analyst, and the reason is operational rather than
    stylistic: focus is what C-lite spends sensor budget on — the focused
    scenario runs every sensor, background scenarios run LLM intel and
    global signals only. A per-user focus would mean the server had to
    honour several at once, at which point "focused" would stop meaning
    what the scoring mode means by it.

    Who set it is still recorded (`actor_id` on the row), so the decision
    trail answers "who moved the tool's attention, and when".
    """
    return latest_after(ledger, FOCUS_SET, until=until, empty=None)


def resolve_focus(ledger, *, target_id, actor_id, until, config=None):
    return focus_state(ledger, until=until)


def apply_focus(before, *, target_id, payload, actor_id, at, config=None):
    return target_id


# ── C2: conclusion feedback (the G-01 path) ─────────────────────────────
def labels_for(ledger, conclusion_id: str, *,
               until: Optional[float] = None) -> dict:
    """`{actor_id: {label, reason, at}}` — the latest label per analyst.

    Latest-per-analyst rather than a list: an analyst who relabels has
    changed their mind, and both labels counting would double their
    weight in a recall computation. The superseded label is not lost —
    it is a row in the log, which is what the decision trail is for.
    """
    return latest_after(ledger, CONCLUSION_LABEL, target_id=conclusion_id,
                        until=until, empty={})


def resolve_labels(ledger, *, target_id, actor_id, until, config=None):
    return labels_for(ledger, target_id, until=until)


def apply_label(before, *, target_id, payload, actor_id, at, config=None):
    label = payload.get("label")
    if label not in ANALYST_LABELS:
        raise DomainError(
            f"unknown label {label!r}: the calibration vocabulary is "
            f"{sorted(ANALYST_LABELS)}. A label outside it cannot be scored "
            f"by the recall metric, and a label the consumer drops is a "
            f"contribution the analyst believes they made.")
    updated = dict(before)
    updated[actor_id] = {
        "label": label,
        "reason": payload.get("reason"),
        # Production's field name, kept letter-for-letter. It is not
        # decoration: `conclusions_v2.py:344-347` promotes a human label
        # to ground truth only when it carries an outcome URL, so
        # projecting the label without the URL would quietly demote every
        # analyst label out of the calibration chain — an insensitive
        # difference (C-02/C-03) produced by a dropped field.
        "observed_outcome_url": payload.get("observed_outcome_url"),
        "at": at,
    }
    return {actor: updated[actor] for actor in sorted(updated)}


# ── C9: human ground truth ──────────────────────────────────────────────
#: What an assertion has to carry to be usable as a teacher signal. An
#: entry without an observation time cannot be placed in a window, and one
#: without a source cannot be checked — the two properties whose absence
#: made incident #1's blanket labels indistinguishable from evidence.
GROUND_TRUTH_FIELDS: tuple[str, ...] = ("observed_at", "source_url",
                                        "description")


def event_id_for(scenario_id: str, payload) -> str:
    """A deterministic identity for an asserted event.

    Deterministic so that asserting the same event twice is visibly the
    same event rather than two, and so a replay of the log rebuilds the
    same ids. Randomness here would make the fold non-reproducible, which
    is the property NP6 needs from every derived value.
    """
    material = "\x1f".join([
        scenario_id,
        f"{float(payload['observed_at']):.6f}",
        str(payload["source_url"]),
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def ground_truth_for(ledger, scenario_id: str, *,
                     until: Optional[float] = None) -> list:
    """Every human-asserted event for a scenario, oldest first."""
    return latest_after(ledger, GROUND_TRUTH_ASSERT, target_id=scenario_id,
                        until=until, empty=[])


def resolve_ground_truth(ledger, *, target_id, actor_id, until, config=None):
    return ground_truth_for(ledger, target_id, until=until)


def apply_ground_truth(before, *, target_id, payload, actor_id, at,
                       config=None):
    missing = [name for name in GROUND_TRUTH_FIELDS
               if payload.get(name) in (None, "")]
    if missing:
        raise DomainError(
            f"a ground-truth assertion needs {missing}: an entry with no "
            f"observation time cannot be placed in a scoring window, and "
            f"one with no source cannot be checked. Incident #1 was labels "
            f"that had neither.")
    try:
        observed_at = float(payload["observed_at"])
    except (TypeError, ValueError):
        raise DomainError(
            f"observed_at must be a unix timestamp, got "
            f"{payload['observed_at']!r}") from None
    if observed_at <= 0:
        raise DomainError("observed_at must be a positive unix timestamp")
    entry = {
        "event_id": event_id_for(target_id, {**payload,
                                             "observed_at": observed_at}),
        "scenario_id": target_id,
        "observed_at": observed_at,
        "source_url": str(payload["source_url"]),
        "description": str(payload["description"]),
        "asserted_by": actor_id,
        "asserted_at": at,
    }
    merged = {existing["event_id"]: existing for existing in before}
    # First assertion wins on identity: re-asserting the same event must
    # not rewrite who asserted it or when. A correction is a new event
    # with a different source, and the log holds both.
    merged.setdefault(entry["event_id"], entry)
    return [merged[key] for key in sorted(
        merged, key=lambda k: (merged[k]["observed_at"], k))]


# ── C7: the configuration override layer (P6 O-18 group (a)) ────────────
#: What an override carries besides its value. `actor_id` and `at` are
#: stamped by `commit()`; `reason` is required by the spec. Together they
#: are why this layer needed no new table: the questions an override table
#: would have to answer — who, when, why, and what was there before — are
#: already columns on `command_record`, and a second store holding the
#: same facts is a second thing to disagree with the audit trail.
OVERRIDE_FIELDS: tuple[str, ...] = ("value", "actor_id", "reason", "at")


def config_state(ledger, key: str, *, until: Optional[float] = None):
    """The last `config` command's `after` for `key`, or None.

    Folds BOTH actions, because `config.override` and `config.clear` write
    the same state and a fold that saw only one would report a cleared key
    as still overridden — the exact class of bug (a write nothing reads,
    or a clear nothing applies) this whole surface exists to end.
    """
    rows = ledger.command_records(target_kind=TARGET_CONFIG, target_id=key,
                                  until=until)
    folded = [row for row in rows
              if row["action"] in (CONFIG_OVERRIDE, CONFIG_CLEAR)]
    return folded[-1]["after"] if folded else None


def config_override(ledger, key: str, *, until: Optional[float] = None):
    """The override layer's answer for `key`: `{value, actor_id, reason, at}`
    or None when the key is not overridden.

    THE top layer of `v3.config.resolution.ConfigResolver`. The resolver
    calls this and nothing else calls it, so "the resolution path reads
    the override rows" is a single edge rather than a convention.
    """
    state = config_state(ledger, key, until=until)
    return None if state is None else state.get("override")


def _require_resolver(config, action: str):
    if config is None:
        raise DomainError(
            f"{action} needs the composition root's ConfigResolver: its "
            f"state IS the resolved value, and resolving without the chain "
            f"would verify the effect against a projection nothing serves. "
            f"That is the G-15 shape, and WP-4.1c refused to ship it.")
    return config


def resolve_config(ledger, *, target_id, actor_id, until, config=None):
    """THE read seam for a config command — the full 3-layer resolution.

    Deliberately not the override row. `commit()` compares this against
    what the command claimed, so making it the resolved value is what
    turns the effect check into a proof that the chain reads the override:
    a resolver that ignored the ledger would return the env or default
    value here and the command would be refused.
    """
    return _require_resolver(config, "config").resolve(
        target_id, ledger=ledger, at=until).as_dict()


def apply_config_override(before, *, target_id, payload, actor_id, at,
                          config=None):
    """Set an override. Pure: `(before, payload) -> after`.

    `registry.coerce_value` refuses a pinned key, an unknown key, and a
    value the unit does not admit — before any row is written, so a
    refused override leaves no trace of a change that did not happen.
    """
    from v3.config import registry as config_registry

    resolver = _require_resolver(config, CONFIG_OVERRIDE)
    if "value" not in payload:
        raise DomainError(
            f"a {CONFIG_OVERRIDE} needs a value: an override with none is "
            f"indistinguishable from a clear, and the two have opposite "
            f"effects on what the tool computes")
    # Normalised the same way `v3.api.write._reason_for` normalises the
    # audit row's column, because the two are the same sentence seen from
    # two places and a whitespace difference between them would be a
    # difference an auditor has to explain.
    reason = payload.get("reason")
    reason = None if reason is None or not str(reason).strip() \
        else str(reason).strip()
    override = {
        "value": config_registry.coerce_value(target_id, payload["value"]),
        "actor_id": actor_id,
        "reason": reason,
        "at": at,
    }
    return resolver.project(target_id, override=override).as_dict()


def apply_config_clear(before, *, target_id, payload, actor_id, at,
                       config=None):
    """Remove an override, returning the key to env-or-default.

    Not a delete. The row saying the override was removed is appended like
    every other, so the decision trail holds the removal as an event with
    an actor and a reason — which is what an operator asking "when did
    this go back to the default, and who did it" needs to find.
    """
    resolver = _require_resolver(config, CONFIG_CLEAR)
    return resolver.project(target_id, override=None).as_dict()


__all__ = ["FOCUS_SET", "CONCLUSION_LABEL", "GROUND_TRUTH_ASSERT",
           "CONFIG_OVERRIDE", "CONFIG_CLEAR",
           "TARGET_SCENARIO", "TARGET_CONCLUSION", "TARGET_CONFIG",
           "ANALYST_LABELS", "OVERRIDE_FIELDS",
           "GROUND_TRUTH_FIELDS", "latest_after", "focus_state", "labels_for",
           "ground_truth_for", "event_id_for", "resolve_focus",
           "apply_focus", "resolve_labels", "apply_label",
           "resolve_ground_truth", "apply_ground_truth",
           "config_state", "config_override", "resolve_config",
           "apply_config_override", "apply_config_clear"]
