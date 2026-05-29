"""Ground-truth ETL classifier — ADR-V2-005.

Pure functions that decide which ``FeedbackLabel`` (if any) a given
``Conclusion`` deserves based on confirmed external escalation evidence
(ACLED political-violence events + GDELT tone spikes). Classification is
intentionally separate from data fetching and DB writes so the rules can be
unit-tested without the network.

The job runner (`scripts/run_ground_truth_etl.py`) is responsible for:

  1. enumerating recent conclusions,
  2. pulling ``ExternalEvent`` evidence for each scenario's participants,
  3. calling :func:`classify_conclusion` here,
  4. writing the resulting :class:`AutoFeedback` rows via
     :func:`save_feedback` with ``analyst_id`` prefixed ``auto:``.

Why split: the classifier is a small set of explicit rules driven by NP1
(sensitivity > precision). They need to be readable, traceable, and easy
to retune as we accumulate analyst-confirmed labels. Mixing in HTTP and
DB code makes that impossible.

Identity convention for auto-rows
---------------------------------
``analyst_id`` is set to ``"auto:acled"`` or ``"auto:gdelt"`` (or
``"auto:both"`` when corroborated) so that the bias-mitigation summary
(``summarize_feedback`` distinct_analysts) treats automated agreement as
*one* analyst per source, not as N independent voters. This prevents the
ETL from drowning out human feedback in the recall calibration.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Iterable, Optional

from radar import config
from radar.conclusions.base import Conclusion, ConclusionType
from radar.conclusions.feedback import AnalystFeedback, FeedbackLabel

if TYPE_CHECKING:
    from radar.database import RadarDB


class EvidenceSource(str, Enum):
    """Which evidence source produced the event.

    ACLED and GDELT are external (public DBs).

    LLM_INTEL and SEQUENCE are internal (our own DB) — added 2026-04-29 to
    keep the recall calculator working when ACLED is unavailable for OPSEC
    reasons. They are deliberately weighted lower than ACLED in the
    FALSE_NEGATIVE rule (require ≥2 distinct internal sources to substitute
    for one ACLED severity≥N event) so a single LLM-confirmed item cannot
    flip a tool conclusion against the analyst's TL=1 call.
    """

    ACLED = "acled"
    GDELT = "gdelt"
    LLM_INTEL = "llm_intel"
    SEQUENCE = "sequence"


# Auto-feedback identity strings. Kept in sync with the test suite so the
# distinct-analyst aggregation rule above stays load-bearing.
AUTO_ANALYST_ACLED = "auto:acled"
AUTO_ANALYST_GDELT = "auto:gdelt"
AUTO_ANALYST_LLM_INTEL = "auto:llm_intel"
AUTO_ANALYST_SEQUENCE = "auto:sequence"
AUTO_ANALYST_BOTH = "auto:both"
AUTO_ANALYST_MIXED = "auto:mixed"  # ≥2 distinct sources of any kind

# Keep auto-feedback notes short and machine-parseable. The drill-down UI
# already has plenty of room for human prose; this field is debug context.
_NOTE_TRUNCATE = 240


@dataclass(frozen=True)
class ExternalEvent:
    """Normalized escalation evidence point. ACLED and GDELT both flatten
    to this shape so the classifier never branches on source type."""

    source: EvidenceSource
    country: str           # ISO-2
    event_at: float        # epoch seconds, UTC
    severity: int          # ordinal: 0 (none) … higher = stronger evidence
    url: str               # provenance link (ACLED source url, GDELT query)
    summary: str           # ≤_NOTE_TRUNCATE chars; for analyst_feedback.notes


@dataclass(frozen=True)
class AutoFeedback:
    """Result of classifying one conclusion. Equivalent to
    :class:`AnalystFeedback` but carries the chosen ``analyst_id`` so the
    job runner can persist it without having to re-derive provenance."""

    conclusion_id: str
    label: FeedbackLabel
    analyst_id: str
    observed_at: float
    observed_outcome_url: Optional[str]
    notes: Optional[str]

    def to_analyst_feedback(self) -> AnalystFeedback:
        return AnalystFeedback(
            conclusion_id=self.conclusion_id,
            label=self.label,
            analyst_id=self.analyst_id,
            observed_at=self.observed_at,
            observed_outcome_url=self.observed_outcome_url,
            notes=self.notes,
        )


# ── classifier ────────────────────────────────────────────────────────────


def _events_in_forward_window(
    events: Iterable[ExternalEvent],
    *,
    start: float,
    end: float,
    countries: Iterable[str],
) -> list[ExternalEvent]:
    """Filter to events that fell inside [start, end] in any of the given
    countries. Both bounds are inclusive — a participant event happening
    exactly at the conclusion's ``observed_at`` is corroboration, not noise.
    """
    cc = {c.upper() for c in countries}
    return [
        e for e in events
        if start <= e.event_at <= end and e.country.upper() in cc
    ]


def _max_severity(events: list[ExternalEvent]) -> int:
    return max((e.severity for e in events), default=0)


def _provenance(events: list[ExternalEvent]) -> tuple[str, Optional[str], str]:
    """Return ``(analyst_id, evidence_url, notes)`` for a list of confirming
    events. URL prefers the highest-severity event; notes describes the
    full source mix so a human can audit without reopening the script.

    Source priority (when assigning analyst_id):
      1. ACLED + GDELT (both external public DBs) → "auto:both"
      2. ACLED-only → "auto:acled"
      3. GDELT-only → "auto:gdelt"
      4. ≥2 distinct internal-only sources (LLM_INTEL + SEQUENCE) → "auto:mixed"
      5. LLM_INTEL-only → "auto:llm_intel"
      6. SEQUENCE-only → "auto:sequence"

    Internal-only paths (4-6) are added 2026-04-29 to keep the auto-feedback
    pipeline producing labels when ACLED is unavailable. They are explicitly
    distinguishable from external-source paths so analysts can filter recall
    metrics by source quality if desired.
    """
    sources = {e.source for e in events}
    has_acled = EvidenceSource.ACLED in sources
    has_gdelt = EvidenceSource.GDELT in sources
    has_llm = EvidenceSource.LLM_INTEL in sources
    has_seq = EvidenceSource.SEQUENCE in sources
    if has_acled and has_gdelt:
        analyst_id = AUTO_ANALYST_BOTH
    elif has_acled:
        analyst_id = AUTO_ANALYST_ACLED
    elif has_gdelt:
        analyst_id = AUTO_ANALYST_GDELT
    elif has_llm and has_seq:
        analyst_id = AUTO_ANALYST_MIXED
    elif has_llm:
        analyst_id = AUTO_ANALYST_LLM_INTEL
    elif has_seq:
        analyst_id = AUTO_ANALYST_SEQUENCE
    else:
        analyst_id = AUTO_ANALYST_ACLED  # fallback; should not occur

    if events:
        top = max(events, key=lambda e: e.severity)
        url = top.url or None
        n_acled = sum(1 for e in events if e.source == EvidenceSource.ACLED)
        n_gdelt = sum(1 for e in events if e.source == EvidenceSource.GDELT)
        n_llm = sum(1 for e in events if e.source == EvidenceSource.LLM_INTEL)
        n_seq = sum(1 for e in events if e.source == EvidenceSource.SEQUENCE)
        notes = (
            f"auto-correlation: ACLED={n_acled} GDELT={n_gdelt} "
            f"LLM_INTEL={n_llm} SEQUENCE={n_seq} "
            f"top_severity={top.severity} top={top.summary}"
        )[:_NOTE_TRUNCATE]
    else:
        url, notes = None, "auto-correlation: no corroborating events"

    return analyst_id, url, notes


def _is_high_severity_conclusion(c: Conclusion) -> bool:
    """High-severity = states the tool is confident enough to bet recall on.

    THREAT_LEVEL ≥ 3 or any FIRED ATTACK_MODE qualifies. This intentionally
    does not include TREND/PER_DOMAIN — those are diagnostic surfaces, not
    primary alerts, and auto-labeling them would generate noise without
    feeding Design W's primary recall metric.
    """
    if c.conclusion_type is ConclusionType.THREAT_LEVEL:
        try:
            return int(c.state or "0") >= 3
        except ValueError:
            return False
    if c.conclusion_type is ConclusionType.ATTACK_MODE:
        return bool(c.state) and c.state != "INSUFFICIENT_DATA"
    return False


def _is_quiet_threat_level(c: Conclusion) -> bool:
    """TL=1 — the tool said "calm". The FALSE_NEGATIVE rule keys off this."""
    return (
        c.conclusion_type is ConclusionType.THREAT_LEVEL
        and c.state == "1"
    )


def classify_conclusion(
    conclusion: Conclusion,
    evidence: Iterable[ExternalEvent],
    *,
    participant_countries: Iterable[str],
    now: Optional[float] = None,
    window_hours: Optional[int] = None,
    false_positive_horizon_days: Optional[int] = None,
    false_negative_fatalities_severity: Optional[int] = None,
) -> Optional[AutoFeedback]:
    """Pick the auto-feedback label for ``conclusion``, or ``None`` if no
    rule fires. ``None`` means "the tool's call is consistent with current
    external evidence but we haven't accumulated enough horizon to call it
    a TRUE_NEGATIVE yet" — the next ETL pass will revisit it.

    Rules (ordered; first matching wins):

    1. **FALSE_NEGATIVE** (NP1 critical). TL=1 and ACLED reports any event
       with ``severity >= false_negative_fatalities_severity`` in a
       participant country inside the forward window. The tool stayed quiet
       through a real escalation — this is the failure mode we *most* need
       to surface.
    2. **TRUE_POSITIVE**. Conclusion is high-severity and any qualifying
       event corroborates inside the forward window.
    3. **FALSE_POSITIVE**. Conclusion is high-severity, observed at least
       ``false_positive_horizon_days`` ago, and zero qualifying events
       appear in the forward horizon.
    4. **TRUE_NEGATIVE**. Conclusion is TL=1, observed at least
       ``false_positive_horizon_days`` ago, and zero events. Quiet call,
       quiet world — small but useful for the Design W denominator.

    Otherwise: ``None``.
    """
    now = now if now is not None else time.time()
    window_h = window_hours if window_hours is not None else config.GROUND_TRUTH_WINDOW_HOURS
    fp_horizon_days = (
        false_positive_horizon_days
        if false_positive_horizon_days is not None
        else config.GROUND_TRUTH_FALSE_POSITIVE_HORIZON_DAYS
    )
    fn_severity = (
        false_negative_fatalities_severity
        if false_negative_fatalities_severity is not None
        else config.GROUND_TRUTH_FALSE_NEGATIVE_FATALITIES
    )

    forward_end = conclusion.observed_at + window_h * 3600.0
    horizon_end = conclusion.observed_at + fp_horizon_days * 86400.0
    in_window = _events_in_forward_window(
        evidence,
        start=conclusion.observed_at,
        end=forward_end,
        countries=participant_countries,
    )

    # Rule 1 — FALSE_NEGATIVE (NP1 critical).
    # Two paths to qualify:
    #   (a) Strong path: ≥1 ACLED event with severity ≥ fn_severity
    #   (b) Internal-source substitute (added 2026-04-29 for ACLED-free
    #       deployments): ≥2 distinct internal sources (LLM_INTEL OR
    #       SEQUENCE) corroborate during the forward window. Two distinct
    #       internal confirmations is a deliberately stricter bar than one
    #       ACLED event because LLM_INTEL is LLM-judged (not human-verified)
    #       and SEQUENCE is our own scoring layer's judgment.
    if _is_quiet_threat_level(conclusion):
        critical = [
            e for e in in_window
            if e.source is EvidenceSource.ACLED and e.severity >= fn_severity
        ]
        # Internal substitute: count distinct internal sources confirming.
        internal_sources_present = {
            e.source for e in in_window
            if e.source in (EvidenceSource.LLM_INTEL, EvidenceSource.SEQUENCE)
        }
        if not critical and len(internal_sources_present) >= 2:
            critical = [
                e for e in in_window
                if e.source in (EvidenceSource.LLM_INTEL, EvidenceSource.SEQUENCE)
            ]
        if critical:
            analyst_id, url, notes = _provenance(critical)
            return AutoFeedback(
                conclusion_id=conclusion.id,
                label=FeedbackLabel.FALSE_NEGATIVE,
                analyst_id=analyst_id,
                observed_at=now,
                observed_outcome_url=url,
                notes=notes,
            )

    # Rule 2 — TRUE_POSITIVE.
    if _is_high_severity_conclusion(conclusion) and in_window:
        analyst_id, url, notes = _provenance(in_window)
        return AutoFeedback(
            conclusion_id=conclusion.id,
            label=FeedbackLabel.TRUE_POSITIVE,
            analyst_id=analyst_id,
            observed_at=now,
            observed_outcome_url=url,
            notes=notes,
        )

    # Rules 3 & 4 — only valid if the horizon has fully elapsed.
    horizon_elapsed = now >= horizon_end
    if not horizon_elapsed:
        return None

    in_horizon = _events_in_forward_window(
        evidence,
        start=conclusion.observed_at,
        end=horizon_end,
        countries=participant_countries,
    )

    if _is_high_severity_conclusion(conclusion) and not in_horizon:
        return AutoFeedback(
            conclusion_id=conclusion.id,
            label=FeedbackLabel.FALSE_POSITIVE,
            analyst_id=AUTO_ANALYST_ACLED,
            observed_at=now,
            observed_outcome_url=None,
            notes=(
                f"auto-correlation: no ACLED/GDELT events in "
                f"{fp_horizon_days}d horizon"
            )[:_NOTE_TRUNCATE],
        )

    if _is_quiet_threat_level(conclusion) and not in_horizon:
        return AutoFeedback(
            conclusion_id=conclusion.id,
            label=FeedbackLabel.TRUE_NEGATIVE,
            analyst_id=AUTO_ANALYST_ACLED,
            observed_at=now,
            observed_outcome_url=None,
            notes=(
                f"auto-correlation: TL=1 + zero events over "
                f"{fp_horizon_days}d horizon"
            )[:_NOTE_TRUNCATE],
        )

    return None


# ── graded under-rating classifier (NP1 — independent-evidence FN) ──────────
#
# The classify_conclusion FALSE_NEGATIVE rule above keys off TL==1 ("the tool
# said calm"). In live operation focused scenarios sit at TL≥2 almost always,
# so that binary gate essentially never fires — verified 2026-05-29: 0 FN
# across 360k conclusions, leaving recall structurally pinned at 1.0.
#
# Two root defects it cannot address, and these functions do:
#   1. *Graded under-rating.* NP1 (recall > precision) cares about a TL=2 call
#      made just before a mass-casualty event just as much as a missed TL=1.
#      We compare the tool's contemporaneous TL against the minimum level the
#      event's magnitude warranted, not a single TL==1 trip-wire.
#   2. *Circular evidence.* The internal-source substitute (LLM_INTEL /
#      SEQUENCE) is the SAME signal set the scoring engine consumes — if it
#      fires, the TL rises, so it can never reveal the tool's own blind spot.
#      These functions are driven ONLY by external kinetic evidence (RSS /
#      ACLED fatality counts), which is independent of the tool's sensors.

EXPECTED_TL_MASS_CASUALTY = 4   # fatalities ≥ mass-casualty threshold
EXPECTED_TL_KINETIC = 3         # armed violence (≥1 fatality or kinetic verb)
EXPECTED_TL_ESCALATION = 2      # escalation signal only (mobilization, etc.)


def expected_tl_floor(
    *,
    fatalities: int,
    confidence: float,
    mass_casualty_threshold: Optional[int] = None,
) -> int:
    """Minimum threat level the tool *should* have been showing given an
    external kinetic event of this magnitude.

    Driven by the rss_extractor severity ladder (NP6 — coupling kept
    explicit): confidence 0.85 ⇒ a counted fatality figure, 0.60 ⇒ a kinetic
    verb, 0.40 ⇒ an escalation verb only. Fatalities at/above the
    mass-casualty threshold demand TL≥4; any armed violence TL≥3; a bare
    escalation signal TL≥2.
    """
    threshold = (
        mass_casualty_threshold
        if mass_casualty_threshold is not None
        else config.GROUND_TRUTH_FALSE_NEGATIVE_FATALITIES
    )
    if fatalities >= threshold:
        return EXPECTED_TL_MASS_CASUALTY
    if fatalities >= 1 or confidence >= 0.60:
        return EXPECTED_TL_KINETIC
    return EXPECTED_TL_ESCALATION


def label_for_threat_level(
    *, tool_tl: int, expected_floor: int
) -> FeedbackLabel:
    """Score a THREAT_LEVEL conclusion against an external event's expected
    floor. FALSE_NEGATIVE when the tool under-rated (its TL fell below the
    level the event warranted); TRUE_POSITIVE when it met or exceeded it.

    This is the load-bearing FN-generating path (NP1). It only makes sense
    for THREAT_LEVEL conclusions paired with *independent* external evidence;
    the caller is responsible for both preconditions.
    """
    if tool_tl < expected_floor:
        return FeedbackLabel.FALSE_NEGATIVE
    return FeedbackLabel.TRUE_POSITIVE


# ── DB helpers ────────────────────────────────────────────────────────────


def list_conclusions_in_window(
    db: "RadarDB",
    *,
    since: float,
    until: Optional[float] = None,
    limit: int = 1000,
    conclusion_type: Optional[str] = None,
    newest_first: bool = False,
) -> list[Conclusion]:
    """Pull conclusions observed in [since, until] for the ETL to classify.

    ``conclusion_type`` (e.g. ``"threat_level"``) restricts the scan at the
    SQL layer so the ``limit`` budget is not consumed by diagnostic rows
    (bg_observer / TREND / PER_DOMAIN), which vastly outnumber THREAT_LEVEL.

    ``newest_first`` orders DESC so the ``limit`` captures the *most recent*
    conclusions — required for the RSS correlator, whose feed contains
    current news: only conclusions whose forward window overlaps recent
    events can be labeled, and those are the newest ones. The result is
    re-sorted ascending before return so downstream callers still see a
    forward-walking sequence regardless of the SQL ordering.

    The ACLED/GDELT classifier keeps the default ASC, unfiltered behaviour.
    """
    from radar.conclusions.persistence import _SELECT_COLS, _row_to_conclusion
    until = until if until is not None else time.time()
    sql = f"SELECT {_SELECT_COLS} FROM conclusions WHERE observed_at >= ? AND observed_at <= ?"
    params: list = [since, until]
    if conclusion_type is not None:
        sql += " AND conclusion_type = ?"
        params.append(conclusion_type)
    sql += " ORDER BY observed_at " + ("DESC" if newest_first else "ASC")
    sql += " LIMIT ?"
    params.append(max(1, min(limit, 20000)))
    rows = db._get_conn().execute(sql, params).fetchall()  # noqa: SLF001
    conclusions = [_row_to_conclusion(r) for r in rows]
    if newest_first:
        conclusions.sort(key=lambda c: c.observed_at)
    return conclusions


def has_existing_auto_feedback(
    db: "RadarDB",
    conclusion_id: str,
    analyst_id: str,
) -> bool:
    """Idempotency check: return True iff an auto-feedback row with this
    (conclusion_id, analyst_id) is already in the ledger. Lets the job
    runner re-execute against the same window without producing duplicates.
    """
    row = db._get_conn().execute(  # noqa: SLF001
        "SELECT 1 FROM analyst_feedback WHERE conclusion_id = ? "
        "AND analyst_id = ? LIMIT 1",
        (conclusion_id, analyst_id),
    ).fetchone()
    return row is not None
