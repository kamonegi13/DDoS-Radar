"""Human-anchor candidate selection — the missing human leg of calibration.

Why this exists (2026-07-04): every calibration metric in this system is
computed from auto-generated labels (RSS/GDELT correlation), and the
auto-labeler itself has now shipped two consecutive silent defects
(blanket-TP 2026-05-29, TL-scale inversion 2026-07-03) that no metric
could catch — because the grader and the graded were the same machinery.
A small, steady stream of HUMAN labels is the only structural fix: it
anchors recall to an independent judgment and makes auto-label drift
detectable (disagreement rate between auto and human labels).

Design (AP1 + AP2): the tool proposes a short weekly queue of the
conclusions whose human label buys the most calibration information,
each with a deterministic template rationale. The analyst answers via
the existing per-conclusion feedback endpoint — one click, no new
ledger. A conclusion with any human feedback row is considered answered
and leaves the queue.

Selection kinds, in priority order:

  1. ``auto_fn_review`` — a conclusion the auto-labeler called
     FALSE_NEGATIVE this week. FN is the NP1-critical class AND the one
     the inverted classifier got exactly backwards; human confirmation
     here directly validates (or refutes) the recall metric.
  2. ``peak_severity`` — the most severe THREAT_LEVEL call per scenario
     this week. Verifies the top of the tool's output where alert
     credibility lives.
  3. ``calm_anchor`` — the newest calm-side call (TL4/TL5) whose
     FALSE_POSITIVE horizon has fully elapsed. Human TN/FP labels are
     the scarcest class (TN≈0 historically), and without negatives the
     precision column of the confusion matrix is meaningless.

Pure module: no Flask, no scheduler. NP3 — selection failures degrade to
an empty list, never raise into the route.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional
from urllib.parse import quote_plus

from radar import config
from radar.conclusions.feedback import FeedbackLabel
from radar.conclusions.severity import severity_of

if TYPE_CHECKING:
    from radar.database import RadarDB

log = logging.getLogger("radar.conclusions.human_anchor")

DEFAULT_QUEUE_LIMIT = 5
DEFAULT_WINDOW_DAYS = 7


@dataclass(frozen=True)
class AnchorCandidate:
    conclusion_id:    str
    scenario_id:      str
    conclusion_type:  str
    state:            str
    observed_at:      float
    kind:             str          # auto_fn_review | peak_severity | calm_anchor
    rationale:        str          # AP2 — deterministic template, no LLM
    suggested_labels: tuple[str, ...]


# ── natural-language answering model (2026-07-05 UX) ────────────────────────
#
# Analysts must never think in TP/FP/TN/FN — those are a DERIVED quantity
# (tool's call × reality). The analyst knows only what happened in the real
# world; the tool knows what IT concluded. So we ask ONE natural question
# ("did a real escalation occur?") and derive the confusion-matrix cell from
# the tool's own stance. This is AP2 (plain-language self-explanation) and
# strictly more transparent than presenting the four cells raw.

_TL_NAMES = {1: "CRITICAL", 2: "SEVERE", 3: "HIGH", 4: "ELEVATED", 5: "NORMAL"}
# severity ≥ 3 ⇔ TL ≤ 3 (HIGH / SEVERE / CRITICAL) counts as an alert.
_ALERT_MIN_SEVERITY = 3

# Analyst-facing prose. The UI is Japanese-only (docs/design/ja-localization.md);
# these strings are rendered in the AP3 labeling panel, not logged.
_SCENARIO_ESCALATION_HINT = {
    "taiwan_contingency": "中国 — 台湾間の軍事エスカレーション",
    "eastern_europe":     "ロシア — ウクライナ間のエスカレーション",
    "middle_east":        "イスラエル — イラン / 代理勢力のエスカレーション",
    "korean_peninsula":   "朝鮮半島での軍事エスカレーション",
    "south_china_sea":    "南シナ海での軍事エスカレーション",
}

# Search terms per scenario — full country names for good news recall,
# kept separate from the prose hint above.
_SCENARIO_SEARCH_TERMS = {
    "taiwan_contingency": "Taiwan China military",
    "eastern_europe":     "Russia Ukraine",
    "middle_east":        "Israel Iran",
    "korean_peninsula":   "North Korea South Korea military",
    "south_china_sea":    "South China Sea military",
}

_DEFAULT_SEARCH_URL = "https://www.google.com/search?tbm=nws&q={query}"


def search_url_for(candidate: AnchorCandidate) -> str:
    """One-click external news-search deep link for verifying whether a
    real escalation occurred in the candidate's forward window.

    This automates the RESEARCH (query construction), never the JUDGMENT:
    the link opens in the analyst's own browser and nothing is ingested
    back into the tool, so the human's answer stays an independent signal —
    the entire reason the anchor exists (an LLM/ETL ground-truth check
    reading the same public feeds would recreate the correlated blind spot
    that broke calibration twice). The engine is a config template
    (``HUMAN_ANCHOR_SEARCH_URL``) with a ``{query}`` placeholder so
    OPSEC-conscious deployments can point it elsewhere.
    """
    terms = _SCENARIO_SEARCH_TERMS.get(
        candidate.scenario_id, candidate.scenario_id.replace("_", " "))
    window_h = config.GROUND_TRUTH_WINDOW_HOURS
    after = time.strftime("%Y-%m-%d", time.gmtime(candidate.observed_at))
    # +1 day margin so the last day of the forward window is fully included.
    before = time.strftime(
        "%Y-%m-%d",
        time.gmtime(candidate.observed_at + window_h * 3600 + 86400),
    )
    query = f"{terms} escalation after:{after} before:{before}"
    template = getattr(config, "HUMAN_ANCHOR_SEARCH_URL", _DEFAULT_SEARCH_URL)
    return template.replace("{query}", quote_plus(query))


@dataclass(frozen=True)
class AnchorAnswer:
    """One natural-language answer + the confusion-matrix label it records."""
    label:         str    # button text the analyst reads
    maps_to:       str    # FeedbackLabel value posted to the feedback API
    is_escalation: bool   # answer asserts a real escalation happened
    tone:          str     # 'escalation' | 'quiet' — for button styling


@dataclass(frozen=True)
class AnswerModel:
    question:          str
    tool_stance:       str    # 'alert' | 'calm'
    tool_stance_label: str    # plain language, e.g. 'raised a HIGH alert'
    options:           tuple[AnchorAnswer, ...]


def _tool_stance(conclusion_type: str, state: str) -> tuple[str, str]:
    """Return (stance, plain-language label). stance ∈ {alert, calm}."""
    if conclusion_type == "threat_level":
        try:
            tl = int(state)
        except (TypeError, ValueError):
            return "calm", "明確な判断を出していない"
        name = _TL_NAMES.get(tl, f"TL{tl}")
        if severity_of(tl) >= _ALERT_MIN_SEVERITY:
            return "alert", f"{name} の警戒を発していた"
        return "calm", f"平穏と判断していた（{name}）"
    # attack_mode and other event-shaped types
    if state and state != "INSUFFICIENT_DATA":
        return "alert", f"{state} を検知していた"
    return "calm", "攻撃を検知していない"


def answer_model_for(candidate: AnchorCandidate) -> AnswerModel:
    """Build the natural-language question + answer options for one
    candidate. The analyst answers whether a real escalation occurred; the
    TP/FP/TN/FN label is derived here from the tool's own stance."""
    stance, stance_label = _tool_stance(
        candidate.conclusion_type, candidate.state)
    hint = _SCENARIO_ESCALATION_HINT.get(
        candidate.scenario_id, "国家間エスカレーション")
    window_days = max(1, config.GROUND_TRUTH_WINDOW_HOURS // 24)
    question = (
        f"この時点から約 {window_days} 日以内に、{hint}は実際に起きましたか?"
    )
    if stance == "alert":
        # Tool alerted: reality-occurred ⇒ TP, reality-quiet ⇒ FP.
        yes_label = FeedbackLabel.TRUE_POSITIVE.value
        no_label = FeedbackLabel.FALSE_POSITIVE.value
    else:
        # Tool calm: reality-occurred ⇒ the miss (FN), reality-quiet ⇒ TN.
        yes_label = FeedbackLabel.FALSE_NEGATIVE.value
        no_label = FeedbackLabel.TRUE_NEGATIVE.value
    options = (
        AnchorAnswer(
            label="はい — エスカレーションが起きた",
            maps_to=yes_label, is_escalation=True, tone="escalation"),
        AnchorAnswer(
            label="いいえ — 平穏なままだった",
            maps_to=no_label, is_escalation=False, tone="quiet"),
    )
    return AnswerModel(
        question=question, tool_stance=stance,
        tool_stance_label=stance_label, options=options)


def _human_labeled_ids(conn) -> set[str]:
    rows = conn.execute(
        "SELECT DISTINCT conclusion_id FROM analyst_feedback "
        "WHERE analyst_id NOT LIKE 'auto:%'"
    ).fetchall()
    return {str(r[0]) for r in rows}


def _auto_fn_candidates(conn, *, since: float, now: float,
                        answered: set[str]) -> list[AnchorCandidate]:
    rows = conn.execute(
        "SELECT c.id, c.scenario_id, c.conclusion_type, c.state, "
        "       c.observed_at, f.notes "
        "FROM analyst_feedback f "
        "JOIN conclusions c ON c.id = f.conclusion_id "
        "WHERE f.analyst_id LIKE 'auto:%' AND f.label = 'FALSE_NEGATIVE' "
        "AND f.observed_at BETWEEN ? AND ? "
        "ORDER BY f.observed_at DESC",
        (since, now),
    ).fetchall()
    out: list[AnchorCandidate] = []
    seen_scenarios: set[str] = set()
    for r in rows:
        cid, sid = str(r[0]), str(r[1])
        if cid in answered or sid in seen_scenarios:
            continue
        seen_scenarios.add(sid)
        evidence = (r[5] or "")[:120]
        out.append(AnchorCandidate(
            conclusion_id=cid,
            scenario_id=sid,
            conclusion_type=str(r[2]),
            state=str(r[3]),
            observed_at=float(r[4]),
            kind="auto_fn_review",
            rationale=(
                f"自動ラベラーは、ここで外部事象を過小評価した"
                f"（FALSE_NEGATIVE）と判定している — NP1 上もっとも重い"
                f"見逃しの類型。見逃しを追認するか、自動ラベルを否定するかを"
                f"判断すること。自動ラベルの根拠: {evidence}"
            ),
            suggested_labels=("FALSE_NEGATIVE", "TRUE_POSITIVE"),
        ))
    return out


def _peak_severity_candidates(conn, *, since: float, now: float,
                              answered: set[str]) -> list[AnchorCandidate]:
    rows = conn.execute(
        "SELECT id, scenario_id, state, observed_at FROM conclusions "
        "WHERE conclusion_type = 'threat_level' "
        "AND observed_at BETWEEN ? AND ? "
        "AND state IN ('1','2','3','4','5') "
        "ORDER BY observed_at DESC",
        (since, now),
    ).fetchall()
    best: dict[str, tuple] = {}  # scenario -> (severity, row)
    for r in rows:
        sev = severity_of(int(r[2]))
        sid = str(r[1])
        if sid not in best or sev > best[sid][0]:
            best[sid] = (sev, r)
    out: list[AnchorCandidate] = []
    for sid, (sev, r) in sorted(best.items()):
        cid = str(r[0])
        if cid in answered:
            continue
        out.append(AnchorCandidate(
            conclusion_id=cid,
            scenario_id=sid,
            conclusion_type="threat_level",
            state=str(r[2]),
            observed_at=float(r[3]),
            kind="peak_severity",
            rationale=(
                f"今週の {sid} で最も深刻な脅威レベル判定 "
                f"(TL{r[2]}、深刻度 {sev}/5)。実際に起きたことに照らして、"
                f"この水準は妥当だったか。警戒の信頼性が問われる"
                f"出力の上端を、この 1 件で固定する。"
            ),
            suggested_labels=("TRUE_POSITIVE", "FALSE_POSITIVE"),
        ))
    return out


def _calm_anchor_candidates(conn, *, now: float, window_days: int,
                            answered: set[str]) -> list[AnchorCandidate]:
    horizon_days = config.GROUND_TRUTH_FALSE_POSITIVE_HORIZON_DAYS
    newest = now - horizon_days * 86400.0
    oldest = newest - window_days * 86400.0
    rows = conn.execute(
        "SELECT id, scenario_id, state, observed_at FROM conclusions "
        "WHERE conclusion_type = 'threat_level' "
        "AND state IN ('4','5') "
        "AND observed_at BETWEEN ? AND ? "
        "ORDER BY observed_at DESC",
        (oldest, newest),
    ).fetchall()
    out: list[AnchorCandidate] = []
    seen_scenarios: set[str] = set()
    for r in rows:
        cid, sid = str(r[0]), str(r[1])
        if cid in answered or sid in seen_scenarios:
            continue
        seen_scenarios.add(sid)
        out.append(AnchorCandidate(
            conclusion_id=cid,
            scenario_id=sid,
            conclusion_type="threat_level",
            state=str(r[2]),
            observed_at=float(r[3]),
            kind="calm_anchor",
            rationale=(
                f"平穏側の判定 (TL{r[2]})。検証期間 {horizon_days} 日が"
                f"完全に経過している。実際に平穏なままだったなら "
                f"TRUE_NEGATIVE、エスカレーションが続いたなら "
                f"FALSE_NEGATIVE。人手による negative は最も不足している"
                f"ラベル類型であり、これが無いと混同行列の precision 側は"
                f"意味を持たない。"
            ),
            suggested_labels=("TRUE_NEGATIVE", "FALSE_NEGATIVE"),
        ))
    return out


def select_anchor_candidates(
    db: "RadarDB",
    *,
    now: Optional[float] = None,
    window_days: int = DEFAULT_WINDOW_DAYS,
    limit: int = DEFAULT_QUEUE_LIMIT,
) -> list[AnchorCandidate]:
    """Deterministic weekly queue: interleave kinds by priority until
    ``limit``. Empty list on any DB error (NP3)."""
    n = float(now) if now is not None else time.time()
    since = n - window_days * 86400.0
    try:
        conn = db._get_conn()  # noqa: SLF001
        answered = _human_labeled_ids(conn)
        pools = [
            _auto_fn_candidates(conn, since=since, now=n,
                                answered=answered),
            _peak_severity_candidates(conn, since=since, now=n,
                                      answered=answered),
            _calm_anchor_candidates(
                conn, now=n, window_days=window_days, answered=answered,
            ),
        ]
    except Exception as exc:
        log.warning("human_anchor selection degraded: %s", exc)
        return []

    out: list[AnchorCandidate] = []
    seen_ids: set[str] = set()
    for pool in pools:
        for cand in pool:
            if len(out) >= limit:
                return out
            if cand.conclusion_id in seen_ids:
                continue
            seen_ids.add(cand.conclusion_id)
            out.append(cand)
    return out


def human_label_count(db: "RadarDB", *, since: float) -> int:
    """How many human feedback rows landed since ``since`` (progress vs
    the weekly target). 0 on DB error."""
    try:
        row = db._get_conn().execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM analyst_feedback "
            "WHERE analyst_id NOT LIKE 'auto:%' AND observed_at >= ?",
            (since,),
        ).fetchone()
        return int(row[0]) if row else 0
    except Exception:
        return 0
