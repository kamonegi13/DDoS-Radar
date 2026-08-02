"""Threat-level severity semantics — the single place that knows the direction.

The TL scale is DEFCON-style, defined by ``radar.scoring.derive_tl``:

    TL1 = CRITICAL   (score ≥ 9, most severe)
    TL2 = SEVERE
    TL3 = HIGH
    TL4 = ELEVATED
    TL5 = NORMAL     (score < 2, calm)

Everyone's intuition says "bigger number = worse"; this scale is the
opposite, and code comparing raw TL integers with ``<``/``>`` has already
produced one calibration disaster (2026-07-03: the ground-truth classifier
was written 5=worst, silently rewarding calm calls during real escalations
for five weeks). Any code that needs to ORDER threat levels must convert
to severity space first via :func:`severity_of` and compare severities —
never raw TLs. ``tests/test_severity.py`` sentinels this contract.
"""

from __future__ import annotations

# Named levels — prefer these over bare integers in comparisons and tests.
TL_CRITICAL = 1
TL_SEVERE = 2
TL_HIGH = 3
TL_ELEVATED = 4
TL_NORMAL = 5

_TL_MIN, _TL_MAX = TL_CRITICAL, TL_NORMAL


def severity_of(tl: int) -> int:
    """Map a DEFCON-style TL (1=CRITICAL … 5=NORMAL) to monotonic severity
    (5=CRITICAL … 1=NORMAL), so that bigger always means worse.

    Raises ``ValueError`` for anything outside 1..5 — an out-of-range TL is
    always a caller bug (e.g. an unparsed state string), and failing fast
    here beats silently mis-grading a conclusion.
    """
    tl_int = int(tl)
    if not _TL_MIN <= tl_int <= _TL_MAX:
        raise ValueError(f"threat level out of range 1..5: {tl!r}")
    return (_TL_MAX + 1) - tl_int
