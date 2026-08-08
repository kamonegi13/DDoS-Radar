"""Label epochs — the series break, made into a type.

Three calibration disasters produced two hard discontinuities in the label
population: 2026-07-04 (the TL inversion remediation, after a classifier
had scored 5=worst for five weeks) and 2026-08-02 (the cross-scenario
attribution repair, after supporting-role mentions had pulled other
conflicts' articles into a scenario's ground truth). Numbers on either
side of those dates are not the same measurement.

The rule "do not compare across the break" existed, and existed only as
procedure. F-16 measured the result: `docs/baselines/recall_metrics.json`
still carries `since: null`, so the CI gate has been comparing the whole
history against itself across both breaks. WP-1.4 built the audit that can
SEE that; S5-VERIF-033 asks for something stronger — the comparison must
be refused by the machine.

A validating check is not that. `compare(baseline, current)` that raises
on mismatched epochs is one forgotten call site away from being F-16
again, and the whole reason this layer is dangerous is that its failures
pass every test. So the refusal lives in the shape of the API instead:

    * a label carries `LabelProvenance` — generator id, generator version,
      rule id, epoch id — as structured fields (S5-VERIF-032);
    * a snapshot carries `EpochStamp` — the epoch it was computed under
      plus a window that may not be open-ended (`since` cannot be None,
      which is the literal shape of F-16);
    * two snapshots become comparable only by forming an `AlignedPair`,
      whose constructor is the only place epochs are checked;
    * every comparison entry point takes the PAIR, and has no parameter
      that would accept two loose snapshots.

There is therefore no expression in this package that compares across
epochs. Not "none that we found" — none that type-checks.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from v3.kernel.errors import DomainError


class EpochMismatchError(DomainError):
    """Two measurements that belong to different label populations.

    A subclass of DomainError so a caller that catches domain errors
    broadly still fails closed (ADR-V3-006), and a distinct type so the
    gate can say "re-baseline" rather than "invalid input".
    """


def _require_text(value, *, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DomainError(
            f"label provenance {name} must be a non-empty string, got "
            f"{value!r}: S5-VERIF-032 requires provenance in structured "
            f"columns, and an empty column is the free-text convention it "
            f"replaces")
    return value.strip()


@dataclass(frozen=True, slots=True)
class LabelEpoch:
    """One continuous label population.

    `generators` is the set of `generator_id:generator_version` pairs whose
    output belongs to this epoch. It is what makes "advance the epoch when
    the generator's semantics change" enforceable rather than aspirational:
    a new generator version has nowhere to be stamped until it is declared
    against an epoch, and declaring it against a NEW epoch is the cheap
    path. See `LabelProvenance.__post_init__`.
    """

    epoch_id: str
    started_at: float
    reason: str
    generators: frozenset
    is_quarantined: bool = False

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "LabelEpoch is final: a subclass could relax the generator "
            "declaration that makes an epoch advance enforceable.")

    def accepts(self, generator_id: str, generator_version: str) -> bool:
        return f"{generator_id}:{generator_version}" in self.generators


# ── the registry ────────────────────────────────────────────────────────
#
# Three epochs, each dated from the remediation that ended the previous
# population. `pre_2026_07_04` exists so that old rows have somewhere
# truthful to point; it is quarantined, which means it can be READ and
# never COMPARED.
_EPOCHS: dict[str, LabelEpoch] = {entry.epoch_id: entry for entry in (
    LabelEpoch(
        epoch_id="pre_2026_07_04",
        # 2026-05-29T00:00:00Z — incident #1's purge, the first date at
        # which any surviving label could have been written.
        started_at=1780012800.0,
        reason="blanket-TP (incident #1) and the TL inversion (incident "
               "#2) both fell inside this window: FN was identically 0 "
               "for one and the classifier scored 5=worst for the other. "
               "The rows are measurement artefacts.",
        generators=frozenset({"rss_etl:1", "ground_truth_etl:1"}),
        is_quarantined=True),
    LabelEpoch(
        epoch_id="e2026_07_04",
        # 2026-07-04T00:00:00Z, the inversion remediation restart.
        started_at=1783123200.0,
        reason="restart after the TL inversion repair (incident #2): "
               "severity space forced, episode granularity introduced, "
               "freshness and relevance gates added.",
        generators=frozenset({"rss_etl:2", "ground_truth_etl:2"}),
        is_quarantined=False),
    LabelEpoch(
        epoch_id="e2026_08_02",
        # 2026-08-02T00:00:00Z, the cross-scenario attribution repair.
        started_at=1785628800.0,
        reason="restart after the cross-scenario attribution repair "
               "(incident #3): attribution narrowed to conflict-party "
               "roles, kinetic tier made to require an action verb, the "
               "freshness gate keyed by direction.",
        generators=frozenset({"rss_etl:3", "ground_truth_etl:3",
                              "human_anchor:1"}),
        is_quarantined=False),
)}

#: The epoch new labels are written under.
CURRENT_EPOCH: LabelEpoch = _EPOCHS["e2026_08_02"]


def registered_epoch_ids() -> tuple[str, ...]:
    return tuple(sorted(_EPOCHS, key=lambda k: _EPOCHS[k].started_at))


def epoch(epoch_id: str) -> LabelEpoch:
    """Resolve an epoch id, or refuse.

    Refusing an unknown id is what stops a caller inventing an epoch to
    make two incomparable snapshots line up.
    """
    if epoch_id not in _EPOCHS:
        raise DomainError(
            f"{epoch_id!r} is not a registered label epoch; known epochs "
            f"are {list(registered_epoch_ids())}. An epoch is declared in "
            f"v3/calibration/epoch.py together with the remediation that "
            f"started it — inventing one at a call site would make the "
            f"comparison guard bypassable (F-16).")
    return _EPOCHS[epoch_id]


def epoch_at(timestamp: float) -> LabelEpoch:
    """The epoch a label observed at `timestamp` belongs to."""
    latest: Optional[LabelEpoch] = None
    for entry in _EPOCHS.values():
        if timestamp >= entry.started_at:
            if latest is None or entry.started_at > latest.started_at:
                latest = entry
    if latest is None:
        raise DomainError(
            f"timestamp {timestamp!r} predates every registered label "
            f"epoch; there is no population it belongs to")
    return latest


@dataclass(frozen=True, slots=True)
class LabelProvenance:
    """S5-VERIF-032's four structured columns, on every label."""

    generator_id: str
    generator_version: str
    rule_id: str
    epoch_id: str

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "LabelProvenance is final: a subclass could relax the epoch "
            "declaration that F-16's repair rests on.")

    def __post_init__(self) -> None:
        object.__setattr__(self, "generator_id",
                           _require_text(self.generator_id,
                                         name="generator_id"))
        object.__setattr__(self, "generator_version",
                           _require_text(self.generator_version,
                                         name="generator_version"))
        object.__setattr__(self, "rule_id",
                           _require_text(self.rule_id, name="rule_id"))
        object.__setattr__(self, "epoch_id",
                           _require_text(self.epoch_id, name="epoch_id"))
        declared = epoch(self.epoch_id)
        if not declared.accepts(self.generator_id, self.generator_version):
            raise DomainError(
                f"generator_version {self.generator_version!r} of "
                f"{self.generator_id!r} is not declared against epoch "
                f"{self.epoch_id!r}. S5-VERIF-032: a change to the label "
                f"generator's semantics advances the epoch. Declare the "
                f"new version against a NEW epoch in "
                f"v3/calibration/epoch.py — stamping it onto the old one "
                f"would silently merge two populations, which is what "
                f"incidents #2 and #3 did.")

    @property
    def epoch(self) -> LabelEpoch:
        return _EPOCHS[self.epoch_id]

    def as_dict(self) -> dict:
        return {"generator_id": self.generator_id,
                "generator_version": self.generator_version,
                "rule_id": self.rule_id, "epoch_id": self.epoch_id}

    def __reduce__(self):
        return (type(self), (self.generator_id, self.generator_version,
                             self.rule_id, self.epoch_id))


@dataclass(frozen=True, slots=True)
class EpochStamp:
    """The epoch and window a recall snapshot was computed under.

    `since` is required. F-16 is literally a null in this position: the
    checked-in baseline says `since: null`, meaning all history, meaning
    the gate compares across both series breaks every time it runs.
    """

    epoch_id: str
    since: float
    until: float
    exclude_auto: bool

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "EpochStamp is final: a subclass could reintroduce the "
            "open-ended window that is F-16.")

    def __post_init__(self) -> None:
        declared = epoch(_require_text(self.epoch_id, name="epoch_id"))
        object.__setattr__(self, "epoch_id", declared.epoch_id)
        for name in ("since", "until"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise DomainError(
                    f"EpochStamp {name} must be a unix timestamp, got "
                    f"{value!r}. `since=None` means all history, which is "
                    f"the exact shape of F-16 — the baseline has carried "
                    f"it across two series breaks.")
            object.__setattr__(self, name, float(value))
        if self.until <= self.since:
            raise DomainError(
                f"EpochStamp window is empty or inverted: since="
                f"{self.since} until={self.until}")
        if self.since < declared.started_at:
            raise DomainError(
                f"window predates its own epoch: since={self.since} is "
                f"before {self.epoch_id} started at "
                f"{declared.started_at}. The rows in that overhang belong "
                f"to a different label population.")
        if not isinstance(self.exclude_auto, bool):
            raise DomainError(
                f"EpochStamp exclude_auto must be a bool, got "
                f"{self.exclude_auto!r}")

    @property
    def epoch(self) -> LabelEpoch:
        return _EPOCHS[self.epoch_id]

    def as_dict(self) -> dict:
        return {"epoch_id": self.epoch_id, "since": self.since,
                "until": self.until, "exclude_auto": self.exclude_auto}

    def __reduce__(self):
        return (type(self), (self.epoch_id, self.since, self.until,
                             self.exclude_auto))


@dataclass(frozen=True, slots=True)
class AlignedPair:
    """Two snapshots proven to measure the same population.

    This is the ONLY way two snapshots meet in this package. Comparison
    functions take `pair: AlignedPair` and have no parameter that would
    accept a loose baseline and a loose current — so a cross-epoch
    comparison is not something a caller can forget to guard, it is
    something a caller cannot write.
    """

    baseline: EpochStamp
    current: EpochStamp

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "AlignedPair is final: a subclass could weaken the alignment "
            "proof, and the proof is the whole mechanism (F-16).")

    def __post_init__(self) -> None:
        for name in ("baseline", "current"):
            value = getattr(self, name)
            if not isinstance(value, EpochStamp):
                raise DomainError(
                    f"AlignedPair {name} must be an EpochStamp, got "
                    f"{type(value).__name__}")
        if self.baseline.epoch_id != self.current.epoch_id:
            raise EpochMismatchError(
                f"cannot compare a {self.baseline.epoch_id} baseline "
                f"against a {self.current.epoch_id} measurement: the "
                f"label populations differ "
                f"({self.current.epoch.reason}). Re-baseline under "
                f"{self.current.epoch_id} first — a comparison across a "
                f"series break reports a change in the ruler as a change "
                f"in the thing measured (F-16 / S5-VERIF-036).")
        if self.baseline.epoch.is_quarantined:
            raise EpochMismatchError(
                f"epoch {self.baseline.epoch_id} is quarantined and "
                f"cannot back a comparison at all: "
                f"{self.baseline.epoch.reason} Rows from it may be read "
                f"for forensics; they may not be measured against.")
        if self.baseline.exclude_auto != self.current.exclude_auto:
            raise EpochMismatchError(
                f"exclude_auto differs between the two sides "
                f"({self.baseline.exclude_auto} vs "
                f"{self.current.exclude_auto}); the current side inherits "
                f"the baseline's value (S1-CALIB-029). Comparing a "
                f"human-only recall against a mixed one measures the "
                f"label mix, not the tool.")

    @property
    def epoch(self) -> LabelEpoch:
        return self.baseline.epoch

    def __reduce__(self):
        return (type(self), (self.baseline, self.current))


def aligned_windows(pair: AlignedPair) -> dict:
    """The window parameters a comparison must run under.

    The current side inherits the baseline's window length and
    `exclude_auto` (S1-CALIB-029). Taking the PAIR rather than two
    snapshots is the point: see the class docstring.
    """
    if not isinstance(pair, AlignedPair):
        raise DomainError(
            f"aligned_windows needs an AlignedPair, got "
            f"{type(pair).__name__}: the pair IS the proof that the two "
            f"sides measure the same population")
    return {"epoch_id": pair.epoch.epoch_id,
            "exclude_auto": pair.baseline.exclude_auto,
            "baseline_window": (pair.baseline.since, pair.baseline.until),
            "current_window": (pair.current.since, pair.current.until)}


__all__ = ["LabelEpoch", "LabelProvenance", "EpochStamp", "AlignedPair",
           "EpochMismatchError", "CURRENT_EPOCH", "epoch", "epoch_at",
           "registered_epoch_ids", "aligned_windows"]
