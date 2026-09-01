"""K — the v3 kernel: types that make the diagnosed defect classes unrepresentable.

Each type here exists because a specific defect survived review, and in
every case the reason it survived was that the wrong code READ correctly.
Documentation was already tried as the defence and already failed (F-06
hid behind a docstring claiming it matched rss_narrative's logic). So the
discipline is: the wrong expression must not run.

    ThreatLevel   ordering refused; severity() = 6 - TL is the only number
    Ratio         a fraction in [0,1]; no implicit bridge to Percentage
    Percentage    a percentage in [0,100]
    Window        built from days x cadence; a bare sample count is refused
    Threshold     resolved through the registry or pinned with provenance
    Provenance    formula + inputs + sources, immutable
    Evidence      a payload reachable only through a freshness check

Nothing in this package has import-time side effects, and nothing imports
the legacy `radar` package except Threshold.registry_backed, lazily, at
resolution time.
"""
from v3.kernel.errors import (
    DomainError,
    KernelError,
    OrderingForbiddenError,
    ProvenanceRequiredError,
    StaleEvidenceError,
    ThresholdResolutionError,
    UnitMismatchError,
)
from v3.kernel.evidence import Evidence
from v3.kernel.provenance import Provenance
from v3.kernel.threat_level import ThreatLevel
from v3.kernel.threshold import (KNOWN_UNITS, ResolvedThreshold, Threshold)
from v3.kernel.units import Percentage, Ratio
from v3.kernel.window import Window

__all__ = [
    # types
    "ThreatLevel",
    "Ratio",
    "Percentage",
    "Window",
    "Threshold",
    "ResolvedThreshold",
    "KNOWN_UNITS",
    "Provenance",
    "Evidence",
    # errors
    "KernelError",
    "DomainError",
    "UnitMismatchError",
    "OrderingForbiddenError",
    "StaleEvidenceError",
    "ProvenanceRequiredError",
    "ThresholdResolutionError",
]
