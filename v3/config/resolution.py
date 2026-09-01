"""v3's own 3-layer resolution: override -> env -> default.

WP-4.1c found the blocker and stated it exactly: `Threshold.registry_backed`
already takes an injected resolver, but with none injected it terminates in
legacy `radar.config_layered`. So an override written on the v3 side would
not be read by the path that answers, `commit()`'s effect verification would
fail every time, and shipping C7 in that state would have been G-15 reproduced
rather than repaired.

The ruling: **the kernel stays pure and the composition root supplies the
chain.** This module is that chain. The kernel keeps taking a resolver and
never imports L1; the root builds one of these
(`v3/runtime/config.py::build_resolver`) with an environment snapshot it read
through the one licensed reader, and injects it wherever v3 resolves a
threshold.

Three layers, highest first:

    override   an operator's change, folded out of `command_record`
               (`v3/commands/state.py`). Append-only, actor-stamped,
               reason-required — the history IS the record, and there is no
               second copy of the value to disagree with it.
    env        the process environment, snapshotted ONCE by the composition
               root. Same variable names production reads, so a deployment
               that exports one gets the same number here.
    default    the value declared beside the formula that consumes it.

**The layer that answered travels with the value.** `ConfigValue.source` is
the whole lesson of G-15: the registry was decorative because nobody could
see that nothing read it. A number without its layer is a number you cannot
audit, so R14 serves the layer and `commit()` verifies against it.

This is the ONE module under `v3/` that passes `resolver=` to
`Threshold.resolve`. The licence is scoped to this FILE by
`scripts/check_kernel_discipline.py::_RESOLVER_OWNER`, exactly as the
environment licence is scoped to `v3/runtime/secrets.py`, and
`tests/test_config_resolution.py` sweeps all of `v3/` by AST to prove no
second module became an injector. A package-wide exemption would put a
private configuration path back within reach of every module, which is the
shape the rule exists to prevent.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Optional

from v3.commands import state as command_state
from v3.config import registry
from v3.kernel import Threshold
from v3.kernel.errors import DomainError

#: The three layers, highest priority first. Spelled once.
SOURCE_OVERRIDE = "override"
SOURCE_ENV = "env"
SOURCE_DEFAULT = "default"
LAYERS: tuple[str, ...] = (SOURCE_OVERRIDE, SOURCE_ENV, SOURCE_DEFAULT)


@dataclass(frozen=True, slots=True)
class ConfigValue:
    """One key's effective value, and the account of how it got there.

    Every field is a JSON primitive or a mapping of them. That is not a
    convenience: this value's `as_dict()` is what a `config` command stores
    as its `after` and what the read-back compares against, and a type that
    does not survive `json.dumps`/`loads` would compare unequal to itself
    forever.

    There is deliberately no wall-clock stamp. `Threshold.resolve()` puts
    `time.time()` on its result, which is right for a disclosure record and
    fatal for an equality check — the effect verification would compare two
    instants and refuse every command.
    """

    key: str
    value: Any
    source: str
    unit: str
    default: Any
    why: str
    consumer: str
    #: `{value, actor_id, reason, at}` or None. Present even when the env
    #: layer wins, so "an override exists but something above it answers"
    #: is never a state the operator has to infer. (It cannot happen —
    #: override is the top layer — but the field being unconditional is
    #: what makes that checkable rather than assumed.)
    override: Optional[Mapping[str, Any]] = None
    #: Whether the environment holds this key at all. Disclosed separately
    #: from `source`, because "the env layer did not win" and "the env
    #: layer is empty" are different operational facts and the second one
    #: is the one that gets deployments wrong.
    env_present: bool = False

    def __post_init__(self) -> None:
        if self.source not in LAYERS:
            raise DomainError(
                f"unknown resolution layer {self.source!r}; the chain is "
                f"{list(LAYERS)}. A value whose layer is unnamed is a value "
                f"nobody can audit, which is defect G-15 exactly.")
        if self.override is not None:
            object.__setattr__(self, "override", dict(self.override))

    def as_dict(self) -> dict:
        return {"key": self.key, "value": self.value, "source": self.source,
                "unit": self.unit, "default": self.default, "why": self.why,
                "consumer": self.consumer,
                "override": None if self.override is None
                else dict(self.override),
                "env_present": self.env_present}


class ConfigResolver:
    """The chain. Built by the composition root, injected everywhere else.

    Immutable and clock-free. The environment snapshot arrives as a plain
    mapping so a test builds one without touching `os.environ` and so the
    root can layer several stores before calling — the same shape, and for
    the same reason, as `v3/runtime/secrets.py::resolve`.
    """

    __slots__ = ("_environment",)

    def __init__(self, environment: Optional[Mapping[str, str]] = None):
        material = {} if environment is None else dict(environment)
        for name, value in material.items():
            if not isinstance(value, str):
                raise DomainError(
                    f"the environment layer holds strings; {name} is a "
                    f"{type(value).__name__}. Parsing is this module's job "
                    f"and it has to be able to fail loudly.")
        object.__setattr__(self, "_environment",
                           MappingProxyType(
                               {k: v for k, v in material.items() if v.strip()}))

    def __setattr__(self, name: str, value) -> None:
        raise DomainError(
            f"a ConfigResolver is immutable; setting {name!r} would let a "
            f"caller re-point the chain after a value had been served "
            f"against it")

    def __repr__(self) -> str:
        return (f"ConfigResolver<{len(registry.VARIABLE_KEYS)} keys, "
                f"{len(self._environment)} from env>")

    @property
    def environment_keys(self) -> tuple[str, ...]:
        """Which variable keys the env layer can answer for. Never values."""
        return tuple(sorted(name for name in self._environment
                            if registry.is_variable(name)))

    # ── the chain ──────────────────────────────────────────────────────
    def project(self, key: str, *,
                override: Optional[Mapping[str, Any]]) -> ConfigValue:
        """Resolve `key` against a SUPPLIED override rather than the ledger.

        The write half. `apply` computes what the state will become from
        the override it is about to append; `resolve` recomputes it from
        the override the ledger now holds; `commit()` refuses unless the
        two agree. That comparison is the effect verification, and it is
        only worth anything because both sides come through this one
        function — a second implementation would agree with itself.
        """
        declared = registry.entry_for(key)
        env_raw = self._environment.get(key)
        common = {"key": key, "unit": declared.unit,
                  "default": declared.default, "why": declared.why,
                  "consumer": declared.consumer,
                  "env_present": env_raw is not None}
        if override is not None:
            return ConfigValue(value=override["value"],
                               source=SOURCE_OVERRIDE,
                               override=dict(override), **common)
        if env_raw is not None:
            return ConfigValue(value=registry.coerce_env_value(key, env_raw),
                               source=SOURCE_ENV, override=None, **common)
        return ConfigValue(value=declared.default, source=SOURCE_DEFAULT,
                           override=None, **common)

    def resolve(self, key: str, *, ledger, at: Optional[float] = None
                ) -> ConfigValue:
        """Resolve `key` through all three layers, ledger included.

        `ledger` is the read seam the API serves from, and `at` bounds the
        override fold — so "what was DOMAIN_CAP at T" is this same call
        with `at=T`. Replay and live are one projection on the config
        surface too (P7 derivation principle 4).
        """
        registry.refuse_if_not_variable(key)
        return self.project(
            key, override=command_state.config_override(ledger, key,
                                                        until=at))

    def resolve_all(self, *, ledger, at: Optional[float] = None
                    ) -> tuple[ConfigValue, ...]:
        return tuple(self.resolve(key, ledger=ledger, at=at)
                     for key in registry.variable_keys())

    def value_of(self, key: str, *, ledger, at: Optional[float] = None) -> Any:
        return self.resolve(key, ledger=ledger, at=at).value

    # ── the kernel seam ────────────────────────────────────────────────
    def threshold_resolver(self, *, ledger, at: Optional[float] = None):
        """A `(key) -> (value, source)` callable for `Threshold.resolve`.

        This is the shape the kernel already accepts. Handing it out here
        rather than teaching the kernel about ledgers is what keeps K pure:
        `v3/kernel/threshold.py` imports nothing of L1 and never learns
        that an override layer exists.
        """
        def answer(key: str) -> tuple:
            resolved = self.resolve(key, ledger=ledger, at=at)
            return (resolved.value, resolved.source)
        return answer

    def resolve_threshold(self, threshold: Threshold, *, ledger,
                          at: Optional[float] = None):
        """`Threshold` in, `ResolvedThreshold` out, through THIS chain.

        The one call site of the `resolver=` seam in production code. A
        pinned threshold passes straight through — `Threshold.resolve`
        never consults a resolver for one — so a caller may hand this
        function either shape without asking which it has.
        """
        if not isinstance(threshold, Threshold):
            raise DomainError(
                f"resolve_threshold takes a Threshold, got "
                f"{type(threshold).__name__}")
        return threshold.resolve(
            resolver=self.threshold_resolver(ledger=ledger, at=at))

    def settings_resolver(self, *, ledger, at: Optional[float] = None):
        """The injection `v3.scoring.settings.resolve_settings` expects."""
        def answer(threshold: Threshold):
            return self.resolve_threshold(threshold, ledger=ledger, at=at)
        return answer


__all__ = ["ConfigResolver", "ConfigValue", "LAYERS", "SOURCE_OVERRIDE",
           "SOURCE_ENV", "SOURCE_DEFAULT"]
