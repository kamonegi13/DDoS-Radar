"""WP-4.1d — v3's own 3-layer chain, and the licence that keeps it one.

WP-4.1c established the blocker in the strongest available form: it did
not say "C7 has not landed yet", it said **C7 must not land**, because
`Threshold.registry_backed` terminated in legacy `radar.config_layered` and
an override written on the v3 side would have been read by nothing. The
ruling that unblocked it — the kernel keeps taking a resolver, the
composition root supplies the chain — is what these tests exercise.

Three properties, and each has a mutation:

  1. **The layer that answered is a fact, not an inference.** Override
     beats env beats default, and `source` says which. G-15's damage was
     that nobody could see nothing was reading the override rows.
  2. **The chain is built, never snapshotted at import.** A composition
     root that reads the environment on import makes every test process a
     configured process.
  3. **Exactly one module injects a resolver.** The seam is licensed to
     `v3/config/resolution.py` by file, like the environment licence, and
     the sweep below proves no sibling inherited it.
"""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from v3.config import registry as R
from v3.config.resolution import (ConfigResolver, ConfigValue, LAYERS,
                                  SOURCE_DEFAULT, SOURCE_ENV, SOURCE_OVERRIDE)
from v3.kernel import Threshold
from v3.kernel.errors import DomainError
from v3.runtime import config as runtime_config

REPO_ROOT = Path(__file__).resolve().parent.parent
KEY = "DOMAIN_CAP"
FLAG_KEY = "GLOBAL_SIGNALS_DECOUPLED"


class _Ledger:
    """A `command_records` stub in the shape the store returns."""

    def __init__(self, rows=()):
        self._rows = list(rows)

    def command_records(self, *, target_kind=None, target_id=None,
                        action=None, until=None, **_kwargs):
        return [row for row in self._rows
                if (target_kind is None or row["target_kind"] == target_kind)
                and (target_id is None or row["target_id"] == target_id)
                and (action is None or row["action"] == action)
                and (until is None or row["issued_at"] <= until)]


def _override_row(key, value, *, at, action="config.override",
                  resolver=None):
    chain = resolver or ConfigResolver()
    override = (None if action == "config.clear" else
                {"value": value, "actor_id": "u-1", "reason": "r", "at": at})
    return {"action": action, "target_kind": "config", "target_id": key,
            "issued_at": at, "after": chain.project(key,
                                                    override=override).as_dict()}


class TestTheLayerThatAnsweredIsCarriedOut:
    def test_nothing_set_answers_from_the_default(self):
        value = ConfigResolver().resolve(KEY, ledger=_Ledger())
        assert value.source == SOURCE_DEFAULT
        assert value.value == R.default_of(KEY)
        assert value.env_present is False

    def test_the_environment_outranks_the_default(self):
        chain = ConfigResolver({KEY: "7.5"})
        value = chain.resolve(KEY, ledger=_Ledger())
        assert (value.source, value.value) == (SOURCE_ENV, 7.5)
        assert value.env_present is True

    def test_an_override_outranks_the_environment(self):
        chain = ConfigResolver({KEY: "7.5"})
        ledger = _Ledger([_override_row(KEY, 9.0, at=10.0, resolver=chain)])
        value = chain.resolve(KEY, ledger=ledger)
        assert (value.source, value.value) == (SOURCE_OVERRIDE, 9.0)
        assert value.override["actor_id"] == "u-1"
        assert value.env_present is True, \
            "the env layer is still disclosed even when it does not win"

    def test_clearing_returns_the_key_to_the_layer_below(self):
        chain = ConfigResolver({KEY: "7.5"})
        ledger = _Ledger([_override_row(KEY, 9.0, at=10.0, resolver=chain),
                          _override_row(KEY, None, at=20.0,
                                        action="config.clear",
                                        resolver=chain)])
        value = chain.resolve(KEY, ledger=ledger)
        assert (value.source, value.value) == (SOURCE_ENV, 7.5)
        assert value.override is None

    def test_the_fold_is_bounded_in_time_so_replay_and_live_agree(self):
        chain = ConfigResolver()
        ledger = _Ledger([_override_row(KEY, 9.0, at=10.0, resolver=chain)])
        assert chain.resolve(KEY, ledger=ledger, at=5.0).source == \
            SOURCE_DEFAULT
        assert chain.resolve(KEY, ledger=ledger, at=10.0).source == \
            SOURCE_OVERRIDE

    def test_a_bool_key_resolves_through_every_layer(self):
        assert ConfigResolver().resolve(
            FLAG_KEY, ledger=_Ledger()).value is True
        assert ConfigResolver({FLAG_KEY: "off"}).resolve(
            FLAG_KEY, ledger=_Ledger()).value is False

    def test_an_unparseable_environment_value_raises_rather_than_defaults(
            self):
        """Silently preferring the default is how an operator comes to
        believe the variable they exported is in effect."""
        with pytest.raises(DomainError):
            ConfigResolver({KEY: "not-a-number"}).resolve(KEY,
                                                          ledger=_Ledger())

    def test_a_pinned_key_cannot_be_resolved_through_this_chain(self):
        with pytest.raises(DomainError) as excinfo:
            ConfigResolver().resolve("TL1_SCORE_FLOOR", ledger=_Ledger())
        assert "pinned" in str(excinfo.value)

    def test_an_unknown_layer_name_is_refused_by_the_type(self):
        with pytest.raises(DomainError) as excinfo:
            ConfigValue(key=KEY, value=1.0, source="somewhere", unit="score",
                        default=1.0, why="w", consumer="m:f")
        assert "G-15" in str(excinfo.value)

    def test_the_layers_are_ordered_highest_first(self):
        assert LAYERS == (SOURCE_OVERRIDE, SOURCE_ENV, SOURCE_DEFAULT)

    def test_resolve_all_covers_the_whole_registry(self):
        values = ConfigResolver().resolve_all(ledger=_Ledger())
        assert [v.key for v in values] == list(R.variable_keys())


class TestTheProjectionIsShared:
    """`apply` and `resolve` must agree, or `commit()` refuses everything.

    They agree because they are the same function with the override
    supplied two ways. A second implementation would agree with itself.
    """

    def test_a_projected_override_equals_the_folded_one(self):
        chain = ConfigResolver({KEY: "7.5"})
        override = {"value": 9.0, "actor_id": "u-1", "reason": "r", "at": 10.0}
        projected = chain.project(KEY, override=override).as_dict()
        ledger = _Ledger([{"action": "config.override", "target_kind": "config",
                           "target_id": KEY, "issued_at": 10.0,
                           "after": projected}])
        assert chain.resolve(KEY, ledger=ledger, at=10.0).as_dict() == projected

    def test_the_projection_is_json_round_trippable(self):
        import json
        projected = ConfigResolver().project(
            KEY, override={"value": 9.0, "actor_id": "u", "reason": None,
                           "at": 1.0}).as_dict()
        assert json.loads(json.dumps(projected)) == projected

    def test_the_projection_carries_no_wall_clock(self):
        """A `time.time()` stamp anywhere in here would make the effect
        check compare two instants and refuse every command."""
        first = ConfigResolver().project(KEY, override=None).as_dict()
        second = ConfigResolver().project(KEY, override=None).as_dict()
        assert first == second


class TestTheKernelSeam:
    def test_a_registry_backed_threshold_resolves_through_the_chain(self):
        chain = ConfigResolver({KEY: "7.5"})
        resolved = chain.resolve_threshold(
            R.entry_for(KEY).threshold, ledger=_Ledger())
        assert resolved.value == 7.5
        assert resolved.source == SOURCE_ENV
        assert resolved.key == KEY

    def test_a_pinned_threshold_passes_straight_through(self):
        pinned = Threshold.pinned(3.0, unit="score", provenance_ref="ref")
        resolved = ConfigResolver().resolve_threshold(pinned,
                                                      ledger=_Ledger())
        assert resolved.source == "pinned"

    def test_the_seam_refuses_a_non_threshold(self):
        with pytest.raises(DomainError):
            ConfigResolver().resolve_threshold("DOMAIN_CAP", ledger=_Ledger())

    def test_the_resolver_is_immutable(self):
        chain = ConfigResolver()
        with pytest.raises(DomainError):
            chain._environment = {}

    def test_the_environment_layer_takes_strings_only(self):
        with pytest.raises(DomainError):
            ConfigResolver({KEY: 7.5})

    def test_environment_keys_names_what_the_env_can_answer_for(self):
        chain = ConfigResolver({KEY: "7.5", "UNRELATED": "x"})
        assert chain.environment_keys == (KEY,)


class TestTheCompositionRootOwnsTheChain:
    def test_build_resolver_reads_exactly_the_registered_keys(self,
                                                              monkeypatch):
        seen = {}

        def fake(key_ids):
            seen["key_ids"] = tuple(key_ids)
            return {KEY: "7.5"}

        monkeypatch.setattr("v3.runtime.secrets.from_environment", fake)
        chain = runtime_config.build_resolver()
        assert seen["key_ids"] == R.variable_keys()
        assert chain.resolve(KEY, ledger=_Ledger()).source == SOURCE_ENV

    def test_the_environment_names_are_derived_from_the_registry(self):
        assert runtime_config.environment_key_names() == R.variable_keys()

    def test_an_explicit_mapping_bypasses_the_environment_entirely(self):
        chain = runtime_config.build_resolver({KEY: "8.0"})
        assert chain.resolve(KEY, ledger=_Ledger()).value == 8.0

    def test_importing_the_factory_reads_no_environment_variable(self):
        proc = subprocess.run(
            [sys.executable, "-c",
             "import os\n"
             "class Tripwire(dict):\n"
             "    def __getitem__(self, key):\n"
             "        raise AssertionError('os.environ read at import')\n"
             "    def get(self, key, default=None):\n"
             "        raise AssertionError('os.environ read at import')\n"
             "os.environ = Tripwire()\n"
             "import v3.runtime.config, v3.config.resolution\n"
             "print('inert')"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=180)
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "inert"


def _modules_passing_the_resolver_kwarg() -> list:
    """Parsed, not grepped: several docstrings NAME the kwarg."""
    offenders = []
    for path in sorted((REPO_ROOT / "v3").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and any(
                    kw.arg == "resolver" for kw in node.keywords):
                offenders.append(path.relative_to(REPO_ROOT).as_posix())
    return sorted(set(offenders))


class TestTheResolverLicenceIsScopedToOneFile:
    """The same shape as the environment licence, for the same reason.

    `os.getenv` available everywhere is how 95 of 98 keys became unread. A
    resolver constructible anywhere is the same hazard one layer up: a
    private configuration path that no other reader can see.
    """

    def test_the_gate_names_exactly_one_resolver_owner(self, discipline_gate):
        assert discipline_gate._RESOLVER_OWNER == "v3/config/resolution.py"

    def test_exactly_two_modules_under_v3_pass_the_seam(self):
        """The chain, plus the kernel module that DEFINES the seam and
        forwards it internally (`exceeded_by` -> `resolve`)."""
        assert _modules_passing_the_resolver_kwarg() == [
            "v3/config/resolution.py", "v3/kernel/threshold.py"]

    def test_the_gate_still_passes_over_all_of_v3(self, discipline_gate):
        assert discipline_gate.main(["v3"]) == 0

    def test_the_owner_may_inject(self, discipline_gate):
        findings = discipline_gate.scan_source(
            "threshold.resolve(resolver=chain)\n",
            "v3/config/resolution.py")
        assert [f.rule for f in findings] == []

    @pytest.mark.parametrize("path", [
        "v3/runtime/config.py",
        "v3/config/registry.py",
        "v3/scoring/settings.py",
        "v3/api/handlers/config.py",
        "v3/adapters/info/rss_narrative.py",
    ])
    def test_no_sibling_inherits_the_injection_licence(self, path,
                                                       discipline_gate):
        findings = discipline_gate.scan_source(
            "threshold.resolve(resolver=chain)\n", path)
        assert {f.rule for f in findings} == {"unlicensed-resolver-injection"}

    def test_the_settings_injection_point_is_not_called_resolver(self):
        """Two differently-scoped things sharing a name is how a licence
        gets inherited by accident."""
        import inspect

        from v3.scoring.settings import resolve_settings
        parameters = inspect.signature(resolve_settings).parameters
        assert "resolver" not in parameters
        assert "resolve_threshold" in parameters
