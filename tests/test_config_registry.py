"""WP-4.1d — the variable-key registry, and the reachability check.

WP-1.2 measured what a registry is worth when nobody reads it: 95 of 98
keys bypassed the resolution chain, so the settings screen wrote override
rows and the tool used something else. The lesson was not "register more"
— P6 O-18 ruled the opposite — it was **a registered key nobody reads is
the defect**.

So v3's registry carries one fact the old one did not: the consumer. And
the check below does not read that field, it EXECUTES it — overriding each
key in turn and asserting the consumed value moves. A registry entry that
nothing consults fails here, which is what stops v3 from growing its own
decorative registry.

The second half is the refusal. Only group-(a) keys are overridable;
group-(b) constants and unknown names are refused with different messages,
because "this exists, is disclosed, and moves by code review" and "this
name is wrong" are different answers and a shrug is neither.
"""
from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

from v3.config import registry as R
from v3.config.resolution import ConfigResolver, SOURCE_OVERRIDE
from v3.kernel import Threshold
from v3.kernel.errors import DomainError
from v3.scoring import thresholds as scoring_thresholds
from v3.scoring.settings import resolve_settings

REPO_ROOT = Path(__file__).resolve().parent.parent


class _EmptyLedger:
    """A ledger with no command rows: the override layer answers nothing."""

    @staticmethod
    def command_records(**_kwargs):
        return []


class _OverriddenLedger:
    """One override row for one key, in the shape `commit()` would write."""

    def __init__(self, key, value, *, at: float = 1_000.0):
        resolver = ConfigResolver()
        after = resolver.project(
            key, override={"value": value, "actor_id": "u-probe",
                           "reason": "reachability probe", "at": at}).as_dict()
        self._rows = [{"action": "config.override", "target_kind": "config",
                       "target_id": key, "after": after, "issued_at": at}]

    def command_records(self, *, target_kind=None, target_id=None,
                        action=None, until=None, **_kwargs):
        return [row for row in self._rows
                if (target_id is None or row["target_id"] == target_id)
                and (target_kind is None or row["target_kind"] == target_kind)]


def _distinct_from(entry: R.RegisteredKey):
    """A value for `entry` that is legal, in range, and not the default."""
    default = entry.default
    if entry.unit == "bool":
        return not default
    if entry.unit == "ratio":
        return round(default / 2.0, 6) if default > 0.1 else 0.9
    return float(default) * 2.0 + 1.0


class TestTheRegistryIsAssembledNotRespelled:
    def test_every_scoring_variable_key_is_registered(self):
        assert set(R.VARIABLE_KEYS) == set(scoring_thresholds.VARIABLE)

    def test_each_entry_carries_the_declaration_it_came_from(self):
        for name, entry in R.VARIABLE_KEYS.items():
            declared = scoring_thresholds.VARIABLE[name]
            assert entry.threshold is declared.threshold
            assert entry.default == declared.default
            assert entry.why == declared.why

    def test_every_entry_is_registry_backed_not_pinned(self):
        for entry in R.VARIABLE_KEYS.values():
            assert entry.threshold.is_registry_backed

    def test_a_pinned_threshold_cannot_be_registered_as_variable(self):
        with pytest.raises(DomainError) as excinfo:
            R.RegisteredKey(
                threshold=Threshold.pinned(1.0, unit="score",
                                           provenance_ref="ref"),
                default=1.0, why="w", consumer="m:f", catalogue="c")
        assert "O-18" in str(excinfo.value)

    def test_an_entry_without_a_consumer_is_refused(self):
        with pytest.raises(DomainError) as excinfo:
            R.RegisteredKey(
                threshold=Threshold.registry_backed("K", unit="score"),
                default=1.0, why="w", consumer="  ", catalogue="c")
        assert "consumer" in str(excinfo.value)

    def test_a_prose_consumer_is_refused_because_it_cannot_be_executed(self):
        with pytest.raises(DomainError) as excinfo:
            R.RegisteredKey(
                threshold=Threshold.registry_backed("K", unit="score"),
                default=1.0, why="w",
                consumer="read by the scoring tick", catalogue="c")
        assert "module:callable" in str(excinfo.value)


class TestOnlyVariableKeysAreOverridable:
    """O-18's partition, enforced rather than described."""

    def test_a_variable_key_passes(self):
        R.refuse_if_not_variable("DOMAIN_CAP")

    def test_a_pinned_key_is_refused_with_its_provenance(self):
        with pytest.raises(DomainError) as excinfo:
            R.refuse_if_not_variable("TL1_SCORE_FLOOR")
        message = str(excinfo.value)
        assert "pinned" in message
        assert "S1-SCORE-004" in message, \
            "a refusal that does not say where the value comes from is a shrug"
        assert "G-15" in message

    def test_an_unknown_key_is_refused_as_unknown(self):
        with pytest.raises(DomainError) as excinfo:
            R.refuse_if_not_variable("NO_SUCH_KEY_WP41D")
        assert "unknown configuration key" in str(excinfo.value)

    def test_the_two_refusals_are_distinguishable(self):
        """A pinned key exists and moves by review; an unknown one does
        not exist. Collapsing the two is how an analyst comes to believe
        a dial is there."""
        with pytest.raises(DomainError) as pinned:
            R.refuse_if_not_variable("TL2_SCORE_FLOOR")
        with pytest.raises(DomainError) as unknown:
            R.refuse_if_not_variable("TL2_SCORE_FLOOOR")
        assert str(pinned.value) != str(unknown.value)

    def test_an_empty_key_is_refused(self):
        with pytest.raises(DomainError):
            R.refuse_if_not_variable("")

    def test_the_pinned_catalogue_covers_all_three_layers(self):
        pinned = R.pinned_disclosure()
        assert "TL1_SCORE_FLOOR" in pinned          # scoring
        assert set(pinned) >= set(scoring_thresholds.pinned_names())
        catalogues = {body["catalogue"] for body in pinned.values()}
        assert catalogues == {"scoring", "conclusions", "calibration"}


class TestValueCoercionRefusesTheShapesThatLie:
    def test_a_bool_key_refuses_an_integer(self):
        with pytest.raises(DomainError) as excinfo:
            R.coerce_value("GLOBAL_SIGNALS_DECOUPLED", 1)
        assert "real boolean" in str(excinfo.value)

    def test_a_numeric_key_refuses_a_bool(self):
        with pytest.raises(DomainError):
            R.coerce_value("DOMAIN_CAP", True)

    def test_a_ratio_key_refuses_a_percent_scaled_number(self):
        """F-08's shape: 3.0 on a [0,1] dial."""
        with pytest.raises(DomainError):
            R.coerce_value("LLM_INTEL_PRIMARY_THRESHOLD", 3.0)

    def test_a_ratio_key_accepts_a_fraction_and_returns_a_json_primitive(self):
        value = R.coerce_value("LLM_INTEL_PRIMARY_THRESHOLD", 0.6)
        assert value == pytest.approx(0.6)
        assert type(value) is float

    def test_a_non_finite_value_is_refused(self):
        with pytest.raises(DomainError) as excinfo:
            R.coerce_value("DOMAIN_CAP", float("nan"))
        assert "never exceeded" in str(excinfo.value)

    def test_coercion_refuses_a_pinned_key_before_any_value_check(self):
        with pytest.raises(DomainError) as excinfo:
            R.coerce_value("TL1_SCORE_FLOOR", 9.0)
        assert "pinned" in str(excinfo.value)

    def test_the_env_layer_parses_strings_and_refuses_nonsense(self):
        assert R.coerce_env_value("GLOBAL_SIGNALS_DECOUPLED", "false") is False
        assert R.coerce_env_value("DOMAIN_CAP", "7.5") == 7.5
        with pytest.raises(DomainError):
            R.coerce_env_value("GLOBAL_SIGNALS_DECOUPLED", "maybe")
        with pytest.raises(DomainError):
            R.coerce_env_value("DOMAIN_CAP", "six")


def _consumer_parts(entry: R.RegisteredKey):
    module_name, _, function_name = entry.consumer.partition(":")
    return module_name, function_name


def _module_path(module_name: str) -> Path:
    return REPO_ROOT / (module_name.replace(".", "/") + ".py")


def _names_bound_to_registry_keys(tree: ast.Module) -> dict:
    """{module-level name -> config key} for `X = Threshold.registry_backed`."""
    bound: dict = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        call = node.value
        if not isinstance(call, ast.Call) or not call.args:
            continue
        callee = call.func
        if not (isinstance(callee, ast.Attribute)
                and callee.attr == "registry_backed"):
            continue
        first = call.args[0]
        if not (isinstance(first, ast.Constant)
                and isinstance(first.value, str)):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                bound[target.id] = first.value
    return bound


def _function_named(tree: ast.Module, name: str):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name == name:
            return node
    return None


def keys_referenced_by(entry: R.RegisteredKey) -> set:
    """Every config key the declared consumer's body names.

    A key is "named" either as a string literal — `values["DOMAIN_CAP"]` —
    or through a module-level alias bound to
    `Threshold.registry_backed("KEY")`, which is how an adapter refers to
    its own dial. Iteration over the registry counts too: a consumer that
    walks `VARIABLE` names every key in it, so the iteration source is
    resolved to the registry it iterates.
    """
    module_name, function_name = _consumer_parts(entry)
    path = _module_path(module_name)
    if not path.exists():
        return set()
    tree = ast.parse(path.read_text(encoding="utf-8"))
    node = _function_named(tree, function_name)
    if node is None:
        return set()
    aliases = _names_bound_to_registry_keys(tree)
    found: set = set()
    walks_the_registry = False
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            found.add(child.value)
        elif isinstance(child, ast.Name):
            if child.id in aliases:
                found.add(aliases[child.id])
            if child.id == "VARIABLE":
                walks_the_registry = True
    if walks_the_registry:
        found |= set(R.VARIABLE_KEYS)
    return found


class TestEveryVariableKeyIsActuallyConsulted:
    """THE reachability check — WP-1.2's finding, made structural in v3.

    Three tests, escalating in strength: the consumer exists, the consumer
    NAMES the key, and — the one that would have caught G-15 — overriding
    the key CHANGES what the consumer produces.
    """

    def test_every_key_declares_a_consumer_that_exists(self):
        for name, entry in R.VARIABLE_KEYS.items():
            module_name, function_name = _consumer_parts(entry)
            module = importlib.import_module(module_name)
            assert callable(getattr(module, function_name, None)), \
                f"{name}'s declared consumer {entry.consumer} is not callable"

    def test_every_key_is_named_by_its_consumer(self):
        for name, entry in R.VARIABLE_KEYS.items():
            assert name in keys_referenced_by(entry), (
                f"{name} is registered as operationally variable but its "
                f"declared consumer {entry.consumer} never names it. That is "
                f"defect G-15 in miniature: a dial the settings screen shows "
                f"and the code does not read.")

    def test_a_consumer_that_does_not_name_its_key_is_detected(self):
        """The mutation. Without it, the test above proves nothing about
        the check — only about today's registry."""
        planted = R.RegisteredKey(
            threshold=Threshold.registry_backed("KEY_NOBODY_READS",
                                                unit="score"),
            default=1.0, why="planted by the reachability test",
            consumer="v3.scoring.settings:_positive", catalogue="planted")
        assert "KEY_NOBODY_READS" not in keys_referenced_by(planted)

    def test_a_consumer_module_that_does_not_exist_is_detected(self):
        planted = R.RegisteredKey(
            threshold=Threshold.registry_backed("KEY_NOBODY_READS",
                                                unit="score"),
            default=1.0, why="planted", consumer="v3.no.such:function",
            catalogue="planted")
        assert keys_referenced_by(planted) == set()

    @pytest.mark.parametrize("key", sorted(R.VARIABLE_KEYS))
    def test_overriding_the_key_changes_what_the_consumer_produces(self, key):
        """Executed, not read. This is the only form of the check that
        could have caught G-15, where every static signal looked right.

        The consumer is run twice through the real chain — once with no
        override and once with one — and the disclosed settings must
        differ. A key the consumer resolves but ignores fails here.
        """
        entry = R.VARIABLE_KEYS[key]
        chain = ConfigResolver()
        baseline = resolve_settings(
            chain.settings_resolver(ledger=_EmptyLedger())).disclosed()

        overridden_value = _distinct_from(entry)
        ledger = _OverriddenLedger(key, R.coerce_value(key, overridden_value))
        assert chain.resolve(key, ledger=ledger).source == SOURCE_OVERRIDE
        after = resolve_settings(
            chain.settings_resolver(ledger=ledger)).disclosed()

        changed = [field for field in baseline
                   if baseline[field] != after[field]]
        assert changed, (
            f"{key} is registered as operationally variable, but overriding "
            f"it changed nothing the consumer produces. A registered key "
            f"nobody reads is the defect (WP-1.2 / G-15).")
        assert len(changed) == 1, (
            f"overriding {key} moved {changed}; one dial should move one "
            f"value, or the disclosure record cannot be attributed")
