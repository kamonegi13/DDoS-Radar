"""WP-2.1 — the kernel discipline gate (scripts/check_kernel_discipline.py).

The kernel enforces its contracts at runtime; this gate catches two of
them earlier and, more importantly, catches them in v3 code that has not
been written yet. A gate nobody tests is a gate that silently stops
matching (G-07 was exactly that shape), so its rules are pinned here.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _gate():
    path = REPO_ROOT / "scripts" / "check_kernel_discipline.py"
    spec = importlib.util.spec_from_file_location("check_kernel_discipline",
                                                  path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_kernel_discipline"] = module
    spec.loader.exec_module(module)
    return module


def _rules(source: str) -> set:
    return {f.rule for f in _gate().scan_source(source, "v3/probe.py")}


class TestDirectEnvReads:
    def test_os_getenv_is_flagged(self):
        assert "direct-env-read" in _rules(
            'import os\nX = os.getenv("GPS_JAM_THRESHOLD", "0.03")\n')

    def test_bare_getenv_is_flagged(self):
        assert "direct-env-read" in _rules(
            'from os import getenv\nX = getenv("K")\n')

    def test_os_environ_is_flagged(self):
        assert "direct-env-read" in _rules('import os\nX = os.environ["K"]\n')

    def test_aliased_os_environ_is_flagged(self):
        assert "direct-env-read" in _rules('import os as _os\nX = _os.environ\n')

    def test_the_message_names_the_sanctioned_alternative(self):
        findings = _gate().scan_source(
            'import os\nX = os.getenv("K")\n', "v3/probe.py")
        assert "Threshold.registry_backed" in findings[0].message


class TestLegacyImports:
    def test_module_scope_radar_import_is_flagged(self):
        assert "legacy-import-at-module-scope" in _rules(
            "from radar import config_layered\n")

    def test_plain_module_scope_radar_import_is_flagged(self):
        assert "legacy-import-at-module-scope" in _rules("import radar.config\n")

    def test_a_lazy_import_inside_a_function_is_allowed(self):
        source = ("def resolve(key):\n"
                  "    from radar import config_layered\n"
                  "    return config_layered.get_config(key)\n")
        assert "legacy-import-at-module-scope" not in _rules(source)

    def test_non_radar_module_scope_imports_are_fine(self):
        assert _rules("import json\nfrom pathlib import Path\n") == set()


class TestThreatLevelHeuristics:
    def test_int_coercion_of_a_threat_level_is_flagged(self):
        assert "threat-level-coercion" in _rules("x = int(threat_level)\n")

    def test_float_coercion_is_flagged(self):
        assert "threat-level-coercion" in _rules("x = float(current_tl)\n")

    def test_ordering_comparison_is_flagged(self):
        assert "threat-level-ordering" in _rules(
            "if threat_level > other:\n    pass\n")

    def test_severity_comparison_is_not_flagged(self):
        assert _rules("if a.severity() > b.severity():\n    pass\n") == set()

    def test_unrelated_names_are_left_alone(self):
        assert _rules("if count > limit:\n    pass\n") == set()

    def test_equality_on_a_threat_level_is_allowed(self):
        assert _rules("if threat_level == other:\n    pass\n") == set()


class TestGateBehaviour:
    def test_the_repository_currently_passes(self):
        assert _gate().main([]) == 0

    def test_a_violating_tree_exits_nonzero(self, tmp_path):
        probe = tmp_path / "bad.py"
        probe.write_text('import os\nX = os.getenv("K")\n', encoding="utf-8")
        assert _gate().main([str(tmp_path)]) == 1

    def test_a_clean_tree_exits_zero(self, tmp_path):
        (tmp_path / "ok.py").write_text("X = 1\n", encoding="utf-8")
        assert _gate().main([str(tmp_path)]) == 0

    def test_a_syntax_error_is_reported_not_swallowed(self, tmp_path):
        (tmp_path / "broken.py").write_text("def (:\n", encoding="utf-8")
        assert _gate().main([str(tmp_path)]) == 1

    def test_a_missing_path_is_not_a_crash(self, tmp_path):
        assert _gate().main([str(tmp_path / "absent")]) == 0

    def test_it_is_wired_into_ci(self):
        script = (REPO_ROOT / "scripts" / "check_ci.sh").read_text(
            encoding="utf-8")
        assert "check_kernel_discipline.py" in script


class TestEnvReadRuleIsAliasProof:
    """Literal-name matching was bypassable three ways. The same lesson as
    config_static_audit: resolve the file's own import bindings instead."""

    def test_from_os_import_environ_without_alias(self):
        assert "direct-env-read" in _rules(
            'from os import environ\nX = environ["K"]\n')

    def test_from_os_import_getenv_with_alias(self):
        assert "direct-env-read" in _rules(
            'from os import getenv as read_env\nX = read_env("K")\n')

    def test_import_os_with_alias(self):
        assert "direct-env-read" in _rules(
            'import os as env_mod\nX = env_mod.getenv("K")\n')

    def test_aliased_environ_subscript(self):
        assert "direct-env-read" in _rules(
            'from os import environ as e\nX = e["K"]\n')

    def test_aliased_environ_get(self):
        assert "direct-env-read" in _rules(
            'import os as m\nX = m.environ.get("K")\n')

    def test_os_environ_setdefault(self):
        assert "direct-env-read" in _rules(
            'import os\nos.environ.setdefault("K", "v")\n')

    def test_an_unrelated_getenv_is_not_flagged(self):
        # A same-named function from somewhere else is not an env read.
        assert "direct-env-read" not in _rules(
            'from mylib import getenv\nX = getenv("K")\n')

    def test_an_unrelated_environ_name_is_not_flagged(self):
        assert "direct-env-read" not in _rules(
            'from mylib import environ\nX = environ["K"]\n')

    def test_a_local_variable_named_environ_is_not_flagged(self):
        assert "direct-env-read" not in _rules(
            'def f(environ):\n    return environ["K"]\n')


class TestValueBypassRule:
    """`tl_a.value > tl_b.value` and `ratio.value >= pct.value` recreate
    both historical defects while touching none of the guarded operators."""

    def test_threat_level_value_comparison_is_flagged(self):
        assert "threat-level-ordering" in _rules(
            "if threat_level.value > other_tl.value:\n    pass\n")

    def test_threat_level_value_coercion_is_flagged(self):
        assert "threat-level-coercion" in _rules("x = int(current_tl.value)\n")

    def test_unit_value_comparison_is_flagged(self):
        assert "unit-value-comparison" in _rules(
            "if jam_ratio.value >= threshold_pct.value:\n    pass\n")

    def test_a_ratio_value_against_a_bare_number_is_flagged(self):
        assert "unit-value-comparison" in _rules(
            "if jam_ratio.value >= 3.0:\n    pass\n")

    def test_comparing_the_types_themselves_is_not_flagged(self):
        assert _rules("if jam_ratio >= threshold:\n    pass\n") == set()

    def test_severity_comparison_stays_clean(self):
        assert _rules(
            "if tl_a.severity() > tl_b.severity():\n    pass\n") == set()

    def test_unrelated_dot_value_is_left_alone(self):
        assert _rules("if row.value > limit.value:\n    pass\n") == set()


class TestResolverSeamRule:
    """resolver= is licensed to ONE file (WP-4.1d).

    It used to be "tests only", because until v3 had its own 3-layer
    chain any injected resolver in production WAS a private configuration
    path. Now the chain exists and the seam is how the composition root
    supplies it — so the rule became a file-scoped licence, exactly like
    the environment licence, rather than a blanket refusal.
    """

    def test_resolver_kwarg_is_flagged_in_v3_code(self):
        assert "unlicensed-resolver-injection" in _rules(
            "x = threshold.resolve(resolver=my_resolver)\n")

    def test_resolver_on_exceeded_by_is_flagged(self):
        assert "unlicensed-resolver-injection" in _rules(
            "x = t.exceeded_by(value, resolver=fake)\n")

    def test_a_plain_resolve_call_is_fine(self):
        assert _rules("x = threshold.resolve()\n") == set()

    def test_tests_are_exempt(self):
        gate = _gate()
        findings = gate.scan_source(
            "x = threshold.resolve(resolver=fake)\n",
            "tests/test_kernel_threshold.py")
        assert {f.rule for f in findings} == set()

    def test_the_one_licensed_file_may_inject(self):
        gate = _gate()
        findings = gate.scan_source(
            "x = threshold.resolve(resolver=chain)\n",
            "v3/config/resolution.py")
        assert {f.rule for f in findings} == set()

    def test_the_licence_does_not_extend_to_the_package(self):
        """Scoped to a file, so a second injector is a new failure."""
        gate = _gate()
        findings = gate.scan_source(
            "x = threshold.resolve(resolver=chain)\n",
            "v3/config/registry.py")
        assert {f.rule for f in findings} == {"unlicensed-resolver-injection"}
