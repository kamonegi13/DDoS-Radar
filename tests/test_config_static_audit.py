"""WP-1.2 — static half of the config reachability audit (S5-VERIF-013/014).

Defect G-15: of the registry-registered config keys, almost all are read
through a channel that bypasses the 3-layer resolution chain (DB override
-> env -> default). Analysts edit a value in SETTINGS, an override row and
an audit row are written, the UI shows the new number, and no code path
ever reads it.

Two layers of tests here:

  1. Unit tests of the AST extractor against synthetic sources — they pin
     the classification rules independently of the repo's current state.
  2. The acceptance test of WP-1.2 完了条件 2/3: run the classifier over
     the real repository and require it to reproduce the enumeration of
     S1-CONF-008 / S1-CONF-009 exactly.

The acceptance numbers are deliberately hard-coded. If they drift, that is
either a classifier regression or a real change in the codebase — both are
findings, and neither may be papered over by loosening the assertion.
"""
import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

import pytest

import radar.config  # noqa: F401  — populates the declarative registry
from radar import config_layered
from radar.config_layered import ConfigKey
from radar.verification import config_static_audit as csa


def _sites(source: str, rel_path: str = "radar/sensors/probe.py"):
    return csa.extract_sites(source, rel_path)


def _by_channel(sites, channel):
    return [s for s in sites if s.channel == channel]


# ── extractor unit tests ────────────────────────────────────────────────────
class TestExtractor:
    def test_direct_getenv_in_production_module(self):
        sites = _sites('import os\nX = os.getenv("FOO", "1")\n')
        direct = _by_channel(sites, csa.CHANNEL_DIRECT_READ)
        assert [(s.key, s.line, s.default_literal) for s in direct] == \
            [("FOO", 2, "1")]

    def test_aliased_import_is_detected(self):
        sites = _sites('import os as _os\nY = float(_os.getenv("BAR", "3.0"))\n')
        assert [s.key for s in _by_channel(sites, csa.CHANNEL_DIRECT_READ)] == ["BAR"]

    def test_bare_getenv_call_is_detected(self):
        sites = _sites('from os import getenv\nZ = getenv("BAZ")\n')
        direct = _by_channel(sites, csa.CHANNEL_DIRECT_READ)
        assert [s.key for s in direct] == ["BAZ"]
        assert direct[0].has_default_literal is False

    def test_config_py_module_scope_is_the_frozen_constant_channel(self):
        sites = _sites('import os\nFOO = os.getenv("FOO", "1")\n',
                       rel_path=csa.FROZEN_CONSTANT_MODULE)
        assert [s.channel for s in sites] == [csa.CHANNEL_FROZEN_CONSTANT]

    def test_config_py_frozen_channel_ignores_the_assignment_name(self):
        # SSL_VERIFY is read into SSL_VERIFY_ENV and post-processed. It is
        # still an import-time constant, so name equality must not gate the
        # channel (this exact site is why S1 counts 71 frozen keys, not 70).
        sites = _sites('import os\nSSL_VERIFY_ENV = os.getenv("SSL_VERIFY", "true").lower()\n',
                       rel_path=csa.FROZEN_CONSTANT_MODULE)
        assert [(s.key, s.channel) for s in sites] == \
            [("SSL_VERIFY", csa.CHANNEL_FROZEN_CONSTANT)]

    def test_config_py_function_scope_is_a_direct_read(self):
        source = 'import os\ndef f():\n    return os.getenv("FOO", "1")\n'
        sites = _sites(source, rel_path=csa.FROZEN_CONSTANT_MODULE)
        assert [s.channel for s in sites] == [csa.CHANNEL_DIRECT_READ]

    def test_resolution_reader_is_detected_both_call_shapes(self):
        source = (
            'from radar.config_layered import get_config\n'
            'import radar.config_layered as cl\n'
            'def f():\n'
            '    return get_config("FOO"), cl.get_config("BAR")\n'
        )
        res = _by_channel(_sites(source), csa.CHANNEL_RESOLUTION)
        assert sorted(s.key for s in res) == ["BAR", "FOO"]

    def test_dynamic_key_is_counted_not_dropped(self):
        source = 'import os\ndef f(name):\n    return os.getenv(name)\n'
        sites = _sites(source)
        assert [s.channel for s in sites] == [csa.CHANNEL_DYNAMIC]
        assert sites[0].key is None

    def test_config_layered_module_is_excluded(self):
        source = 'import os\ndef f(k):\n    return os.getenv("FOO")\n'
        assert _sites(source, rel_path="radar/config_layered.py") == ()

    # ── import-binding resolution (review FIX 4) ────────────────────────────
    def test_any_os_alias_is_resolved_not_only_the_known_ones(self):
        # `import os as env_mod` used to be invisible: neither a direct read
        # nor a dynamic site, i.e. a silently dropped bypass.
        sites = _sites('import os as env_mod\nX = env_mod.getenv("K", "1")\n')
        assert [(s.key, s.channel) for s in sites] == \
            [("K", csa.CHANNEL_DIRECT_READ)]

    def test_getenv_through_an_unresolvable_receiver_is_surfaced(self):
        source = 'def f(mod):\n    return mod.getenv("K")\n'
        assert [s.channel for s in _sites(source)] == [csa.CHANNEL_DYNAMIC]

    def test_bare_getenv_without_an_os_import_is_not_a_direct_read(self):
        source = 'from mylib import getenv\nX = getenv("K")\n'
        assert [s.channel for s in _sites(source)] == [csa.CHANNEL_DYNAMIC]

    def test_environ_alias_get_is_a_direct_read(self):
        sites = _sites('from os import environ as env2\nX = env2.get("K", "1")\n')
        assert [(s.key, s.channel) for s in sites] == \
            [("K", csa.CHANNEL_DIRECT_READ)]

    def test_environ_alias_subscript_is_a_direct_read(self):
        sites = _sites('from os import environ as env2\nX = env2["K"]\n')
        assert [(s.key, s.channel) for s in sites] == \
            [("K", csa.CHANNEL_DIRECT_READ)]

    def test_get_config_on_an_unrelated_receiver_is_not_resolution(self):
        # A coincidentally-named method must not mask a bypass by counting
        # as a resolution reader.
        source = 'def f(client):\n    return client.get_config("K")\n'
        sites = _sites(source)
        assert [s.channel for s in sites] == [csa.CHANNEL_DYNAMIC]

    def test_module_aliased_get_config_is_resolution(self):
        source = ('import radar.config_layered as cl\n'
                  'def f():\n    return cl.get_config("K")\n')
        assert [(s.key, s.channel) for s in _sites(source)] == \
            [("K", csa.CHANNEL_RESOLUTION)]

    def test_fully_dotted_get_config_is_resolution(self):
        source = ('import radar.config_layered\n'
                  'def f():\n    return radar.config_layered.get_config("K")\n')
        assert [(s.key, s.channel) for s in _sites(source)] == \
            [("K", csa.CHANNEL_RESOLUTION)]

    def test_from_package_import_module_get_config_is_resolution(self):
        source = ('from radar import config_layered\n'
                  'def f():\n    return config_layered.get_config("K")\n')
        assert [(s.key, s.channel) for s in _sites(source)] == \
            [("K", csa.CHANNEL_RESOLUTION)]

    def test_relative_import_of_get_config_is_resolution(self):
        source = ('from .config_layered import get_config\n'
                  'def f():\n    return get_config("K")\n')
        assert [(s.key, s.channel) for s in _sites(source)] == \
            [("K", csa.CHANNEL_RESOLUTION)]

    def test_function_local_import_still_binds(self):
        source = ('def f():\n    import os\n    return os.getenv("K")\n')
        assert [s.channel for s in _sites(source)] == [csa.CHANNEL_DIRECT_READ]

    def test_environ_subscript_in_config_py_module_scope_is_frozen(self):
        sites = _sites('import os\nX = os.environ["K"]\n',
                       rel_path=csa.FROZEN_CONSTANT_MODULE)
        assert [s.channel for s in sites] == [csa.CHANNEL_FROZEN_CONSTANT]

    def test_environ_write_is_not_a_read(self):
        sites = _sites('import os\ndef f(v):\n    os.environ["K"] = v\n')
        assert sites == ()

    def test_non_literal_default_is_flagged_without_a_value(self):
        source = ('import os\n'
                  'p = os.getenv("PLUGIN_DIR", os.path.join("a", "b"))\n')
        site = _by_channel(_sites(source), csa.CHANNEL_DIRECT_READ)[0]
        assert site.has_default_literal is False
        assert site.default_literal is None

    def test_implicitly_concatenated_default_is_one_literal(self):
        source = 'import os\nX = os.getenv("NODES",\n    "a,"\n    "b")\n'
        site = _by_channel(_sites(source), csa.CHANNEL_DIRECT_READ)[0]
        assert site.default_literal == "a,b"

    def test_syntax_error_does_not_raise(self):
        assert _sites("def broken(:\n") == ()


# ── classification unit tests ───────────────────────────────────────────────
def _key(name: str, **kw) -> ConfigKey:
    kw.setdefault("domain", "test")
    kw.setdefault("default", "d")
    kw.setdefault("type_", "str")
    return ConfigKey(key=name, **kw)


class TestClassification:
    def _audit(self, tmp_path, files: dict, keys):
        for rel, src in files.items():
            path = tmp_path / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(src, encoding="utf-8")
        return csa.audit(root=tmp_path, keys=keys)

    def test_resolution_only_is_full(self, tmp_path):
        res = self._audit(
            tmp_path,
            {"radar/a.py": 'from radar.config_layered import get_config\n'
                           'v = get_config("A")\n'},
            [_key("A")])
        assert res.keys["A"].verdict == csa.CLASS_FULL

    def test_both_channels_is_partial(self, tmp_path):
        res = self._audit(
            tmp_path,
            {"radar/a.py": 'import os\n'
                           'from radar.config_layered import get_config\n'
                           'x = os.getenv("A", "1")\n'
                           'v = get_config("A")\n'},
            [_key("A")])
        assert res.keys["A"].verdict == csa.CLASS_PARTIAL

    def test_bypass_only_is_bypassed(self, tmp_path):
        res = self._audit(tmp_path,
                          {"radar/a.py": 'import os\nx = os.getenv("A", "1")\n'},
                          [_key("A")])
        assert res.keys["A"].verdict == csa.CLASS_BYPASSED

    def test_no_consumer_at_all_is_dead(self, tmp_path):
        res = self._audit(tmp_path, {"radar/a.py": "x = 1\n"}, [_key("A")])
        assert res.keys["A"].verdict == csa.CLASS_DEAD

    def test_unregistered_resolution_read_is_reported(self, tmp_path):
        res = self._audit(
            tmp_path,
            {"radar/a.py": 'from radar.config_layered import get_config\n'
                           'v = get_config("GHOST")\n'},
            [_key("A")])
        assert "GHOST" in res.unregistered_resolution_reads
        assert "GHOST" not in res.keys

    def test_dynamic_sites_are_surfaced(self, tmp_path):
        res = self._audit(
            tmp_path,
            {"radar/a.py": 'import os\ndef f(k):\n    return os.getenv(k)\n'},
            [_key("A")])
        assert len(res.dynamic_getenv_sites) == 1

    def test_counts_cover_every_registered_key(self, tmp_path):
        res = self._audit(
            tmp_path,
            {"radar/a.py": 'import os\nx = os.getenv("A", "1")\n'},
            [_key("A"), _key("B")])
        assert sum(res.counts.values()) == 2 == res.registered_total

    def test_result_is_immutable(self, tmp_path):
        res = self._audit(tmp_path, {"radar/a.py": "x = 1\n"}, [_key("A")])
        with pytest.raises(Exception):
            res.keys["A"] = None  # type: ignore[index]


class TestDefaultMismatch:
    def _one(self, tmp_path, source, key):
        (tmp_path / "radar").mkdir(parents=True, exist_ok=True)
        (tmp_path / "radar" / "a.py").write_text(source, encoding="utf-8")
        return csa.audit(root=tmp_path, keys=[key]).default_mismatches

    def test_int_default_mismatch_is_detected(self, tmp_path):
        mis = self._one(tmp_path, 'import os\nx = os.getenv("A", "3000")\n',
                        _key("A", default=5000, type_="int"))
        assert len(mis) == 1
        assert (mis[0].registry_default, mis[0].direct_default) == (5000, 3000)

    def test_matching_default_is_not_reported(self, tmp_path):
        assert self._one(tmp_path, 'import os\nx = os.getenv("A", "5000")\n',
                         _key("A", default=5000, type_="int")) == ()

    def test_list_default_is_compared_after_coercion(self, tmp_path):
        mis = self._one(tmp_path, 'import os\nx = os.getenv("A", "p,q")\n',
                        _key("A", default=[], type_="list[str]"))
        assert mis[0].direct_default == ["p", "q"]

    def test_plugin_enabled_is_marked_as_a_semantic_inversion(self, tmp_path):
        mis = self._one(tmp_path, 'import os\nx = os.getenv("PLUGIN_ENABLED", "")\n',
                        _key("PLUGIN_ENABLED", default="*", type_="str"))
        assert mis[0].note == csa.NOTE_SEMANTIC_INVERSION

    def test_non_literal_default_is_never_a_mismatch(self, tmp_path):
        mis = self._one(
            tmp_path,
            'import os\nx = os.getenv("A", os.path.join("a", "b"))\n',
            _key("A", default="zzz", type_="str"))
        assert mis == ()

    def test_secret_key_values_are_redacted(self, tmp_path):
        # review FIX 1: a secret's defaults must not reach /api/v2/self_eval
        # (jwt-only) nor l5_check_result.measured_json (persisted 365d).
        mis = self._one(
            tmp_path, 'import os\nx = os.getenv("A", "hunter2")\n',
            _key("A", default="s3cr3t", type_="str", secret=True))
        assert len(mis) == 1
        assert mis[0].redacted is True
        assert mis[0].registry_default is None
        assert mis[0].direct_default is None
        # the finding itself stays actionable
        assert mis[0].key == "A" and mis[0].site.endswith(":2")

    def test_non_secret_values_are_not_redacted(self, tmp_path):
        mis = self._one(tmp_path, 'import os\nx = os.getenv("A", "b")\n',
                        _key("A", default="a", type_="str"))
        assert mis[0].redacted is False
        assert mis[0].direct_default == "b"


# ── review FIX 2: registry extraction without importing the app ─────────────
class TestRegistryFromAst:
    """`import radar` boots the whole application (DB migrations, ~30 sensor
    threads, outbound HTTP). The CI gate must classify the repo without that,
    so the registry is read from radar/config.py's AST. This parity test runs
    in the normal test process — where the app IS booted — and guards the two
    sources against drift."""

    def test_key_set_matches_the_live_registry(self):
        ast_keys = {k.key for k in csa.registry_from_ast()}
        live_keys = {k.key for k in config_layered.all_keys(include_secrets=True)}
        assert ast_keys == live_keys

    def test_defaults_types_and_secret_flags_match_the_live_registry(self):
        ast_reg = {k.key: k for k in csa.registry_from_ast()}
        for live in config_layered.all_keys(include_secrets=True):
            extracted = ast_reg[live.key]
            assert extracted.default == live.default, live.key
            assert extracted.type_ == live.type_, live.key
            assert extracted.secret == live.secret, live.key

    def test_module_constant_defaults_are_resolved(self):
        # SIGNAL_LEDGER_RETENTION_DAYS declares
        # default=SIGNAL_LEDGER_RETENTION_DAYS_DEFAULT, a module constant.
        reg = {k.key: k for k in csa.registry_from_ast()}
        assert reg["SIGNAL_LEDGER_RETENTION_DAYS"].default == 60

    def test_audit_over_the_ast_registry_matches_the_live_audit(self):
        ast_result = csa.audit(keys=csa.registry_from_ast())
        live_result = csa.audit()
        assert dict(ast_result.counts) == dict(live_result.counts)
        assert {m.key for m in ast_result.default_mismatches} == \
            {m.key for m in live_result.default_mismatches}


# ── WP-1.2 完了条件 2/3: acceptance against the real repository ─────────────
#
# Ground truth: S1-CONF-008 (docs/design/v3/S1-analytics-config.md:463-480)
# and S1-CONF-009 (:482-487). 98 keys registered when S1 was written; WP-0.1
# added SIGNAL_LEDGER_RETENTION_DAYS as the second fully-resolving key.
S1_RESOLVING = {
    "CHRONIC_INCONCLUSIVE_THRESHOLD_DAYS": "FULL_RESOLUTION",
    "SIGNAL_LEDGER_RETENTION_DAYS": "FULL_RESOLUTION",   # WP-0.1
    "LLM_TIMEOUT": "PARTIAL",
    "SCENARIO_IMPROVER_AUTO_APPLY_ENABLED": "PARTIAL",
    "LLM_OVERRIDE_WINDOW": "DEAD",                       # zero consumers
}

# S1 §6.3 (:539-548) — registered keys frozen as import-time constants in
# radar/config.py whose ONLY bypass channel is that constant (the 33 keys
# that also have a direct read live in §6.2 instead).
S1_FROZEN_ONLY = {
    "ACLED_API_EMAIL", "ACLED_API_KEY", "ADAPTIVE_ZSCORE_ENABLED",
    "ADAPTIVE_ZSCORE_MIN_SAMPLES", "ADAPTIVE_ZSCORE_SENSITIVITY",
    "AIRSPACE_WINDOW", "AIS_ANCHOR_RADIUS_KM", "AIS_DARK_GAP_THRESHOLD",
    "CACHE_EXPIRY", "CERTSPOTTER_API_TOKEN", "CF_API_TOKEN",
    "DEFAULT_FOCUSED_SCENARIO", "DERIVATIVE_WINDOW", "DOMAIN_CAP",
    "FLASK_DEBUG", "GLOBAL_SIGNAL_WEIGHT", "HTTPS_PROXY", "HTTP_PROXY",
    "LLM_ENABLED", "LLM_HOST", "LLM_MODEL", "LLM_TIMEOUT",
    "NARRATIVE_POLL_INTERVAL", "OPENSKY_CLIENT_ID", "OPENSKY_CLIENT_SECRET",
    "OPENSKY_MIN_INTERVAL", "OWM_API_KEY", "PERSISTENCE_SAVE_INTERVAL",
    "SERVER_HOST", "SERVER_PORT", "SHOW_BACKGROUND_TL",
    "SILENT_DIVERGENCE_THRESHOLD", "SSL_VERIFY", "SYNC_C2_THRESHOLD",
    "THEATER_BASELINE_MIN_SAMPLES", "THEATER_BASELINE_WINDOW",
    "THREAT_LEVEL_HYSTERESIS_CYCLES", "TRIANGULATION_BONUS",
}

# S1-CONF-009 — {key: (registry default, direct-read default)}.
S1_DEFAULT_MISMATCHES = {
    "PLUGIN_ENABLED": ("*", ""),
    "CHECKHOST_TIMEOUT_MS": (5000, 3000),
    "TELEGRAM_MIRROR_POLL_INTERVAL": (300, 900),
    "CHECKHOST_NODES": ([], 5),          # 5 hardcoded nodes
    "TELEGRAM_ATTACK_KEYWORDS": ([], 9),  # 9 hardcoded keywords
}


@pytest.fixture(scope="module")
def repo_audit():
    return csa.audit()


class TestAcceptanceAgainstS1:
    def test_registry_size(self, repo_audit):
        assert repo_audit.registered_total == 99, \
            "98 keys at S1 authoring time + SIGNAL_LEDGER_RETENTION_DAYS (WP-0.1)"

    def test_resolving_keys_are_exactly_the_s1_set(self, repo_audit):
        actual = {k: c.verdict for k, c in repo_audit.keys.items()
                  if c.verdict != csa.CLASS_BYPASSED}
        assert actual == S1_RESOLVING

    def test_ninety_five_keys_never_reach_the_resolution_chain(self, repo_audit):
        # S1-CONF-008: "98 キー中 95 キーについて実行時は誰もその値を読まない".
        # 94 BYPASSED + the 1 DEAD key, over the 98 pre-WP-0.1 keys.
        no_reader = [k for k, c in repo_audit.keys.items()
                     if c.verdict in (csa.CLASS_BYPASSED, csa.CLASS_DEAD)]
        assert len(no_reader) == 95
        assert repo_audit.counts[csa.CLASS_BYPASSED] == 94
        assert repo_audit.counts[csa.CLASS_DEAD] == 1
        assert repo_audit.counts[csa.CLASS_PARTIAL] == 2
        assert repo_audit.counts[csa.CLASS_FULL] == 2  # +1 from WP-0.1

    def test_signal_ledger_retention_is_classified_as_resolving(self, repo_audit):
        # WP-1.2 完了条件 2 names this key explicitly: the detector must not
        # regress WP-0.1's fix into the bypass bucket.
        assert repo_audit.keys["SIGNAL_LEDGER_RETENTION_DAYS"].verdict == \
            csa.CLASS_FULL

    def test_direct_read_channel_matches_s1_6_2(self, repo_audit):
        keys = [k for k, c in repo_audit.keys.items() if c.direct_read_sites]
        sites = sum(len(repo_audit.keys[k].direct_read_sites) for k in keys)
        assert (len(keys), sites) == (58, 65), "S1 §6.2: 58 キー / 65 箇所"

    def test_frozen_constant_channel_matches_s1_6_3(self, repo_audit):
        frozen = {k for k, c in repo_audit.keys.items() if c.frozen_constant_sites}
        direct = {k for k, c in repo_audit.keys.items() if c.direct_read_sites}
        assert len(frozen) == 71, "P3:156 — import 時凍結 71 キー"
        assert len(frozen & direct) == 71 - 38 == 33, "S1 ①②の重複 33 キー"
        assert frozen - direct == S1_FROZEN_ONLY, "S1 §6.3 の 38 キー"

    def test_the_five_default_mismatches_are_detected(self, repo_audit):
        found = {m.key: m for m in repo_audit.default_mismatches}
        assert set(found) == set(S1_DEFAULT_MISMATCHES), \
            "S1-CONF-009 enumerates exactly 5 mismatching keys"
        assert found["PLUGIN_ENABLED"].registry_default == "*"
        assert found["PLUGIN_ENABLED"].direct_default == ""
        assert found["PLUGIN_ENABLED"].note == csa.NOTE_SEMANTIC_INVERSION
        assert found["CHECKHOST_TIMEOUT_MS"].direct_default == 3000
        assert found["TELEGRAM_MIRROR_POLL_INTERVAL"].direct_default == 900
        assert len(found["CHECKHOST_NODES"].direct_default) == 5
        assert len(found["TELEGRAM_ATTACK_KEYWORDS"].direct_default) == 9

    def test_mismatch_sites_are_citable(self, repo_audit):
        found = {m.key: m for m in repo_audit.default_mismatches}
        assert found["PLUGIN_ENABLED"].site.startswith("radar/plugin_loader.py:")
        assert found["CHECKHOST_TIMEOUT_MS"].site.startswith(
            "radar/sensors/checkhost.py:")

    def test_reverse_defect_unregistered_resolution_reads(self, repo_audit):
        # S1-CONF-010: read through get_config but never registered, so the
        # raw env string (None when unset) is returned with no coercion.
        assert set(repo_audit.unregistered_resolution_reads) == {
            "CHRONIC_DUTY_WINDOW_DAYS", "CHRONIC_DUTY_THRESHOLD"}

    def test_dynamic_getenv_sites_are_reported_not_dropped(self, repo_audit):
        # S5-VERIF-006: an unclassifiable site must stay visible.
        assert len(repo_audit.dynamic_getenv_sites) > 0
        assert all(s.key is None for s in repo_audit.dynamic_getenv_sites)

    def test_gps_jam_threshold_is_bypassed(self, repo_audit):
        # D2 G-04, the single key the original defect was filed against.
        cls = repo_audit.keys["GPS_JAM_THRESHOLD"]
        assert cls.verdict == csa.CLASS_BYPASSED
        assert any(s.file.endswith("gps_jamming.py") for s in cls.direct_read_sites)


class TestAuditIsCheap:
    def test_repeated_audits_are_served_from_cache(self):
        csa.clear_cache()
        first = csa.audit_cached()
        second = csa.audit_cached()
        assert first is second
        csa.clear_cache()
        assert csa.audit_cached() is not first


class TestDocstringNoLongerClaimsACIGate:
    def test_config_layered_docstring_states_reality(self):
        source = config_layered.__doc__ or ""
        assert "CI\ngates assert no" not in source
        assert "gates assert no `os.getenv`" not in source, \
            "the import-time CI gate claimed here has never existed (P3:148)"
        assert "config_reachability" in source or "reachability" in source
