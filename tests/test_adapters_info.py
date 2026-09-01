"""WP-2.7 — the information-domain adapters, against recorded payloads.

Same discipline as the WP-2.6 suites: fixtures are the upstream, no test
reaches the network, and every assertion traces either to an S1 clause or
to the consumer in `radar/routes/core.py` the port has to reproduce.

The AST helpers matter more here than they did in WP-2.6. These sensors
carry large keyword ledgers, query templates and per-feed tables that a
port can plausibly *paraphrase*, and a paraphrased ledger changes what the
system detects while looking like a transcription. Every such table is
compared against the live sensor rather than against a copy of it.
"""
import ast
from pathlib import Path

import pytest

from v3.adapters.info import (bg_observer_rss, gdelt, kinetic,
                              rss_narrative, telegram_mirror, tor_metrics,
                              travel_advisory)
from v3.adapters.llm import diplomatic, extraction as ex
from v3.adapters.llm import hacktivist_news
from v3.adapters.llm import military_exercise
from v3.fetch import parse
from v3.adapters.types import (AdapterId, FetchedPayload, NormalizeContext,
                               STATUS_FIRED, STATUS_NO_DATA, STATUS_OBSERVED,
                               STATUS_OK, STATUS_SUPPRESSED)

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "adapters"
T0 = 1_700_000_000.0


def legacy_source(relative_path: str) -> str:
    """The text of a live module, read but never imported."""
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def literal_in(relative_path: str, name: str):
    """A named literal from anywhere in a module — module or class body."""
    for node in ast.walk(ast.parse(legacy_source(relative_path))):
        if isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == name \
                    and node.value is not None:
                return ast.literal_eval(node.value)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return ast.literal_eval(node.value)
    raise AssertionError(f"{name} is not a literal in {relative_path}")


def legacy_literal(module: str, name: str):
    return literal_in(f"radar/sensors/{module}.py", name)


def payload(adapter: str, name: str, *, url="https://upstream.test/x",
            label="", status=200, content_type="application/json"
            ) -> FetchedPayload:
    body = (FIXTURES / adapter / name).read_bytes()
    return FetchedPayload(url=url, status=status, body=body, fetched_at=T0,
                          content_type=content_type, label=label)


def synthetic(body: bytes, *, label="", url="https://upstream.test/x",
              content_type="application/json") -> FetchedPayload:
    return FetchedPayload(url=url, status=200, body=body, fetched_at=T0,
                          content_type=content_type, label=label)


def context(adapter_id: str, **overrides) -> NormalizeContext:
    base = {"adapter_id": AdapterId(adapter_id), "now": T0,
            "countries": ("TW",)}
    base.update(overrides)
    return NormalizeContext(**base)


# ── tor_metrics (S1-SENSI-019..021) ─────────────────────────────────────

class TestTorMetricsRelaySummary:
    def _drafts(self, name="summary.json", **kwargs):
        return tor_metrics.normalize(
            payload("tor_metrics", name,
                    url="https://onionoo.torproject.org/summary?country=tw",
                    label="summary:TW", **kwargs),
            context("tor_metrics"))

    def test_only_running_relays_are_counted(self):
        """`sum(1 for r in relays if r.get("r", False))`
        (`radar/sensors/tor_metrics.py:66`). The fixture holds three relays,
        one of them down."""
        draft = self._drafts()[0]
        assert draft.flags["running"] == 2

    def test_only_running_bridges_are_counted(self):
        """`tor_metrics.py:67` — same predicate, the bridges array."""
        assert self._drafts()[0].flags["bridges"] == 1

    def test_bandwidth_sums_running_relays_only(self):
        """`sum(r.get("bw", 0) for r in relays if r.get("r"))` (`:68`).

        The down relay's 4000 is excluded, which is what makes this a
        capacity reading rather than an inventory."""
        assert self._drafts()[0].flags["bandwidth_kbps"] == 20000

    def test_the_relay_verdict_is_withheld_until_l1_holds_the_previous_count(
            self):
        """DP12 / §7-2 #9's family: `drop_pct` needs the PREVIOUS cycle.

        Production keeps it in `self._prev_relay_counts`
        (`tor_metrics.py:34`), so a restart silently disables drop
        detection. v3 declares the dependency and withholds the verdict
        rather than reporting OK, which would read as "measured, nothing
        wrong" — the shape NP1 refuses.
        """
        draft = self._drafts()[0]
        assert draft.status == STATUS_OBSERVED
        assert draft.raw_score == 0.0
        assert draft.flags["drop_verdict"] == "pending_l1_prev_relay_count"

    def test_the_pending_marker_does_not_occupy_a_typed_key(self):
        """§7-2 #9's discipline. `drop_pct` is a NUMBER in production
        (`tor_metrics.py:78`); a string there would be compared against
        `>= 0.40` and raise, or worse, be read as truthy. The key that
        carries the verdict is ABSENT and a sibling names why."""
        flags = self._drafts()[0].flags
        assert "drop_pct" not in flags
        assert "status" not in flags

    def test_the_signal_source_is_productions_add_rat_name(self):
        """`add_rat("tor_metrics", ...)` (`radar/routes/core.py:1576`).

        It is the ledger's dedup identity and WP-2.8's join key, so a
        shortened name would silently unjoin the two sides.
        """
        assert self._drafts()[0].signal_source == "tor_metrics"

    def test_the_domain_is_info(self):
        """`add_rat("tor_metrics", "info", ...)` — `core.py:1576`."""
        assert self._drafts()[0].domain == "info"

    def test_a_body_that_is_not_an_object_yields_nothing(self):
        assert tor_metrics.normalize(
            synthetic(b"[]", label="summary:TW"),
            context("tor_metrics")) == ()


class TestTorMetricsClientEstimates:
    def _draft(self, name="clients.json"):
        return tor_metrics.normalize(
            payload("tor_metrics", name,
                    url="https://onionoo.torproject.org/clients?country=tw",
                    label="clients:TW"),
            context("tor_metrics"))[0]

    def test_bridge_users_sum_only_the_requested_countrys_column(self):
        """`if cc_lower in avg_clients: total_users += avg_clients[cc_lower]`
        (`tor_metrics.py:100-102`). The fixture's third bridge reports only
        US clients and must not be counted; the first reports both TW and
        CN and contributes its TW column alone."""
        assert self._draft().flags["bridge_users"] == pytest.approx(150.75)

    def test_the_country_lookup_is_lower_case(self):
        """`cc_lower = code.lower()` (`:100`). Onionoo keys its
        `average_clients` map in lower case; an upper-case lookup finds
        nothing and every country reads as zero bridge users — a silent
        floor, not an error."""
        body = b'{"bridges": [{"average_clients": {"TW": 5.0}}]}'
        draft = tor_metrics.normalize(
            synthetic(body, label="clients:TW"), context("tor_metrics"))[0]
        assert draft.flags["bridge_users"] == 0

    def test_the_client_half_carries_its_own_signal_source(self):
        """§7-2 #11's family, and a CONSTRAINT rather than a choice.

        Both endpoints answer for the same country in the same tick, and
        L1 is `UNIQUE (tick_id, sensor, signal_source, country)`. Two rows
        under one name are either a `DomainError` or — when the scores
        match, which is exactly the quiet case — silently dropped."""
        assert self._draft().signal_source == "tor_clients"

    def test_the_surge_verdict_is_withheld_until_l1_holds_the_previous_count(
            self):
        draft = self._draft()
        assert draft.status == STATUS_OBSERVED
        assert draft.raw_score == 0.0
        assert draft.flags["trend_verdict"] == "pending_l1_prev_user_count"
        assert "surge_pct" not in draft.flags
        assert "trend" not in draft.flags


class TestTorMetricsThresholdsAreTranscribed:
    def test_the_relay_drop_threshold_matches_the_live_sensor(self):
        assert tor_metrics.RELAY_DROP_FALLBACK_PCT == legacy_literal(
            "tor_metrics", "RELAY_DROP_FALLBACK_PCT")

    def test_the_user_surge_threshold_matches_the_live_sensor(self):
        assert tor_metrics.USER_SURGE_FALLBACK_PCT == legacy_literal(
            "tor_metrics", "USER_SURGE_FALLBACK_PCT")

    def test_the_drop_trend_threshold_is_the_asymmetric_one(self):
        """Production's DROP arm is `surge_pct < -0.3` (`:108`) — not the
        negation of the 1.00 surge arm. Symmetrising it would change what
        the sensor reports and is the kind of tidying a port invents."""
        assert tor_metrics.USER_DROP_PCT == -0.3

    def test_the_status_ladder_is_productions(self):
        """`tor_metrics.py:129-136`, and the scores `core.py:1561` gives
        them: CENSORSHIP_INDICATOR 2, RELAY_DROP 1, USER_SURGE **0**.

        The last one is the surprise and it is deliberate: a user surge on
        its own does not fire, because `_tor_fired` tests membership of
        `("RELAY_DROP", "CENSORSHIP_INDICATOR")` (`core.py:1560`).
        """
        assert tor_metrics.STATUS_SCORES == {
            "CENSORSHIP_INDICATOR": 2.0, "RELAY_DROP": 1.0,
            "USER_SURGE": 0.0, "NORMAL": 0.0}
        assert tor_metrics.FIRING_STATUSES == ("RELAY_DROP",
                                               "CENSORSHIP_INDICATOR")

    def test_the_status_ladder_agrees_with_the_live_scoring_branch(self):
        """Read out of `core.py` rather than trusted."""
        text = legacy_source("radar/routes/core.py")
        assert ('_tor_fired = _tor_core_status in ("RELAY_DROP", '
                '"CENSORSHIP_INDICATOR")') in text
        assert ("_tor_score = 2 if _tor_core_status == "
                '"CENSORSHIP_INDICATOR" else (1 if _tor_fired else 0)') in text


class TestTorMetricsDeclaration:
    def test_both_endpoints_are_declared_in_productions_order(self):
        specs = tor_metrics.TOR_METRICS_ADAPTER.declared_specs
        assert [spec.url for spec in specs] == [
            "https://onionoo.torproject.org/summary",
            "https://onionoo.torproject.org/clients"]

    def test_the_country_parameter_is_lower_cased_on_the_wire(self):
        """`params = {"country": code.lower()}` (`tor_metrics.py:54,89`).

        Onionoo matches case-sensitively, so an upper-case code returns an
        empty relay list — HTTP 200 with nothing in it, which reads as a
        country with no Tor presence rather than as a bad request.
        """
        for spec in tor_metrics.TOR_METRICS_ADAPTER.declared_specs:
            assert spec.param_values("country") == ("{country_lower}",)

    def test_the_accept_header_travels(self):
        for spec in tor_metrics.TOR_METRICS_ADAPTER.declared_specs:
            assert spec.headers["Accept"] == "application/json"

    def test_the_courtesy_delay_is_declared_not_slept(self):
        """`time.sleep(0.5)` (`tor_metrics.py:81,118`) inside the sensor is
        the "how to fetch" an adapter must not express."""
        assert tor_metrics.TOR_METRICS_ADAPTER.min_interval_sec == 0.5

    def test_the_cadence_is_the_live_one(self):
        """`super().__init__("tor_metrics", "info", 1800)` (`:33`)."""
        assert tor_metrics.TOR_METRICS_ADAPTER.cadence.cadence_sec == 1800.0

    def test_no_credential_is_declared(self):
        """"All endpoints are free, require no authentication" (`:8`)."""
        assert not tor_metrics.TOR_METRICS_ADAPTER.auth.declares_credential

    def test_both_baselines_are_declared(self):
        assert set(tor_metrics.TOR_METRICS_ADAPTER.baseline_refs) == {
            "tor_prev_relay_count", "tor_prev_user_count"}


# ── gdelt (S1-SENSI-001..004, K15/K18) ──────────────────────────────────

class TestGdeltQueryLedger:
    def test_the_query_templates_match_the_live_sensor(self):
        """Eight hand-written queries. Each one decides what the tone
        series MEASURES, so a paraphrase is a different sensor wearing the
        same name — and the difference would surface as a tone shift
        attributed to the world rather than to the port."""
        for node in ast.walk(ast.parse(
                legacy_source("radar/sensors/gdelt.py"))):
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "QUERY_TEMPLATES"
                    for t in node.targets):
                assert gdelt.QUERY_TEMPLATES == ast.literal_eval(node.value)
                return
        raise AssertionError("QUERY_TEMPLATES is gone from the live sensor")

    def test_the_fallback_query_is_productions(self):
        """`gdelt.py:47` — used for any country with no hand-written
        template. It is built from the country NAME, which is why the
        ledger travels in `NormalizeContext` rather than being read here."""
        assert gdelt.fallback_query("Philippines") == (
            '"Philippines" (military OR conflict OR attack OR defense OR war)')

    def test_a_templated_country_does_not_take_the_fallback(self):
        assert gdelt.query_for("TW", {"TW": "Taiwan"}) == \
            gdelt.QUERY_TEMPLATES["TW"]

    def test_an_untemplated_country_takes_the_fallback_by_name(self):
        assert gdelt.query_for("PH2", {"PH2": "Elbonia"}) == \
            gdelt.fallback_query("Elbonia")

    def test_a_country_with_no_name_falls_back_to_its_code(self):
        """`COUNTRY_COORDS.get(code, {}).get("name", code)` (`gdelt.py:46`)
        — the code itself is the last resort, not an empty string."""
        assert gdelt.query_for("ZZ", {}) == gdelt.fallback_query("ZZ")


class TestGdeltTone:
    def _drafts(self, name, label="tone_1d:TW", **kwargs):
        return gdelt.normalize(payload("gdelt", name, label=label),
                               context("gdelt", **kwargs))

    def test_the_tone_is_the_mean_of_the_series_rounded_to_three(self):
        """`round(sum(values) / len(values), 3)` (`gdelt.py:31`)."""
        assert self._drafts("tone_1d.json")[0].flags["tone"] == -19.5

    def test_a_series_with_no_points_is_no_data(self):
        """`if not timeline: return None` (`:29`) — and a None current tone
        makes the country `{"status": "NO_DATA"}` (`:55`). Distinct from a
        quiet day, which is the distinction NP1 exists to keep."""
        draft = self._drafts("tone_empty.json")[0]
        assert draft.status == STATUS_NO_DATA
        assert draft.raw_score == 0.0

    def test_a_rate_limited_response_is_no_data_not_zero_tone(self):
        """`if res.status_code in (429, 503): return None` (`:27`).

        Reading a throttle as tone 0.0 would publish neutral sentiment the
        source never reported — and 0.0 is above the alert threshold, so
        the fabrication is silent in the calm direction.
        """
        draft = gdelt.normalize(
            payload("gdelt", "tone_1d.json", label="tone_1d:TW", status=429),
            context("gdelt"))[0]
        assert draft.status == STATUS_NO_DATA

    def test_a_tone_below_the_alert_threshold_fires(self):
        """`tone_current < alert_threshold` (`gdelt.py:73,76`) is one arm of
        an OR, so it decides ALERT on its own — no baseline needed."""
        draft = self._drafts("tone_1d.json")[0]
        assert draft.status == STATUS_FIRED
        assert draft.raw_score == 1.0
        assert draft.reason == "Media tone collapse"

    def test_the_fired_reason_is_productions_string(self):
        """`core.py:1132` — the sentence an analyst reads next to the
        verdict."""
        text = legacy_source("radar/routes/core.py")
        assert '"Media tone collapse" if gdelt_alert else None' in text

    def test_a_quiet_tone_withholds_rather_than_reporting_ok(self):
        """The other arm of the OR is `dow_z < -2.0`, and the day-of-week
        baseline lives in L1 (`db.gdelt_dow_same_weekday`). Until it is
        wired, "not below the fixed threshold" is not the same as "not
        alerting", so the row says OBSERVED and names what it is missing.
        """
        draft = self._drafts("tone_quiet.json")[0]
        assert draft.status == STATUS_OBSERVED
        assert draft.raw_score == 0.0
        assert draft.flags["dow_verdict"] == "pending_l1_dow_baseline"

    def test_the_withheld_row_does_not_occupy_the_typed_keys(self):
        flags = self._drafts("tone_quiet.json")[0].flags
        for typed in ("is_alert", "dow_z", "status"):
            assert typed not in flags

    def test_the_baseline_window_lands_under_its_own_signal_source(self):
        """§7-2 #11's family: two timespans, one country, one tick."""
        draft = gdelt.normalize(
            payload("gdelt", "tone_28d.json", label="tone_28d:TW"),
            context("gdelt"))[0]
        assert draft.signal_source == "gdelt_baseline"
        assert draft.status == STATUS_OBSERVED
        assert draft.raw_score == 0.0
        assert draft.flags["tone"] == -2.0

    def test_the_current_window_keeps_productions_signal_source(self):
        assert self._drafts("tone_1d.json")[0].signal_source == "gdelt"


class TestGdeltThresholds:
    def test_the_dow_minimum_sample_count_matches_the_live_sensor(self):
        assert gdelt.DOW_MIN_SAMPLES == 3

    def test_the_dow_daily_cap_matches_the_live_sensor(self):
        assert gdelt.DOW_MAX_PER_DAY == 20

    def test_the_dow_retention_is_the_product_the_sensor_stores(self):
        """`max_entries=self.DOW_MAX_PER_DAY * 7` (`gdelt.py:64`) — seven
        weekday buckets, not seven days."""
        assert gdelt.DOW_MAX_ENTRIES == 140

    def test_both_dow_constants_match_the_live_class_body(self):
        assert gdelt.DOW_MIN_SAMPLES == legacy_literal("gdelt",
                                                       "DOW_MIN_SAMPLES")
        assert gdelt.DOW_MAX_PER_DAY == legacy_literal("gdelt",
                                                       "DOW_MAX_PER_DAY")

    def test_the_standard_deviation_floor_discloses_its_provenance(self):
        """A7: the 0.5 floor is hard-coded with no stated origin
        (`gdelt.py:70`). §3-3 rules that v3 must disclose where it came
        from, so it is a pinned `Threshold` rather than a bare literal —
        the value is unchanged, the silence is not."""
        resolved = gdelt.DOW_STDDEV_FLOOR.resolve()
        assert resolved.value == 0.5
        assert "gdelt.py:70" in resolved.provenance_ref

    def test_the_alert_threshold_discloses_its_provenance(self):
        resolved = gdelt.TONE_ALERT_THRESHOLD.resolve()
        assert resolved.value == -15.0
        assert "GDELT_TONE_ALERT_THRESHOLD" in resolved.provenance_ref

    def test_the_dow_z_threshold_is_productions(self):
        """`_dow_z < -2.0` (`gdelt.py:73`)."""
        assert gdelt.DOW_Z_ALERT == -2.0


class TestKnowledgeItemsPinnedByThisBatch:
    """D1 §4's facts, one test each, with the fact in the test's name
    (design sheet §6-2). These exist because D1 says the knowledge lives
    only in comments and branches — and a comment that stops being true
    stays green."""

    def test_k18_gdelt_tone_is_baselined_per_weekday(self):
        """K18: GDELT tone carries a day-of-week bias, so the baseline is
        per weekday — not a rolling mean over all days.

        The consequence of getting this wrong is not noise, it is a
        recurring false positive: weekend news is a different mix of
        stories, so a Sunday measured against a Tuesday-weighted mean
        looks hostile every single week, and an analyst learns to ignore
        the sensor.

        Pinned three ways — the samples the z-score consumes are
        same-weekday only, the minimum sample count is production's, and
        the retention is per-weekday x 7 rather than seven days.
        """
        assert gdelt.DOW_MIN_SAMPLES == 3
        assert gdelt.DOW_MAX_ENTRIES == gdelt.DOW_MAX_PER_DAY * 7

        # Below the minimum, production does NOT compute a z-score at all
        # (`gdelt.py:68`) — it falls back to the fixed threshold. Returning
        # a z-score from one or two samples would be an alarm derived from
        # a baseline that does not exist.
        with pytest.raises(ValueError):
            gdelt.dow_zscore(-10.0, [-2.0, -3.0])

        # Same-weekday samples: four quiet Sundays, then a hostile one.
        z = gdelt.dow_zscore(-10.0, [-2.0, -2.0, -3.0, -1.0])
        assert z < gdelt.DOW_Z_ALERT

        # The floor is what stops a flat baseline from manufacturing an
        # enormous z-score out of an ordinary move (A7).
        flat = gdelt.dow_zscore(-1.5, [-1.0, -1.0, -1.0, -1.0])
        assert flat == pytest.approx(-1.0)

        # And the sensor declares the fact it is relying on.
        assert "K18" in gdelt.GDELT_ADAPTER.knowledge_refs

    def test_the_baseline_the_zscore_needs_is_declared_not_held(self):
        """K18's history is L1's (`db.gdelt_dow_*`), and DP3 is the record
        of what happens when a sensor keeps it in process memory instead."""
        assert "gdelt_dow_tone" in gdelt.GDELT_ADAPTER.baseline_refs


class TestGdeltDeclaration:
    def test_both_timespans_are_declared(self):
        specs = gdelt.GDELT_ADAPTER.declared_specs
        assert [spec.param_values("timespan") for spec in specs] == [
            ("1d",), ("{history_window}d",)]

    def test_every_request_names_the_doc_api(self):
        for spec in gdelt.GDELT_ADAPTER.declared_specs:
            assert spec.url == "https://api.gdeltproject.org/api/v2/doc/doc"

    def test_the_mode_and_format_are_productions(self):
        """`mode=TimelineTone`, `format=json` (`gdelt.py:26`). A different
        mode returns a different document shape, which the parser reads as
        an empty timeline — NO_DATA forever, and nothing says why."""
        for spec in gdelt.GDELT_ADAPTER.declared_specs:
            assert spec.param_values("mode") == ("TimelineTone",)
            assert spec.param_values("format") == ("json",)

    def test_the_parameter_order_is_productions(self):
        """`{"query", "mode", "timespan", "format"}` (`gdelt.py:26`)."""
        for spec in gdelt.GDELT_ADAPTER.declared_specs:
            assert [name for name, _ in spec.params] == [
                "query", "mode", "timespan", "format"]

    def test_the_courtesy_delay_is_k15s(self):
        """K15: GDELT 0.5s (`gdelt.py:43`)."""
        assert gdelt.GDELT_ADAPTER.min_interval_sec == 0.5

    def test_the_knowledge_refs_are_k15_and_k18(self):
        assert set(gdelt.GDELT_ADAPTER.knowledge_refs) == {"K15", "K18"}

    def test_the_cadence_is_the_live_one(self):
        """`super().__init__("gdelt", "info", 1800)` (`gdelt.py:23`)."""
        assert gdelt.GDELT_ADAPTER.cadence.cadence_sec == 1800.0

    def test_the_baseline_dependency_is_declared(self):
        assert "gdelt_dow_tone" in gdelt.GDELT_ADAPTER.baseline_refs


class TestGdeltWeatherSuppressionIsNotForgotten:
    def test_the_suppression_is_registered_as_a_wp41_join(self):
        """§7-2 #35: `weather_conditions` comes from ANOTHER adapter, so
        `normalize` cannot reach it (barrier 4). WEATHER_NOISE is
        therefore unreachable here, and the row says so rather than
        letting the absence look like fair weather."""
        draft = gdelt.normalize(
            payload("gdelt", "tone_1d.json", label="tone_1d:TW"),
            context("gdelt"))[0]
        assert draft.suppressed is False
        assert draft.flags["weather_verdict"] == "pending_wp41_weather_join"
        assert draft.status != STATUS_SUPPRESSED

    def test_the_suppressed_status_is_never_emitted_by_this_layer(self):
        for name in ("tone_1d.json", "tone_quiet.json", "tone_empty.json"):
            for draft in gdelt.normalize(
                    payload("gdelt", name, label="tone_1d:TW"),
                    context("gdelt")):
                assert draft.status != STATUS_SUPPRESSED
                assert draft.status != STATUS_OK


# ── bg_observer_rss (S1-SENSI-026..030) ─────────────────────────────────


def regex_pattern(relative_path: str, name: str) -> str:
    """The pattern string of a module-level `re.compile(...)` assignment.

    These tables are not literals, so `literal_in` cannot reach them — and
    they are exactly the transcriptions worth pinning, because a widened
    or narrowed verb list changes what the system detects while leaving
    every identifier, threshold and output shape intact.
    """
    for node in ast.walk(ast.parse(legacy_source(relative_path))):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not (isinstance(target, ast.Name) and target.id == name):
                continue
            call = node.value
            assert isinstance(call, ast.Call), f"{name} is not a call"
            return ast.literal_eval(call.args[0])
    raise AssertionError(f"{name} is not a compiled pattern in {relative_path}")


def rss_payload(body: bytes, *, status=200, url="https://wire.test/rss",
                content_type="application/rss+xml") -> FetchedPayload:
    return FetchedPayload(url=url, status=status, body=body, fetched_at=T0,
                          content_type=content_type, label=f"feed:{url}")


BG_PARTICIPANTS = ("TW", "CN", "JP", "UA", "RU", "US")


class TestBgObserverFeedLedger:
    """The nine feeds ARE the sensor's field of view."""

    def test_the_shipped_ledger_is_the_deployed_one_not_the_code_default(self):
        """`config.env:187` holds nine feeds; `config.py:654-661` defaults to
        three. The sensor exists to correct a Western-source bias, and the
        six the deployment adds — SCMP, TASS, Xinhua, CNA, Japan Times,
        Yonhap, Taipei Times — are the ones that make the Taiwan and Korea
        scenarios visible at all. Transcribing the code default would have
        left the wire looking quiet about Taiwan.
        """
        assert len(bg_observer_rss.FEEDS) == 9
        assert bg_observer_rss.FEEDS != bg_observer_rss.CODE_DEFAULT_FEEDS
        for url in bg_observer_rss.CODE_DEFAULT_FEEDS[:2]:
            assert url in bg_observer_rss.FEEDS

    def test_the_deployed_ledger_matches_config_env_exactly(self):
        """Read from the deployment rather than from a memory of it."""
        env = REPO_ROOT / "config.env"
        if not env.exists():                     # CI without a deployment
            pytest.skip("config.env is not present in this checkout")
        line = [l for l in env.read_text(encoding="utf-8").splitlines()
                if l.startswith("BG_OBSERVER_FEEDS=")]
        assert line, "BG_OBSERVER_FEEDS is not set in config.env"
        deployed = tuple(u.strip() for u in
                         line[0].split("=", 1)[1].split(",") if u.strip())
        assert bg_observer_rss.FEEDS == deployed

    def test_three_feeds_are_plaintext_http_and_that_is_preserved(self):
        """§7-2 #46. `config.py:648-653` made the DEFAULT list TLS-only so a
        network-path adversary could not inject RSS into the analysis
        pipeline; the deployment re-added THREE `http://` sources over that
        ruling — Xinhua, TASS and the Taipei Times. Ported as deployed — an
        `https://` guess that 404s removes the feed, which is the
        insensitive direction — and registered."""
        plaintext = tuple(u for u in bg_observer_rss.FEEDS
                          if u.startswith("http://"))
        assert plaintext == bg_observer_rss.PLAINTEXT_FEEDS
        assert len(plaintext) == 3

    def test_every_feed_is_declared_as_its_own_request(self):
        specs = bg_observer_rss.BG_OBSERVER_RSS_ADAPTER.declared_specs
        assert [spec.url for spec in specs] == list(bg_observer_rss.FEEDS)

    def test_the_user_agent_is_productions(self):
        """`background_observer.py:155`. Several of the nine answer a bare
        urllib agent with 403, and a refused feed is indistinguishable from
        a quiet one once the item count reaches zero."""
        assert bg_observer_rss.USER_AGENT == literal_in(
            "radar/background_observer.py", "_HTTP_USER_AGENT")
        for spec in bg_observer_rss.BG_OBSERVER_RSS_ADAPTER.declared_specs:
            assert spec.headers["User-Agent"] == bg_observer_rss.USER_AGENT
            assert spec.headers["Accept"] == "*/*"


class TestBgObserverExtractionIsTranscribed:
    """Every table compared against the live extractor, not against a copy."""

    EXTRACTOR = "radar/conclusions/rss_extractor.py"

    def test_the_country_alias_ledger_matches_the_live_extractor(self):
        assert kinetic.COUNTRY_ALIASES == literal_in(
            self.EXTRACTOR, "_COUNTRY_ALIASES")

    def test_the_word_form_numbers_match_the_live_extractor(self):
        assert kinetic.WORDS == literal_in(self.EXTRACTOR, "_WORDS")

    @pytest.mark.parametrize("ours,theirs", [
        ("NUMERIC_FATALITIES", "_NUMERIC_FATALITIES"),
        ("NUMERIC_FATALITIES_INVERTED", "_NUMERIC_FATALITIES_INVERTED"),
        ("WORD_FATALITIES", "_WORD_FATALITIES"),
        ("KINETIC_VERBS", "_KINETIC_VERBS"),
        ("ESCALATION_VERBS", "_ESCALATION_VERBS"),
    ])
    def test_the_vocabularies_match_the_live_extractor(self, ours, theirs):
        assert getattr(kinetic, ours).pattern == regex_pattern(
            self.EXTRACTOR, theirs)

    def test_bare_weapon_nouns_do_not_count_as_violence(self):
        """The 2026-08-02 audit: 12 of 15 korean_peninsula false negatives
        were posture articles graded as kinetic violence through bare
        nouns. A missile named without a strike verb is escalation, not
        an attack."""
        assert not kinetic.has_kinetic_verb("North Korea unveils a missile")
        assert kinetic.has_escalation_verb("North Korea missile test")

    def test_a_period_final_alias_still_matches(self):
        """`(?!\\w)` and not `\\b` — `rss_extractor.py:271-272`. "U.S."
        never forms a `\\b` against following whitespace, so the historic
        boundary dropped one of the five US aliases silently."""
        assert kinetic.detect_countries("U.S. carrier sails",
                                        allowed=("US",)) == ("US",)

    def test_the_highest_count_wins_not_the_first(self):
        """`max(counts)` — `rss_extractor.py:346`. "kills 5; toll rose to
        30" is a 30-fatality event."""
        assert kinetic.detect_fatalities(
            "Strike kills 5; toll rose to 30") == 30

    def test_an_unstated_toll_is_none_and_not_zero(self):
        """None and 0 are different facts and land on different rungs: a
        count of zero would score 0.4 through the fatality tier, an
        unstated one scores 0.45 through the kinetic tier."""
        assert kinetic.detect_fatalities("Shelling continued") is None

    def test_the_escalation_relevance_veto_is_deliberately_absent(self):
        """`rss_extractor.py:169-170` states it plainly: the veto gates
        GROUND-TRUTH LABELS and is "not applied to the bg_observer sensing
        path". Importing it here would narrow recall — the direction NP1
        forbids — while looking like extra rigour."""
        assert not hasattr(kinetic, "is_escalation_relevant")
        source = (REPO_ROOT / "v3/adapters/info/kinetic.py").read_text("utf-8")
        assert "_NONCONFLICT_NOISE" not in source
        assert "_MILITARY_ACTORS" not in source


class TestBgObserverScoreLadder:
    """S1-SENSI-028 — three tiers, five hard-coded numbers."""

    def _match(self, confidence, fatalities=0):
        return kinetic.KineticMatch(country="TW", fatalities=fatalities,
                                    summary="", source="regex",
                                    confidence=confidence)

    def test_a_fatality_count_scores_base_plus_five_hundredths_each(self):
        assert kinetic.raw_score(self._match(0.85, 12)) == pytest.approx(1.0)
        assert kinetic.raw_score(self._match(0.85, 2)) == pytest.approx(0.5)

    def test_the_fatality_tier_is_capped_at_one(self):
        assert kinetic.raw_score(self._match(0.85, 400)) == 1.0

    def test_a_kinetic_verb_alone_scores_forty_five_hundredths(self):
        assert kinetic.raw_score(self._match(0.60)) == 0.45

    def test_posture_alone_scores_twenty_five_hundredths(self):
        assert kinetic.raw_score(self._match(0.40)) == 0.25

    def test_the_ladder_keys_on_confidence_not_on_the_tier_name(self):
        """`background_observer.py:387-391` compares confidence, so an
        intermediate value lands on the lower rung in both systems."""
        assert kinetic.raw_score(self._match(0.84, 9)) == 0.45
        assert kinetic.raw_score(self._match(0.59)) == 0.25


class TestBgObserverNormalize:
    def _drafts(self, **kwargs):
        body = (FIXTURES / "bg_observer_rss" / "world_feed.xml").read_bytes()
        return bg_observer_rss.normalize(
            rss_payload(body, **kwargs),
            context("bg_observer_rss", countries=BG_PARTICIPANTS))

    def test_one_item_naming_two_participants_emits_both(self):
        """SENSI-027. "Russia strikes Ukraine ... 12 killed" is one event
        involving both, and the per-scenario participant filter routes each
        country's contribution. The predecessor returned one arbitrary
        country and dropped the other."""
        by_country = {d.country: d for d in self._drafts()}
        assert by_country["RU"].raw_score == pytest.approx(1.0)
        assert by_country["UA"].raw_score == pytest.approx(1.0)

    def test_only_participants_are_considered(self):
        """`allowed_countries=participants` — `background_observer.py:362`."""
        drafts = bg_observer_rss.normalize(
            rss_payload((FIXTURES / "bg_observer_rss"
                         / "world_feed.xml").read_bytes()),
            context("bg_observer_rss", countries=("JP",)))
        assert {d.country for d in drafts} == {"JP"}

    def test_a_story_with_no_verb_and_no_count_produces_nothing(self):
        """`rss_extractor.py:436-437`. The bank-holiday item names no
        country and no violence; under-reporting beats fabrication."""
        assert all(d.country != "" for d in self._drafts())
        assert len(self._drafts()) == 5

    def test_several_stories_about_one_country_fold_to_the_highest(self):
        """SENSI-028 requires ONE `signal_source` for every signal, and L1
        is `UNIQUE (tick_id, sensor, signal_source, country)`. The fixture
        names Ukraine twice — a 12-fatality strike and a shelling report —
        and the fold is MAX, which is what
        `dedup_by_source_country_max` (`radar/scoring.py:1424-1432`)
        applies downstream regardless."""
        ua = [d for d in self._drafts() if d.country == "UA"]
        assert len(ua) == 1
        assert ua[0].raw_score == pytest.approx(1.0)

    def test_the_signal_source_is_not_the_sensor_name(self):
        """`sensor="bg_observer_rss"` but `signal_source="bg_observer"`
        (`background_observer.py:392-393`). The ledger's dedup identity is
        the second, and using the first would unjoin WP-2.8's comparison."""
        assert bg_observer_rss.SIGNAL_SOURCE == "bg_observer"
        for draft in self._drafts():
            assert draft.signal_source == "bg_observer"

    def test_the_domain_is_info(self):
        for draft in self._drafts():
            assert draft.domain == "info"

    def test_the_value_string_is_productions(self):
        """`f"rss:{country} fatalities={n} conf={c:.2f}"` — `:394-397`."""
        by_country = {d.country: d for d in self._drafts()}
        assert by_country["RU"].value == "rss:RU fatalities=12 conf=0.85"
        assert by_country["JP"].value == "rss:JP fatalities=0 conf=0.40"

    def test_the_item_link_travels_as_evidence(self):
        """§7-2 #47 — additive. Production sets `evidence_url=None`
        (`:398`), so an analyst reading the score cannot reach the article
        that produced it, which is the verification path NP6 requires."""
        by_country = {d.country: d for d in self._drafts()}
        assert by_country["RU"].evidence_url == "https://news.test/a"

    def test_the_alias_gap_is_reported_and_not_fatal(self):
        """SENSI-030: an uncovered participant produces no match, and the
        only way to tell that apart from "the wire said nothing" is to
        publish the gap. Processing continues either way (NP1)."""
        drafts = bg_observer_rss.normalize(
            rss_payload((FIXTURES / "bg_observer_rss"
                         / "world_feed.xml").read_bytes()),
            context("bg_observer_rss", countries=BG_PARTICIPANTS + ("XX",)))
        assert drafts
        assert drafts[0].flags["alias_gap"] == ["XX"]

    def test_an_empty_participant_union_fetches_nothing_and_attributes_nothing(
            self):
        """SENSI-027. Attributing a story to "everyone" when the union is
        empty is the Phase 9-E attribution pollution in another costume."""
        assert bg_observer_rss.normalize(
            rss_payload((FIXTURES / "bg_observer_rss"
                         / "world_feed.xml").read_bytes()),
            context("bg_observer_rss", countries=())) == ()

    def test_the_analysed_text_joins_title_and_summary_productions_way(self):
        """`(title + " — " + summary).strip()` — `:356`. The separator is
        unconditional, so an item with no summary ends in a dangling em
        dash; the excerpt is capped at 240 characters and a different
        separator shifts the cut."""
        assert bg_observer_rss.item_text("T", "") == "T —"
        assert bg_observer_rss.item_text("T", "S") == "T — S"


class TestBgObserverFeedLiveness:
    def test_k08_feeds_get_a_two_stage_parse_and_a_named_death_cause(self):
        """K08 / §1-7. A-02 measured RSS parsing duplicated four to five
        times with the tolerant two-stage parser in `diplomatic` ALONE, so
        the same malformed feed parsed or did not depending on which sensor
        fetched it — which is not a property of the feed. One parser, and
        five named causes instead of one `failed` counter."""
        broken = b"<rss><channel><item><title>Taiwan attack</title>"
        assert bg_observer_rss.classify_feed(rss_payload(broken)) == parse.OK
        assert bg_observer_rss.classify_feed(
            rss_payload(b"<!doctype html><html>gone</html>")) == \
            parse.RETURNS_HTML
        assert bg_observer_rss.classify_feed(
            rss_payload(b"", status=404)) == parse.HTTP_ERROR
        assert bg_observer_rss.classify_feed(
            rss_payload(b"<rss><channel/></rss>")) == parse.RSS_EMPTY
        assert bg_observer_rss.classify_feed(
            rss_payload(b"nope", status=451)) == parse.GEO_BLOCK
        assert parse.DEATH_CAUSES >= {parse.RETURNS_HTML, parse.RSS_EMPTY,
                                      parse.UNPARSEABLE, parse.HTTP_ERROR,
                                      parse.GEO_BLOCK}

    def test_a_recoverable_feed_still_yields_its_items(self):
        """Stage 2 exists because a malformed feed is the normal case. The
        unterminated fixture above is what four of the nine wires send on a
        bad day, and `defusedxml` alone would have discarded it."""
        broken = (b"<rss><channel><item><title>Taiwan airstrike reported"
                  b"</title><link>https://x.test/1</link></item>")
        drafts = bg_observer_rss.normalize(
            rss_payload(broken),
            context("bg_observer_rss", countries=BG_PARTICIPANTS))
        assert [d.country for d in drafts] == ["TW"]

    def test_a_dead_feed_emits_no_observation(self):
        """Production answers a dead feed with a `feeds_failed` counter in
        the cycle record, never a signal. Inventing a row here would put an
        observation in the ledger that the system under comparison never
        emits — and a country-less row cannot be emitted nine times in one
        tick anyway (L1's uniqueness)."""
        for body, status in ((b"<!doctype html><html/>", 200),
                             (b"", 503), (b"", 200)):
            assert bg_observer_rss.normalize(
                rss_payload(body, status=status),
                context("bg_observer_rss", countries=BG_PARTICIPANTS)) == ()

    def test_an_entity_attack_is_not_merely_unparseable(self):
        """A billion-laughs payload is hostile rather than broken, and
        stage 2 would have returned a tree and reported it OK."""
        bomb = (b'<!DOCTYPE r [<!ENTITY a "aaaaaaaaaa">'
                b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
                b'<rss><channel><item><title>&b;</title></item></channel></rss>')
        assert bg_observer_rss.classify_feed(
            rss_payload(bomb)) == parse.ENTITY_ATTACK


class TestBgObserverDeclaration:
    ADAPTER = bg_observer_rss.BG_OBSERVER_RSS_ADAPTER

    def test_the_cadence_is_the_deployed_interval(self):
        """`BG_OBSERVER_INTERVAL_SEC` = 300 (`config.env:184`)."""
        assert self.ADAPTER.cadence.cadence_sec == 300.0

    def test_the_freshness_horizon_is_the_signal_ttl(self):
        """`BG_OBSERVER_SIGNAL_TTL_SEC` = 1800 (`config.env:185`). In
        production this is a deque's lifetime in process memory; here it is
        the L1 horizon, which is the same fact told to a store that
        survives a restart."""
        assert self.ADAPTER.freshness_horizon_sec == 1800.0

    def test_the_adapter_owns_no_thread(self):
        """DP1/B-01 disappears structurally. Production's private daemon
        (`bg_observer.py:144-155`) never consults the breaker and never
        reports to it, so the breaker for this sensor is permanently
        closed and an RSS outage throttles nothing."""
        source = (REPO_ROOT / "v3/adapters/info/bg_observer_rss.py").read_text(
            "utf-8")
        assert "threading" not in source
        assert "time.sleep" not in source

    def test_it_needs_no_credential(self):
        """SENSI-026: no API key, no registration, no LLM — the adapter has
        to work in an air-gapped deployment."""
        assert self.ADAPTER.auth.kind == "none"
        for spec in self.ADAPTER.declared_specs:
            assert spec.auth is None

    def test_it_claims_k08(self):
        assert self.ADAPTER.knowledge_refs == ("K08",)


# ── military_exercise (S1-SENSI-035..037 + INGEST-*) ────────────────────

MIL_SOURCE = "radar/sensors/military_exercise.py"


def prompt_constants(relative_path: str, varname: str) -> list:
    """Every fixed text segment of a prompt built by string concatenation.

    The prompt IS the measurement: its BIAS CHECK block is what keeps a
    Mediterranean exercise out of the Taiwan theatre, and its confidence
    guide is what the 0.35 floor is calibrated against. A paraphrase
    changes the distribution of answers while leaving every threshold,
    identifier and output shape intact — which is the exact failure the
    97-infidelity sweep was measuring.
    """
    tree = ast.parse(legacy_source(relative_path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == varname
                for t in node.targets):
            # A format spec (`{z:.2f}`) is a Constant too, and it is
            # markup rather than prompt text — comparing it against the
            # RENDERED prompt would look for the literal ".2f".
            specs = {id(sub.format_spec) for sub in ast.walk(node.value)
                     if isinstance(sub, ast.FormattedValue)
                     and sub.format_spec is not None}
            skip = {id(inner) for spec in ast.walk(node.value)
                    if id(spec) in specs
                    for inner in ast.walk(spec)}
            return [sub.value for sub in ast.walk(node.value)
                    if isinstance(sub, ast.Constant)
                    and id(sub) not in skip
                    and isinstance(sub.value, str) and sub.value.strip()]
    raise AssertionError(f"{varname} is not assigned in {relative_path}")


def mil_payload(name="pacom_feed.xml", *, label="PACOM_NEWS", status=200,
                url="https://www.pacom.mil/Media/News/rss/"):
    return payload("military_exercise", name, url=url, label=label,
                   status=status, content_type="application/rss+xml")


MIL_NAMES = {"TW": "Taiwan", "JP": "Japan", "KP": "North Korea",
             "PH": "Philippines"}


def mil_context(**over):
    base = {"countries": ("TW", "JP", "KP", "PH"), "country_names": MIL_NAMES}
    base.update(over)
    return context("military_exercise", **base)


class TestMilitaryExerciseLedgersAreTranscribed:
    def test_the_seven_feeds_match_the_live_sensor(self):
        assert military_exercise.MILITARY_SOURCES == literal_in(
            MIL_SOURCE, "_MILITARY_SOURCES")

    def test_the_theatre_lists_are_part_of_the_ledger(self):
        """An article whose theatre is not in its FEED's list is discarded
        (`military_exercise.py:365`), so widening a list admits
        attributions production refuses and narrowing one blinds a
        theatre. TASS's entry carries the written reason: restricting it
        to `UA` "forced Iran/ME articles into UA theater"."""
        assert military_exercise.MILITARY_SOURCES[
            "TASS_MILITARY"]["theaters"] == ["UA", "IR", "IL", "SY", "KP"]

    def test_the_exercise_keywords_match_the_live_sensor(self):
        assert list(military_exercise.EXERCISE_KEYWORDS) == literal_in(
            MIL_SOURCE, "_EXERCISE_KEYWORDS")

    def test_the_dedup_key_is_productions_hash(self):
        """`md5(f"mil-{source}-{title[:60]}")` (`:109-112`). The separator
        and the 60-character cut are both part of the key; a key that
        differs is a dedup ledger that cannot cross the cutover."""
        import hashlib
        title = "T" * 90
        expected = hashlib.md5(f"mil-PACOM_NEWS-{'T' * 60}".encode(),
                               usedforsecurity=False).hexdigest()
        assert military_exercise.dedup_key("PACOM_NEWS", title) == expected

    def test_the_user_agent_is_productions(self):
        assert military_exercise.USER_AGENT in legacy_source(MIL_SOURCE)
        assert military_exercise.USER_AGENT == "Mozilla/5.0 (OSINT-Radar/8.0)"
        for spec in military_exercise.MILITARY_EXERCISE_ADAPTER.declared_specs:
            assert spec.headers["User-Agent"] == military_exercise.USER_AGENT

    def test_the_score_tables_match_the_clause(self):
        """S1-SENSI-036 — `base + bonus`, additive so the ceiling is a sum
        and not a product (`:396-401`)."""
        assert military_exercise.URGENCY_BASE == {
            "critical": 2.5, "high": 2.0, "medium": 1.5, "low": 1.0}
        assert military_exercise.SCALE_BONUS == {
            "strategic": 0.5, "operational": 0.2, "tactical": 0.0}

    def test_the_event_type_vocabulary_matches_the_live_sensor(self):
        """The FULL enum has to be declared, not only the acting rules:
        `safe_enum` folds every unrecognised answer onto `none`, and
        `none` is a DROP, so an undeclared member would be discarded as
        though the model had said nothing."""
        assert set(military_exercise.EVENT_TYPES) == literal_in(
            MIL_SOURCE, "_EVENT_TYPES")


class TestMilitaryExercisePromptIsTranscribed:
    def _rendered(self):
        return military_exercise.prompt(
            {"title": "T", "summary": "S"},
            {"theaters": ("TW", "JP"), "org": "USNI", "today": "2026-08-08"})

    def test_every_fixed_segment_of_the_system_prompt_survives(self):
        system, _ = self._rendered()
        for part in prompt_constants(MIL_SOURCE, "system_prompt"):
            assert part in system, part[:80]

    def test_every_fixed_segment_of_the_user_prompt_survives(self):
        _, user = self._rendered()
        for part in prompt_constants(MIL_SOURCE, "user_prompt"):
            assert part in user, part[:80]

    def test_the_bias_check_block_is_present_verbatim(self):
        """The block exists because the model filed a Mediterranean
        exercise under TW for "signalling deterrence"."""
        _, user = self._rendered()
        assert "BIAS CHECK" in user
        assert "is NOT a direct theater link" in user
        assert "set theater=null instead" in user

    def test_the_token_budget_is_this_sources_own(self):
        """`max_tokens=300` (`:315`) — one of the eight values A-02
        measured drifting across 200-512."""
        assert military_exercise.PROFILE.max_tokens == 300


class TestMilitaryExerciseSelection:
    def test_slot_one_takes_five_keyword_articles(self):
        drafts = military_exercise.normalize(mil_payload(), mil_context())
        titles = [d.value for d in drafts]
        assert sum(1 for t in titles if t.startswith("Joint exercise")) == 5

    def test_a_sixth_keyword_article_is_dropped_not_demoted(self):
        """`continue` fires whether or not slot 1 had room (`:182-186`).
        Demoting the overflow into slot 2 is a wider candidate set — an
        unregistered sensitivity difference and a larger model bill."""
        drafts = military_exercise.normalize(mil_payload(), mil_context())
        assert "Joint exercise 6 begins near the strait" not in [
            d.value for d in drafts]

    def test_slot_two_takes_two_theatre_name_articles(self):
        drafts = military_exercise.normalize(mil_payload(), mil_context())
        assert sum(1 for d in drafts
                   if d.value.startswith("Taiwan trade delegation")) == 2

    def test_the_result_is_slot_one_then_slot_two_not_feed_order(self):
        """`return keyword_articles + theater_only_articles` (`:196`)."""
        drafts = military_exercise.normalize(mil_payload(), mil_context())
        kinds = ["kw" if d.value.startswith("Joint") else "th"
                 for d in drafts]
        assert kinds == ["kw"] * 5 + ["th"] * 2

    def test_a_stale_article_is_outside_the_forty_eight_hour_window(self):
        drafts = military_exercise.normalize(mil_payload(), mil_context())
        assert "Old amphibious landing rehearsal" not in [
            d.value for d in drafts]

    def test_an_undated_article_is_kept(self):
        """`not (pub_ts > 0 and pub_ts < cutoff)` (`:176`). Dropping it
        would make an odd date format indistinguishable from a quiet
        week, and NP1 prefers a stale candidate to a dropped one."""
        body = (b'<rss><channel><item><title>Undated drill</title>'
                b'<description>x</description></item></channel></rss>')
        drafts = military_exercise.normalize(
            synthetic(body, label="PACOM_NEWS"), mil_context())
        assert [d.value for d in drafts] == ["Undated drill"]

    def test_a_repeated_title_is_suppressed(self):
        drafts = military_exercise.normalize(mil_payload(), mil_context())
        assert [d.value for d in drafts].count(
            "Joint exercise 1 begins near the strait") == 1

    def test_an_article_matching_neither_ledger_is_excluded(self):
        drafts = military_exercise.normalize(mil_payload(), mil_context())
        assert "Quarterly earnings released" not in [d.value for d in drafts]

    def test_the_candidates_carry_their_dedup_key_and_feed(self):
        draft = military_exercise.normalize(mil_payload(), mil_context())[0]
        assert draft.flags["feed"] == "PACOM_NEWS"
        assert draft.flags["article"]["dedup_key"] == \
            military_exercise.dedup_key("PACOM_NEWS", draft.value)
        assert draft.flags["article"]["org"] == "USINDOPACOM"

    def test_a_candidate_is_observed_and_not_fired(self):
        """An article becomes a signal only once the model attributes it.
        FIRING here would score a headline nobody has read."""
        for draft in military_exercise.normalize(mil_payload(),
                                                 mil_context()):
            assert draft.status == STATUS_OBSERVED
            assert draft.raw_score == 0.0

    def test_the_row_domain_is_the_sensors_not_the_items(self):
        """`super().__init__("military_exercise", "info", ...)` (`:203`)
        against `"domain": "physical"` on the item (`:426`). Two different
        facts; conflating them puts a pre-model candidate row into the
        domain that gates TL1."""
        for draft in military_exercise.normalize(mil_payload(),
                                                 mil_context()):
            assert draft.domain == "info"
        assert military_exercise.PROFILE.domain == "physical"


class TestMilitaryExerciseFeedScope:
    def test_a_feed_with_no_theatre_in_the_union_yields_nothing(self):
        """`:227-229` — the feed is not fetched at all."""
        assert military_exercise.normalize(
            mil_payload(), mil_context(countries=("SK",))) == ()

    def test_an_empty_union_means_no_narrowing_at_all(self):
        """`if t in strategic_theaters or not strategic_theaters` (`:227`)
        — an empty union keeps every declared theatre rather than
        producing an empty list."""
        assert military_exercise.feed_theaters(
            "PACOM_NEWS", mil_context(countries=())) == (
                "TW", "JP", "KP", "PH")

    def test_the_theatre_names_come_from_the_supplied_ledger(self):
        """`COUNTRY_COORDS[code]["name"].lower()` (`:98-106`), supplied
        through `NormalizeContext` because nothing under `v3/` reads
        configuration."""
        assert military_exercise.theater_names(
            "PACOM_NEWS", mil_context()) == (
                "taiwan", "japan", "north korea", "philippines")

    def test_a_theatre_with_no_name_contributes_nothing(self):
        assert military_exercise.theater_names(
            "PACOM_NEWS", mil_context(country_names={"TW": "Taiwan"})) == (
                "taiwan",)

    def test_a_dead_feed_names_its_cause(self):
        """`_fetch_rss` returns "" for every non-200 including 429
        (`:122-125`), and `_parse_articles("")` returns [] — production
        cannot tell a rate limit from an empty week."""
        draft = military_exercise.normalize(
            synthetic(b"", label="PACOM_NEWS"), mil_context())[0]
        assert draft.status == STATUS_NO_DATA
        assert draft.flags["outcome"] == parse.RSS_EMPTY
        draft = military_exercise.normalize(
            FetchedPayload(url="https://x.test", status=429, body=b"",
                           fetched_at=T0, label="PACOM_NEWS"),
            mil_context())[0]
        assert draft.flags["outcome"] == parse.HTTP_ERROR


class TestMilitaryExerciseDispositions:
    """S1-SENSI-035 as data. 裁定要求 10, ruled 2026-08-08."""

    def _item(self, **over):
        data = {"headline": "Carrier group sails", "escalation_signal": True,
                "event_type": "new_deployment", "theater": "TW",
                "countries": ["TW"], "theater_link": "direct",
                "urgency": "high", "scale": "operational", "confidence": 0.9}
        data.update(over)
        return ex.build_item(military_exercise.PROFILE, data,
                             {"title": "t", "link": "https://mil.test/x"},
                             now=T0, scope=("TW", "JP"))

    def test_a_non_event_is_dropped_under_its_own_reason(self):
        """`record_sensor_drop("event_type_none")` (`:345`). Collapsing it
        into the shared `no_escalation_signal` makes "the model saw
        nothing" and "this was not an event" the same sentence, and
        S1-INGEST-020 exists because they call for different repairs."""
        item, reason = self._item(event_type="none")
        assert (item, reason) == (None, "event_type_none")

    def test_an_unrecognised_event_type_folds_onto_none(self):
        """`safe_enum(data.get("event_type"), _EVENT_TYPES, "none")`
        (`:339`) — and `none` is a discard, so an invented answer is
        dropped rather than accepted."""
        for bad in ("parade", "", "NEW-DEPLOYMENT"):
            item, reason = self._item(event_type=bad)
            assert (item, reason) == (None, "event_type_none"), bad

    def test_a_status_report_is_kept_at_a_capped_confidence(self):
        """S1-SENSI-035: never auto-confirmed, but above the floor so an
        analyst still sees it (NP1). `min(confidence, 0.50)` (`:348`)."""
        item, _ = self._item(event_type="status_report", confidence=0.95)
        assert item is not None
        assert item.confidence == 0.50

    def test_historical_analysis_is_capped_the_same_way(self):
        item, _ = self._item(event_type="historical_analysis",
                             confidence=0.88)
        assert item.confidence == 0.50

    def test_a_real_event_type_is_not_capped(self):
        item, _ = self._item(event_type="exercise_start", confidence=0.9)
        assert item.confidence == 0.9

    def test_an_indirect_theatre_link_is_capped_at_this_sources_value(self):
        """0.50 here, 0.45 for `diplomatic` (`:385` vs
        `diplomatic.py:518`). One shared value would be an invention."""
        item, _ = self._item(theater_link="indirect", confidence=0.9)
        assert item.confidence == 0.50

    def test_a_theatre_outside_this_feeds_list_is_a_legitimate_discard(self):
        """`llm_theater not in theaters` (`:365`) is a per-FEED scope, not
        the abolished A9 discard — `hacktivist_news`'s
        `theater_not_strategic` was ruled away (§3-3 A9) and this one was
        not, because this prompt tells the model to choose FROM the
        list."""
        item, reason = self._item(theater="UA", countries=["UA"])
        assert (item, reason) == (None, ex.NOT_IN_SCOPE)

    def test_the_dispositions_carry_no_callables(self):
        for rule in military_exercise.DISPOSITIONS:
            assert not callable(rule.field)
            assert all(not callable(value) for value in rule.values)


class TestMilitaryExerciseScoring:
    def test_the_score_is_the_additive_sum(self):
        """S1-SENSI-036 — `round(base + bonus, 1)` (`:401`)."""
        assert military_exercise.score_delta(
            {"urgency": "critical", "scale": "strategic"}) == 3.0
        assert military_exercise.score_delta(
            {"urgency": "medium", "scale": "operational"}) == 1.7

    def test_an_unrecognised_urgency_scores_as_low(self):
        """`safe_enum(..., "low")` (`:397`) — the default is part of the
        arithmetic, and dropping the item instead would be a different
        sensor."""
        assert military_exercise.score_delta({"urgency": "extreme"}) == 1.0

    def test_an_unrecognised_scale_earns_no_bonus(self):
        assert military_exercise.score_delta(
            {"urgency": "high", "scale": "planetary"}) == 2.0

    def test_the_ceiling_is_exactly_the_tl1_physical_gate(self):
        """A6 — the deferred question, stated rather than left to be
        rediscovered from a TL1 nobody can explain. S1-SENSI-037 fixes
        these items into `physical`, S1-SCORE-004's TL1 gate has a
        `physical >= 3.0` floor, and ONE `critical` + `strategic` wire
        story reaches it."""
        ceiling = max(military_exercise.URGENCY_BASE.values()) + max(
            military_exercise.SCALE_BONUS.values())
        assert ceiling == 3.0
        assert military_exercise.PROFILE.domain == "physical"


class TestMilitaryExerciseDeclaration:
    ADAPTER = military_exercise.MILITARY_EXERCISE_ADAPTER

    def test_every_feed_is_declared_in_the_ledgers_order(self):
        assert [spec.url for spec in self.ADAPTER.declared_specs] == [
            meta["url"] for meta in
            military_exercise.MILITARY_SOURCES.values()]

    def test_each_request_is_labelled_with_its_ledger_key(self):
        """The label is what `normalize` reads back to recover the feed's
        theatre list and its dedup key, and the key is the UPPER_SNAKE
        dict name rather than a label of our own."""
        assert [spec.label for spec in self.ADAPTER.declared_specs] == list(
            military_exercise.MILITARY_SOURCES)

    def test_the_cadence_is_the_live_poll_interval(self):
        """`_POLL_INTERVAL` = 3600 (`:37`)."""
        assert self.ADAPTER.cadence.cadence_sec == 3600.0

    def test_it_needs_no_credential(self):
        assert self.ADAPTER.auth.kind == "none"

    def test_the_category_is_llm(self):
        """§3-3 groups rows 29-34 as LLM/meta; rows 23-28 are info."""
        assert self.ADAPTER.category == "llm"


# ── diplomatic (S1-SENSI-032/034 + INGEST-*, K07/K08) ───────────────────

DIP_SOURCE = "radar/sensors/diplomatic.py"


def evaluated_in(relative_path: str, *names: str) -> dict:
    """Module-level assignments EXECUTED rather than literal-evaluated.

    `_DIPLOMATIC_SOURCES` builds its URLs with `.format()`, so
    `ast.literal_eval` cannot reach it — and the formatted query string is
    exactly the part worth pinning, because a re-encoded `+` returns a
    different corpus from the same-looking URL. The statements are
    compiled from the live file's AST and run in an empty namespace: the
    module itself is never imported.
    """
    tree = ast.parse(legacy_source(relative_path))
    namespace: dict = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in names
                for t in node.targets):
            exec(compile(ast.Module([node], []), "<legacy>", "exec"),
                 namespace)
    return namespace


def dip_payload(name="us_state.xml", *, label="US_STATE", status=200):
    return payload("diplomatic", name, url="https://news.google.com/rss/x",
                   label=label, status=status,
                   content_type="application/rss+xml")


DIP_NAMES = {"TW": "Taiwan", "UA": "Ukraine", "KP": "North Korea",
             "IR": "Iran", "IL": "Israel", "JP": "Japan",
             "PH": "Philippines"}


def dip_context(**over):
    base = {"countries": ("TW", "UA", "KP", "IR", "IL", "JP", "PH"),
            "country_names": DIP_NAMES}
    base.update(over)
    return context("diplomatic", **base)


class TestDiplomaticLedgersAreTranscribed:
    def test_the_eleven_sources_match_the_live_sensor(self):
        live = evaluated_in(DIP_SOURCE, "_GNEWS_BASE", "_DIPLOMATIC_SOURCES")
        assert diplomatic.DIPLOMATIC_SOURCES == live["_DIPLOMATIC_SOURCES"]

    def test_the_google_news_query_template_is_not_re_encoded(self):
        """`_GNEWS_BASE` (`:66`). The queries arrive percent-encoded; a
        port that re-encodes them double-escapes the `+` separators and
        fetches a different corpus from a URL that still looks right."""
        live = evaluated_in(DIP_SOURCE, "_GNEWS_BASE")
        assert diplomatic.GNEWS_BASE == live["_GNEWS_BASE"]
        assert "%22State+Department%22" in \
            diplomatic.DIPLOMATIC_SOURCES["US_STATE"]["url"]

    def test_the_escalation_keywords_match_the_live_sensor(self):
        assert list(diplomatic.ESC_KEYWORDS) == literal_in(
            DIP_SOURCE, "_ESC_KEYWORDS")

    def test_the_transliterated_place_names_are_part_of_the_ledger(self):
        """The last six entries exist because the escalation vocabulary
        alone misses a statement that names only a geography."""
        for name in ("taiwan strait", "south china sea", "senkaku",
                     "diaoyu", "korean peninsula", "indo-pacific"):
            assert name in diplomatic.ESC_KEYWORDS

    def test_all_three_browser_headers_travel(self):
        assert diplomatic.BROWSER_HEADERS == literal_in(
            DIP_SOURCE, "_BROWSER_HEADERS")
        for spec in diplomatic.DIPLOMATIC_ADAPTER.declared_specs:
            assert set(spec.headers) == {"User-Agent", "Accept",
                                         "Accept-Language"}

    def test_the_dedup_prefix_is_not_the_military_one(self):
        """`dipl-` (`:157`) against `mil-` (`military_exercise.py:111`).
        One prefix for both would suppress the second sensor's read of a
        syndicated article that both feeds carry."""
        assert diplomatic.dedup_key("US_STATE", "T") != \
            military_exercise.dedup_key("US_STATE", "T")

    def test_the_urgency_map_is_the_four_way_one(self):
        """S1-SENSI-034 (`:526`). NOT military_exercise's additive base —
        a diplomatic item's score is its urgency and nothing else."""
        assert diplomatic.URGENCY_SCORE == {"critical": 3.0, "high": 2.0,
                                            "medium": 1.5, "low": 1.0}
        assert diplomatic.score_delta({"urgency": "critical"}) == 3.0
        assert diplomatic.score_delta({"urgency": "unheard-of"}) == 1.0

    def test_the_indirect_cap_is_not_the_military_one(self):
        """0.45 (`:518`) against 0.50 (`military_exercise.py:385`). The
        per-source cap is measured, not invented."""
        assert diplomatic.INDIRECT_CAP == 0.45
        assert military_exercise.INDIRECT_CAP == 0.50

    def test_the_age_window_is_the_default_that_actually_runs(self):
        """`max_age_h: int = 48` (`:262`) — the docstring one line above
        says 24h and no caller overrides the default (`:389`). The
        docstring is not what runs."""
        assert diplomatic.ARTICLE_AGE_WINDOW_HOURS == 48


class TestDiplomaticKnowledge:
    def test_k07_the_diplomatic_feed_liveness_ledger_survives_as_data(self):
        """K07. Seven primary MFA/NATO endpoints are dead, each with its
        own cause, and in production the whole audit exists only as a
        comment block (`diplomatic.py:38-65`). D1's complaint is exactly
        that: a comment that stops being true stays green, and this
        knowledge was expensive — every entry was learned from a feed
        failing in production."""
        ledger = diplomatic.FEED_POST_MORTEM
        assert set(ledger) == {"US_STATE", "JP_MOFA", "CN_MFA", "TW_MOFA",
                               "RU_MFA", "KCNA_WATCH", "NATO"}
        assert ledger["CN_MFA"][1] == parse.RETURNS_HTML
        assert ledger["JP_MOFA"][1] == parse.HTTP_ERROR
        assert ledger["KCNA_WATCH"][1] == parse.RSS_EMPTY
        # Every cause is a cause the shared parser can actually report,
        # so the ledger and the runtime speak one vocabulary.
        for _endpoint, cause, _detail in ledger.values():
            assert cause in parse.DEATH_CAUSES
        # And the comment the ledger was read from still says so.
        comment = legacy_source(DIP_SOURCE)
        for endpoint, _cause, _detail in ledger.values():
            assert endpoint in comment, endpoint

    def test_the_replacement_strategy_is_visible_in_the_shipped_urls(self):
        """The dead primaries were replaced by Google News boolean
        queries, which survive an MFA website redesign. Two primaries did
        survive and are kept as complements (TASS, NK News)."""
        urls = [meta["url"]
                for meta in diplomatic.DIPLOMATIC_SOURCES.values()]
        assert sum(1 for u in urls if "news.google.com" in u) == 8
        assert "https://tass.com/rss/v2.xml" in urls
        assert "https://www.nknews.org/feed/" in urls


class TestDiplomaticPromptIsTranscribed:
    def _rendered(self):
        return diplomatic.prompt(
            {"title": "T", "summary": "S"},
            {"theaters": ("TW", "UA"), "country": "US",
             "today": "2026-08-08"})

    def test_every_fixed_segment_of_the_system_prompt_survives(self):
        system, _ = self._rendered()
        for part in prompt_constants(DIP_SOURCE, "system_prompt"):
            assert part in system, part[:80]

    def test_every_fixed_segment_of_the_user_prompt_survives(self):
        _, user = self._rendered()
        for part in prompt_constants(DIP_SOURCE, "user_prompt"):
            assert part in user, part[:80]

    def test_the_bias_check_keeps_its_worked_example(self):
        """"EU sanctions on Russia is 'direct' for UA, but 'none' for TW".
        Dropping the example is how a general instruction stops being
        followed."""
        _, user = self._rendered()
        assert "EU sanctions on Russia is 'direct' for UA" in user

    def test_the_token_budget_is_this_sources_own(self):
        assert diplomatic.PROFILE.max_tokens == 256
        assert military_exercise.PROFILE.max_tokens == 300


class TestDiplomaticSelection:
    def test_slot_one_takes_five_keyword_articles(self):
        drafts = diplomatic.normalize(dip_payload(), dip_context())
        assert sum(1 for d in drafts
                   if d.value.startswith("State Department")) == 5

    def test_a_sixth_keyword_article_is_dropped_not_demoted(self):
        drafts = diplomatic.normalize(dip_payload(), dip_context())
        assert "State Department issues a warning 6" not in [
            d.value for d in drafts]

    def test_slot_two_takes_two_theatre_name_articles(self):
        drafts = diplomatic.normalize(dip_payload(), dip_context())
        assert sum(1 for d in drafts
                   if d.value.startswith("Taiwan cultural")) == 2

    def test_a_stale_article_is_outside_the_window(self):
        drafts = diplomatic.normalize(dip_payload(), dip_context())
        assert "Old sanction announcement" not in [d.value for d in drafts]

    def test_a_repeated_title_is_suppressed(self):
        drafts = diplomatic.normalize(dip_payload(), dip_context())
        assert [d.value for d in drafts].count(
            "State Department issues a warning 1") == 1

    def test_slot_three_sends_the_most_recent_article_when_nothing_matched(
            self):
        """`:336-341`. This is what keeps a feed whose statements are all
        in Japanese from being invisible — dropping the fallback while
        porting would be a silent recall loss on exactly the non-English
        sources the sensor exists to read."""
        drafts = diplomatic.normalize(dip_payload("quiet.xml"),
                                      dip_context())
        assert [d.value for d in drafts] == ["Ambassador attends a concert"]
        assert drafts[0].flags["selection_slot"] == "most_recent_fallback"

    def test_the_fallback_is_not_used_when_a_slot_matched(self):
        drafts = diplomatic.normalize(dip_payload(), dip_context())
        assert all(d.flags["selection_slot"] == "keyword_or_theater"
                   for d in drafts)

    def test_an_undated_tie_goes_to_the_first_article(self):
        """`pub_ts > fallback.pub_ts` is STRICT (`:318`), and an
        unparseable date is 0.0 — so an undated feed's fallback is its
        FIRST item, not its last."""
        body = (b"<rss><channel>"
                b"<item><title>First quiet item</title></item>"
                b"<item><title>Second quiet item</title></item>"
                b"</channel></rss>")
        drafts = diplomatic.normalize(synthetic(body, label="TW_MOFA"),
                                      dip_context())
        assert [d.value for d in drafts] == ["First quiet item"]

    def test_the_candidates_carry_the_issuing_country(self):
        """`meta["country"]` is the ISSUER and lands in
        `llm_fields.source_country` (`:544`), which is a different fact
        from the theatre the statement is about."""
        draft = diplomatic.normalize(dip_payload(), dip_context())[0]
        assert draft.flags["article"]["country"] == "US"

    def test_a_feed_with_no_theatre_in_the_union_yields_nothing(self):
        assert diplomatic.normalize(
            dip_payload(label="TW_MOFA"),
            dip_context(countries=("UA",))) == ()

    def test_a_dead_feed_carries_its_post_mortem(self):
        draft = diplomatic.normalize(
            synthetic(b"<!doctype html><html>gone</html>", label="CN_MFA"),
            dip_context(countries=("TW", "JP", "PH", "IN")))[0]
        assert draft.status == STATUS_NO_DATA
        assert draft.flags["outcome"] == parse.RETURNS_HTML
        assert draft.flags["post_mortem"][1] == parse.RETURNS_HTML


class TestDiplomaticExtraction:
    def _item(self, **over):
        data = {"headline": "MFA warns over the strait",
                "escalation_signal": True, "theater": "TW",
                "countries": ["TW", "CN"], "theater_link": "direct",
                "urgency": "high", "confidence": 0.8}
        data.update(over)
        return ex.build_item(
            diplomatic.PROFILE, data,
            {"title": "t", "link": "https://dip.test/x"}, now=T0,
            scope=("TW", "UA"),
            headline_fallback=diplomatic.headline_fallback("US_STATE", "TW"))

    def test_the_item_domain_is_info(self):
        """S1-SENSI-034 fixes it, and it differs from
        `military_exercise`'s `physical` — which is the value that gates
        TL1."""
        item, _ = self._item()
        assert item.domain == "info"
        assert military_exercise.PROFILE.domain == "physical"

    def test_an_indirect_link_is_capped_at_this_sources_value(self):
        item, _ = self._item(theater_link="indirect", confidence=0.9)
        assert item.confidence == 0.45

    def test_a_missing_headline_takes_the_sources_fallback(self):
        """`data.get("headline", f"...")` (`:539`) — the ABSENT key takes
        the fallback and it names the source and the theatre, so an item
        the model left unheadlined is still identifiable."""
        item, _ = self._item()
        stripped = {k: v for k, v in
                    {"escalation_signal": True, "theater": "TW",
                     "countries": ["TW"], "theater_link": "direct",
                     "urgency": "low", "confidence": 0.8}.items()}
        built, _ = ex.build_item(
            diplomatic.PROFILE, stripped, {"title": "t"}, now=T0,
            headline_fallback=diplomatic.headline_fallback("US_STATE", "TW"))
        assert built.headline == "Diplomatic escalation signal: US_STATE / TW"
        assert item.headline == "MFA warns over the strait"

    def test_a_deliberately_empty_headline_is_kept_empty(self):
        """`.get(key, default)` fires on ABSENCE, not on emptiness."""
        item, _ = self._item(headline="")
        assert item.headline == ""

    def test_this_source_has_no_event_type_gate(self):
        """`diplomatic_action` is carried as a field and never used to
        drop or cap (`:543`). Adding a gate here because the sibling has
        one would be an invented discard."""
        fields = {rule.field for rule in diplomatic.DISPOSITIONS}
        assert fields == {"theater_link"}
        assert "diplomatic_action" in diplomatic.PROFILE.llm_field_keys


class TestDiplomaticDeclaration:
    ADAPTER = diplomatic.DIPLOMATIC_ADAPTER

    def test_every_source_is_declared_in_the_ledgers_order(self):
        assert [spec.label for spec in self.ADAPTER.declared_specs] == list(
            diplomatic.DIPLOMATIC_SOURCES)

    def test_the_cadence_is_the_live_poll_interval(self):
        assert self.ADAPTER.cadence.cadence_sec == 3600.0

    def test_it_claims_k07_and_k08(self):
        assert set(self.ADAPTER.knowledge_refs) == {"K07", "K08"}

    def test_it_needs_no_credential(self):
        assert self.ADAPTER.auth.kind == "none"


# ── hacktivist_news (S1-SENSI-041..043 + INGEST-*) ──────────────────────

HN_SOURCE = "radar/sensors/hacktivist_news_sensor.py"


def hn_payload(name="the_record.xml", *, label="THE_RECORD", status=200):
    return payload("hacktivist_news", name, url="https://therecord.media/feed",
                   label=label, status=status,
                   content_type="application/rss+xml")


def hn_context(**over):
    base = {"countries": ("TW", "UA")}
    base.update(over)
    return context("hacktivist_news", **base)


class TestHacktivistNewsLedgersAreTranscribed:
    def test_the_five_wires_match_the_live_sensor(self):
        assert hacktivist_news.NEWS_SOURCES == literal_in(
            HN_SOURCE, "_NEWS_SOURCES")

    def test_the_keyword_roster_matches_the_live_sensor(self):
        """The first fourteen entries are GROUP NAMES. A group that stops
        being listed stops being seen, so this is a threat-actor roster
        rather than a style choice."""
        assert list(hacktivist_news.HACKTIVIST_KEYWORDS) == literal_in(
            HN_SOURCE, "_HACKTIVIST_KEYWORDS")
        assert "noname057" in hacktivist_news.HACKTIVIST_KEYWORDS
        assert "it army of ukraine" in hacktivist_news.HACKTIVIST_KEYWORDS

    def test_the_discard_keywords_match_the_live_sensor(self):
        assert list(hacktivist_news.DISCARD_KEYWORDS) == literal_in(
            HN_SOURCE, "_DISCARD_KEYWORDS")

    def test_the_dedup_prefix_is_this_sensors_own(self):
        assert hacktivist_news.dedup_key("X", "t") != diplomatic.dedup_key(
            "X", "t")

    def test_the_summary_width_is_five_hundred_not_four(self):
        """`summary_clean[:500]` (`:198`) against `diplomatic`'s 400.
        The width decides how much text the model reads."""
        assert hacktivist_news.SUMMARY_CHARS == 500
        assert diplomatic.SUMMARY_CHARS == 400

    def test_the_token_budget_is_this_sources_own(self):
        assert hacktivist_news.PROFILE.max_tokens == 250


class TestHacktivistNewsSelection:
    def test_at_most_five_articles_survive(self):
        drafts = hacktivist_news.normalize(hn_payload(), hn_context())
        assert len(drafts) == 5

    def test_markup_is_stripped_before_the_gates_read_the_text(self):
        """`re.sub("<[^>]+>", " ")` (`:184-186`). A wire that wraps its
        summary in markup would otherwise hide every keyword inside an
        attribute."""
        assert hacktivist_news.strip_markup(
            "<p>took <b>down</b>   sites</p>") == "took down sites"
        draft = hacktivist_news.normalize(hn_payload(), hn_context())[0]
        assert "<" not in draft.flags["article"]["summary"]

    def test_the_marketing_discard_runs_before_the_keyword_gate(self):
        """"How to protect against a DDoS campaign" matches the campaign
        vocabulary without reporting a campaign (`:190-191`)."""
        drafts = hacktivist_news.normalize(hn_payload(), hn_context())
        assert "How to protect against a DDoS campaign" not in [
            d.value for d in drafts]

    def test_an_article_with_no_keyword_is_excluded(self):
        drafts = hacktivist_news.normalize(hn_payload(), hn_context())
        assert "Quarterly patch roundup" not in [d.value for d in drafts]

    def test_a_stale_article_is_outside_the_window(self):
        drafts = hacktivist_news.normalize(hn_payload(), hn_context())
        assert "Killnet DDoS attack on ports" not in [d.value for d in drafts]

    def test_an_atom_published_date_still_parses(self):
        """Two of the five wires publish Atom, whose date is ISO-8601
        (`:172-177`). Without the second attempt every Atom article dated
        to 0.0 and survived the window by accident rather than by rule."""
        assert hacktivist_news.published_timestamp(
            "2026-08-08T04:00:00Z") > 0

    def test_a_dead_wire_names_its_cause(self):
        draft = hacktivist_news.normalize(
            synthetic(b"<!doctype html><html/>", label="THE_RECORD"),
            hn_context())[0]
        assert draft.status == STATUS_NO_DATA
        assert draft.flags["outcome"] == parse.RETURNS_HTML


class TestHacktivistNewsA9IsAbolished:
    """§3-3 A9 / §7-2 #3 — the discard this port removes."""

    def _item(self, **over):
        data = {"headline": "Ports knocked offline", "is_active_campaign": True,
                "theater": "PL", "countries": ["PL"], "group_name": "NoName057",
                "attack_type": "DDoS", "urgency": "high", "confidence": 0.8}
        data.update(over)
        # NO `scope` — passing it would resurrect the abolished discard
        # through the shared out-of-scope check.
        return ex.build_item(hacktivist_news.PROFILE, data,
                             {"title": "t", "link": "https://sec.test/x"},
                             now=T0)

    def test_a_target_outside_the_union_is_kept(self):
        """Production drops it (`:392-398`,
        `record_sensor_drop("theater_not_strategic")`) and is the ONLY one
        of the eight LLM sensors that does. §7-2 #3 registers the
        removal, direction sensitive."""
        item, reason = self._item()
        assert item is not None, reason
        assert item.country == "PL"

    def test_the_prompt_already_promised_python_would_filter(self):
        """The discard contradicted its own prompt, in capitals. That is
        why the prompt is right and the Python was wrong."""
        _, user = hacktivist_news.prompt(
            {"title": "t", "summary": "s"},
            {"theaters": ("TW",), "org": "TheRecord", "today": "x"})
        assert "Do NOT force-assign a theater from that list" in user
        assert "the system will handle filtering" in user

    def test_this_adapter_never_declares_a_scope(self):
        """The regression guard. Passing `scope` for this source is the
        same discard by a different door, and it would look like ordinary
        wiring."""
        source = (REPO_ROOT / "v3/adapters/llm/hacktivist_news.py").read_text(
            "utf-8")
        assert "scope=" not in source

    def test_an_unnamed_target_is_still_discarded(self):
        """`theater in ("NULL", "NONE")` or empty (`:386-391`). A9
        abolished the SCOPE filter, not the requirement that the model
        name a country — an item attributed to nobody cannot be scored."""
        for absent in (None, "", "NULL", "none"):
            item, reason = self._item(theater=absent)
            assert (item, reason) == (None, ex.NO_PRIMARY_COUNTRY), absent


class TestHacktivistNewsSignalField:
    def test_the_signal_key_is_is_active_campaign(self):
        """`data.get("is_active_campaign", False)` (`:362`) — this source
        asks whether a campaign is ONGOING, not whether something
        escalated. Seven sources use the other key."""
        assert hacktivist_news.PROFILE.signal_field == "is_active_campaign"
        assert diplomatic.PROFILE.signal_field == "escalation_signal"

    def test_the_silence_has_this_sources_own_name(self):
        """`record_sensor_drop("not_active_campaign")` (`:367`).
        S1-INGEST-020: "the article is a retrospective" and "nothing
        escalated" point at different prompts."""
        item, reason = ex.build_item(
            hacktivist_news.PROFILE,
            {"is_active_campaign": False, "theater": "TW",
             "confidence": 0.9}, {"title": "t"}, now=T0)
        assert (item, reason) == (None, "not_active_campaign")

    def test_this_source_declares_no_relevance_rules(self):
        """The prompt never asks for `theater_link` (`:311-330`), and
        every rule set that declares it DROPS an answer that does not
        carry it — attaching `relevance_rules` here would discard every
        item this sensor produces."""
        assert hacktivist_news.DISPOSITIONS == ()
        _, user = hacktivist_news.prompt({"title": "t"}, {})
        assert "theater_link" not in user


class TestHacktivistNewsScoring:
    def test_the_score_is_urgency_base_plus_type_bonus(self):
        assert hacktivist_news.score_delta(
            {"urgency": "critical", "attack_type": "DDoS"}) == 2.5
        assert hacktivist_news.score_delta(
            {"urgency": "low", "attack_type": "data_leak"}) == 0.7

    def test_the_urgency_default_is_medium_not_low(self):
        """`safe_enum(..., "medium")` (`:407-410`) — the two RSS sensors
        default to `low`. Harmonising them would change the score of every
        malformed answer."""
        assert hacktivist_news.URGENCY_DEFAULT == "medium"
        assert military_exercise.URGENCY_DEFAULT == "low"

    def test_a_malformed_answer_is_scored_as_a_ddos_campaign(self):
        """§3-5 H-4, PRESERVED. `safe_enum(attack_type, {...}, "DDoS")`
        (`:411-414`) means an omitted or garbled field earns +0.5 — the
        largest bonus in the table and the same one a confirmed DDoS
        campaign gets. An answer with nothing in it therefore outscores a
        correctly-reported low-urgency data leak.

        Ported as production has it: changing a default mid-port is the
        tidying that turns a transcription into a rewrite, and the
        conservative alternative (`"none"`) is a registered change
        somebody has to approve."""
        assert hacktivist_news.ATTACK_TYPE_DEFAULT == "DDoS"
        assert hacktivist_news.score_delta({}) == 1.5
        assert hacktivist_news.score_delta({}) > hacktivist_news.score_delta(
            {"urgency": "low", "attack_type": "data_leak"})

    def test_the_attack_type_match_is_case_sensitive_like_productions(self):
        """`safe_enum` compares against `{"DDoS", ...}` (`:411-414`), so
        a lower-case `ddos` is NOT a member and falls to the default —
        which happens to be `DDoS` anyway, so the score is unchanged and
        the field recorded is the default. Reproduced rather than
        case-folded."""
        assert hacktivist_news.score_delta(
            {"urgency": "low", "attack_type": "ddos"}) == 1.0

    def test_the_headline_fallback_keeps_productions_placeholder(self):
        """`data.get('group_name', '?')` (`:441`). "? / TW" says the group
        was not identified; "unknown / TW" reads as a group called
        unknown."""
        assert hacktivist_news.headline_fallback("", "TW") == \
            "Hacktivist campaign: ? / TW"


class TestHacktivistNewsPromptIsTranscribed:
    def _rendered(self):
        return hacktivist_news.prompt(
            {"title": "T", "summary": "S"},
            {"theaters": ("TW", "UA"), "org": "TheRecord",
             "today": "2026-08-08"})

    def test_every_fixed_segment_of_the_system_prompt_survives(self):
        system, _ = self._rendered()
        for part in prompt_constants(HN_SOURCE, "system_prompt"):
            assert part in system, part[:80]

    def test_every_fixed_segment_of_the_user_prompt_survives(self):
        _, user = self._rendered()
        for part in prompt_constants(HN_SOURCE, "user_prompt"):
            assert part in user, part[:80]

    def test_an_empty_union_renders_as_the_word_any(self):
        """`", ".join(sorted(...)) if strategic_theaters else "any"`
        (`:303`) — a word the model can read, rather than an empty list
        it would fill in."""
        _, user = hacktivist_news.prompt({"title": "t"}, {})
        assert "Active strategic theaters: any" in user


class TestHacktivistNewsDeclaration:
    ADAPTER = hacktivist_news.HACKTIVIST_NEWS_ADAPTER

    def test_every_wire_is_declared_in_the_ledgers_order(self):
        assert [spec.label for spec in self.ADAPTER.declared_specs] == list(
            hacktivist_news.NEWS_SOURCES)

    def test_the_cadence_is_the_live_poll_interval(self):
        """`_POLL_INTERVAL` = 1800 (`:37`) — half `diplomatic`'s."""
        assert self.ADAPTER.cadence.cadence_sec == 1800.0

    def test_it_needs_no_credential(self):
        assert self.ADAPTER.auth.kind == "none"


# ── telegram_mirror (S1-SENSI-012..018, K13) ────────────────────────────

TG_SOURCE = "radar/sensors/telegram.py"


def tg_payload(name="channel.html", *, channel="noname057", status=200,
               url=None):
    body = (FIXTURES / "telegram_mirror" / name).read_bytes()
    return FetchedPayload(
        url=url or f"https://t.me/s/{channel}", status=status, body=body,
        fetched_at=T0, content_type="text/html", label=f"channel:{channel}")


def tg_context(**over):
    return context("telegram_mirror", **over)


class TestTelegramLedgersAreTranscribed:
    def test_k13_the_user_agent_pool_and_the_backoff_are_both_present(self):
        """K13. `t.me` answers a library user-agent with 403, and a 403
        that leaves the previous reading in place is indistinguishable
        from a channel that went quiet. The POOL is declared data here;
        the retry/backoff is the kernel's, because "how to fetch" is what
        an adapter may not write (§1-5).

        The rotation ACROSS the pool needs a per-request choice the
        declaration model has no slot for, so the shipped request carries
        the first entry and §7-2 #50 names WP-4.1 as the landing."""
        live = evaluated_in(TG_SOURCE, "_SCRAPER_UA_POOL")
        assert list(telegram_mirror.USER_AGENT_POOL) == live[
            "_SCRAPER_UA_POOL"]
        assert len(telegram_mirror.USER_AGENT_POOL) == 5
        spec = telegram_mirror.TELEGRAM_MIRROR_ADAPTER.declared_specs[0]
        assert spec.headers["User-Agent"] == telegram_mirror.USER_AGENT_POOL[0]
        assert spec.headers["Accept-Language"] == "en-US,en;q=0.9"
        # The backoff the kernel applies to the 403/429 this fact is about.
        from v3.fetch import policy
        assert policy.backoff_delay(2) > policy.backoff_delay(1)

    def test_the_preview_url_keeps_its_s_segment(self):
        """`t.me/s/{channel}` (`:57`). Without `/s/` the URL serves the
        app-install page and every channel reads as empty."""
        assert telegram_mirror.PREVIEW_URL == "https://t.me/s/{channel}"

    def test_the_attack_keywords_are_the_deployed_default(self):
        assert list(telegram_mirror.ATTACK_KEYWORDS) == [
            "target", "attack", "ddos", "http flood", "under attack",
            "down", "offline", "op", "#target"]

    def test_the_two_government_pattern_lists_are_kept_apart(self):
        """`:185-188` has nine patterns including `bank` / `energy` /
        `telecom`; the staged confidence (`:437-440`) uses three. Merging
        them would raise a bank target to a ministry's corroboration."""
        assert len(telegram_mirror.GOV_TARGET_PATTERNS) == 9
        assert telegram_mirror.GOV_CONFIDENCE_PATTERNS == (
            ".gov", ".mil", ".parliament")

    def test_the_staged_confidences_match_the_live_sensor(self):
        live = evaluated_in(TG_SOURCE, "_CONF_DECLARATION_ONLY",
                            "_CONF_WITH_GOV_TARGETS",
                            "_CONF_WITH_ZSCORE_BURST")
        assert telegram_mirror.CONF_DECLARATION_ONLY == live[
            "_CONF_DECLARATION_ONLY"]
        assert telegram_mirror.CONF_WITH_GOV_TARGETS == live[
            "_CONF_WITH_GOV_TARGETS"]
        assert telegram_mirror.CONF_WITH_ZSCORE_BURST == live[
            "_CONF_WITH_ZSCORE_BURST"]

    def test_the_post_window_is_the_widened_one(self):
        """8h dropped 100% of posts on every active channel while the
        channels were healthy (`:24-30`). Hacktivist channels post in
        bursts and go silent for 24-72h."""
        assert telegram_mirror.POST_MAX_AGE_HOURS == 48


class TestTelegramDP6IsUnspellable:
    def test_the_baseline_window_knows_its_own_sample_count(self):
        """DP6 — F-06's twin. Production capped the baseline at
        `NARRATIVE_BASELINE_DAYS` ENTRIES while polling every 900s, so a
        declared 30-day window held 30 samples: about seven and a half
        hours. The z-score normalised a burst against the burst.

        Here the window IS both facts and derives one from the other, so
        a count and a duration can never disagree again."""
        window = telegram_mirror.BASELINE_WINDOW
        assert window.effective_days == 30
        assert window.effective_samples == 30 * (86400 // 900)
        assert window.effective_samples == 2880

    def test_the_defect_needed_a_hand_multiplication_in_production(self):
        """The repair (2026-08-07) is `days * cycles_per_day` computed at
        the one call site that truncates the list — which is exactly the
        arithmetic a type can hold instead."""
        source = legacy_source(TG_SOURCE)
        assert "cycles_per_day" in source
        assert "int(86400 / max(1, poll_interval))" in source

    def test_no_sample_count_is_written_as_a_bare_number(self):
        module = (REPO_ROOT / "v3/adapters/info/telegram_mirror.py").read_text(
            "utf-8")
        assert "2880" not in module


class TestTelegramMatchingRules:
    def test_a_two_character_keyword_is_skipped(self):
        """`if len(kw) <= 2: continue` (`:198`). "op" matched everything —
        the rule is why the ledger can keep the word at all."""
        assert telegram_mirror.keyword_hit("op is live", "op") is False

    def test_a_bare_word_matches_on_boundaries(self):
        """"target" must not fire on "targeting" (`:205`)."""
        assert telegram_mirror.keyword_hit("targeting them", "target") is False
        assert telegram_mirror.keyword_hit("new target list", "target") is True

    def test_a_phrase_or_hashtag_matches_as_a_substring(self):
        """`:201-203` — specific enough that a boundary is unnecessary,
        and `\\b` would not match before a `#` anyway."""
        assert telegram_mirror.keyword_hit("we #targeted x", "#target")
        assert telegram_mirror.keyword_hit("site is under attack now",
                                           "under attack")

    def test_the_hit_count_counts_occurrences_not_keywords(self):
        """The z-score's numerator (`:328-337`) — a post naming ten
        targets is ten hits, not one."""
        assert telegram_mirror.count_keyword_hits(
            "attack attack ddos") == 3

    def test_the_snippet_geometry_is_productions(self):
        """60 characters of lead, 100 of trail, whitespace collapsed,
        wrapped in ellipses (`:220-230`)."""
        text = "x" * 100 + " under attack " + "y" * 200
        out = telegram_mirror.snippet(text, ("under attack",))
        assert out.startswith("...") and out.endswith("...")
        assert "under attack" in out
        assert len(out) <= 60 + len("under attack") + 100 + 6


class TestTelegramNormalize:
    def test_a_recent_post_yields_its_keywords_and_targets(self):
        draft = telegram_mirror.normalize(tg_payload(), tg_context())[0]
        assert draft.flags["detection_status"] == "INTENT_DETECTED"
        assert "#target" in draft.flags["keywords_matched"]
        assert "under attack" in draft.flags["keywords_matched"]
        assert any(".gov" in url for url in draft.flags["target_urls"])

    def test_the_narrow_government_list_decides_the_corroboration_flag(self):
        """A bank URL is a target; a ministry is corroboration."""
        draft = telegram_mirror.normalize(tg_payload(), tg_context())[0]
        assert draft.flags["gov_confidence_target"] is True
        assert any("bank" in url for url in draft.flags["target_urls"])

    def test_a_post_outside_the_window_is_not_read(self):
        draft = telegram_mirror.normalize(tg_payload(), tg_context())[0]
        assert "old.gov.example" not in str(draft.flags["target_urls"])

    def test_a_post_with_no_timestamp_is_skipped_not_dated_to_now(self):
        """`if not time_match: continue` (`:147-149`). Dating it to now
        would put every undatable post inside the window forever."""
        html = b"<div class='tgme_widget_message_wrap'>attack</div>"
        assert telegram_mirror.parse_posts(html.decode(), T0) == ()

    def test_a_missing_text_div_falls_back_to_the_whole_part(self):
        """`raw_text = text_match.group(1) if text_match else part`
        (`:165`). A post whose markup changed is kept rather than lost."""
        draft = telegram_mirror.normalize(tg_payload(), tg_context())[0]
        assert draft.flags["posts_in_window"] == 3

    def test_the_verdict_is_withheld_until_l1_holds_the_baseline(self):
        """The four-way ladder starts with a z-score against a 30-day
        baseline this layer does not hold, and the aggregation is per
        THEATRE across channels (§7-2 #9 and #11)."""
        draft = telegram_mirror.normalize(tg_payload(), tg_context())[0]
        assert draft.status == STATUS_OBSERVED
        assert draft.raw_score == 0.0
        assert draft.flags["burst_verdict"] == "pending_l1_telegram_baseline"
        assert "is_burst" not in draft.flags
        assert "z_score" not in draft.flags
        assert "claim_confidence" not in draft.flags

    def test_each_channel_carries_its_own_signal_source(self):
        """§7-2 #51 — a CONSTRAINT. L1 is `UNIQUE (tick_id, sensor,
        signal_source, country)` and two rows under one name with
        matching scores are dropped in SILENCE (`store.py:290`), which is
        exactly the quiet case."""
        first = telegram_mirror.normalize(tg_payload(channel="a"),
                                          tg_context())[0]
        second = telegram_mirror.normalize(tg_payload(channel="b"),
                                           tg_context())[0]
        assert first.signal_source != second.signal_source
        assert first.signal_source == "telegram_a"

    def test_a_quiet_channel_is_observed_and_not_clear_at_score_zero(self):
        draft = telegram_mirror.normalize(tg_payload("quiet.html"),
                                          tg_context())[0]
        assert draft.flags["detection_status"] == "CLEAR"
        assert draft.flags["snippet"] == ""
        assert draft.status == STATUS_OBSERVED


class TestTelegramTheThreeSilences:
    """Before 2026-04-29 all three returned "" and were the same fact."""

    def test_a_preview_disabled_by_the_admin_is_its_own_cause(self):
        """`t.me/s/x` redirecting to `t.me/x` means the channel LIST is
        stale — an operator action, not an outage (`:101-107`)."""
        draft = telegram_mirror.normalize(
            tg_payload(url="https://t.me/noname057"), tg_context())[0]
        assert draft.status == STATUS_NO_DATA
        assert draft.flags["reason"] == telegram_mirror.PREVIEW_DISABLED

    def test_throttling_is_its_own_cause(self):
        for status in (403, 429):
            draft = telegram_mirror.normalize(
                FetchedPayload(url="https://t.me/s/x", status=status,
                               body=b"", fetched_at=T0, label="channel:x"),
                tg_context())[0]
            assert draft.flags["reason"] == f"http_{status}"

    def test_an_auth_wall_page_is_its_own_cause(self):
        """`len(res.text) > _MIN_CONTENT_LEN` (`:108`) — a real preview is
        several KB; a thin page is a login gate."""
        draft = telegram_mirror.normalize(
            FetchedPayload(url="https://t.me/s/x", status=200, body=b"tiny",
                           fetched_at=T0, label="channel:x"),
            tg_context())[0]
        assert draft.flags["reason"] == telegram_mirror.TOO_SHORT

    def test_a_page_without_the_post_marker_is_its_own_cause(self):
        """`"tgme_widget_message_wrap" in res.text` (`:110`) — private and
        restricted channels return a "View in Telegram" stub."""
        body = ("<html>" + "x" * 3000 + "</html>").encode()
        draft = telegram_mirror.normalize(
            FetchedPayload(url="https://t.me/s/x", status=200, body=body,
                           fetched_at=T0, label="channel:x"),
            tg_context())[0]
        assert draft.flags["reason"] == telegram_mirror.NO_POST_CONTENT

    def test_a_healthy_page_with_no_recent_posts_is_its_own_cause(self):
        body = (("<div class=\"tgme_widget_message_wrap\">"
                 "<time datetime=\"2000-01-01T00:00:00+00:00\"></time>"
                 "old</div>") + "x" * 3000).encode()
        draft = telegram_mirror.normalize(
            FetchedPayload(url="https://t.me/s/x", status=200, body=body,
                           fetched_at=T0, label="channel:x"),
            tg_context())[0]
        assert draft.flags["reason"] == telegram_mirror.NO_RECENT_POSTS


class TestTelegramExportedLadders:
    """DP4's lesson: the join that CAN evaluate these must call them."""

    def test_a_burst_outranks_a_declaration(self):
        assert telegram_mirror.theater_status(3.5, True, True) == \
            "CRITICAL_BURST"
        assert telegram_mirror.theater_status(2.5, False, False) == "BURST"
        assert telegram_mirror.theater_status(0.0, True, True) == \
            "INTENT_DETECTED"
        assert telegram_mirror.theater_status(0.0, False, True) == \
            "TARGETS_FOUND"
        assert telegram_mirror.theater_status(0.0, False, False) == "CLEAR"

    def test_the_staged_confidence_is_zero_when_nothing_was_declared(self):
        """An absence, not a floor (`:448-449`)."""
        assert telegram_mirror.claim_confidence(False, False, False) == 0.0
        assert telegram_mirror.claim_confidence(False, True, False) == 0.2
        assert telegram_mirror.claim_confidence(False, True, True) == 0.4
        assert telegram_mirror.claim_confidence(True, False, False) == 0.6

    def test_the_dedup_fingerprint_is_productions(self):
        """`sha256(channel:theater:snippet[:200]:first-five-targets)[:32]`
        (`:245-249`). A different fingerprint means a pinned post is
        re-logged every fifteen minutes and the ledger fills with one
        post."""
        import hashlib
        expected = hashlib.sha256(
            "ch:TW:snip:a,b".encode(), usedforsecurity=False).hexdigest()[:32]
        assert telegram_mirror.content_hash("ch", "TW", "snip",
                                            ("a", "b")) == expected


class TestTelegramDeclaration:
    ADAPTER = telegram_mirror.TELEGRAM_MIRROR_ADAPTER

    def test_one_declaration_expands_per_channel(self):
        """`{channel}` is a scope placeholder: production scrapes each
        unique channel exactly once and reuses the result across every
        theatre that names it (`:346-356`)."""
        specs = self.ADAPTER.declared_specs
        assert len(specs) == 1
        assert "{channel}" in specs[0].url
        assert specs[0].label == "channel:{channel}"

    def test_the_cadence_is_the_live_poll_interval(self):
        assert self.ADAPTER.cadence.cadence_sec == 900.0

    def test_the_baseline_dependency_is_declared(self):
        assert "telegram_keyword_frequency" in self.ADAPTER.baseline_refs

    def test_it_claims_k13(self):
        assert self.ADAPTER.knowledge_refs == ("K13",)

    def test_it_needs_no_credential(self):
        """No phone number and no login — the reason `t.me/s/` is used at
        all (S1-SENSI-012)."""
        assert self.ADAPTER.auth.kind == "none"


# ── rss_narrative (S1-SENSI-005..011 + INGEST-*) ────────────────────────

RN_SOURCE = "radar/sensors/rss_narrative.py"

RN_KEYWORDS = {"TW": ("combat readiness", "encirclement", "reunification"),
               "UA": ("mobilization", "special military operation",
                      "shelling")}
RN_GEO = {"TW": ("taiwan", "taipei", "taiwan strait"),
          "UA": ("ukraine", "kyiv", "donbas")}


def rn_payload(name="tass.xml", *, feed="tass", status=200):
    return payload("rss_narrative", name, url="https://tass.com/rss/v2.xml",
                   label=f"feed:{feed}", status=status,
                   content_type="application/rss+xml")


def rn_context(**over):
    base = {"countries": ("TW", "UA"), "tactical_keywords": RN_KEYWORDS,
            "geo_terms": RN_GEO}
    base.update(over)
    return context("rss_narrative", **base)


class TestNarrativeLedgerIsNotInTheSensor:
    def test_the_feed_ledger_matches_geo_data_json(self):
        """The trap this port had to survive: `ADVERSARY_NARRATIVE_SOURCES`
        is in `geo_data.json`, reached through `radar/config.py:99,117`.
        Auditing `rss_narrative.py` alone finds no feed list at all."""
        import json
        ledger = json.loads(
            (REPO_ROOT / "geo_data.json").read_text(encoding="utf-8")
        )["ADVERSARY_NARRATIVE_SOURCES"]
        shipped = {(adversary, name, url)
                   for adversary, name, url in rss_narrative.FEEDS}
        declared = {(adversary, name, url)
                    for adversary, feeds in ledger.items()
                    for name, url in feeds.items()}
        assert shipped == declared

    def test_tass_answers_for_two_adversaries(self):
        """RU's wire is BY's only source, so a Russian burst raises
        Belarus's count as well. The duplication is the ledger's, and
        deduplicating it while porting would silence Belarus."""
        assert rss_narrative.adversary_of(
            "tass", "https://tass.com/rss/v2.xml") == ("BY", "RU")

    def test_one_url_is_fetched_once_however_many_adversaries_claim_it(self):
        """§2-1: a declaration whose text does not change is fetched
        once. Two requests to TASS per cycle is the same bytes twice."""
        urls = [spec.url for spec in
                rss_narrative.RSS_NARRATIVE_ADAPTER.declared_specs]
        # Eight ledger rows, seven distinct URLs — TASS is listed for RU
        # and for BY.
        assert len(rss_narrative.FEEDS) == 8
        assert len(urls) == len(set(urls)) == 7

    def test_the_two_large_ledgers_are_supplied_not_transcribed(self):
        """110 countries of tactical keywords and 36 of geo terms are
        deployment data that changes without a code release. A copy under
        `v3/` would be a second ledger to keep in step."""
        module = (REPO_ROOT / "v3/adapters/info/rss_narrative.py").read_text(
            "utf-8")
        assert "TACTICAL_KEYWORDS" not in module.replace(
            "`TACTICAL_KEYWORDS`", "")
        assert "context.tactical_keywords" in module
        assert "context.geo_terms" in module


class TestNarrativeMatching:
    def test_the_stopwords_match_the_live_sensor(self):
        live = evaluated_in(RN_SOURCE, "_TERM_STOPWORDS")
        assert set(rss_narrative.TERM_STOPWORDS) == set(
            live["_TERM_STOPWORDS"])

    def test_the_generic_news_words_are_stopwords_too(self):
        """`policy`, `relations`, `tensions`, `crisis`, `operations` are
        not grammar — they appear in too many news contexts to
        discriminate, and dropping them from the set makes every article
        a hit."""
        for word in ("policy", "relations", "tensions", "crisis",
                     "operations"):
            assert word in rss_narrative.TERM_STOPWORDS

    def test_phrases_and_atomic_terms_are_both_extracted(self):
        phrases, atomic = rss_narrative.expand_keywords(
            ["combat readiness", "encirclement"])
        assert phrases == ("combat readiness",)
        assert atomic == ("combat", "encirclement", "readiness")

    def test_a_hyphenated_entry_counts_as_a_phrase(self):
        phrases, _ = rss_narrative.expand_keywords(["pre-operation"])
        assert phrases == ("pre-operation",)

    def test_one_atomic_term_is_not_a_hit(self):
        """`len(matches) >= 2` (`:213`). Production's comment says why:
        single-word matches inflate the baseline, and an inflated
        baseline is a burst that never fires."""
        items = (parse.FeedItem(title="Readiness improves", summary=""),)
        hits, articles = rss_narrative.count_keywords(
            items, ["combat readiness", "encirclement"])
        assert (hits, articles) == (0, 1)

    def test_two_atomic_terms_are_a_hit(self):
        items = (parse.FeedItem(title="Combat units raise readiness",
                                summary=""),)
        assert rss_narrative.count_keywords(
            items, ["combat readiness"])[0] == 1

    def test_a_short_geo_term_gets_word_boundaries(self):
        """`len(t_lower) >= 6` decides substring vs boundary (`:82-85`).
        "Kyiv" inside "Kyivan" is a false positive; "Taiwan Strait" inside
        a longer phrase is not."""
        pattern = rss_narrative.geo_pattern(["kyiv"])
        assert pattern.search("kyiv reports") is not None
        assert pattern.search("kyivan rus") is None

    def test_an_article_about_another_theatre_is_geo_classified_other(self):
        assert rss_narrative.classify_geo("kyiv shelling", "TW",
                                          RN_GEO) == "other"
        assert rss_narrative.classify_geo("taipei drills", "TW",
                                          RN_GEO) == "match"
        assert rss_narrative.classify_geo("cultural festival", "TW",
                                          RN_GEO) == "generic"

    def test_an_article_naming_both_counts_for_the_current_theatre(self):
        """The CURRENT country is tested first (`:106-110`)."""
        assert rss_narrative.classify_geo("taipei and kyiv", "TW",
                                          RN_GEO) == "match"

    def test_the_denominator_is_never_filtered(self):
        """The geographic filter removes an article from `keyword_hits`
        and NOT from `article_count` (`:190-204`). Filtering both would
        leave the ratio unchanged while the evidence vanished."""
        drafts = {d.country: d for d in
                  rss_narrative.normalize(rn_payload(), rn_context())}
        assert drafts["TW"].flags["article_count"] == 4
        assert drafts["UA"].flags["article_count"] == 4
        # The Ukraine article is geo-classified `other` for TW and is
        # therefore not a TW hit — but it is still in TW's denominator.
        assert drafts["TW"].flags["keyword_hits"] == 1
        assert drafts["UA"].flags["keyword_hits"] == 1


class TestNarrativeNormalize:
    def test_one_row_per_watched_country(self):
        drafts = rss_narrative.normalize(rn_payload(), rn_context())
        assert {d.country for d in drafts} == {"TW", "UA"}

    def test_each_feed_carries_its_own_signal_source(self):
        """§7-2 #51's family — one theatre is counted against several
        feeds in one tick, and L1 refuses two rows under one name.
        Production has none to borrow: it folds the feeds together BEFORE
        naming the entry `narrative_{theater}`."""
        first = rss_narrative.normalize(rn_payload(feed="tass"),
                                        rn_context())[0]
        second = rss_narrative.normalize(rn_payload(feed="ria"),
                                         rn_context())[0]
        assert first.signal_source == "narrative_tass"
        assert second.signal_source == "narrative_ria"

    def test_the_burst_pool_uses_the_same_gate_as_the_counter(self):
        """Production's comment (`:225-228`): a different gate made
        burst-detected articles come back empty when only atomic terms
        had matched."""
        draft = {d.country: d for d in
                 rss_narrative.normalize(rn_payload(), rn_context())}["TW"]
        assert len(draft.flags["burst_articles"]) == \
            draft.flags["keyword_hits"]

    def test_a_repeated_title_is_counted_once(self):
        draft = rss_narrative.normalize(rn_payload(), rn_context())[0]
        assert draft.flags["article_count"] == 4

    def test_the_verdict_is_withheld_until_l1_holds_the_baseline(self):
        draft = rss_narrative.normalize(rn_payload(), rn_context())[0]
        assert draft.status == STATUS_OBSERVED
        assert draft.raw_score == 0.0
        assert draft.flags["burst_verdict"] == \
            "pending_l1_narrative_baseline"
        assert "z_score" not in draft.flags
        assert "status" not in draft.flags

    def test_a_country_with_no_keywords_falls_back_to_the_default_set(self):
        drafts = rss_narrative.normalize(
            rn_payload(),
            rn_context(countries=("PL",),
                       tactical_keywords={"DEFAULT": ("combat readiness",)}))
        assert [d.country for d in drafts] == ["PL"]

    def test_a_dead_feed_names_its_cause(self):
        draft = rss_narrative.normalize(
            synthetic(b"<!doctype html><html/>", label="feed:tass"),
            rn_context())[0]
        assert draft.status == STATUS_NO_DATA
        assert draft.flags["outcome"] == parse.RETURNS_HTML


class TestNarrativeA8:
    def test_the_first_signal_threshold_is_disclosed(self):
        """A8. The most sensitive number in the sensor is read straight
        from the environment at the comparison site (`:610`) and appears
        in no registry. Pinned here WITH its origin (§7-2 #52)."""
        resolved = rss_narrative.FIRST_SIGNAL_ZSCORE.resolve()
        assert resolved.value == 3.0
        assert "NARRATIVE_ZSCORE_FIRST_SIGNAL" in \
            rss_narrative.FIRST_SIGNAL_ZSCORE.provenance_ref
        assert "A8" in rss_narrative.FIRST_SIGNAL_ZSCORE.provenance_ref

    def test_the_first_activity_against_a_silent_baseline_is_a_burst(self):
        """Returning 0.0 there — which is what the arithmetic gives —
        reports silence on the single most informative reading the sensor
        can take."""
        assert rss_narrative.first_signal_zscore(0.4, 0.0, 0.0) == 3.0
        assert rss_narrative.burst_status(
            rss_narrative.first_signal_zscore(0.4, 0.0, 0.0)) == \
            "CRITICAL_BURST"

    def test_a_silent_reading_against_a_silent_baseline_is_not_a_burst(self):
        assert rss_narrative.first_signal_zscore(0.0, 0.0, 0.0) == 0.0

    def test_the_ordinary_z_score_is_unchanged(self):
        assert rss_narrative.first_signal_zscore(3.0, 1.0, 1.0) == 2.0


class TestNarrativeClustering:
    def test_one_response_explodes_into_several_items(self):
        """`rss_narrative` is the only source whose answer carries SEVERAL
        answers. The single-synthesis flow it replaced was "forced to
        fabricate a common narrative" across unrelated articles
        (`:307-311`)."""
        assert rss_narrative.PROFILE.response_items_key == "clusters"
        data = {"clusters": [{"headline": "a"}, {"headline": "b"}]}
        assert len(ex.explode(rss_narrative.PROFILE, data)) == 2

    def test_an_answer_that_ignores_the_schema_becomes_one_cluster(self):
        """`raw_clusters = [data]; legacy_fallback = True` (`:445-449`).
        Dropping it would make a schema the model did not follow
        indistinguishable from a quiet day."""
        flat = {"headline": "a", "narrative_type": "threat_escalation"}
        assert ex.explode(rss_narrative.PROFILE, flat) == (flat,)
        assert ex.explode(rss_narrative.PROFILE,
                          {"clusters": []}) == ({"clusters": []},)

    def test_the_other_sources_carry_one_answer_each(self):
        for profile in (diplomatic.PROFILE, military_exercise.PROFILE,
                        hacktivist_news.PROFILE):
            assert profile.response_items_key == ""

    def test_conditioning_outscores_escalation(self):
        """`:541-547`. Conditioning an audience BEFORE an operation is the
        earlier indicator, which is the entire premise of watching state
        media."""
        assert rss_narrative.score_delta(
            {"narrative_type": "pre-operation_conditioning"}) > \
            rss_narrative.score_delta(
                {"narrative_type": "threat_escalation"})
        assert rss_narrative.score_delta(
            {"narrative_type": "pre-operation_conditioning",
             "urgency": "critical"}) == 3.0

    def test_an_unrecognised_narrative_type_scores_as_unknown(self):
        assert rss_narrative.score_delta({"narrative_type": "invented"}) == 1.0

    def test_the_never_fabricate_instruction_is_verbatim(self):
        system, _ = rss_narrative.prompt({"pool": []}, {})
        assert "NEVER fabricate a common narrative across unrelated " \
               "articles." in system

    def test_every_fixed_segment_of_the_prompts_survives(self):
        system, user = rss_narrative.prompt(
            {"pool": [{"title": "T", "summary": "S"}]},
            {"country": "TW", "z_score": 3.1, "sources": "tass",
             "today": "2026-08-08"})
        for part in prompt_constants(RN_SOURCE, "system_prompt"):
            assert part in system, part[:80]
        for part in prompt_constants(RN_SOURCE, "user_prompt"):
            assert part in user, part[:80]

    def test_the_token_budget_is_the_largest_of_the_eight(self):
        """512 (`:409`), because this one asks the model to CLUSTER
        several articles rather than judge one."""
        assert rss_narrative.PROFILE.max_tokens == 512
        assert all(profile.max_tokens < 512 for profile in
                   (diplomatic.PROFILE, military_exercise.PROFILE,
                    hacktivist_news.PROFILE))


# ── travel_advisory (S1-SENSI-022..025, K20) ────────────────────────────

TA_SOURCE = "radar/sensors/travel_advisory.py"
TA_NAMES = {"TW": "Taiwan", "UA": "Ukraine", "JP": "Japan", "RU": "Russia"}


def ta_payload(name, *, source, status=200, content_type="application/xml"):
    body = (FIXTURES / "travel_advisory" / name).read_bytes()
    return FetchedPayload(url=travel_advisory.SOURCES[source]["url"],
                          status=status, body=body, fetched_at=T0,
                          content_type=content_type, label=f"source:{source}")


def ta_context(**over):
    base = {"countries": ("TW", "UA", "JP"), "country_names": TA_NAMES}
    base.update(over)
    return context("travel_advisory", **base)


class TestTravelAdvisoryK20:
    def test_k20_three_governments_publish_in_three_formats(self):
        """K20. US State publishes RSS, the UK FCDO publishes Atom, and
        Canada GAC DISCONTINUED its feed so its advisories are scraped
        out of an HTML table. Each has its own level vocabulary — the UK
        never says "level 3", it says "advise against all but essential
        travel" — and reading one vocabulary against another source
        reports zero advisories from a feed that is working."""
        assert travel_advisory.SOURCES == literal_in(TA_SOURCE, "_SOURCES")
        assert set(travel_advisory.SOURCES) == {"US", "UK", "CA"}
        assert travel_advisory.SOURCES["CA"]["html_scrape"] is True
        assert "atom" in travel_advisory.SOURCES["UK"]["url"]
        # Three vocabularies, none of which is the others.
        assert travel_advisory.parse_level_us("Level 4: Do Not Travel") == 4
        assert travel_advisory.parse_level_us(
            "FCDO advise against all travel") == 0
        assert travel_advisory.parse_level_fcdo(
            "advise against all travel") == 4
        assert travel_advisory.parse_level_gac("Avoid all travel") == 4
        # And the per-source Accept header, because a scrape and a feed
        # do not ask for the same thing.
        headers = {spec.label: spec.headers["Accept"] for spec in
                   travel_advisory.TRAVEL_ADVISORY_ADAPTER.declared_specs}
        assert headers["source:CA"].startswith("text/html")
        assert headers["source:UK"].startswith("application/atom+xml")

    def test_the_level_maps_match_the_live_sensor(self):
        assert travel_advisory.FCDO_LEVEL_MAP == literal_in(
            TA_SOURCE, "_FCDO_LEVEL_MAP")
        assert travel_advisory.GAC_LEVEL_MAP == literal_in(
            TA_SOURCE, "_GAC_LEVEL_MAP")

    def test_both_fcdo_verb_forms_are_listed(self):
        """The FCDO uses "advise" and "advises"; dropping either halves
        what the UK source detects."""
        assert travel_advisory.parse_level_fcdo(
            "the FCDO advises against all travel") == 4
        assert travel_advisory.parse_level_fcdo(
            "we advise against all travel") == 4

    def test_the_gac_icon_is_a_second_encoding_of_the_level(self):
        """`:279-285`. The icon filename survives a wording change in the
        table, which is what a scrape needs."""
        assert travel_advisory.gac_level(
            "unrecognised wording",
            '<img src="/icons/increased-caution.svg">') == 2


class TestTravelAdvisoryA3IsAbolished:
    """§7-2 #4 / 裁定要求 4, ruled — the one INSENSITIVE entry."""

    def test_the_parser_gives_up_fallback_is_gone(self):
        """Production ends with `if "travel" in text_lower: return 2`
        (`:341-343`), and every entry in a feed called "foreign travel
        advice" contains the word. The effect is a level-2 advisory
        manufactured for practically every country the UK publishes."""
        assert travel_advisory.parse_level_fcdo(
            "Japan travel advice — updated information for travellers") == 0
        assert 'if "travel" in text_lower' in legacy_source(TA_SOURCE)

    def test_a_fabricated_level_would_have_entered_the_convergence_count(
            self):
        """NP2: a false corroboration is worse than none, because it
        makes one source look like two. With the fallback, an unparsed UK
        entry contributed level 2 to `converge`; without it the country
        is simply not reported by the UK."""
        drafts = travel_advisory.normalize(
            ta_payload("uk_fcdo.atom", source="UK"), ta_context())
        assert {d.country for d in drafts} == {"UA"}

    def test_the_genuine_fcdo_arms_all_survive(self):
        """Everything ABOVE the fallback is kept — the four phrases and
        both severity-hint tiers — so a real FCDO warning still parses."""
        assert travel_advisory.parse_level_fcdo("armed conflict ongoing") == 4
        assert travel_advisory.parse_level_fcdo("significant risk area") == 3

    def test_unknown_is_now_a_reachable_label(self):
        """With A3 gone, "this parser did not reach a verdict" is a state
        the system can report rather than a level it invents."""
        assert travel_advisory.level_label(0) == "UNKNOWN"


class TestTravelAdvisoryNormalize:
    def test_the_us_feed_yields_its_levels(self):
        drafts = {d.country: d for d in travel_advisory.normalize(
            ta_payload("us_state.xml", source="US"), ta_context())}
        assert drafts["UA"].flags["level"] == 4
        assert drafts["UA"].flags["level_label"] == "DO_NOT_TRAVEL"
        assert drafts["TW"].flags["level"] == 1

    def test_an_entry_naming_no_known_country_is_skipped(self):
        drafts = travel_advisory.normalize(
            ta_payload("us_state.xml", source="US"), ta_context())
        assert len(drafts) == 2

    def test_the_canada_table_is_scraped_including_its_icon_row(self):
        drafts = {d.country: d for d in travel_advisory.normalize(
            ta_payload("ca_gac.html", source="CA",
                       content_type="text/html"), ta_context())}
        assert drafts["UA"].flags["level"] == 4
        assert drafts["JP"].flags["level"] == 1
        assert drafts["TW"].flags["level"] == 2

    def test_each_government_carries_its_own_signal_source(self):
        """§7-2 #51's family, and a CONSTRAINT: one country is reported by
        all three in one tick and L1 refuses two rows under one name.
        Production folds the three BEFORE naming the entry."""
        us = travel_advisory.normalize(
            ta_payload("us_state.xml", source="US"), ta_context())[0]
        ca = travel_advisory.normalize(
            ta_payload("ca_gac.html", source="CA",
                       content_type="text/html"), ta_context())[0]
        assert us.signal_source == "advisory_us"
        assert ca.signal_source == "advisory_ca"

    def test_the_upgrade_verdict_is_withheld_until_l1_holds_the_history(self):
        """A1 — `prev.get(code, level)` seeds the previous level with the
        CURRENT one (`:129`), so the first sighting can never be an
        upgrade. A2 — and the memory is a process dictionary (`:76-78`),
        so "first sighting" recurs at every deploy."""
        draft = travel_advisory.normalize(
            ta_payload("us_state.xml", source="US"), ta_context())[0]
        assert draft.status == STATUS_OBSERVED
        assert draft.raw_score == 0.0
        assert draft.flags["upgrade_verdict"] == "pending_l1_previous_level"
        assert "upgraded" not in draft.flags
        assert "prev_level" not in draft.flags

    def test_a_watched_country_wins_over_the_ledger_fallback(self):
        """`_match_country_code` scans TARGETS first, then everyone
        (`:376-388`) — a title naming two countries resolves to the
        watched one."""
        assert travel_advisory.match_country(
            "Russia comments on Japan", ("JP",), TA_NAMES) == "JP"
        assert travel_advisory.match_country(
            "Russia comments", (), TA_NAMES) == "RU"

    def test_a_non_two_hundred_response_names_its_status(self):
        """`!= 200` including 429 (`:96-102`). Production returns
        `(data, False)` for both and the caller cannot tell them apart."""
        for status in (429, 503):
            draft = travel_advisory.normalize(
                FetchedPayload(url="https://travel.state.gov/x",
                               status=status, body=b"", fetched_at=T0,
                               label="source:US"), ta_context())[0]
            assert draft.status == STATUS_NO_DATA
            assert draft.flags["reason"] == f"http_{status}"

    def test_the_dialect_is_chosen_by_the_body_not_by_the_source(self):
        """`if "<entry>" in text` (`:106`). Reading Atom's tags out of an
        RSS body returns empty strings, which parse to level 0 — a
        working feed reporting nothing."""
        assert travel_advisory.extract_tag(
            "<title>x</title><summary>y</summary>", "summary") == "y"
        assert travel_advisory.extract_tag("<title>x</title>",
                                           "description") == ""

    def test_a_cdata_title_is_unwrapped(self):
        assert travel_advisory.extract_tag(
            "<title><![CDATA[Ukraine - Level 4]]></title>",
            "title") == "Ukraine - Level 4"


class TestTravelAdvisoryConvergence:
    """S1-SENSI-025, exported for WP-4.1 rather than written twice."""

    def test_two_governments_at_level_three_converge(self):
        verdict = travel_advisory.converge({"US": 4, "UK": 3, "CA": 1})
        assert verdict["level"] == 4
        assert verdict["convergence_count"] == 2
        assert verdict["converged"] is True
        assert verdict["single_source_warning"] is False

    def test_one_government_alone_raises_the_political_warning(self):
        """The flag that says "this upgrade may be a domestic political
        act" — the entire reason three governments are read."""
        verdict = travel_advisory.converge({"US": 4, "UK": 1})
        assert verdict["converged"] is False
        assert verdict["single_source_warning"] is True

    def test_low_levels_do_not_count_toward_convergence(self):
        verdict = travel_advisory.converge({"US": 2, "UK": 2, "CA": 2})
        assert verdict["convergence_count"] == 0
        assert verdict["converged"] is False
        assert verdict["single_source_warning"] is False

    def test_a_country_nobody_reported_is_unknown(self):
        verdict = travel_advisory.converge({})
        assert verdict["level"] == 0
        assert verdict["label"] == "UNKNOWN"

    def test_the_thresholds_are_the_clauses(self):
        assert travel_advisory.CONVERGENCE_MIN_SOURCES == 2
        assert travel_advisory.CONVERGENCE_MIN_LEVEL == 3


class TestTravelAdvisoryDeclaration:
    ADAPTER = travel_advisory.TRAVEL_ADVISORY_ADAPTER

    def test_all_three_sources_are_declared(self):
        assert [spec.label for spec in self.ADAPTER.declared_specs] == [
            "source:US", "source:UK", "source:CA"]

    def test_the_cadence_is_the_live_poll_interval(self):
        assert self.ADAPTER.cadence.cadence_sec == 3600.0

    def test_it_claims_k20(self):
        assert self.ADAPTER.knowledge_refs == ("K20",)

    def test_it_needs_no_credential(self):
        assert self.ADAPTER.auth.kind == "none"

    def test_the_baseline_dependency_is_declared(self):
        assert "travel_advisory_previous_level" in self.ADAPTER.baseline_refs
