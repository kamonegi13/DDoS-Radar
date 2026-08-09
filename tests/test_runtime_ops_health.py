"""R7's `ops_health` — WP-0.3's ruling, ported to v3's own facts.

The ruling that matters is one sentence: **an unknown backup age is
INSUFFICIENT, never OK.** It exists because between 2026-07-04 and
08-03 the backup cron failed on every run (docker was not on cron's
PATH), each failure went to a log nobody read, and the system's state
during that month was not "no backups" but "nobody could say".

The second property is the reason §7-2 #94 was registered at all: a fold
must not report `trusted` while some of its inputs are missing. Here that
applies one level down — the ops block itself folds four monitors, two of
which v3 cannot answer today, and it says so per monitor instead of
averaging them away.
"""
from __future__ import annotations

import json

import pytest

from v3.api import ApiRequest, ReadContext, ReadOnlyLedger, handle
from v3.api.request import Principal
from v3.api.vocabulary import ROLE_VIEWER
from v3.ledger import LedgerStore
from v3.runtime import ops_health as O

NOW = 1_800_000_000.0
HOUR = 3600.0
VIEWER = Principal(user_id="v-1", role=ROLE_VIEWER)


@pytest.fixture()
def store(tmp_path):
    handle_ = LedgerStore(str(tmp_path / "ops.db"))
    yield handle_
    handle_.close()


def _marker(tmp_path, completed_at, *, raw=None):
    path = tmp_path / O.BACKUP_MARKER_NAME
    path.write_text(json.dumps({"completed_at": completed_at})
                    if raw is None else raw, encoding="utf-8")
    return path


class TestTheBackupVerdictIsProductionsRule:
    @pytest.mark.parametrize("age_hours,verdict,reason", [
        (1.0, O.OK, O.REASON_BACKUP_FRESH),
        (25.9, O.OK, O.REASON_BACKUP_FRESH),
        (26.0, O.WARN, O.REASON_BACKUP_OVERDUE),
        (49.9, O.WARN, O.REASON_BACKUP_OVERDUE),
        (50.0, O.ANOMALY, O.REASON_BACKUP_SILENT),
    ])
    def test_the_boundaries_are_26_and_50_hours(self, tmp_path, age_hours,
                                                verdict, reason):
        path = _marker(tmp_path, NOW - age_hours * HOUR)
        result = O.backup_monitor(path, now=NOW)
        assert (result["verdict"], result["reason"]) == (verdict, reason)

    def test_a_missing_marker_is_insufficient_not_ok(self, tmp_path):
        result = O.backup_monitor(tmp_path / "nope.json", now=NOW)
        assert result["verdict"] == O.INSUFFICIENT
        assert result["reason"] == O.REASON_BACKUP_ABSENT
        assert result["verdict"] != O.OK, (
            "the month of silence WAS this state; calling it OK is how it "
            "stayed invisible")

    def test_a_corrupt_marker_is_insufficient(self, tmp_path):
        result = O.backup_monitor(_marker(tmp_path, None, raw="{oops"),
                                  now=NOW)
        assert result["verdict"] == O.INSUFFICIENT
        assert result["reason"] == O.REASON_BACKUP_CORRUPT

    def test_a_marker_from_the_future_is_insufficient(self, tmp_path):
        result = O.backup_monitor(_marker(tmp_path, NOW + HOUR), now=NOW)
        assert result["reason"] == O.REASON_BACKUP_SKEW

    def test_the_probe_never_raises(self, tmp_path):
        assert O.backup_monitor(tmp_path, now=NOW)["verdict"] in (
            O.INSUFFICIENT, O.ANOMALY, O.WARN, O.OK)


class TestCapacityIsMeasuredFromV3sOwnLedger:
    def test_an_unreadable_ledger_is_insufficient_not_zero(self, tmp_path):
        result = O.capacity_monitor(tmp_path / "absent.db", span_sec=None)
        assert result["verdict"] == O.INSUFFICIENT
        assert result["db_bytes"] is None, (
            "recording 0 bytes would put a phantom sample in the trend")

    def test_a_short_span_is_insufficient_and_says_so(self, store):
        result = O.capacity_monitor(store.path, span_sec=2 * 86400.0)
        assert result["verdict"] == O.INSUFFICIENT
        assert result["reason"] == O.REASON_CAPACITY_EARLY

    def test_a_full_span_projects_to_the_retention_target(self, store):
        result = O.capacity_monitor(
            store.path, span_sec=O.RETENTION_TARGET_DAYS * 86400.0)
        assert result["verdict"] in (O.OK, O.WARN)
        assert result["retention_target_days"] == 60.0
        assert result["estimated_steady_state_gb"] is not None


class TestTheFoldRefusesToRoundUp:
    def test_two_green_out_of_four_is_not_green(self):
        folded = O.fold(
            [O.monitor(O.MONITOR_BACKUP, O.OK, "backup_fresh"),
             O.monitor(O.MONITOR_CAPACITY, O.OK, "capacity_within_band")]
            + [dict(item) for item in O.UNSUPPLIED_MONITORS], now=NOW)
        assert folded["worst_band"] == O.BAND_RESERVED
        assert folded["failing_count"] == 2

    def test_an_anomaly_wins_over_everything(self):
        folded = O.fold([
            O.monitor(O.MONITOR_BACKUP, O.ANOMALY, "backup_silent"),
            O.monitor(O.MONITOR_CAPACITY, O.OK, "capacity_within_band"),
        ], now=NOW)
        assert folded["worst_band"] == O.BAND_DISTRUST
        assert folded["worst_monitor"] == O.MONITOR_BACKUP

    def test_ties_break_on_declaration_order(self):
        folded = O.fold([
            O.monitor(O.MONITOR_CAPACITY, O.WARN, "capacity_estimate_divergent"),
            O.monitor(O.MONITOR_BACKUP, O.WARN, "backup_overdue"),
        ], now=NOW)
        assert folded["worst_monitor"] == O.MONITOR_BACKUP

    def test_all_four_are_declared_when_nothing_probed(self):
        folded = O.probe_absent(now=NOW)
        assert [row["monitor"] for row in folded["monitors"]] == list(
            O.MONITOR_IDS)
        assert all(row["reason"] for row in folded["monitors"])


class TestTheSweepMonitorSaysHowMuchOfTheCatalogueSpoke:
    """G-19. The budget makes a partial sweep normal; this is what stops a
    partial sweep from being SILENT."""

    def _sweep(self, *, deferred=(), dark=(), fetched=5):
        return {"due": fetched + len(deferred), "fetched": fetched,
                "deferred": list(deferred),
                "deferred_never_observed": list(dark),
                "complete": not deferred,
                "coverage": round(fetched / (fetched + len(deferred)), 3)}

    def test_a_complete_sweep_is_ok(self):
        row = O.sweep_monitor(self._sweep())
        assert row["verdict"] == O.OK
        assert row["reason"] == O.REASON_SWEEP_COMPLETE

    def test_a_staged_sweep_of_sources_still_in_force_is_insufficient(self):
        row = O.sweep_monitor(self._sweep(deferred=("gdelt",)))
        assert row["verdict"] == O.INSUFFICIENT
        assert row["reason"] == O.REASON_SWEEP_PARTIAL

    def test_a_deferred_source_that_never_spoke_is_an_anomaly(self):
        """The cold-start state. Transient by design and reported as
        loudly as a fault, because a conclusion drawn from 40% of the
        catalogue must not read like a quiet world."""
        row = O.sweep_monitor(self._sweep(deferred=("gdelt",), dark=("gdelt",)))
        assert row["verdict"] == O.ANOMALY
        assert row["reason"] == O.REASON_SWEEP_DARK
        assert row["deferred_never_observed"] == ["gdelt"]

    def test_no_report_is_unsupplied_and_never_ok(self):
        assert O.sweep_monitor(None)["verdict"] == O.UNSUPPLIED
        assert O.sweep_monitor(None)["reason"] == O.REASON_SWEEP_UNSUPPLIED

    def test_an_empty_report_is_also_unsupplied(self):
        """`TickReport.sweep` defaults empty. An empty mapping has not told
        us the sweep was whole — it has told us nothing."""
        assert O.sweep_monitor({})["verdict"] == O.UNSUPPLIED

    def test_the_probe_carries_it(self, store):
        folded = O.probe(store.path, span_sec=None, now=NOW,
                         marker=store.path + ".missing",
                         sweep=self._sweep(deferred=("a",), dark=("a",)))
        row = O.monitor_named(folded, O.MONITOR_SWEEP)
        assert row["verdict"] == O.ANOMALY
        assert folded["worst_verdict"] == O.ANOMALY
        assert folded["worst_monitor"] == O.MONITOR_SWEEP


class TestR7ServesIt:
    def _self_eval(self, store, *, ops=None):
        response = handle(
            ApiRequest(method="GET", path="/api/v3/self_eval",
                       principal=VIEWER),
            ReadContext(ledger=ReadOnlyLedger(store), now=NOW,
                        ops_health=ops))
        assert response.status == 200
        return response.as_dict()["self_eval"]["ops_health"]

    def test_the_field_exists_even_with_no_probe(self, store):
        block = self._self_eval(store)
        assert block["worst_band"] == O.BAND_RESERVED
        # `tick_loop` leads the declaration order, so it wins the tie —
        # deliberately: when several monitors are equally unanswerable,
        # the one an operator acts on first is "has this tool concluded
        # anything".
        assert block["worst_monitor"] == O.MONITOR_LOOP
        assert block["threshold"] == 0
        # Six since G-19 added `sweep`: with no probe composed, every one
        # of the six is non-OK, which is the whole shape of the block.
        assert block["failing_count"] == 6

    def test_a_probed_deployment_serves_its_measurements(self, store,
                                                         tmp_path):
        probed = O.probe(store.path, span_sec=O.RETENTION_TARGET_DAYS * 86400.0,
                         now=NOW, marker=_marker(tmp_path, NOW - HOUR))
        block = self._self_eval(store, ops=probed)
        by_id = {row["monitor"]: row for row in block["monitors"]}
        assert by_id[O.MONITOR_BACKUP]["verdict"] == O.OK
        assert by_id[O.MONITOR_L5]["verdict"] == O.UNSUPPLIED
        assert block["worst_band"] == O.BAND_RESERVED, (
            "two answerable monitors green must not make the block green "
            "while two are structurally unsupplied — that is G-17")

    def test_the_chips_five_components_are_now_all_served(self, store):
        """§7-2 #94's resolution condition, checked from the server side."""
        body = handle(
            ApiRequest(method="GET", path="/api/v3/self_eval",
                       principal=VIEWER),
            ReadContext(ledger=ReadOnlyLedger(store), now=NOW)
        ).as_dict()["self_eval"]
        for key in ("calibration", "null_zone", "data", "ops_health"):
            assert key in body, key
