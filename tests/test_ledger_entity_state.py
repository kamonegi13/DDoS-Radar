"""WP-4.1b ruling 2 — L1 gets a table with an explicit entity dimension.

`ct_log`'s known-CA ledger, `check_host`'s per-URL latency, `ais`'s
per-MMSI snapshot and the two narrative frequency baselines are per-ENTITY
series. `baseline_stat` is keyed `(baseline_id, sensor, country, bucket)`,
so holding them there would have meant putting a domain, a URL or an MMSI
in the `country` column — a schema that says one thing and holds another,
which is the same class of defect as a declared window the code does not
honor (F-06).

Two tables, because there are two lifetimes and one policy cannot be
honest about both:

  entity_observation  a per-entity SERIES. Observational, therefore
                      append-only and pruned like every other observation.
  entity_marker       first-seen / set membership. Updated in place, and
                      PERMANENT: `first_seen` is what ends a warm-up, so
                      expiring it restarts the warm-up and re-silences a
                      detection that had already graduated (insensitive —
                      C-02/C-03). Nor can a first-seen be backfilled.

Production's own split is the same two tables
(`ct_log_known_ca_per_domain` / `ct_log_domain_first_observed`,
`radar/database.py:1271-1286`), neither of which has ever been pruned.
"""
import pytest

from v3.kernel.errors import DomainError
from v3.ledger import LedgerStore
from v3.ledger import schema as schema_module

NOW = 1_786_000_000.0
DAY = 86400.0


@pytest.fixture
def store(tmp_path):
    instance = LedgerStore(str(tmp_path / "entity.db"))
    yield instance
    instance.close()


class TestTheSchemaSaysWhatItHolds:
    def test_both_tables_are_declared_and_have_a_retention_policy(self):
        declared = {p.table for p in schema_module.RETENTION_POLICIES}
        assert "entity_observation" in schema_module.PERSISTED_TABLES
        assert "entity_marker" in schema_module.PERSISTED_TABLES
        assert {"entity_observation", "entity_marker"} <= declared

    def test_the_marker_table_is_permanent_and_says_why(self):
        policy = next(p for p in schema_module.RETENTION_POLICIES
                      if p.table == "entity_marker")
        assert policy.is_permanent
        assert "warm" in policy.rationale.lower()

    def test_the_series_bound_comes_from_the_longest_consumer(self):
        """The bound is decided by what actually reads it, not by taste:
        the narrative frequency baselines look back
        `NARRATIVE_BASELINE_DAYS` (30, `radar/config.py:360`), and nothing
        reads further."""
        policy = next(p for p in schema_module.RETENTION_POLICIES
                      if p.table == "entity_observation")
        assert policy.retention_days == 30
        assert policy.time_column == "observed_at"

    def test_the_store_reports_the_new_schema_version(self, store):
        assert store.schema_version() == schema_module.SCHEMA_VERSION
        assert schema_module.SCHEMA_VERSION >= 4

    def test_an_old_store_is_migrated_rather_than_recreated(self, tmp_path):
        """The upgrade path is the one that has to work — a fresh store
        would pass on `CREATE TABLE IF NOT EXISTS` alone."""
        import sqlite3
        path = str(tmp_path / "old.db")
        first = LedgerStore(path)
        first.close()
        connection = sqlite3.connect(path)
        connection.execute("DROP TABLE entity_observation")
        connection.execute("DROP TABLE entity_marker")
        connection.execute("UPDATE schema_meta SET value = '3' "
                           "WHERE key = 'version'")
        connection.commit()
        connection.close()

        second = LedgerStore(path)
        try:
            assert second.schema_version() == schema_module.SCHEMA_VERSION
            second.append_entity_observation(
                series="checkhost_latency_history", sensor="check_host",
                entity="https://example.tw", observed_at=NOW, value=1.0,
                now=NOW)
        finally:
            second.close()


class TestTheEntitySeries:
    def test_a_sample_is_recorded_and_read_back_oldest_first(self, store):
        for index in range(3):
            store.append_entity_observation(
                series="checkhost_latency_history", sensor="check_host",
                entity="https://a.tw", observed_at=NOW + index,
                value=float(index), now=NOW + index)
        values = store.entity_series_values(
            "checkhost_latency_history", sensor="check_host",
            entity="https://a.tw")
        assert values == [0.0, 1.0, 2.0]

    def test_the_newest_n_are_kept_and_the_rest_fall_out(self, store):
        """`deque(maxlen=12)` (`checkhost.py:143`) is a bound production
        enforces on the WRITE. Keeping more here would compute a rolling
        average over a longer history than production's and diverge
        exactly when a latency spike matters."""
        for index in range(20):
            store.append_entity_observation(
                series="checkhost_latency_history", sensor="check_host",
                entity="https://a.tw", observed_at=NOW + index,
                value=float(index), max_samples=12, now=NOW + index)
        values = store.entity_series_values(
            "checkhost_latency_history", sensor="check_host",
            entity="https://a.tw")
        assert values == [float(i) for i in range(8, 20)]

    def test_the_bound_is_per_entity(self, store):
        for index in range(20):
            for entity in ("https://a.tw", "https://b.tw"):
                store.append_entity_observation(
                    series="checkhost_latency_history", sensor="check_host",
                    entity=entity, observed_at=NOW + index,
                    value=float(index), max_samples=12, now=NOW + index)
        for entity in ("https://a.tw", "https://b.tw"):
            assert len(store.entity_series_values(
                "checkhost_latency_history", sensor="check_host",
                entity=entity)) == 12

    def test_every_entity_comes_back_in_one_read(self, store):
        """The composition root reads a whole series once per cycle, the
        way production holds one dict in memory; a per-entity read inside
        the fold would put a database call in a pure function."""
        for entity in ("a", "b", "c"):
            for index in range(4):
                store.append_entity_observation(
                    series="ais_vessel_history", sensor="ais_maritime",
                    entity=entity, observed_at=NOW + index,
                    value=float(index), now=NOW + index)
        snapshot = store.entity_series_tail("ais_vessel_history",
                                            sensor="ais_maritime",
                                            per_entity=2)
        assert set(snapshot) == {"a", "b", "c"}
        assert [row["value"] for row in snapshot["a"]] == [2.0, 3.0]

    def test_a_payload_travels_with_the_sample(self, store):
        store.append_entity_observation(
            series="ais_vessel_history", sensor="ais_maritime",
            entity="123456789", observed_at=NOW,
            payload={"lat": 25.0, "lng": 121.0}, now=NOW)
        rows = store.entity_series_tail("ais_vessel_history",
                                        sensor="ais_maritime", per_entity=1)
        assert rows["123456789"][0]["payload"] == {"lat": 25.0, "lng": 121.0}

    def test_a_recorded_sample_cannot_be_edited(self, store):
        store.append_entity_observation(
            series="ais_vessel_history", sensor="ais_maritime",
            entity="1", observed_at=NOW, value=1.0, now=NOW)
        with pytest.raises(Exception) as caught:
            store._connection().execute(          # noqa: SLF001
                "UPDATE entity_observation SET value = 2.0")
        assert "append-only" in str(caught.value)

    def test_a_recorded_sample_cannot_be_deleted_outside_the_prune(
            self, store):
        store.append_entity_observation(
            series="ais_vessel_history", sensor="ais_maritime",
            entity="1", observed_at=NOW, value=1.0, now=NOW)
        with pytest.raises(Exception) as caught:
            store._connection().execute(          # noqa: SLF001
                "DELETE FROM entity_observation")
        assert "retention job" in str(caught.value)

    def test_the_retention_job_prunes_the_series(self, store):
        store.append_entity_observation(
            series="ais_vessel_history", sensor="ais_maritime", entity="old",
            observed_at=NOW - 40 * DAY, value=1.0, now=NOW - 40 * DAY)
        store.append_entity_observation(
            series="ais_vessel_history", sensor="ais_maritime", entity="new",
            observed_at=NOW - 1 * DAY, value=1.0, now=NOW - DAY)
        deleted = store.prune_expired(now=NOW)
        assert deleted["entity_observation"] == 1
        assert set(store.entity_series_tail("ais_vessel_history",
                                            sensor="ais_maritime",
                                            per_entity=1)) == {"new"}

    def test_an_empty_entity_key_is_refused(self, store):
        """An empty entity collapses every vessel, URL and domain into one
        series, and the collapse is invisible in the numbers."""
        with pytest.raises(DomainError):
            store.append_entity_observation(
                series="ais_vessel_history", sensor="ais_maritime",
                entity="", observed_at=NOW, value=1.0, now=NOW)


class TestTheEntityMarker:
    def test_first_seen_is_set_once_and_last_seen_moves(self, store):
        store.touch_entity_marker(series="ct_log_domain_first_observed",
                                  sensor="ct_log", entity="gov.tw", now=NOW)
        store.touch_entity_marker(series="ct_log_domain_first_observed",
                                  sensor="ct_log", entity="gov.tw",
                                  now=NOW + DAY)
        row = store.entity_marker("ct_log_domain_first_observed",
                                  sensor="ct_log", entity="gov.tw")
        assert row["first_seen"] == NOW
        assert row["last_seen"] == NOW + DAY
        assert row["observation_count"] == 2

    def test_first_seen_cannot_be_moved_even_by_raw_sql(self, store):
        """The warm-up ends `CT_LOG_WARMUP_DAYS` after `first_seen`
        (`ct_log.py:273-275`). Moving it forward re-opens a warm-up that
        had closed, and an adapter in warm-up does not emit score 3."""
        store.touch_entity_marker(series="ct_log_domain_first_observed",
                                  sensor="ct_log", entity="gov.tw", now=NOW)
        with pytest.raises(Exception) as caught:
            store._connection().execute(          # noqa: SLF001
                "UPDATE entity_marker SET first_seen = ?", (NOW + DAY,))
        assert "first_seen" in str(caught.value)

    def test_members_of_an_entity_are_a_set(self, store):
        for member in ("digicert", "letsencrypt", "digicert"):
            store.touch_entity_marker(
                series="ct_log_known_ca_per_domain", sensor="ct_log",
                entity="gov.tw", member=member, now=NOW)
        assert store.entity_members("ct_log_known_ca_per_domain",
                                    sensor="ct_log",
                                    entity="gov.tw") == ("digicert",
                                                         "letsencrypt")

    def test_members_come_back_for_every_entity_in_one_read(self, store):
        store.touch_entity_marker(series="ct_log_known_ca_per_domain",
                                  sensor="ct_log", entity="a.tw",
                                  member="digicert", now=NOW)
        store.touch_entity_marker(series="ct_log_known_ca_per_domain",
                                  sensor="ct_log", entity="b.tw",
                                  member="sectigo", now=NOW)
        snapshot = store.entity_member_sets("ct_log_known_ca_per_domain",
                                            sensor="ct_log")
        assert snapshot == {"a.tw": ("digicert",), "b.tw": ("sectigo",)}

    def test_markers_survive_the_retention_job(self, store):
        store.touch_entity_marker(series="ct_log_domain_first_observed",
                                  sensor="ct_log", entity="gov.tw",
                                  now=NOW - 400 * DAY)
        store.prune_expired(now=NOW)
        assert store.entity_marker("ct_log_domain_first_observed",
                                   sensor="ct_log", entity="gov.tw")

    def test_the_marker_read_uses_the_read_only_connection(self, store):
        store.touch_entity_marker(series="ct_log_domain_first_observed",
                                  sensor="ct_log", entity="gov.tw", now=NOW)
        before = store.entity_marker("ct_log_domain_first_observed",
                                     sensor="ct_log", entity="gov.tw")
        store.entity_members("ct_log_domain_first_observed", sensor="ct_log",
                             entity="gov.tw")
        after = store.entity_marker("ct_log_domain_first_observed",
                                    sensor="ct_log", entity="gov.tw")
        assert before == after
