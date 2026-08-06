"""WP-2.1 K kernel — Evidence makes B-03 unrepresentable.

B-03: ground_osint received observations carrying a STALE marker and used
them anyway, because the freshness field was informational — reading it
was optional, and the code that consumed the payload simply did not.

Evidence inverts that. The payload is not an attribute; the only way to
reach it is `fresh()`, which raises when the observation is past its
horizon. Ignoring freshness is no longer an omission you can make — it is
a call you would have to write deliberately (`assume_fresh()`), which is
greppable and reviewable.
"""
import pytest

from v3.kernel import Evidence
from v3.kernel.errors import DomainError, StaleEvidenceError

NOW = 1_786_000_000.0
HOUR = 3600.0


def _evidence(**overrides):
    payload = {
        "payload": {"jam_ratio": 0.08},
        "observed_at": NOW,
        "freshness_horizon_sec": 6 * HOUR,
        "source": "gps_jamming",
    }
    payload.update(overrides)
    return Evidence.observe(**payload)


class TestConstruction:
    def test_a_complete_observation_builds(self):
        evidence = _evidence()
        assert evidence.source == "gps_jamming"
        assert evidence.observed_at == NOW
        assert evidence.freshness_horizon_sec == 6 * HOUR

    @pytest.mark.parametrize("horizon", [0, -1, None, "6h"])
    def test_an_invalid_horizon_raises(self, horizon):
        with pytest.raises(DomainError):
            _evidence(freshness_horizon_sec=horizon)

    @pytest.mark.parametrize("observed_at", [0, -1, None, "yesterday"])
    def test_an_invalid_timestamp_raises(self, observed_at):
        with pytest.raises(DomainError):
            _evidence(observed_at=observed_at)

    @pytest.mark.parametrize("source", ["", "   ", None])
    def test_a_missing_source_raises(self, source):
        with pytest.raises(DomainError) as exc:
            _evidence(source=source)
        assert "source" in str(exc.value)

    def test_a_none_payload_is_allowed(self):
        # "the sensor returned nothing" is itself an observation.
        assert _evidence(payload=None).fresh(now=NOW) is None

    def test_is_immutable(self):
        with pytest.raises(Exception):
            _evidence().observed_at = 0

    def test_has_no_dict(self):
        assert not hasattr(_evidence(), "__dict__")


class TestFreshnessGatesThePayload:
    def test_fresh_returns_the_payload_inside_the_horizon(self):
        assert _evidence().fresh(now=NOW + HOUR) == {"jam_ratio": 0.08}

    def test_fresh_at_the_moment_of_observation(self):
        assert _evidence().fresh(now=NOW) == {"jam_ratio": 0.08}

    def test_fresh_raises_past_the_horizon(self):
        with pytest.raises(StaleEvidenceError) as exc:
            _evidence().fresh(now=NOW + 7 * HOUR)
        message = str(exc.value)
        assert "gps_jamming" in message, "the error must name the source"
        assert "6" in message or "21600" in message, \
            "the error must state the horizon it exceeded"

    def test_the_horizon_boundary_is_still_fresh(self):
        assert _evidence().fresh(now=NOW + 6 * HOUR) is not None

    def test_one_second_past_the_horizon_is_stale(self):
        with pytest.raises(StaleEvidenceError):
            _evidence().fresh(now=NOW + 6 * HOUR + 1)

    def test_an_observation_from_the_future_is_refused(self):
        # Clock skew must not read as maximally fresh.
        with pytest.raises(StaleEvidenceError) as exc:
            _evidence().fresh(now=NOW - HOUR)
        assert "future" in str(exc.value).lower()


class TestNoUncheckedPath:
    def test_the_payload_is_not_a_public_attribute(self):
        assert not hasattr(_evidence(), "payload")

    def test_the_payload_is_not_in_the_repr(self):
        # A secret or a large blob must not leak through logging, and the
        # repr must not become an accidental unchecked accessor.
        assert "jam_ratio" not in repr(_evidence())

    def test_is_fresh_answers_without_yielding_the_payload(self):
        evidence = _evidence()
        assert evidence.is_fresh(now=NOW + HOUR) is True
        assert evidence.is_fresh(now=NOW + 7 * HOUR) is False

    def test_age_seconds_is_available_for_reporting(self):
        assert _evidence().age_seconds(now=NOW + HOUR) == pytest.approx(HOUR)

    def test_assume_fresh_is_explicit_and_requires_a_reason(self):
        # The escape hatch exists (replay legitimately needs it) but it is
        # loud: greppable name, mandatory justification.
        evidence = _evidence()
        with pytest.raises(DomainError):
            evidence.assume_fresh(reason="")
        assert evidence.assume_fresh(
            reason="S5 replay: horizon is evaluated at the replayed instant"
        ) == {"jam_ratio": 0.08}


class TestHistoricalDefect:
    """B-03: the STALE marker that was read and ignored."""

    def test_consuming_a_stale_observation_raises_rather_than_returning_it(self):
        stale = Evidence.observe(
            payload={"headline": "old news"}, observed_at=NOW - 48 * HOUR,
            freshness_horizon_sec=6 * HOUR, source="ground_osint")
        with pytest.raises(StaleEvidenceError):
            stale.fresh(now=NOW)

    def test_there_is_no_attribute_that_bypasses_the_check(self):
        stale = Evidence.observe(
            payload={"headline": "old news"}, observed_at=NOW - 48 * HOUR,
            freshness_horizon_sec=6 * HOUR, source="ground_osint")
        public = {name for name in dir(stale) if not name.startswith("_")}
        # Everything public is either a check, a report, or the loud hatch.
        assert public == {"observed_at", "freshness_horizon_sec", "source",
                          "fresh", "is_fresh", "age_seconds", "assume_fresh",
                          "observe"}
