"""`threatfox` — S1-SENS-014, D1 §4 K10. Known hostile infrastructure.

K10: **abuse.ch requires `Auth-Key` on `get_iocs` too.** It did not
always, which is why the legacy client sent the header only on some
calls; today an unauthenticated request is a 401, and a 401 that keeps
the previous cache looks exactly like a quiet day. The requirement is a
declaration here, so the composition root either supplies the key or the
fetch records AUTH_MISSING — it cannot silently proceed keyless.

The other operational fact: abuse.ch blocks script user-agents, so the
request carries a browser one. Recorded rather than rediscovered.

A11 — an IoC tagged `apt` and an IoC tagged with the country's English
name count equally, with no threshold. Country-name tags appear in
unrelated contexts, so this over-counts; the design sheet rules it
ACCIDENTAL and ports it unchanged.
"""
from __future__ import annotations

from v3.adapters.common import list_or_empty, load_json, mapping_or_empty
from v3.adapters.types import (AdapterId, AUTH_API_KEY, AuthRequirement,
                               CYBER, NormalizeContext, ObservationDraft,
                               RequestSpec, SourceAdapter, STATUS_FIRED,
                               STATUS_OK)
from v3.kernel import Window

THREATFOX = AdapterId("threatfox")

_THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
#: abuse.ch 403s script user-agents.
_BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
               "AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/120.0.0.0 Safari/537.36")
#: Both are ordinary successes; anything else is a failed query.
OK_QUERY_STATUSES: frozenset = frozenset({"ok", "no_result"})
LOOKBACK_DAYS = 1
#: The rationale `value` production writes for this sensor, on BOTH the
#: FIRED and the OK branch (`radar/routes/core.py:1190`). It is a match
#: target for noise-exclusion rules (`core.py:950`), so it is one string,
#: not two.
RATIONALE_VALUE = "APT C2 Hit"
#: The `fired_reason` production passes at `radar/routes/core.py:1190` —
#: also unconditionally, on the OK branch as well as the FIRED one. The
#: port dropped it entirely, which empties the sentence an analyst reads
#: next to the verdict and the `detail.fired_reason` that
#: `hidden_signal_log` records when the entry is muted (`core.py:988`).
RATIONALE_REASON = "Known APT infra matched"
#: `COUNTRY_COORDS.get(code, {}).get("name", "Unknown")` — the legacy
#: default for a country with no name (`radar/sensors/threatfox.py:59`).
UNKNOWN_COUNTRY_NAME = "Unknown"

_CADENCE = Window.from_days(1.0, cadence_sec=3600.0)
_FRESHNESS_HORIZON_SEC = 6 * 3600.0


def _tag_matches(tags, country_name: str) -> bool:
    """A11's rule, unchanged: the `apt` tag OR the country's name."""
    for tag in list_or_empty(tags):
        text = str(tag).lower()
        if "apt" in text or (country_name and country_name in text):
            return True
    return False


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """One global fetch -> one observation per country in scope.

    Countries with no hits still get an OK observation. The legacy cache
    omitted them, which made "no APT infrastructure seen" and "not looked
    at" the same absence — and NP1 needs those distinguishable.
    """
    document = mapping_or_empty(load_json(payload))
    status = str(document.get("query_status") or "").lower()
    if status not in OK_QUERY_STATUSES:
        return ()
    iocs = list_or_empty(document.get("data"))
    names = getattr(context, "country_names", None) or {}

    drafts: list[ObservationDraft] = []
    for country in context.countries:
        # `"unknown"` is the legacy default, not `""`
        # (`radar/sensors/threatfox.py:59`,
        # `COUNTRY_COORDS.get(code, {}).get("name", "Unknown").lower()`), and
        # it is substring-matched against tags like any other name.
        name = str(names.get(country) or UNKNOWN_COUNTRY_NAME).lower()
        count = sum(1 for ioc in iocs
                    if _tag_matches(mapping_or_empty(ioc).get("tags"), name))
        drafts.append(ObservationDraft(
            signal_source="threatfox", domain=CYBER, country=country,
            status=STATUS_FIRED if count else STATUS_OK,
            raw_score=1.0 if count else 0.0,
            # `core.py:1190` passes `"APT C2 Hit"` unconditionally — on the
            # OK branch too. `value` is what `noise_excl_match` matches on
            # (`core.py:950`), so a second literal here would silently
            # unmatch every migrated exclusion rule.
            value=RATIONALE_VALUE,
            reason=RATIONALE_REASON,
            flags={"count": count,
                   "description": f"{count} APT/State-linked IoCs detected"},
            evidence_url=payload.url))
    return tuple(drafts)


THREATFOX_ADAPTER = SourceAdapter(
    adapter_id=THREATFOX, category=CYBER,
    requests=(RequestSpec(url=_THREATFOX_URL, method="POST",
                          expect_content="json",
                          # `radar/sensors/threatfox.py:20,42` —
                          # `requests.post(url, json={"query": "get_iocs",
                          # "days": 1})`. The WP-2.6 port sent this as a
                          # query string, which abuse.ch does not read.
                          body={"query": "get_iocs", "days": LOOKBACK_DAYS},
                          body_content_type="application/json",
                          headers={"User-Agent": _BROWSER_UA},
                          label="get_iocs"),),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    # MANDATORY, deliberately — and this is the one place the model's new
    # `optional` flag is NOT used where a first reading suggests it. The
    # criterion for optional is "production proceeds anonymously", and
    # ThreatFox does not: `radar/sensors/threatfox.py:35-38` SKIPS the call
    # and then calls `log_fetch(True, ...)` with zero hits — a keyless run
    # is recorded as a SUCCESS that found nothing. K10 says a keyless
    # get_iocs is a 401, so there is no anonymous mode to fall back to.
    # Reproducing the skip would reproduce the silent failure; AUTH_MISSING
    # says "could not ask", which is the fact.
    auth=AuthRequirement(kind=AUTH_API_KEY, key_id="THREATFOX_API_KEY",
                         name="Auth-Key", value_template="{secret}",
                         note="K10: get_iocs requires Auth-Key since 2024. "
                              "Production's keyless path logs success with "
                              "zero hits; v3 records AUTH_MISSING instead."),
    rate_limit_group="abusech", knowledge_refs=("K10",))

__all__ = ["THREATFOX", "THREATFOX_ADAPTER", "normalize",
           "OK_QUERY_STATUSES", "LOOKBACK_DAYS", "RATIONALE_VALUE",
           "RATIONALE_REASON", "UNKNOWN_COUNTRY_NAME"]
