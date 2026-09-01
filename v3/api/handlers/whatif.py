"""P7 C6 — ONE counterfactual system, run on the server's own kernel.

Production has three: `POST /api/whatif/simulate`, `POST /api/scenarios/
<sid>/whatif_weights`, and an `X-Scenario-Overlay` request header that
re-scored whatever endpoint it was attached to. G-09 is the reason the
header matters: the frontend reimplemented the scoring arithmetic so the
"what if" answer and the real answer came from two different formulas,
and only one of them was the tool's own.

So this handler does not compute a score. It calls the SAME kernel the
tick calls, through the seam `v3/runtime/scoring.py::assemble` exists for:
`assemble(...)` reads L1 and writes nothing, `score(...)` is pure, and the
result is discarded rather than persisted.

**A POST that writes nothing.** The route declares `side_effect=False`, so
the dispatcher hands this function a `ReadContext` — it holds no
`CommandLedger`, has no `commit`, and the ledger it does hold is opened
`mode=ro`. That is why POST is safe here: the verb says only that the call
carries a body, and the context says the call cannot write.
`tests/test_api_whatif.py` counts every table before and after.

The overlay vocabulary is CLOSED. `settings` accepts the scoring
settings' own field names and `weights` accepts declared participants;
anything else is a 400 naming what is accepted, because a counterfactual
that silently ignored half its inputs would answer a question nobody
asked.
"""
from __future__ import annotations

from dataclasses import replace

from v3.api import errors as E
from v3.api.envelope import ApiResponse, tool_response
from v3.api.vocabulary import TOOL_SCOPE
from v3.kernel.errors import DomainError
from v3.runtime import scoring as scoring_module
from v3.scoring import Participant, Scenario

#: What may be varied. Two families, matching the two production systems
#: P7 §5 collapses into this one (`whatif/simulate` varied settings,
#: `whatif_weights` varied coupling weights).
OVERLAY_KEYS: tuple[str, ...] = ("settings", "weights", "focus")

_NO_CHAIN = ("この配備は設定解決チェーンを持ちません"
             "（反実仮想は実際の解決値からの差分として答えます）")


def _chain(context):
    if context.config is None:
        raise E.ApiFailure(503, E.ApiError(
            code=E.UNAVAILABLE, message=_NO_CHAIN, detail={}))
    return context.config


def _scenarios(context, weights) -> tuple:
    """The kernel's scenarios, with the requested weights substituted.

    Built from the composition root's `ScenarioRef`s rather than from
    `geo_data.json`: the API does not read deployment data, and a second
    reader of it is a second ledger that drifts.

    `chain_country` carries the DECLARED core country through, so a
    single-core scenario keeps its owner here for the same reason the
    tick's `scenarios_for` reads it. A dual-core one arrives with None
    and `assemble` measures its owner from the observations.
    """
    built = []
    for ref in context.scenarios:
        overlay = dict(weights.get(ref.scenario_id, {}))
        unknown = sorted(set(overlay) - set(ref.participants))
        if unknown:
            raise E.bad_request(
                f"シナリオ {ref.scenario_id} に存在しない参加国です: "
                f"{', '.join(unknown)}",
                scenario_id=ref.scenario_id, unknown=unknown,
                participants=sorted(ref.participants),
                reason="参加国の追加はシナリオ定義の変更であり反実仮想では"
                       "ありません（C11 の領分）")
        merged = {country: float(overlay.get(country, weight))
                  for country, weight in ref.participants.items()}
        built.append(Scenario(
            scenario_id=ref.scenario_id,
            participants=tuple(
                Participant(country=country, weight=weight,
                            role=str(dict(ref.roles).get(country, "")))
                for country, weight in sorted(
                    merged.items(), key=lambda item: (-item[1], item[0]))),
            enabled=True, core_country=ref.chain_country))
    return tuple(built)


def _settings(context, overrides):
    base = scoring_module.settings_for(context.ledger,
                                       config=_chain(context),
                                       at=context.now)
    if not overrides:
        return base, base
    accepted = set(base.disclosed())
    unknown = sorted(set(overrides) - accepted)
    if unknown:
        raise E.bad_request(
            f"未知の設定キー: {', '.join(unknown)}", unknown=unknown,
            accepted=sorted(accepted),
            reason="反実仮想の語彙は採点設定そのものです")
    try:
        return base, replace(base, **{key: overrides[key]
                                      for key in overrides})
    except (DomainError, TypeError, ValueError) as exc:
        raise E.bad_request(str(exc), overrides=dict(overrides)) from exc


def simulate(context) -> ApiResponse:
    """C6 — score the ledger's current observations under other settings.

    Returns BOTH runs. A counterfactual reported alone is a number with no
    scale: the question is always "compared to what", and answering with
    both means the analyst is not subtracting against a figure fetched
    separately, which could have been scored at another instant.
    """
    body = dict(context.body)
    unknown = sorted(set(body) - set(OVERLAY_KEYS))
    if unknown:
        raise E.bad_request(
            f"未知の反実仮想キー: {', '.join(unknown)}", unknown=unknown,
            accepted=list(OVERLAY_KEYS))
    weights = body.get("weights") or {}
    if not isinstance(weights, dict):
        raise E.bad_request("weights はシナリオ ID をキーとする object です")
    for scenario_id in weights:
        if context.scenario(str(scenario_id)) is None:
            raise E.not_found(f"シナリオ {scenario_id}",
                              scenario_id=scenario_id)
    overrides = body.get("settings") or {}
    if not isinstance(overrides, dict):
        raise E.bad_request("settings はキーと値の object です")
    focus = body.get("focus")
    if focus is not None and context.scenario(str(focus)) is None:
        raise E.not_found(f"シナリオ {focus}", scenario_id=focus)
    if not context.scenarios:
        raise E.bad_request(
            "この配備にはシナリオが登録されていません",
            reason="反実仮想は登録済シナリオの採点を別の値で回すものです")

    baseline_settings, varied_settings = _settings(context, overrides)
    baseline_scenarios = _scenarios(context, {})
    varied_scenarios = _scenarios(context, weights)
    focused = None if focus is None else str(focus)

    # The sequence chain's owner is NOT passed in. `assemble` measures it
    # from the same observations it is about to score (§7-2 #115), which is
    # exactly what the tick does — so a counterfactual reads the same
    # belligerent's chain the real run reads, without this handler holding
    # a second copy of the rule.
    def _run(scenarios, settings):
        inputs = scoring_module.assemble(
            now=context.now, store=context.ledger,
            geography=None, scenario_ids=[s.scenario_id for s in scenarios],
            settings=settings, focused_scenario_id=focused,
            scenarios=scenarios)
        return scoring_module.score(inputs)

    try:
        baseline = _run(baseline_scenarios, baseline_settings)
        varied = _run(varied_scenarios, varied_settings)
    except DomainError as exc:
        raise E.bad_request(str(exc)) from exc

    baseline_rows = {sid: result.as_dict()
                     for sid, result in baseline.results.items()}
    varied_rows = {sid: result.as_dict()
                   for sid, result in varied.results.items()}
    return tool_response(
        observed_at=context.now,
        baseline={"settings": baseline_settings.disclosed(),
                  "scenarios": baseline_rows},
        counterfactual={"settings": varied_settings.disclosed(),
                        "scenarios": varied_rows},
        overlay={"settings": dict(overrides), "weights": dict(weights),
                 "focus": focused},
        accepted_keys=list(OVERLAY_KEYS),
        note="反実仮想はサーバの L2 カーネルを dry-run で呼びます"
             "（フロント再実装の禁止 = G-09）。台帳への書込みはありません")


__all__ = ["OVERLAY_KEYS", "simulate", "TOOL_SCOPE"]
