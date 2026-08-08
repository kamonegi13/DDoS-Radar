"""THE route table. One place where a route exists and who may call it.

Completion condition 4 is structural here rather than procedural. G-01
was one endpoint out of four forgetting `_require_analyst()`, invisible
because a missing call and an unneeded call look the same. In this table:

* `access` is a required field with no default. A `Route` without an
  authorization decision raises `TypeError` at import, which is a failing
  build rather than an open endpoint.
* `Access` refuses to exist without a decision AND a reason, so "public"
  is a written choice reviewable against S2-PROP-021's matrix.
* `side_effect` is declared and cross-checked: a GET declaring a side
  effect is refused at construction (completion condition 1, A-01).

Everything about a route is data. `tests/test_api_surface.py` reads this
table against P7 §1 and reports what is served versus what is owed, so
"the surface is implemented" is a computed claim rather than a memory.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from v3.api.authorization import Access
from v3.api.handlers import commands as H_commands
from v3.api.handlers import conclusions as H_conclusions
from v3.api.handlers import config as H_config
from v3.api.handlers import disclosure as H_disclosure
from v3.api.handlers import evidence as H_evidence
from v3.api.handlers import reliability as H_reliability
from v3.api.handlers import scenarios as H_scenarios
from v3.api.vocabulary import (API_PREFIX, DELETE, GET, METHODS, POST,
                               ROLE_ANALYST, ROLE_VIEWER, SAFE_METHODS)
from v3.kernel.errors import DomainError

_READ_ONLY = ("読み取り射影。AP3 の透明性情報を含め viewer に開放する"
              "（S2-PROP-021: 「今このツールをどこまで信じるか」は全利用者が"
              "見るべき情報）")
_PROBE = "起動・死活 probe。トークンを要求すると再起動役が使えない"
#: G-01, permanently. The defect was that `POST .../feedback` reached the
#: calibration chain's input without the gate its three sibling endpoints
#: had. Here the gate is this field: the route cannot exist without it.
_ANALYST_WRITE = ("指令。較正系の入力または採点予算の配分を動かすため "
                  "analyst 以上（G-01 の恒久化: 認可はルート宣言であり "
                  "ハンドラ本体の呼び出しではない）")


@dataclass(frozen=True, slots=True)
class Route:
    """One declared endpoint. `access` has no default, on purpose."""

    route_id: str
    method: str
    path: str
    access: Access
    handler: Callable
    serves: tuple[str, ...]
    side_effect: bool = False
    note: str = ""

    def __post_init__(self) -> None:
        if self.method not in METHODS:
            raise DomainError(f"unknown method {self.method!r}")
        if not self.path.startswith("/"):
            raise DomainError(f"path must be absolute: {self.path!r}")
        if not callable(self.handler):
            raise DomainError(f"route {self.route_id} has no handler")
        if self.side_effect and self.method in SAFE_METHODS:
            raise DomainError(
                f"route {self.route_id} declares a side effect on a "
                f"{self.method}. That is defect A-01 exactly: "
                f"GET /api/threat_data ran the scoring tick, so polling "
                f"could not be stopped and a scoring failure flagged by one "
                f"GET was cleared by the next.")
        object.__setattr__(self, "serves", tuple(self.serves))

    @property
    def segments(self) -> tuple[str, ...]:
        return tuple(part for part in self.path.split("/") if part)

    def as_dict(self) -> dict:
        return {"route_id": self.route_id, "method": self.method,
                "path": self.path, "access": self.access.as_dict(),
                "serves": list(self.serves), "side_effect": self.side_effect,
                "note": self.note}


def _read(route_id: str, path: str, handler: Callable, serves: tuple,
          *, access: Optional[Access] = None, note: str = "") -> Route:
    return Route(route_id=route_id, method=GET, path=path,
                 access=access or Access.at_least(ROLE_VIEWER,
                                                  reason=_READ_ONLY),
                 handler=handler, serves=serves, side_effect=False, note=note)


def _command(route_id: str, path: str, handler: Callable, serves: tuple,
             *, method: str = POST, access: Optional[Access] = None,
             note: str = "") -> Route:
    """A command route. `side_effect=True` is not optional here.

    Declared rather than inferred, and the two directions are enforced in
    opposite places: `Route.__post_init__` refuses a GET that declares an
    effect (A-01), and `tests/test_api_surface.py` refuses a command that
    does not — because an undeclared effect is a route the dispatcher
    would hand a read context and a handler that would then have nothing
    to write through.
    """
    return Route(route_id=route_id, method=method, path=path,
                 access=access or Access.at_least(ROLE_ANALYST,
                                                  reason=_ANALYST_WRITE),
                 handler=handler, serves=serves, side_effect=True, note=note)


ROUTES: tuple[Route, ...] = (
    _read("R1", f"{API_PREFIX}/scenarios", H_scenarios.read_scenarios,
          ("I-2",), note="シナリオ台帳 + focus 状態 + TL サマリ"),
    _read("R2", f"{API_PREFIX}/scenarios/<scenario_id>/conclusions",
          H_conclusions.read_conclusions,
          ("O-1", "O-2", "O-3", "O-4", "O-5", "O-7", "O-8", "O-12"),
          note="?at= は live と同一射影"),
    _read("R3", f"{API_PREFIX}/scenarios/<scenario_id>/conclusions/history",
          H_conclusions.read_history, ("O-2", "O-7"),
          note="L1 無間引き TL ストリームの派生ビュー（P6 O-16）"),
    _read("R4", f"{API_PREFIX}/conclusions/<conclusion_id>",
          H_conclusions.read_conclusion, ("O-6",)),
    _read("R4d", f"{API_PREFIX}/conclusions/<conclusion_id>/derivation",
          H_conclusions.read_derivation, ("O-6",),
          note="式 ID・実効閾値・一次ソース・prompt sha・ガード評価"),
    _read("R5", f"{API_PREFIX}/scenarios/<scenario_id>/evidence",
          H_evidence.read_evidence, ("O-4", "O-6"),
          note="抑制済み行は理由付きで返す（E-17）"),
    _read("R7", f"{API_PREFIX}/self_eval", H_reliability.read_self_eval,
          ("O-11",), note="AP3。8 面を 1 本へ吸収"),
    _read("R8", f"{API_PREFIX}/sensors", H_reliability.read_sensors,
          ("O-11",), note="センサー健全性の単一形（現行 4〜5 形を統合）"),
    _read("R8o", f"{API_PREFIX}/sensors/<sensor_id>/observations",
          H_evidence.read_observations, ("O-4",)),
    _read("R10", f"{API_PREFIX}/thresholds", H_disclosure.read_thresholds,
          ("O-6",), note="O-18 の可変キーと provenance 付き定数の両方"),
    _read("R14", f"{API_PREFIX}/config", H_config.read_config, ("I-2",),
          note="O-18 の可変キーのみ。値・出所層（override/env/default）・"
               "既定値・可変である理由・読み手を返す"),
    _read("R12", f"{API_PREFIX}/scenarios/<scenario_id>/report.md",
          H_disclosure.read_report, ("O-6", "O-8"),
          note="唯一の報告出力。SALUTE/weather/sitrep/daily は持たない"),
    _read("R15c", f"{API_PREFIX}/app_config", H_disclosure.read_app_config,
          ("I-2",)),
    Route(route_id="R15h", method=GET, path="/healthz",
          access=Access.public_route(reason=_PROBE),
          handler=H_disclosure.read_health, serves=("I-2",),
          side_effect=False, note="唯一の public route"),
    # ── P7 §1.2 — the command surface ───────────────────────────────────
    _read("C9g", f"{API_PREFIX}/ground_truth", H_commands.read_ground_truth,
          ("I-2",), note="C9 の読み取り半分。C9p の効果が実在する先"),
    _command("C1", f"{API_PREFIX}/focus", H_commands.set_focus, ("I-2",),
             note="focus 登録。GET の副作用から分離（PROP-001）"),
    _command("C2", f"{API_PREFIX}/conclusions/<conclusion_id>/feedback",
             H_commands.submit_feedback, ("I-2",),
             note="G-01 の当事者。認可はこの表の宣言であり本体呼び出しではない"),
    _command("C9p", f"{API_PREFIX}/scenarios/<scenario_id>/ground_truth",
             H_commands.assert_ground_truth, ("I-2",),
             note="S9 の教師信号。観測時刻と検証可能な出典を必須とする"),
    _command("C7s", f"{API_PREFIX}/config/<key>", H_config.set_config,
             ("I-2",),
             note="可変キーの変更。効果は 3 層チェーンで読み戻される"
                  "（読まれない変更は commit が拒否する = G-15 の恒久化）"),
    _command("C7d", f"{API_PREFIX}/config/<key>", H_config.clear_config,
             ("I-2",), method=DELETE,
             note="override の解除。削除ではなく追記 — 誰がいつ既定へ戻したかが"
                  "判断履歴に残る（AP4）"),
)


def _matches(route: Route, segments: tuple[str, ...]) -> Optional[dict]:
    declared = route.segments
    if len(declared) != len(segments):
        return None
    captured: dict = {}
    for template, actual in zip(declared, segments):
        if template.startswith("<") and template.endswith(">"):
            captured[template[1:-1]] = actual
        elif template != actual:
            return None
    return captured


def match(method: str, path: str) -> tuple[Optional[Route], dict, bool]:
    """(route, path params, path_exists_under_another_method).

    The third value is what lets the dispatcher answer 405 rather than
    404 for a known path with the wrong verb — the distinction the legacy
    surface collapsed, so a client could not tell "no such thing" from
    "not like that".
    """
    segments = tuple(part for part in path.split("/") if part)
    path_seen = False
    for route in ROUTES:
        captured = _matches(route, segments)
        if captured is None:
            continue
        path_seen = True
        if route.method == method:
            return route, captured, True
    return None, {}, path_seen


def by_id(route_id: str) -> Optional[Route]:
    for route in ROUTES:
        if route.route_id == route_id:
            return route
    return None


__all__ = ["Route", "ROUTES", "match", "by_id"]
