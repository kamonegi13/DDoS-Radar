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
from v3.api.cookies import (CSRF_COOKIE, REFRESH_COOKIE, CookiePolicy,
                            NO_COOKIES)
from v3.api.handlers import attention as H_attention
from v3.api.handlers import auth as H_auth
from v3.api.handlers import commands as H_commands
from v3.api.handlers import decisions as H_decisions
from v3.api.handlers import conclusions as H_conclusions
from v3.api.handlers import config as H_config
from v3.api.handlers import disclosure as H_disclosure
from v3.api.handlers import evidence as H_evidence
from v3.api.handlers import intel as H_intel
from v3.api.handlers import observations as H_observations
from v3.api.handlers import proposals as H_proposals
from v3.api.handlers import reliability as H_reliability
from v3.api.handlers import scenarios as H_scenarios
from v3.api.handlers import whatif as H_whatif
from v3.api.vocabulary import (API_PREFIX, DELETE, GET, METHODS, POST,
                               PUT, ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER,
                               SAFE_METHODS)
from v3.kernel.errors import DomainError

_READ_ONLY = ("読み取り射影。AP3 の透明性情報を含め viewer に開放する"
              "（S2-PROP-021: 「今このツールをどこまで信じるか」は全利用者が"
              "見るべき情報）")
_PROBE = "起動・死活 probe。トークンを要求すると再起動役が使えない"
#: The only other public decision on the surface, and it is forced: a
#: caller who has no token is exactly the caller these two routes exist
#: for. Everything they can learn is bounded by S1-SVC-002's uniform
#: refusal — "no such user" and "wrong password" are one answer — so being
#: public does not make them an enumeration oracle.
_SESSION_PUBLIC = ("トークン取得・更新の経路。未認証の呼び手のために存在する"
                   "ため public だが、失敗応答は一意（利用者の存在は"
                   "漏れない）")
#: S1-SVC-008: registration, listing, standing changes and removal are the
#: administrator's alone. The self-service pair is open to any
#: authenticated reader, because a viewer must be able to end their own
#: session and change their own password.
_INTEL_READ = ("インテルキュー。裁定は analyst の職務であり、"
               "キュー自体も analyst 以上に限る（P7 R11「認可は analyst」）")
_USER_ADMIN = ("利用者管理。登録・一覧・役割変更・無効化は admin のみ"
               "（S1-SVC-008）")
_SELF_SERVICE = ("自分自身のセッション／資格情報に対する操作。"
                 "viewer を含む全認証利用者に開く")
#: G-01, permanently. The defect was that `POST .../feedback` reached the
#: calibration chain's input without the gate its three sibling endpoints
#: had. Here the gate is this field: the route cannot exist without it.
_ANALYST_WRITE = ("指令。較正系の入力または採点予算の配分を動かすため "
                  "analyst 以上（G-01 の恒久化: 認可はルート宣言であり "
                  "ハンドラ本体の呼び出しではない）")
#: §7-2 #103. The refresh token never appears in a body: it rides an
#: httpOnly + SameSite=Strict cookie scoped to the refresh path, paired
#: with a readable companion the SPA echoes into `X-CSRF-TOKEN`. Declaring
#: it here rather than checking it in `H_auth.refresh` is the G-01 lesson —
#: a gate written in a handler is a gate the next handler can be written
#: without.
_REFRESH_TRANSPORT = ("refresh token の輸送。本文に載せることを S1-SVC-004 / "
                      "S2-API-010 が MUST NOT とし、S1-UI-002 は cookie 化を "
                      "CORE と判定している（XSS による窃取の構造的封鎖）")


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
    #: What this route does with cookies (§7-2 #103). Defaulted, and that
    #: is safe rather than sloppy: the two forgettable mistakes have no
    #: spelling. `CookiePolicy` refuses `presents` without `csrf`, so a
    #: cookie-borne credential cannot be admitted without the companion,
    #: and the dispatcher refuses a response emitting a cookie the policy
    #: did not name. What is left to default is "this route has nothing to
    #: do with cookies", which is true of every route but three.
    cookies: CookiePolicy = NO_COOKIES

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
        if not isinstance(self.cookies, CookiePolicy):
            raise DomainError(
                f"route {self.route_id} declares cookies as "
                f"{type(self.cookies).__name__}; it is a CookiePolicy, which "
                f"is where the CSRF pairing is enforced")
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
             cookies: CookiePolicy = NO_COOKIES, note: str = "") -> Route:
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
                 handler=handler, serves=serves, side_effect=True, note=note,
                 cookies=cookies)


#: A POST that changes nothing. The set is CLOSED and each member states
#: why, because "an unsafe method with no declared effect" is otherwise
#: indistinguishable from a command whose author forgot to declare one —
#: and that one would be handed a read context and would silently do
#: nothing. Membership is not a promise: the dispatcher gives these routes
#: a `ReadContext`, which holds no writer and a `mode=ro` connection, so
#: the claim is enforced by the type they receive.
DRY_RUN_ROUTES: dict = {
    "C6": "反実仮想。L2 カーネルを dry-run で呼ぶだけで台帳へ 1 行も書かない"
          "（POST なのは本体を持つため。書けないことは ReadContext が保証）",
}


#: A POST that mints or presents a session and writes NO ledger row.
#: Closed and reasoned like `DRY_RUN_ROUTES`, and separate from it because
#: the two are different claims: a dry run declines to write, a session
#: route has nothing to write. A session is a signed statement about the
#: user fold, not a state beside it — the states these DO move (a
#: revocation floor) are moved by `C13logout`, which is an ordinary
#: command with an ordinary audit row.
SESSION_ROUTES: dict = {
    "C13login": "資格情報を検証してトークン対を発行する。台帳へは 1 行も"
                "書かない（失敗回数はプロセス内のログインガードが持つ）",
    "C13refresh": "refresh トークンから access トークンを再発行する。"
                  "役割はその時点の fold から解決する（S1-SVC-005）",
}


#: Commands a VIEWER may issue. Closed, reasoned per member, and checked
#: by `tests/test_api_commands.py` — the same shape as `DRY_RUN_ROUTES`,
#: and for the same reason: the general rule (a command needs analyst or
#: above) is about the calibration chain's input and the sensor budget,
#: and an exception that was merely allowed rather than declared would be
#: indistinguishable from a route whose author picked the wrong floor.
#:
#: Both members act ONLY on the caller's own identity — the handler takes
#: the target from `context.actor_id`, never from the request — so no
#: privilege is reachable through them that the caller does not already
#: hold. Refusing them at analyst would mean a viewer could not end their
#: own session or change their own password, which is worse security, not
#: better.
SELF_SERVICE_ROUTES: dict = {
    "C13logout": "自分のセッションを失効させる。対象は context.actor_id で"
                 "あり要求からは取らない",
    "C13password": "自分の資格情報を変更する。現行パスワードの検証を伴い、"
                   "対象は同じく context.actor_id",
}


def _session(route_id: str, path: str, handler: Callable, serves: tuple,
             *, cookies: CookiePolicy, note: str = "") -> Route:
    """A public POST with a body and no ledger write. Must be declared.

    `cookies` has NO default here, unlike on the ordinary constructors.
    The session routes are the two that carry the refresh token, and a
    session route composed without a cookie decision is the exact state
    §7-2 #103 recorded: a token with nowhere to ride but the body.
    """
    if route_id not in SESSION_ROUTES:
        raise DomainError(
            f"route {route_id} is a public unsafe method declaring no side "
            f"effect and is not in SESSION_ROUTES.")
    return Route(route_id=route_id, method=POST, path=path,
                 access=Access.public_route(reason=_SESSION_PUBLIC),
                 handler=handler, serves=serves, side_effect=False, note=note,
                 cookies=cookies)


def _dry_run(route_id: str, path: str, handler: Callable, serves: tuple,
             *, access: Optional[Access] = None, note: str = "") -> Route:
    """A POST with a body and no effect. Must be listed in DRY_RUN_ROUTES."""
    if route_id not in DRY_RUN_ROUTES:
        raise DomainError(
            f"route {route_id} is an unsafe method declaring no side effect "
            f"and is not in DRY_RUN_ROUTES. An undeclared effect is a command "
            f"the dispatcher hands a read context — a POST that answers 200 "
            f"having done nothing.")
    return Route(route_id=route_id, method=POST, path=path,
                 access=access or Access.at_least(ROLE_ANALYST,
                                                  reason=_ANALYST_WRITE),
                 handler=handler, serves=serves, side_effect=False, note=note)


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
    _read("R16", f"{API_PREFIX}/observations/board",
          H_observations.read_observation_board, ("O-4",),
          note="NP9 観測レイヤ（P8 §9）: 国別観測数 + 掃引 3 帯。"
               "帯が無い件数地図は G-17 の新形（未掃引が静けさに見える）"),
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
    # ── WP-4.1f: the attention ledger, its commands, and the rest of the
    #    read surface that was waiting on it ──────────────────────────────
    _read("R6", f"{API_PREFIX}/attention", H_attention.read_attention,
          ("O-9",),
          note="S8 台帳が書いた順位をそのまま射影する（フロント再計算の"
               "禁止 = P5 O-8 / G-03）。行ごとに導出（3 因子の実効値）と"
               "利用者別状態を含む"),
    _read("R9", f"{API_PREFIX}/decisions", H_decisions.read_decisions,
          ("O-12",),
          note="統一判断台帳（AP4）。command_record の全 target_kind + S8 "
               "順位スナップショットの 1 射影。監査 5 面を 1 本化"),
    _read("R9i", f"{API_PREFIX}/decisions/<command_id>",
          H_decisions.read_decision, ("O-12",)),
    _read("R13", f"{API_PREFIX}/proposals", H_proposals.read_proposals,
          ("I-2",),
          note="較正・センサー無効化・シナリオ改善の統一提案キュー。"
               "?at= は発行窓と裁定 fold の両方を束縛する"),
    _command("C4a", f"{API_PREFIX}/attention/<item_id>/ack",
             H_attention.ack_attention, ("I-2",),
             note="利用者ごと。次の順位付けの analyst_blindness が下がる"
                  "（= 読み手が 2 つある）"),
    _command("C4s", f"{API_PREFIX}/attention/<item_id>/snooze",
             H_attention.snooze_attention, ("I-2",),
             note="minutes 既定 30 / 上限 1440（本番の clamp と同一）"),
    _command("C4d", f"{API_PREFIX}/attention/<item_id>/dismiss",
             H_attention.dismiss_attention, ("I-2",),
             note="24h（本番の固定 TTL と同一）。行は消えず状態が付く"),
    _command("C4t", f"{API_PREFIX}/attention/thresholds",
             H_attention.set_thresholds, ("I-2",), method=PUT,
             note="G-02 の当事者。resolve は R6 の射影が呼ぶ関数そのもので、"
                  "commit の効果検証が『順位付けが読んでいる』ことの証明になる"),
    _command("C5a", f"{API_PREFIX}/proposals/<proposal_id>/apply",
             H_proposals.apply_proposal, ("I-2",)),
    _command("C5d", f"{API_PREFIX}/proposals/<proposal_id>/dismiss",
             H_proposals.dismiss_proposal, ("I-2",)),
    _command("C5f", f"{API_PREFIX}/proposals/<proposal_id>/defer",
             H_proposals.defer_proposal, ("I-2",),
             note="裁定要求 11: 本番の Defer は復活後 1 ティックで自動却下"
                  "される。v3 は parity 窓の手前で差分を作らないため保存"
                  "（§7-2 #82）"),
    _dry_run("C6", f"{API_PREFIX}/whatif", H_whatif.simulate, ("I-2",),
             note="反実仮想 1 系統。assemble + score を呼び L1 へ書かない。"
                  "POST だが side_effect=False — ReadContext が構造的に保証"),
    # ── WP-4.1g / P7 C13 — the auth family ──────────────────────────────
    _session("C13login", f"{API_PREFIX}/auth/login", H_auth.login, ("I-2",),
             cookies=CookiePolicy(emits=(REFRESH_COOKIE, CSRF_COOKIE),
                                  reason=_REFRESH_TRANSPORT),
             note="資格情報の検証とトークン対の発行。台帳へは書かない。"
                  "refresh token は本文ではなく httpOnly cookie で出す"),
    _session("C13refresh", f"{API_PREFIX}/auth/refresh", H_auth.refresh,
             ("I-2",),
             cookies=CookiePolicy(presents=(REFRESH_COOKIE,), csrf=True,
                                  reason=_REFRESH_TRANSPORT),
             note="役割は fold から再解決する（S1-SVC-005）。cookie と "
                  "X-CSRF-TOKEN の対が揃わなければハンドラに到達しない"),
    _command("C13logout", f"{API_PREFIX}/auth/logout", H_auth.logout,
             ("I-2",),
             access=Access.at_least(ROLE_VIEWER, reason=_SELF_SERVICE),
             cookies=CookiePolicy(emits=(REFRESH_COOKIE, CSRF_COOKIE),
                                  reason=_REFRESH_TRANSPORT),
             note="失効の床を動かす指令。読み手は principal_for。"
                  "同時に refresh cookie 対を消す（本番 unset_jwt_cookies）"),
    _command("C13password", f"{API_PREFIX}/auth/password",
             H_auth.change_password, ("I-2",),
             access=Access.at_least(ROLE_VIEWER, reason=_SELF_SERVICE),
             note="現行パスワードの検証つき。成功時に当人の全セッションが失効"),
    _command("C13register", f"{API_PREFIX}/auth/register", H_auth.register,
             ("I-2",),
             access=Access.at_least(ROLE_ADMIN, reason=_USER_ADMIN),
             note="識別子と最初の資格情報を 1 行で作る"),
    _read("C13users", f"{API_PREFIX}/auth/users", H_auth.read_users,
          ("I-2",),
          access=Access.at_least(ROLE_ADMIN, reason=_USER_ADMIN),
          note="資格情報は決して返さない（S1-SVC-008）"),
    _read("C13user", f"{API_PREFIX}/auth/users/<user_id>", H_auth.read_user,
          ("I-2",),
          access=Access.at_least(ROLE_ADMIN, reason=_USER_ADMIN)),
    _command("C13role", f"{API_PREFIX}/auth/users/<user_id>",
             H_auth.set_user_standing, ("I-2",), method=PUT,
             access=Access.at_least(ROLE_ADMIN, reason=_USER_ADMIN),
             note="自分自身は変更できない。発行済み access トークンは即時失効"),
    # ── WP-4.1g / P7 R11 + C3 — the intel queue ─────────────────────────
    _read("R11", f"{API_PREFIX}/intel", H_intel.read_intel, ("I-2",),
          access=Access.at_least(ROLE_ANALYST, reason=_INTEL_READ),
          note="LLM インテルの L1 観測 × 裁定 fold。NP7 envelope は"
               "他の全射影と同一（現行 /api/intel/pending/triage の欠落を解消）"),
    _command("C3c", f"{API_PREFIX}/intel/<item_id>/confirm",
             H_intel.confirm_intel, ("I-2",),
             note="pending キューから外れる（読み手は R11 の ?state=）"),
    _command("C3r", f"{API_PREFIX}/intel/<item_id>/reject",
             H_intel.reject_intel, ("I-2",),
             note="採点から外れる。読み手は observations_at — "
                  "『除外したのに除外されない』を作らないための配線"),
    _command("C3v", f"{API_PREFIX}/intel/<item_id>/revert",
             H_intel.revert_intel, ("I-2",),
             note="未裁定からの revert は拒否（本番は 0 行一致で成功を返す）"),
    _command("C13remove", f"{API_PREFIX}/auth/users/<user_id>",
             H_auth.remove_user, ("I-2",), method=DELETE,
             access=Access.at_least(ROLE_ADMIN, reason=_USER_ADMIN),
             note="無効化であって削除ではない。判断履歴は残る"),
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


__all__ = ["Route", "ROUTES", "SESSION_ROUTES", "DRY_RUN_ROUTES", "match", "by_id"]
