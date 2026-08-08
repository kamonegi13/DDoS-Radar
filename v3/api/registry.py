"""The surface ledger: P7 §1 against what is actually served.

Same reason as `v3.conclusions.registry` and `v3.scoring.registry`. A
completion condition that reads "P7's surface is implemented" is
satisfiable by remembering wrong, so the partition is code: every P7
endpoint is either SERVED by a named route, or DEFERRED to a named work
package with a reason. The suite fails if the two stop covering P7's
list, which means a forgotten endpoint is a red build rather than a
discovery during cutover.

The duplicate-pair table is completion condition 2 in the same form.
S2-PROP-002..011 named ten v1/v2 pairs that returned the same information
in two shapes; each row here states the ONE v3 destination, and the test
asserts every pair has exactly one — because "unified" is otherwise a
claim about intent rather than about the table.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from v3.api import routes as R


class Owner:
    """Which work package owes a deferred part of the surface.

    WP-4.1c revised these. The old reason for most of the C family was
    「書込面」 — true but uninformative, and the write seam has landed, so
    it no longer explains anything. Each remaining entry now names the
    blocker that actually stops it, and for most of them the blocker is
    the same one: **the command would have no reader**. A command whose
    effect no projection shows is defect G-15 whatever its audit row says,
    so shipping one to raise a coverage number would be shipping the
    defect this work package exists to end.
    """

    API_COMMANDS = "WP-4.1g (L6: 指令面の残り)"
    # INTEL は WP-4.1g で解消（R11 / C3）。裁定状態は command_record の
    # fold であり、繰延理由だった「キューの裁定状態を持つ表」は作らずに
    # 済んだ — 表が要ると読んだこと自体が誤りだった。
    # ATTENTION / DECISIONS / PROPOSALS は WP-4.1f で解消（R6/C4, R9,
    # R13/C5 が着地）。CONFIG は WP-4.1d で解消（R14 / C7）。NARRATIVE も
    # WP-4.1f で解消（v3/attention/narrative.py が P7 §4 の唯一のエンジン）。
    # 誰も負っていないオーナー定数は残さない — 「誰かが負っている」の
    # 見た目だけが残るため。
    SCORING_TICK = "抑制規則の fold 配線 (v3/runtime)"
    HUMAN_ANCHOR = "較正アンカー経路 (出題器 + 回答の取り込み口)"
    SCENARIO_SOURCE = "シナリオ解決チェーン (geo_data.json を default 層に)"
    LLM_PATH = "LLM 投入経路 (v3/fetch/llm.py::submit の本番呼び手)"
    # AUTH は WP-4.1g で解消（C13 の 9 本が着地。利用者ストアは
    # command_record の fold で、第 2 の表は作らなかった）。
    NOTIFICATIONS = "WP-4.2 (通知スライス。v3 に通知系そのものが無い)"


@dataclass(frozen=True, slots=True)
class Served:
    p7_id: str
    summary: str
    route_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Deferred:
    p7_id: str
    summary: str
    owner: str
    reason: str


#: P7 §1.1 — the 15 read projections.
READ_SURFACE: tuple[str, ...] = (
    "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11",
    "R12", "R13", "R14", "R15")

#: P7 §1.2 — the 13 command families.
COMMAND_SURFACE: tuple[str, ...] = tuple(f"C{n}" for n in range(1, 14))

#: P7 §1.3 — the one channel's four events.
WS_EVENTS: tuple[str, ...] = ("conclusion_update", "attention_update",
                              "sensor_status", "notification_result")

P7_SURFACE: tuple[str, ...] = READ_SURFACE + COMMAND_SURFACE

SERVED: tuple[Served, ...] = (
    Served("R1", "シナリオ台帳 + focus + TL サマリ", ("R1",)),
    Served("R2", "5 結論型 + 結論不可 + ?at= 過去断面", ("R2",)),
    Served("R3", "TL 系列・トレンド窓・null-zone・慢性判定", ("R3",)),
    Served("R4", "結論単体 + 完全導出", ("R4", "R4d")),
    Served("R5", "兆候行列・抑制済み+理由・観測参照", ("R5",)),
    Served("R7", "合成信頼度 + 内訳（AP3）", ("R7",)),
    Served("R8", "センサー健全性の単一形 + 観測系列", ("R8", "R8o")),
    Served("R10", "閾値レジストリの現在値と出典", ("R10",)),
    Served("R14", "O-18 可変キーの現在値・出所層・読み手", ("R14",)),
    Served("R12", "唯一の報告出力（結論 Markdown）", ("R12",)),
    Served("R15", "起動設定 / 死活 probe", ("R15c", "R15h")),
    # ── WP-4.1c: the command surface's first three ──────────────────────
    Served("C1", "focus 登録（読み取りの副作用から分離）", ("C1",)),
    Served("C2", "結論フィードバック投稿（G-01 の恒久化）", ("C2",)),
    Served("C9", "人手 ground truth（GET/POST）", ("C9g", "C9p")),
    # ── WP-4.1d: the override layer, once it had a reader ───────────────
    Served("C7", "可変キーの変更・解除（POST/DELETE）", ("C7s", "C7d")),
    # ── WP-4.1f: the attention ledger, and everything it unblocked ──────
    # P7 R6 also says 「L5 の drift signal も注目行として合流」. There is
    # nothing to merge: v3 has no drift-signal family at all — P7 §5 sent
    # `drift_signals` x2 into R13/C5 and the L5 monitors into R7's
    # breakdown — so the ranked kind is `conclusion` alone. Stated here
    # rather than left as a quiet shortfall; a second `item_kind` is a row
    # in the same table when a drift family exists.
    Served("R6", "順位付き注目リスト（AP1、S8 台帳の射影。item_kind は "
                 "conclusion のみ — v3 に drift signal 族が無いため）",
           ("R6",)),
    Served("R9", "統一判断台帳（AP4）— 指令台帳 + 順位スナップショット",
           ("R9", "R9i")),
    Served("R13", "較正・センサー・シナリオ改善の統一提案キュー", ("R13",)),
    Served("C4", "注目 ack/snooze/dismiss + 利用者別閾値",
           ("C4a", "C4s", "C4d", "C4t")),
    Served("C5", "提案 apply/dismiss/defer", ("C5a", "C5d", "C5f")),
    Served("C6", "反実仮想 1 系統（L2 カーネルの dry-run）", ("C6",)),
    # ── WP-4.1g: the cutover precondition (§7-2 #99) ────────────────────
    # 9 routes, and the two that mint a session write no ledger row —
    # a session is a signed statement ABOUT the user fold, not a state
    # beside it. What IS ledger state (the revocation floor, the standing,
    # the credential) is the fold of `command_record` like everything
    # else here, so there is one mechanism and R9 already projects it.
    Served("R11", "インテルキュー読み取り（L1 観測 × 裁定 fold）。"
                  "NP7 envelope は他射影と同一", ("R11",)),
    Served("C3", "インテル裁定 3 動詞（confirm/reject/revert）。"
                 "override は §7-2 #104 で繰延 — 訂正を読む先が無い",
           ("C3c", "C3r", "C3v")),
    Served("C13", "auth 族 9 本（login/refresh/logout/register/password + "
                  "利用者 CRUD）。auth/settings は PROP-014 どおり持たない",
           ("C13login", "C13refresh", "C13logout", "C13password",
            "C13register", "C13users", "C13user", "C13role", "C13remove")),
)

DEFERRED: tuple[Deferred, ...] = (
    Deferred("C8", "ノイズ除外規則", Owner.SCORING_TICK,
             "消費者（採点ティック）は WP-4.1e で着地したが、それは阻害の"
             "片方でしかない。残るのは規則そのものを fold / gating に読ませる"
             "経路: v3/runtime/suppression.py は adapter 間の抑制しか持たず、"
             "指令台帳の除外規則を参照する辺が無い。配線前に出すと"
             "『除外したのに除外されない』。"
             "**WP-4.1g の注**: C3 の reject は同じ問いに答えを出した — "
             "`observations_at` が 1 辺で除外を効かせる。C8 はそれを"
             "「規則」（sensor × country × 期間のパターン）へ一般化する"
             "スライスであり、辺の位置は同じで済む"),
    Deferred("C10", "AP3 人間アンカー", Owner.HUMAN_ANCHOR,
             "**読み手ゼロ**（WP-4.1g で再確認）。回答を採点するのは較正の"
             "アンカー経路で、v3 にはまだ (a) 独立性を壊さない出題器"
             "（S1-UI-028）も (b) 回答を取り込む較正側の入口も無い。"
             "v3/calibration/ に anchor の語が 1 つも無いことが実測。"
             "受け取った回答が何にも影響しない指令は G-15 そのもの"),
    Deferred("C11", "シナリオ CRUD", Owner.SCENARIO_SOURCE,
             "**裁定（WP-4.1g）: 第 2 の供給源は作らない**。シナリオは"
             "合成ルート（v3/runtime/geo.py が geo_data.json を読む）が"
             "供給し、participants / weights は L2 の採点に直接入る。"
             "operator 可変にする正しい形は C7 と同じ 3 層解決"
             "（geo_data.json = default 層、command_record の fold = "
             "override 層）であり、第 2 の表でも第 2 の loader でもない。"
             "ただしそれは採点入力を動かすスライスであって API 面の"
             "スライスではないため、ここでは出さない。"
             "着地条件: v3/runtime/geo.py が resolver シームを受け取り、"
             "採点ティックがそれ経由でシナリオを組むこと"),
    Deferred("C12", "LLM 運用族", Owner.LLM_PATH,
             "**繰延理由を WP-4.1g で強化**。旧理由は「fold を読ませる配線"
             "が無い」だったが、実測はより単純だった: "
             "`v3/fetch/llm.py::submit` を呼ぶ本番経路が v3 に 1 つも無い"
             "（AST 実測。呼び手はテストのみ）。kill switch は歩かれない"
             "経路を止めるスイッチになる。LLM 投入経路そのものが着地する"
             "スライスで同時に出すのが正しい — `submit` は既に "
             "`available` 引数と `DISABLED` 結果を持っており、"
             "fold を読む辺はその 1 箇所で足りる"),
)


#: P7 §1.3's transport. WP-4.1f shipped it (`v3/api/ws_publish.py`) for the
#: three events that have a publisher; the fourth is registered here rather
#: than left as an absence, because 「黙って残す選択肢は存在しない」.
#:
#: The deferral is now ONE EVENT, not the channel. `emissions_for` derives
#: every payload from a `TickReport`, so what a client receives is also in
#: the tick's own record — the AP4 property the transport was waiting for,
#: and the reason it could not ship before the ranking existed.
WS_TRANSPORT: Deferred = Deferred(
    "WS.notification_result", "通知結果イベント", Owner.NOTIFICATIONS,
    "**チャネルは着地**（WP-4.1f、v3/api/ws_publish.py）。3/4 イベントは "
    "TickReport から導出される — conclusion_update / sensor_status は "
    "WP-4.1e の採点ティック配線、attention_update は WP-4.1f の S8 台帳。"
    "残る 1 件だけが依然として発行者ゼロで、しかも阻害は束縛ではない: "
    "**v3 に通知系そのものが存在しない**（Telegram 送出も、その結果を"
    "保持する表も無い）ため、報告すべき『結果』が無い。空で流すと"
    "「通知は成功した」と読めるため出さない。"
    "`ws_publish.UNPUBLISHED_EVENTS` がクライアント向けの同じ宣言で、"
    "PUBLISHED と合わせて ws.EVENTS を過不足なく分割する")


@dataclass(frozen=True, slots=True)
class DuplicatePair:
    """One of S2-PROP-002..011's v1/v2 pairs and its single v3 home."""

    proposal: str
    v1: str
    v2: str
    v3_route: Optional[str]
    disposition: str


#: Completion condition 2. `v3_route=None` means the pair collapsed to
#: NOTHING — P7 dropped both members with a reason, which is also "one
#: contract" (there is no second shape when there is no shape).
DUPLICATE_PAIRS: tuple[DuplicatePair, ...] = (
    DuplicatePair("PROP-002", "/api/cooccurrence",
                  "/api/v2/discovery/cooccurrence", None,
                  "両者 drop（凍結）。実消費者ゼロ（D6）。シナリオ発見は "
                  "価値実証後に R13 の提案 kind として再設計（P7 §5）"),
    DuplicatePair("PROP-003", "/api/history/threat_levels",
                  "/api/v2/scenarios/<sid>/threat_history", "R3",
                  "v1 は全シナリオ横断でシナリオ中心設計と非整合。"
                  "v2 側の envelope 欠陥は 1 envelope 化で同時に解消"),
    DuplicatePair("PROP-004", "/api/score_breakdown",
                  "/api/v2/conclusions/<id>/audit_trace", "R4d",
                  "NP6 の導出開示は結論単位。v1 は無参照（drop 済）"),
    DuplicatePair("PROP-005", "/api/analytics/calibration_advisory",
                  "/api/v2/calibration/health", "R7",
                  "自己評価の内訳ブロックへ吸収（P7 R7）"),
    DuplicatePair("PROP-006", "/api/analytics/confidence_distribution",
                  "(較正パイプライン内部)", "R7",
                  "endpoint を持たない。必要なら R7 の 1 ブロック"),
    DuplicatePair("PROP-007", "/api/sensor_reliability",
                  "/api/admin/sensor_health", "R8",
                  "同じセンサー健全性。認可 analyst なのにパスが admin "
                  "だった歪みも消える（R8 は viewer 開放）"),
    DuplicatePair("PROP-008", "/api/daily_summary", "/api/sitrep", "R12",
                  "報告 1 系統化。sitrep/daily/SALUTE/weather は P7 §5 で "
                  "drop、需要は R2+R12 が満たす"),
    DuplicatePair("PROP-009", "/api/whatif/simulate",
                  "/api/scenarios/<sid>/whatif_weights", "C6",
                  "反実仮想 1 系統（未実装・C6 として登録）"),
    DuplicatePair("PROP-010", "/api/v2/config_audit",
                  "/api/v2/llm_routing/audit", "R9",
                  "統一判断台帳へ（未実装・R9 として登録）"),
    DuplicatePair("PROP-011", "/api/threat_data",
                  "/api/v2/scenarios/<sid>/conclusions", "R2",
                  "最大の対。R1+R2+R5+R7+R8 の 5 射影へ分解（P7 §3）"),
)


def served_ids() -> frozenset:
    return frozenset(item.p7_id for item in SERVED)


def deferred_ids() -> frozenset:
    return frozenset(item.p7_id for item in DEFERRED)


def unaccounted() -> frozenset:
    """P7 entries claimed by neither list. Must be empty."""
    return frozenset(P7_SURFACE) - served_ids() - deferred_ids()


def double_counted() -> frozenset:
    return served_ids() & deferred_ids()


def coverage() -> dict:
    return {"p7_total": len(P7_SURFACE),
            "served": len(served_ids()),
            "deferred": len(deferred_ids()),
            "routes": len(R.ROUTES),
            "unaccounted": sorted(unaccounted())}


__all__ = ["SERVED", "DEFERRED", "WS_TRANSPORT", "DUPLICATE_PAIRS",
           "P7_SURFACE",
           "READ_SURFACE", "COMMAND_SURFACE", "WS_EVENTS", "Owner",
           "Served", "Deferred", "DuplicatePair", "served_ids",
           "deferred_ids", "unaccounted", "double_counted", "coverage"]
