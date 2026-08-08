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

    API_COMMANDS = "WP-4.1d (L6: 指令面の残り)"
    ATTENTION = "WP-3.3b (S8 注目台帳) + WP-4.1d"
    DECISIONS = "WP-4.1d (統一判断台帳の射影)"
    INTEL = "WP-4.1d (インテルキュー読み取り)"
    PROPOSALS = "WP-4.1d (提案キュー統合)"
    # CONFIG は WP-4.1d で解消（R14 / C7 が着地）。オーナー定数を残すと
    # 「誰かが負っている」の見た目だけが残るため削除する。
    NARRATIVE = "WP-4.1d (P7 §4 決定論ナラティブ)"
    SCORING_TICK = "WP-4.1d + 採点ティック配線 (v3/runtime)"
    AUTH = "WP-4.1d (認証・利用者ストア)"
    FRONTEND = "WP-4.2 (L7 フロントエンド)"


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
)

DEFERRED: tuple[Deferred, ...] = (
    Deferred("R6", "順位付き注目リスト（AP1）", Owner.ATTENTION,
             "**未着手**。WP-3.3 は較正台帳 2 面（ラベル・提案）を出したが "
             "S8 注目台帳は出していない。順位を書く表が L1 に無い状態は "
             "変わらず、フロントで再計算すると P5 O-8（台帳に残らない順位）"
             "を再生産する。attention_score の入力（novelty / "
             "confidence_delta / analyst_blindness）はいずれも L1 の既存表"
             "から導けるため、阻害は設計ではなく単純に未実装"),
    Deferred("R9", "統一判断台帳（AP4）", Owner.DECISIONS,
             "**供給側は 5 面中 4 面が揃った**（WP-3.3）: focus / label / "
             "config / ground_truth に加えて提案裁定が command_record に載り、"
             "v3/commands/state.py::proposal_history が 1 提案の時系列を返す。"
             "**decision 表を新設する必要は無い** — command_record が既に"
             "統一台帳であり、R9 は複数 target_kind を跨ぐ 1 射影で足りる。"
             "残る阻害は 5 面目（R6 の注目 ack）と、射影ハンドラそのもの"),
    Deferred("R11", "インテルキュー読み取り", Owner.INTEL,
             "intel item は L1 の観測として落ちる（§4-2）が、キューの "
             "裁定状態を持つ表がまだ無い"),
    Deferred("R13", "統一提案キュー", Owner.PROPOSALS,
             "**阻害は解消**（WP-3.3）: calibration_proposal 表が着地し、"
             "v3/calibration/queue.py::entries が「発行行 + 畳んだ状態 + "
             "裁定履歴」を返す。?at= 過去断面も同じ 1 射影で答える。"
             "残るのは L6 のルート束縛とレスポンス語彙のみで、"
             "読み手不在ではなくなった"),
    Deferred("C3", "インテル裁定 4 動詞", Owner.INTEL,
             "R11 と対。キューの裁定状態を持つ表が無く、確定した裁定を"
             "読み返す先が存在しない"),
    Deferred("C4", "注目 ack/snooze/dismiss + 閾値", Owner.ATTENTION,
             "R6 が未着地のため ack する対象そのものが射影されない。"
             "指令台帳は着地済（ack 状態は fold で表現できる）が、"
             "順位を書く S8 台帳が無い以上 ack は読み手のいない書込みになる"
             "（= G-15）。R6 と同時に着地させる"),
    Deferred("C5", "提案 apply/dismiss/defer", Owner.PROPOSALS,
             "**阻害 2 件とも解消**（WP-3.3）: ①同一性は "
             "lifecycle.proposal_id_for（epoch を含む決定論的 id）②生成入力 "
             "CalibrationEvidence は labels.evidence_for が L1 から組む。"
             "遷移関数（resolve_proposal / apply_proposal_*）も "
             "v3/commands/state.py に着地済で、読み手（R13）も存在する。"
             "残るのは CommandSpec 登録とルート束縛 = L6 スライスのみ"),
    Deferred("C6", "反実仮想 1 系統", Owner.API_COMMANDS,
             "**入力組み立ての阻害は解消**（WP-4.1e）: "
             "v3/runtime/scoring.py::assemble が ScoringInputs を採点ティック"
             "外で構成し、settings を引数で受ける純関数境界を持つ。反実仮想は "
             "assemble(..., settings=<別値>) + score() で、L1 へ 1 行も書かない"
             "（test_runtime_scoring_wiring.py が実証）。残るのは L6 側だけ — "
             "side_effect=False の POST ハンドラと、どの値を反実仮想の対象に"
             "許すかの語彙。分割・配線ではなく API スライス"),
    Deferred("C8", "ノイズ除外規則", Owner.SCORING_TICK,
             "消費者（採点ティック）は WP-4.1e で着地したが、それは阻害の"
             "片方でしかない。残るのは規則そのものを fold / gating に読ませる"
             "経路: v3/runtime/suppression.py は adapter 間の抑制しか持たず、"
             "指令台帳の除外規則を参照する辺が無い。配線前に出すと"
             "『除外したのに除外されない』"),
    Deferred("C10", "AP3 人間アンカー", Owner.API_COMMANDS,
             "設問の生成側（S1-UI-028 の独立性を壊さない出題）が未着地。"
             "回答だけ受け取っても採点されない"),
    Deferred("C11", "シナリオ CRUD", Owner.API_COMMANDS,
             "シナリオは合成ルート（v3/runtime/geo.py）が供給する。"
             "指令台帳を第 2 の供給源にすると 2 系統が乖離する"),
    Deferred("C12", "LLM 運用族", Owner.API_COMMANDS,
             "kill switch は NP3 上重要だが、消費者は v3/fetch/llm.py。"
             "fold を読ませる配線が無い状態で出すと"
             "『止めたのに止まらない』"),
    Deferred("C13", "auth 族", Owner.AUTH,
             "principal の供給元。利用者ストアとパスワード機構は"
             "この面より大きく、単独スライスが適切"),
)


#: P7 §1.3's transport, registered as deferred rather than left as an
#: absence. WP-4.1c examined it and declined; the reason is here so the
#: decline is reviewable (「黙って残す選択肢は存在しない」).
WS_TRANSPORT: Deferred = Deferred(
    "WS", "1 チャネル 4 イベントの socket 層", Owner.FRONTEND,
    "語彙（v3/api/ws.py）は着地済で、`theater` 系イベントは既に消えている。"
    "transport を出さなかった理由は依存ではなく**発行者が存在しない**こと。"
    "**4 イベント中 2 件は解消**（WP-4.1e）: 採点ティックが配線され "
    "(v3/runtime/tick.py::score_cycle)、TickReport が scenario 毎の "
    "ScoringResult と InputHealth を返すので conclusion_update / "
    "sensor_status には発行者がある。残る 2 件は依然として発行者ゼロ — "
    "attention_update は R6（WP-3.3 の S8 注目台帳）、notification_result は "
    "v3 に通知系そのものが無い。半分だけ発行するチャネルは"
    "「4 イベント契約」を満たさないため、R6 の着地と同時に出す。"
    "flask-socketio は依存に存在するため技術的障害は無い")


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
