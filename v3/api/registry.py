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
    ATTENTION = "WP-3.3 (S8 注目台帳) + WP-4.1d"
    DECISIONS = "WP-3.3 (統一判断台帳) + WP-4.1d"
    INTEL = "WP-4.1d (インテルキュー読み取り)"
    PROPOSALS = "WP-4.1d (提案キュー統合)"
    CONFIG = "WP-4.1d (O-18 可変キーレジストリ)"
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
    Served("R12", "唯一の報告出力（結論 Markdown）", ("R12",)),
    Served("R15", "起動設定 / 死活 probe", ("R15c", "R15h")),
    # ── WP-4.1c: the command surface's first three ──────────────────────
    Served("C1", "focus 登録（読み取りの副作用から分離）", ("C1",)),
    Served("C2", "結論フィードバック投稿（G-01 の恒久化）", ("C2",)),
    Served("C9", "人手 ground truth（GET/POST）", ("C9g", "C9p")),
)

DEFERRED: tuple[Deferred, ...] = (
    Deferred("R6", "順位付き注目リスト（AP1）", Owner.ATTENTION,
             "S8 が順位を書く台帳が L1 に無い。フロントで再計算すると "
             "P5 O-8（台帳に残らない順位）を再生産するため、台帳の着地を待つ"),
    Deferred("R9", "統一判断台帳（AP4）", Owner.DECISIONS,
             "監査 5 面を 1 本化する先の decision 表が L1 に無い"),
    Deferred("R11", "インテルキュー読み取り", Owner.INTEL,
             "intel item は L1 の観測として落ちる（§4-2）が、キューの "
             "裁定状態を持つ表がまだ無い"),
    Deferred("R13", "統一提案キュー", Owner.PROPOSALS,
             "v3/calibration/proposals.py は提案を生成できるが、"
             "キューの永続化と裁定履歴が L1 に無い"),
    Deferred("R14", "O-18 可変キーの現在値", Owner.CONFIG,
             "可変キー 20〜30 の registry が v3 に未着地（§7-2 #52 の "
             "retire 条件と同一の依存）"),
    Deferred("C3", "インテル裁定 4 動詞", Owner.INTEL,
             "R11 と対。キューの裁定状態を持つ表が無く、確定した裁定を"
             "読み返す先が存在しない"),
    Deferred("C4", "注目 ack/snooze/dismiss + 閾値", Owner.ATTENTION,
             "R6 が未着地のため ack する対象そのものが射影されない。"
             "指令台帳は着地済（ack 状態は fold で表現できる）が、"
             "順位を書く S8 台帳が無い以上 ack は読み手のいない書込みになる"
             "（= G-15）。R6 と同時に着地させる"),
    Deferred("C5", "提案 apply/dismiss/defer", Owner.PROPOSALS,
             "阻害 2 件のうち 1 件は解消: 裁定履歴は指令台帳が持てる。"
             "残る 1 件は提案の同一性 — v3/calibration/proposals.py の "
             "Proposal は id を持たず、生成の入力 CalibrationEvidence を"
             "組み立てる側が未着地（WP-3.3）"),
    Deferred("C6", "反実仮想 1 系統", Owner.API_COMMANDS,
             "副作用の無い指令（side_effect=False の POST）として着地"
             "できるが、L2 カーネルを dry-run で呼ぶ入力組み立てが "
             "v3/runtime/reduce.py 側にあり、そこは 1,078 行で分割待ち。"
             "同一スライスで触ると分割と機能追加が混ざる"),
    Deferred("C7", "可変キーの変更・解除", Owner.CONFIG,
             "**着地させてはならない状態**: v3 の 3 層解決は "
             "v3/kernel/threshold.py の Threshold.registry_backed が "
             "legacy radar.config_layered に委譲して終端する。v3 側に "
             "override を書いても解決経路がそれを読まないため、"
             "commit の効果検証が必ず失敗する — つまり今 C7 を出すことは "
             "G-15 の再生産そのもの。解決経路を v3 に移す設計判断が先"),
    Deferred("C8", "ノイズ除外規則", Owner.SCORING_TICK,
             "消費者は採点ティック。規則を fold から読ませる配線が "
             "v3/runtime 側の変更（reduce.py の分割を含む）になる。"
             "配線前に出すと『除外したのに除外されない』"),
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
    "transport を出さなかった理由は依存ではなく**発行者が存在しない**こと: "
    "4 イベントのうち attention_update は R6（繰延）、notification_result は "
    "v3 に通知系が無く、sensor_status/conclusion_update の発行者は採点ティック"
    "（v3/runtime、reduce.py の 800 行分割を含む配線）。発行者ゼロのチャネルは"
    "「読み手のいない書込み」の鏡像であり、本 WP が C4/C7/C8 を繰延した理由と"
    "同じ規律で繰延する。flask-socketio は依存に存在するため技術的障害は無い")


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
