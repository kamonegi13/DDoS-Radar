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
    """Which work package owes a deferred part of the surface."""

    API_COMMANDS = "WP-4.1c (L6: 指令面 C1-C13)"
    ATTENTION = "WP-3.3 (S8 注目台帳) + WP-4.1c"
    DECISIONS = "WP-3.3 (統一判断台帳) + WP-4.1c"
    INTEL = "WP-4.1c (インテルキュー読み取り)"
    PROPOSALS = "WP-4.1c (提案キュー統合)"
    CONFIG = "WP-4.1c (O-18 可変キーレジストリ)"
    NARRATIVE = "WP-4.1c (P7 §4 決定論ナラティブ)"
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
    Deferred("C1", "focus 登録", Owner.API_COMMANDS,
             "書込面。読み取り面（条件 1）を先に構造で閉じる方針"),
    Deferred("C2", "結論フィードバック投稿", Owner.API_COMMANDS,
             "ラベル台帳（WP-3.3）に依存"),
    Deferred("C3", "インテル裁定 4 動詞", Owner.API_COMMANDS, "R11 と対"),
    Deferred("C4", "注目 ack/snooze/dismiss + 閾値", Owner.API_COMMANDS,
             "R6 と対"),
    Deferred("C5", "提案 apply/dismiss/defer", Owner.API_COMMANDS,
             "R13 と対"),
    Deferred("C6", "反実仮想 1 系統", Owner.API_COMMANDS,
             "L2 カーネルの dry-run 呼び出し。書込面ではないが指令であり "
             "C 族としてまとめて着地させる"),
    Deferred("C7", "可変キーの変更・解除", Owner.API_COMMANDS, "R14 と対"),
    Deferred("C8", "ノイズ除外規則", Owner.API_COMMANDS, "書込面"),
    Deferred("C9", "人手 ground truth", Owner.API_COMMANDS,
             "S9 の教師信号。ラベル台帳（WP-3.3）に依存"),
    Deferred("C10", "AP3 人間アンカー", Owner.API_COMMANDS, "書込面"),
    Deferred("C11", "シナリオ CRUD", Owner.API_COMMANDS,
             "シナリオストア（WP-3.3）に依存"),
    Deferred("C12", "LLM 運用族", Owner.API_COMMANDS, "書込面"),
    Deferred("C13", "auth 族", Owner.API_COMMANDS,
             "principal の供給元。現状は binding が供給する形のみ定義"),
)


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


__all__ = ["SERVED", "DEFERRED", "DUPLICATE_PAIRS", "P7_SURFACE",
           "READ_SURFACE", "COMMAND_SURFACE", "WS_EVENTS", "Owner",
           "Served", "Deferred", "DuplicatePair", "served_ids",
           "deferred_ids", "unaccounted", "double_counted", "coverage"]
