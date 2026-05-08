"""db_op verifier — claim about a database operation vs evidence (row counts, SQL, etc.).

Pure stdlib, no DB connection. Compares row-count deltas and SQL operation kind
against the natural-language claim.
"""
from __future__ import annotations

import re


# Verb → expected row-count direction
VERB_TO_DIR = {
    # delete: count should decrease
    "delete": -1, "deleted": -1, "deletes": -1, "deleting": -1,
    "remove": -1, "removed": -1, "removes": -1,
    "drop": -1, "dropped": -1, "drops": -1,
    # insert/create: count should increase
    "insert": +1, "inserted": +1, "inserts": +1, "inserting": +1,
    "create": +1, "created": +1, "creates": +1, "creating": +1,
    "add": +1, "added": +1, "adds": +1, "adding": +1,
    # update: count typically unchanged
    "update": 0, "updated": 0, "updates": 0, "updating": 0,
    "modify": 0, "modified": 0, "modifies": 0,
    "change": 0, "changed": 0, "changes": 0,
    "set": 0,
}

# JP verb stems → (normalized English verb, direction). Stem-based so we
# match 削除した / 削除しました / 削除し / 削除中 etc. by substring presence.
# Order matters: longer / more specific stems first to avoid weak matches.
JP_VERB_PATTERNS: list[tuple[str, str, int]] = [
    # delete (-1)
    ("削除", "deleted", -1),
    ("消去", "deleted", -1),
    ("抹消", "deleted", -1),
    # insert / create (+1)
    ("作成", "created", +1),
    ("生成", "created", +1),
    ("新規", "created", +1),
    ("追加", "added", +1),
    ("挿入", "inserted", +1),
    # update (0)
    ("更新", "updated", 0),
    ("変更", "updated", 0),
    ("編集", "updated", 0),
    ("修正", "updated", 0),
    # send (0) — covered for api_call but harmless here
    ("送信", "sent", 0),
    ("発行", "sent", 0),
    ("送付", "sent", 0),
]

RX_TABLE_FROM_CLAIM = re.compile(
    r"\b(?:from|in|to|on|table|of|of\s+the)\s+([a-zA-Z_][\w]*)",
    re.IGNORECASE,
)
# Numeric identifier extraction.
# - `id=N` / `id: N` / `id N` (any digit count)
# - `user N` / `row N` / `item N` / `record N` / `customer N` / `account N` / `order N`
#   (any digit count — handles single-digit IDs in claim text like "deleted user 1")
# - Standalone 2+ digit numbers (avoids noise from row counts like "1 row affected")
RX_NUMERIC_ID = re.compile(
    r"\b(?:id\s*[=:]?\s*|(?:user|row|item|record|customer|account|order)[\s_]+)(\d+)"
    r"|\b(\d{2,})\b",
    re.IGNORECASE,
)


def _claim_classify(claim_lower: str, claim_orig: str = "") -> tuple[str, int]:
    """Return (verb, expected row delta direction). 'unknown' if no verb found.

    Tries ASCII tokens first (English verb dictionary), then falls back to
    Japanese stem matching on the original (non-lowered) claim.
    """
    tokens = re.findall(r"[a-z]+", claim_lower)
    for t in tokens:
        if t in VERB_TO_DIR:
            return t, VERB_TO_DIR[t]
    # JP fallback: scan the original claim for verb stems.
    target = claim_orig or claim_lower
    for stem, normalized_verb, direction in JP_VERB_PATTERNS:
        if stem in target:
            return normalized_verb, direction
    return "unknown", 0


def _classify_sql(sql: str) -> str:
    """Return 'delete' / 'insert' / 'update' / 'select' / 'unknown' from raw SQL."""
    if not sql:
        return "unknown"
    head = sql.strip().split()[0].lower() if sql.strip() else ""
    if head in {"delete", "insert", "update", "select"}:
        return head
    return "unknown"


SQL_TO_DIR = {"delete": -1, "insert": +1, "update": 0, "select": 0, "unknown": None}


def verify(claim: str, evidence: dict, context: str | None = None) -> dict:
    e = evidence or {}
    before = e.get("before_count")
    after = e.get("after_count")
    affected = e.get("affected_rows")
    op_text = (e.get("operation") or "").strip()
    sql_kind = _classify_sql(op_text)

    claim_lower = claim.lower()
    verb, expected_dir = _claim_classify(claim_lower, claim)

    pos: list[str] = []
    neg: list[str] = []

    # 1) Row-count delta vs claim verb direction
    delta: int | None = None
    if isinstance(before, (int, float)) and isinstance(after, (int, float)):
        delta = int(after - before)
        if expected_dir > 0 and delta > 0:
            pos.append(f"row count rose by {delta} (claim implies insertion)")
        elif expected_dir < 0 and delta < 0:
            pos.append(f"row count fell by {abs(delta)} (claim implies deletion)")
        elif expected_dir == 0 and delta == 0:
            pos.append("row count unchanged (claim implies update)")
        elif expected_dir != 0 and delta == 0:
            neg.append(f"claim implies count change but row count is unchanged (before={before}, after={after})")
        elif (expected_dir > 0 and delta < 0) or (expected_dir < 0 and delta > 0):
            neg.append(
                f"row-count direction contradicts claim verb '{verb}' (delta={delta})"
            )

    # 2) SQL kind matches claim verb
    if sql_kind != "unknown" and verb != "unknown":
        sql_dir = SQL_TO_DIR[sql_kind]
        if sql_dir is not None and sql_dir == expected_dir:
            pos.append(f"SQL operation '{sql_kind.upper()}' matches claim verb '{verb}'")
        elif sql_dir is not None and sql_dir != expected_dir:
            neg.append(
                f"SQL operation '{sql_kind.upper()}' contradicts claim verb '{verb}'"
            )

    # 3) affected_rows sanity
    if isinstance(affected, (int, float)):
        if affected == 0 and expected_dir != 0:
            neg.append(f"affected_rows=0 contradicts claim implying change")
        if delta is not None and expected_dir != 0:
            if abs(delta) != int(abs(affected)) and (expected_dir > 0 or expected_dir < 0):
                # Loose check — affected_rows might equal the change
                neg.append(
                    f"affected_rows={affected} doesn't match row-count delta={delta}"
                )

    # 4) Identifier coherence: numeric id in claim vs SQL.
    # ID mismatch is DEFINITIVE — operation may have succeeded but on the wrong row.
    critical: list[str] = []
    claim_ids = set(filter(None, sum([(a or '', b or '') for a, b in RX_NUMERIC_ID.findall(claim)], ())))
    sql_ids = set(filter(None, sum([(a or '', b or '') for a, b in RX_NUMERIC_ID.findall(op_text)], ())))
    if claim_ids and sql_ids:
        common = claim_ids & sql_ids
        if common:
            pos.append(f"identifier(s) match between claim and SQL: {sorted(common)[:3]}")
        else:
            critical.append(
                f"claim id(s) {sorted(claim_ids)[:3]} not in SQL id(s) {sorted(sql_ids)[:3]}"
            )
            neg.append(critical[-1])

    # Verdict
    confidence = max(0.0, min(1.0, 0.5 + 0.12 * len(pos) - 0.18 * len(neg)))
    if critical:
        verdict = "mismatch"
        confidence = max(confidence, 0.7)
    elif neg and len(neg) >= len(pos):
        verdict = "mismatch"
    elif pos and not neg:
        verdict = "ok" if confidence >= 0.7 else "uncertain"
    elif not pos and not neg:
        verdict = "uncertain"
    else:
        verdict = "uncertain"

    reasoning_parts: list[str] = []
    if pos:
        reasoning_parts.append("Coherent: " + "; ".join(pos))
    if neg:
        reasoning_parts.append("Inconsistent: " + "; ".join(neg))
    if not reasoning_parts:
        reasoning_parts.append(
            "Insufficient evidence (no row counts and no SQL op) to verify a DB-op claim."
        )
    reasoning = " | ".join(reasoning_parts)

    return {
        "verdict": verdict,
        "reasoning": reasoning[:1000],
        "confidence": round(confidence, 3),
        "verifier_used": "db_op_v1",
        "details": {
            "claim_verb": verb,
            "expected_direction": expected_dir,
            "sql_kind": sql_kind,
            "row_delta": delta,
            "affected_rows": affected,
        },
    }
