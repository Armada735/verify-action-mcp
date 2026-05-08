"""file_op verifier — claim about a filesystem operation vs evidence
(exists_before/after, line_count, size_bytes, path).
"""
from __future__ import annotations

import re


CREATE_VERBS = {"create", "created", "creates", "creating", "make", "made", "makes",
                "wrote", "writes", "write", "writing", "generate", "generated", "generates"}
DELETE_VERBS = {"delete", "deleted", "deletes", "deleting", "remove", "removed", "removes",
                "rm", "unlink", "unlinks"}
MODIFY_VERBS = {"modify", "modified", "modifies", "edit", "edited", "edits", "update", "updated",
                "updates", "patched", "patches", "rewrote", "rewrites"}
RENAME_VERBS = {"rename", "renamed", "renames", "renaming", "move", "moved", "moves"}

RX_PATH_LIKE = re.compile(r"(?:[/\w.-]+/)?[\w.-]+\.[\w]{1,8}|/[\w./-]+")
RX_NUM = re.compile(r"\b(\d+(?:\.\d+)?)\b")
SIZE_UNITS = {
    "b": 1, "byte": 1, "bytes": 1,
    "kb": 1024, "kib": 1024,
    "mb": 1024 ** 2, "mib": 1024 ** 2,
    "gb": 1024 ** 3, "gib": 1024 ** 3,
    "lines": "lines", "line": "lines", "rows": "lines",
}


def _classify(claim_lower: str) -> str:
    tokens = set(re.findall(r"[a-z]+", claim_lower))
    if tokens & CREATE_VERBS: return "create"
    if tokens & DELETE_VERBS: return "delete"
    if tokens & RENAME_VERBS: return "rename"
    if tokens & MODIFY_VERBS: return "modify"
    return "unknown"


def _extract_size_or_lines(claim_lower: str) -> dict:
    """Best-effort extract a numeric size or line count expectation from claim.
    Returns {'size_bytes': int|None, 'line_count': int|None}.
    """
    out = {"size_bytes": None, "line_count": None}
    # match "200 lines" / "12 KB" / "1.5 MB" patterns
    for m in re.finditer(r"\b(\d+(?:\.\d+)?)\s*([a-z]+)\b", claim_lower):
        n = float(m.group(1))
        unit = m.group(2)
        if unit in SIZE_UNITS:
            mult = SIZE_UNITS[unit]
            if mult == "lines":
                out["line_count"] = int(n)
            elif isinstance(mult, int):
                out["size_bytes"] = int(n * mult)
            break
    return out


def verify(claim: str, evidence: dict, context: str | None = None) -> dict:
    e = evidence or {}
    path_ev = e.get("path")
    exists_before = e.get("exists_before")
    exists_after = e.get("exists_after")
    line_count = e.get("line_count")
    size_bytes = e.get("size_bytes")
    new_path = e.get("new_path")

    claim_lower = claim.lower()
    action = _classify(claim_lower)

    pos: list[str] = []
    neg: list[str] = []

    # 1) Existence transition vs verb
    if isinstance(exists_before, bool) and isinstance(exists_after, bool):
        before, after = exists_before, exists_after
        if action == "create":
            if (not before) and after:
                pos.append("file did not exist before, exists after (matches creation)")
            elif before and after:
                neg.append("claim says 'create' but file existed before")
            elif (not before) and (not after):
                neg.append("claim says 'create' but file does not exist after either")
        elif action == "delete":
            if before and (not after):
                pos.append("file existed before, does not exist after (matches deletion)")
            elif (not before) and (not after):
                neg.append("claim says 'delete' but file did not exist before either")
            elif after:
                neg.append("claim says 'delete' but file still exists after")
        elif action == "modify":
            if before and after:
                pos.append("file existed before and after (consistent with modification)")
            elif not before:
                neg.append("claim says 'modify' but file did not exist before")
            elif not after:
                neg.append("claim says 'modify' but file does not exist after")
        elif action == "rename":
            if before and (not after):
                pos.append("original path no longer exists (consistent with rename)")
            elif not new_path:
                neg.append("claim says 'rename' but no new_path supplied")

    # 2) Path coherence
    if path_ev:
        path_str = str(path_ev)
        # Look for the path-tail in claim
        tail = path_str.rsplit("/", 1)[-1]
        if tail and tail in claim:
            pos.append(f"path tail '{tail}' present in claim")

    # 3) Numeric expectations from claim. Large divergence is DEFINITIVE.
    critical: list[str] = []
    expected = _extract_size_or_lines(claim_lower)
    if expected["line_count"] is not None and isinstance(line_count, int):
        exp = expected["line_count"]
        if exp == line_count:
            pos.append(f"line count matches: {line_count}")
        elif abs(exp - line_count) <= max(1, exp // 10):
            pos.append(f"line count close to claim ({line_count} vs expected ~{exp})")
        else:
            msg = f"line count {line_count} differs from claim's ~{exp}"
            # Definitive when off by >2x or >50 absolute
            if exp > 0 and (abs(line_count - exp) > exp * 0.5 or abs(line_count - exp) > 50):
                critical.append(msg)
            neg.append(msg)
    if expected["size_bytes"] is not None and isinstance(size_bytes, (int, float)):
        exp = expected["size_bytes"]
        if abs(int(size_bytes) - exp) <= max(100, exp // 10):
            pos.append(f"size {size_bytes}B close to claim's ~{exp}B")
        else:
            msg = f"size {size_bytes}B differs significantly from claim's ~{exp}B"
            if exp > 0 and abs(int(size_bytes) - exp) > exp * 0.5:
                critical.append(msg)
            neg.append(msg)

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
        reasoning_parts.append("Insufficient evidence; supply exists_before/after, path, line_count, or size_bytes.")
    reasoning = " | ".join(reasoning_parts)

    return {
        "verdict": verdict,
        "reasoning": reasoning[:1000],
        "confidence": round(confidence, 3),
        "verifier_used": "file_op_v1",
        "details": {
            "action_class": action,
            "evidence_path": path_ev,
            "exists_transition": [exists_before, exists_after],
            "expected": expected,
        },
    }
