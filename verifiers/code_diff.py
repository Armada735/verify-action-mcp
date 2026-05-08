"""code_diff verifier — claim about code changes vs unified-diff evidence.

Heuristic: extract entities (file paths, identifiers, action verbs) from claim,
then compare to what the diff actually touches. Returns ok/mismatch/uncertain.

Pure stdlib. No code execution.
"""
from __future__ import annotations

import re
from typing import Any


# ---- diff parsing ----------------------------------------------------

# Matches "diff --git a/path b/path" or "+++ b/path" header lines
RX_DIFF_HEADER = re.compile(r"^diff --git\s+a/(\S+)\s+b/(\S+)", re.MULTILINE)
RX_BPATH = re.compile(r"^\+\+\+\s+b/(\S+)", re.MULTILINE)
RX_AT_HUNK = re.compile(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@", re.MULTILINE)
RX_ADDED = re.compile(r"^\+(?!\+\+)(.*)$", re.MULTILINE)
RX_REMOVED = re.compile(r"^-(?!--)(.*)$", re.MULTILINE)

# claim → action verbs mapping
ADD_VERBS = {"add", "added", "adds", "adding", "introduce", "introduces", "create", "created", "creates",
             "implement", "implemented", "implements"}
REMOVE_VERBS = {"remove", "removed", "removes", "removing", "delete", "deleted", "deletes", "drop", "dropped"}
MODIFY_VERBS = {"modify", "modified", "modifies", "change", "changed", "changes", "update", "updated",
                "updates", "fix", "fixed", "fixes", "refactor", "refactored", "refactors", "rename", "rewrote",
                "rewrites", "edit", "edited", "patches", "patched"}
CHECK_VERBS = {"check", "checked", "validate", "validated", "guard", "ensure", "verify", "verified"}

# Known source-file extensions for path detection (avoids treating
# `user.email` and similar identifier-like dotted names as file paths)
_KNOWN_EXTS = (
    r"py|pyi|js|ts|tsx|jsx|mjs|cjs|go|rs|java|kt|swift|c|cpp|cc|cxx|h|hpp|"
    r"rb|php|cs|fs|ml|hs|scala|sql|sh|bash|zsh|fish|md|rst|adoc|"
    r"yml|yaml|toml|json|jsonc|xml|html|htm|css|scss|sass|less|"
    r"txt|csv|tsv|conf|ini|cfg|env|lock|log|tf|hcl|proto|graphql|"
    r"dockerfile|makefile|gitignore|gitattributes|gradle|pom"
)

RX_PATH = re.compile(
    r"(?:[a-zA-Z_][\w-]*/)*[a-zA-Z_][\w.-]*\.(?:" + _KNOWN_EXTS + r")\b",
    re.IGNORECASE,
)

# identifier: backtick-quoted, OR a dotted name, OR a sufficiently-long alnum.
RX_IDENT = re.compile(r"`([^`]+)`|[a-zA-Z_][a-zA-Z_0-9]*\.[a-zA-Z_][a-zA-Z_0-9.]*|[a-zA-Z_][a-zA-Z_0-9]{2,}")

# Common English / generic words that shouldn't be treated as code identifiers.
_IDENT_STOPWORDS = {
    "the", "and", "for", "with", "this", "that", "from", "into", "they",
    "have", "has", "was", "were", "are", "been", "being", "should", "would", "could",
    # action verbs
    "add", "added", "adds", "adding",
    "remove", "removed", "removes", "removing",
    "modify", "modified", "modifies",
    "delete", "deleted", "deletes",
    "create", "created", "creates",
    "update", "updated", "updates",
    "fix", "fixed", "fixes", "fixing",
    "check", "checked", "checks", "checking",
    "null", "true", "false", "none",
    "function", "method", "class", "module", "file", "files",
    "code", "test", "tests", "name", "value", "values",
    "before", "after", "where", "when", "while", "until",
}


def _parse_diff(diff: str) -> dict:
    files = set()
    for m in RX_BPATH.finditer(diff):
        files.add(m.group(1))
    for m in RX_DIFF_HEADER.finditer(diff):
        files.add(m.group(2))
    added_lines = [m.group(1) for m in RX_ADDED.finditer(diff)]
    removed_lines = [m.group(1) for m in RX_REMOVED.finditer(diff)]
    n_hunks = len(list(RX_AT_HUNK.finditer(diff)))
    return {
        "files": sorted(files),
        "n_files": len(files),
        "n_added_lines": len(added_lines),
        "n_removed_lines": len(removed_lines),
        "n_hunks": n_hunks,
        "added_text": "\n".join(added_lines)[:8000],
        "removed_text": "\n".join(removed_lines)[:8000],
    }


def _classify_action(claim_lower: str) -> str:
    """Return one of: 'add', 'remove', 'modify', 'check', 'unknown'."""
    tokens = set(re.findall(r"[a-z]+", claim_lower))
    if tokens & ADD_VERBS:
        return "add"
    if tokens & REMOVE_VERBS:
        return "remove"
    if tokens & CHECK_VERBS:
        return "check"
    if tokens & MODIFY_VERBS:
        return "modify"
    return "unknown"


def _extract_paths(claim: str) -> list[str]:
    paths = []
    for m in RX_PATH.finditer(claim):
        p = m.group(0)
        # Filter out very short hits and obvious noise
        if len(p) >= 4 and "." in p and not p.startswith("."):
            paths.append(p)
    return paths


def _extract_idents(claim: str) -> list[str]:
    out: list[str] = []
    for m in RX_IDENT.finditer(claim):
        s = m.group(1) if m.group(1) else m.group(0)
        if len(s) < 3:
            continue
        sl = s.lower()
        # Skip generic English / action-verb tokens
        if sl in _IDENT_STOPWORDS:
            continue
        # Skip if it's a path-like that the path extractor will already capture
        if RX_PATH.fullmatch(s) or RX_PATH.fullmatch(sl):
            continue
        out.append(s)
    return out


def verify(claim: str, evidence: dict, context: str | None = None) -> dict:
    """Compare a code-change claim to a unified diff."""
    diff = (evidence or {}).get("diff", "")
    if not isinstance(diff, str) or not diff.strip():
        return {
            "verdict": "uncertain",
            "reasoning": "No diff supplied in evidence; cannot verify code-change claim.",
            "confidence": 0.0,
            "verifier_used": "code_diff_v1",
        }

    parsed = _parse_diff(diff)
    claim_lower = claim.lower()
    action = _classify_action(claim_lower)
    claimed_paths = _extract_paths(claim)
    claimed_idents = _extract_idents(claim)

    pos_signals: list[str] = []
    neg_signals: list[str] = []
    critical_signals: list[str] = []

    # 1) Path coherence: claimed file mentioned in claim must appear in diff.
    # If NONE of the claimed paths appear in the diff, that's DEFINITIVE —
    # the change happened somewhere else than what the claim says.
    if claimed_paths:
        in_diff = [p for p in claimed_paths if any(p in f or f.endswith(p) for f in parsed["files"])]
        not_in_diff = [p for p in claimed_paths if p not in in_diff]
        if in_diff:
            pos_signals.append(f"claim references {len(in_diff)}/{len(claimed_paths)} paths actually in diff")
        if not_in_diff and not in_diff:
            critical_signals.append(
                f"none of the claimed paths {not_in_diff[:3]} appear in diff (diff touches {parsed['files']})"
            )
            neg_signals.append(critical_signals[-1])
        elif not_in_diff:
            neg_signals.append(f"claim references {len(not_in_diff)} path(s) not in diff: {not_in_diff[:3]}")

    # 2) Action verb coherence
    if action in ("add", "modify", "check"):
        if parsed["n_added_lines"] > 0:
            pos_signals.append(f"claim implies addition/modification; diff added {parsed['n_added_lines']} lines")
        else:
            neg_signals.append("claim implies addition but diff has no added lines")
    elif action == "remove":
        if parsed["n_removed_lines"] > parsed["n_added_lines"]:
            pos_signals.append("claim implies removal; diff removes more than it adds")
        elif parsed["n_added_lines"] > 0 and parsed["n_removed_lines"] == 0:
            neg_signals.append("claim implies removal but diff only adds")

    # 3) Identifier presence: claimed identifiers should appear somewhere in
    # the diff (added, removed, OR context — modifying X often surrounds X
    # with context lines rather than touching X itself).
    if claimed_idents:
        haystack = diff
        present = [i for i in claimed_idents if i in haystack]
        absent = [i for i in claimed_idents if i not in present]
        if present:
            pos_signals.append(f"{len(present)}/{len(claimed_idents)} identifier(s) present in diff")
        # Only flag "absent" as negative if NONE are present — otherwise the
        # presence of even one named entity is a stronger signal than the
        # absence of generic words.
        if absent and not present and len(claimed_idents) >= 2:
            neg_signals.append(f"none of the claimed identifiers found in diff: {absent[:3]}")

    # 4) Scope-creep heuristic: claim mentions one file but diff touches many
    if claimed_paths and parsed["n_files"] > 0:
        if len(claimed_paths) == 1 and parsed["n_files"] >= 3:
            neg_signals.append(
                f"scope mismatch: claim mentions 1 file but diff touches {parsed['n_files']} files"
            )

    # Verdict
    confidence = max(0.0, min(1.0, 0.5 + 0.1 * len(pos_signals) - 0.18 * len(neg_signals)))
    if critical_signals:
        verdict = "mismatch"
        confidence = max(confidence, 0.7)
    elif neg_signals and len(neg_signals) >= len(pos_signals):
        verdict = "mismatch"
    elif pos_signals and not neg_signals:
        verdict = "ok" if confidence >= 0.7 else "uncertain"
    elif not pos_signals and not neg_signals:
        verdict = "uncertain"
    else:
        verdict = "uncertain"

    reasoning_parts: list[str] = []
    if pos_signals:
        reasoning_parts.append("Coherent: " + "; ".join(pos_signals))
    if neg_signals:
        reasoning_parts.append("Inconsistent: " + "; ".join(neg_signals))
    if not reasoning_parts:
        reasoning_parts.append("No strong signals either way; rule-based verifier insufficient for this claim.")
    reasoning = " | ".join(reasoning_parts)

    return {
        "verdict": verdict,
        "reasoning": reasoning[:1000],
        "confidence": round(confidence, 3),
        "verifier_used": "code_diff_v1",
        "details": {
            "action_class": action,
            "files_in_diff": parsed["files"],
            "n_added_lines": parsed["n_added_lines"],
            "n_removed_lines": parsed["n_removed_lines"],
            "n_hunks": parsed["n_hunks"],
        },
    }
