#!/usr/bin/env python3
"""verify_action — top-level dispatcher and CLI for the verify_action tool.

Phase A — pure stdlib, no LLM, no network. Each kind has a specialized
rule-based verifier in ./verifiers/. Generic fallback when kind unknown.

Public API:
    from verifier import verify
    result = verify(claim, evidence, kind="code_diff", context=None)

CLI:
    echo '{"claim":"...","evidence":{...}}' | python3 verifier.py
    python3 verifier.py --json '{"claim":"...","evidence":{...},"kind":"db_op"}'
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from typing import Any

from verifiers import code_diff as _code_diff
from verifiers import db_op as _db_op
from verifiers import file_op as _file_op
from verifiers import api_call as _api_call
from verifiers import generic as _generic


VERIFIER_VERSION = "0.2.0"  # bumped for AAR receipt emission

VERIFIERS = {
    "code_diff": _code_diff.verify,
    "db_op": _db_op.verify,
    "file_op": _file_op.verify,
    "api_call": _api_call.verify,
    "generic": _generic.verify,
}


def _utc_iso() -> str:
    return _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _infer_kind(claim: str, evidence: Any) -> str:
    """Heuristic: pick a kind based on evidence shape and claim words."""
    if not isinstance(evidence, dict):
        return "generic"
    e = evidence
    # Strong signals
    if "diff" in e and isinstance(e.get("diff"), str):
        return "code_diff"
    if any(k in e for k in ("before_count", "after_count", "operation", "affected_rows")):
        return "db_op"
    if any(k in e for k in ("exists_before", "exists_after", "line_count", "size_bytes")) \
            or ("path" in e and ("line_count" in e or "size_bytes" in e or "exists_after" in e)):
        return "file_op"
    if any(k in e for k in ("response_status", "response_body", "request")):
        return "api_call"
    # Weak: verbs in claim (English + JP stems)
    cl = (claim or "").lower()
    has_db_evidence = any(k in e for k in ("operation", "before_count", "after_count", "affected_rows"))
    if any(t in cl for t in ("delete", "deleted", "insert", "inserted", "update")):
        return "db_op" if has_db_evidence else "generic"
    if any(t in (claim or "") for t in ("削除", "作成", "更新", "挿入", "追加", "変更", "消去")):
        return "db_op" if has_db_evidence else "generic"
    return "generic"


def verify(
    claim: str,
    evidence: Any,
    kind: str | None = None,
    context: str | None = None,
) -> dict:
    """Dispatch to the appropriate verifier and return a uniform result."""
    if not isinstance(claim, str) or not claim.strip():
        return {
            "verdict": "uncertain",
            "reasoning": "Empty claim; nothing to verify.",
            "confidence": 0.0,
            "verifier_used": "none",
            "verifier_version": VERIFIER_VERSION,
            "verified_at": _utc_iso(),
        }
    chosen = (kind or _infer_kind(claim, evidence) or "generic").lower()
    if chosen not in VERIFIERS:
        chosen = "generic"
    fn = VERIFIERS[chosen]
    try:
        result = fn(claim, evidence, context)
    except Exception as e:
        return {
            "verdict": "uncertain",
            "reasoning": f"Verifier '{chosen}' raised an exception ({type(e).__name__}); treat as uncertain.",
            "confidence": 0.0,
            "verifier_used": f"{chosen}_v1",
            "verifier_version": VERIFIER_VERSION,
            "verified_at": _utc_iso(),
        }
    # Always stamp metadata
    if "verifier_version" not in result:
        result["verifier_version"] = VERIFIER_VERSION
    result["kind_dispatched"] = chosen
    result["verified_at"] = _utc_iso()
    return result


# ====== CLI ======

def _cli(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="verify_action — third-party agent action verification (Phase A)",
    )
    parser.add_argument("--json", help="JSON object {claim, evidence, kind?, context?}")
    parser.add_argument("--claim", help="The claim string (alternative to --json)")
    parser.add_argument("--evidence-file", help="Path to JSON file with evidence (use with --claim)")
    parser.add_argument("--kind", default=None, help="Optional kind override")
    parser.add_argument("--context", default=None, help="Optional context string")
    args = parser.parse_args(argv)

    if args.json:
        try:
            payload = json.loads(args.json)
        except json.JSONDecodeError as e:
            sys.stderr.write(f"Invalid JSON: {e}\n")
            return 2
        claim = payload.get("claim")
        evidence = payload.get("evidence")
        kind = payload.get("kind") or args.kind
        context = payload.get("context") or args.context
    elif args.claim:
        claim = args.claim
        evidence = {}
        if args.evidence_file:
            try:
                evidence = json.loads(open(args.evidence_file, encoding="utf-8").read())
            except Exception as e:
                sys.stderr.write(f"Couldn't read evidence file: {e}\n")
                return 2
        kind = args.kind
        context = args.context
    else:
        # Read JSON from stdin
        try:
            payload = json.loads(sys.stdin.read())
        except json.JSONDecodeError as e:
            sys.stderr.write(f"No --json/--claim and stdin not valid JSON: {e}\n")
            return 2
        claim = payload.get("claim")
        evidence = payload.get("evidence")
        kind = payload.get("kind") or args.kind
        context = payload.get("context") or args.context

    result = verify(claim, evidence, kind=kind, context=context)
    sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
