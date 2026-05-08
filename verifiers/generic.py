"""generic verifier — fallback when no specialized kind dispatched.

Approach: extract named entities (numbers, identifiers, paths, emails, URLs)
from claim and evidence; flag mismatches when claim cites entities absent from
evidence. This is intentionally conservative — most outputs will be 'uncertain'.
"""
from __future__ import annotations

import json
import re

RX_NUMBER = re.compile(r"\b\d+(?:\.\d+)?\b")
RX_EMAIL = re.compile(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}")
RX_URL = re.compile(r"https?://[\w.-]+(?:/[\w./?=&%-]*)?")
RX_IDENT = re.compile(r"`([^`]+)`|[a-zA-Z_][a-zA-Z_0-9]{4,}")


def _flatten_evidence(ev) -> str:
    """Flatten evidence to a single searchable string."""
    if ev is None:
        return ""
    try:
        return json.dumps(ev, ensure_ascii=False, default=str)
    except Exception:
        return str(ev)


def _entities(text: str) -> dict:
    nums = set(RX_NUMBER.findall(text))
    emails = set(RX_EMAIL.findall(text))
    urls = set(m.group(0) for m in RX_URL.finditer(text))
    idents = set()
    for m in RX_IDENT.finditer(text):
        s = m.group(1) if m.group(1) else m.group(0)
        if len(s) >= 5 and not s.isdigit():
            # Filter common stopwords
            if s.lower() not in {"there", "their", "those", "these", "where", "after", "before", "until"}:
                idents.add(s)
    return {"nums": nums, "emails": emails, "urls": urls, "idents": idents}


def verify(claim: str, evidence, context: str | None = None) -> dict:
    ev_str = _flatten_evidence(evidence)
    claim_ents = _entities(claim)
    ev_ents = _entities(ev_str)

    pos: list[str] = []
    neg: list[str] = []

    for kind in ("emails", "urls", "nums", "idents"):
        c = claim_ents[kind]
        if not c:
            continue
        e = ev_ents[kind]
        common = c & e
        absent = c - e
        if common:
            pos.append(f"{kind}: {len(common)}/{len(c)} entities present in evidence")
        if absent and len(absent) > len(c) * 0.5:
            preview = sorted(absent)[:3]
            neg.append(f"{kind}: majority absent from evidence (e.g., {preview})")

    # Generic fallback is intentionally weak. Most cases → uncertain.
    if not pos and not neg:
        verdict = "uncertain"
        reasoning = (
            "Generic verifier insufficient for this kind of claim. "
            "Provide a specific 'kind' (code_diff / db_op / file_op / api_call) "
            "for stronger verification."
        )
        confidence = 0.2
    else:
        confidence = max(0.0, min(1.0, 0.45 + 0.1 * len(pos) - 0.18 * len(neg)))
        if neg and len(neg) >= len(pos):
            verdict = "mismatch"
        elif pos and not neg:
            verdict = "ok" if confidence >= 0.7 else "uncertain"
        else:
            verdict = "uncertain"
        reasoning_parts: list[str] = []
        if pos:
            reasoning_parts.append("Some entity matches: " + "; ".join(pos))
        if neg:
            reasoning_parts.append("Entity gaps: " + "; ".join(neg))
        reasoning = " | ".join(reasoning_parts)

    return {
        "verdict": verdict,
        "reasoning": reasoning[:1000],
        "confidence": round(confidence, 3),
        "verifier_used": "generic_v1",
        "details": {
            "claim_entity_counts": {k: len(v) for k, v in claim_ents.items()},
            "evidence_entity_counts": {k: len(v) for k, v in ev_ents.items()},
        },
    }
