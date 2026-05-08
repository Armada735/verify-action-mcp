"""api_call verifier — claim about an HTTP API call vs request/response evidence."""
from __future__ import annotations

import re


SUCCESS_VERBS = {"sent", "send", "sends", "posted", "posts", "created", "creates",
                 "submitted", "succeeded", "succeed", "succeeds", "successful",
                 "completed", "completes", "delivered", "delivers", "received"}
FAILURE_VERBS = {"failed", "fails", "fail", "errored", "errors", "rejected", "rejects",
                 "denied", "denies", "blocked"}

SUCCESS_BODY_HINTS = {"sent", "ok", "success", "completed", "delivered", "succeeded", "true", "200"}
FAILURE_BODY_HINTS = {"error", "failed", "rejected", "denied", "invalid", "false", "unauthorized"}

RX_TOKEN = re.compile(r"[\w.@+-]+")
RX_EMAIL = re.compile(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}")
RX_URL = re.compile(r"https?://[\w.-]+(/[\w./?=&%-]*)?")


def _classify(claim_lower: str) -> str:
    tokens = set(re.findall(r"[a-z]+", claim_lower))
    if tokens & SUCCESS_VERBS: return "success"
    if tokens & FAILURE_VERBS: return "failure"
    return "unknown"


def _body_signal(body) -> str:
    """Look at response body for hints. Returns 'success' / 'failure' / 'unknown'."""
    if body is None:
        return "unknown"
    s = str(body).lower()
    if any(h in s for h in FAILURE_BODY_HINTS):
        return "failure"
    if any(h in s for h in SUCCESS_BODY_HINTS):
        return "success"
    return "unknown"


def verify(claim: str, evidence: dict, context: str | None = None) -> dict:
    e = evidence or {}
    request = e.get("request") or {}
    response_status = e.get("response_status")
    response_body = e.get("response_body")

    claim_lower = claim.lower()
    intent = _classify(claim_lower)

    pos: list[str] = []
    neg: list[str] = []

    # 1) HTTP status alignment
    if isinstance(response_status, int):
        is_2xx = 200 <= response_status < 300
        is_4xx = 400 <= response_status < 500
        is_5xx = 500 <= response_status < 600
        if intent == "success" and is_2xx:
            pos.append(f"HTTP {response_status} OK (claim implies success)")
        elif intent == "success" and (is_4xx or is_5xx):
            neg.append(f"claim implies success but HTTP {response_status}")
        elif intent == "failure" and (is_4xx or is_5xx):
            pos.append(f"HTTP {response_status} (claim implies failure)")
        elif intent == "failure" and is_2xx:
            neg.append(f"claim implies failure but HTTP {response_status} OK")

    # 2) Response body keyword alignment
    body_sig = _body_signal(response_body)
    if intent == "success" and body_sig == "success":
        pos.append("response body indicates success")
    elif intent == "success" and body_sig == "failure":
        neg.append("response body indicates failure (e.g., 'error' / 'denied') despite claim of success")
    elif intent == "failure" and body_sig == "failure":
        pos.append("response body indicates failure")

    # 3) Target coherence: emails / URLs in claim vs request
    request_str = ""
    if isinstance(request, dict):
        try:
            import json as _j
            request_str = _j.dumps(request, ensure_ascii=False)
        except Exception:
            request_str = str(request)
    elif request is not None:
        request_str = str(request)

    # Target email/URL mismatch is DEFINITIVE — operation went somewhere else.
    critical: list[str] = []
    claim_emails = set(RX_EMAIL.findall(claim))
    req_emails = set(RX_EMAIL.findall(request_str))
    if claim_emails:
        if claim_emails & req_emails:
            pos.append(f"email target matches: {sorted(claim_emails & req_emails)[:2]}")
        else:
            msg = f"email in claim {sorted(claim_emails)[:2]} not in request {sorted(req_emails)[:2]}"
            critical.append(msg)
            neg.append(msg)

    claim_urls = set(m.group(0) for m in RX_URL.finditer(claim))
    req_urls = set(m.group(0) for m in RX_URL.finditer(request_str))
    if claim_urls:
        if claim_urls & req_urls:
            pos.append("URL target matches between claim and request")

    # Verdict
    confidence = max(0.0, min(1.0, 0.5 + 0.13 * len(pos) - 0.18 * len(neg)))
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
        reasoning_parts.append("Insufficient evidence; supply response_status and response_body at minimum.")
    reasoning = " | ".join(reasoning_parts)

    return {
        "verdict": verdict,
        "reasoning": reasoning[:1000],
        "confidence": round(confidence, 3),
        "verifier_used": "api_call_v1",
        "details": {
            "claim_intent": intent,
            "response_status": response_status,
            "body_signal": body_sig,
        },
    }
