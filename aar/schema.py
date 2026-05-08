"""AAR receipt schema (verify_action_receipt.v0).

Design notes (from chisiki q043 + synthesis_v2_q039-q047):
- Content-addressed: claim and evidence referenced only by SHA-256 hash. The
  verifier computes the hash; receipt holders can re-verify if they hold the
  raw values.
- 4-value verdict: includes `insufficient_evidence` as a first-class output
  (Q047 verification asymmetry — refusing to claim certainty is information,
  not failure).
- Reason codes are free-form strings; conventions are documented but not
  enforced at v0. A future v1 may catalogue allowed codes.
- Signing: HMAC-SHA256 with a server-side secret. Symmetric, single-issuer.
  Every receipt carries a `kid` (key id) so rotation does not break the schema;
  v0 ships with `kid="v0-default"`. Upgrade path to ed25519 asymmetric signing
  + multi-issuer is documented in SCHEMA_UPGRADES.md.
- Schema versioning: every receipt carries `"schema": "verify_action_receipt.v0"`.
  Consumers MUST reject receipts with unknown schema strings.

The Python module is pure stdlib (hashlib + hmac + json + secrets).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
from typing import Any


# === Constants ===

SCHEMA_NAME = "verify_action_receipt"
SCHEMA_VERSION = "v0"
SCHEMA_FULL = f"{SCHEMA_NAME}.{SCHEMA_VERSION}"

# Default kid for v0 single-key deployments. Operators rotating keys SHOULD
# pass a fresh kid (e.g. "v0-2026-05") so verifiers can pick the right secret.
DEFAULT_KID = "v0-default"

# Default issuer string. Self-describing so receipts make sense without a
# domain binding; operators MAY override per deployment (e.g. once a stable
# domain is provisioned, switch to a did:web identifier).
DEFAULT_ISSUER = "aar:reference-impl@v0"

# 4-value verdict enum. `insufficient_evidence` is intentionally distinct from
# `unsafe_to_verify` — the former means "the verifier examined the evidence
# and could not reach a determination", the latter means "the verifier did not
# attempt or could not begin verification (malformed input, error, out of scope)".
VERDICTS = (
    "verified",            # claim matches evidence (high confidence)
    "contradicted",        # evidence directly contradicts claim
    "insufficient_evidence",  # examined but inconclusive (Q047 asymmetry primitive)
    "unsafe_to_verify",    # could not attempt (input error / out of scope)
)

# Allowed `verifier_method` values for the v0 reference implementation. Other
# verifiers may add their own methods using the `<verifier_id>.<method>` shape.
ALLOWED_VERIFIER_METHODS = (
    "rule_based.code_diff",
    "rule_based.db_op",
    "rule_based.file_op",
    "rule_based.api_call",
    "rule_based.generic",
    "rule_based.unknown",
    "pii_guard.rejected",   # PII guard rejected; not a verification per se
)


# Map from existing 02 verifier verdicts to AAR verdict enum.
LEGACY_VERDICT_MAP = {
    "ok": "verified",
    "mismatch": "contradicted",
    "uncertain": "insufficient_evidence",
    "rejected": "unsafe_to_verify",
}


def _utc_iso() -> str:
    return _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sha256_hex(data) -> str:
    """Canonical SHA-256 of a value: serialize JSON with sorted keys, hash bytes."""
    if isinstance(data, (bytes, bytearray)):
        return hashlib.sha256(bytes(data)).hexdigest()
    if isinstance(data, str):
        return hashlib.sha256(data.encode("utf-8")).hexdigest()
    # dict / list / etc — canonical JSON
    serialized = json.dumps(data, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=False, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def claim_hash(claim) -> str:
    """sha256:HEX of the claim. Stored in receipt; raw claim never stored."""
    return f"sha256:{_sha256_hex(claim)}"


def evidence_manifest_hash(evidence) -> str:
    """sha256:HEX of the evidence manifest (canonical JSON). Stored in receipt;
    raw evidence never stored on the server."""
    return f"sha256:{_sha256_hex(evidence)}"


# === Signing ===

def _sign_hmac_sha256(payload: dict, secret: bytes) -> str:
    """HMAC-SHA256 signature over canonical JSON.
    Returns 'hmac-sha256:<base64-no-padding>' string."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, default=str).encode("utf-8")
    mac = hmac.new(secret, canonical, hashlib.sha256).digest()
    import base64
    sig = base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")
    return f"hmac-sha256:{sig}"


def verify_receipt_signature(receipt: dict, secret: bytes) -> bool:
    """Verify the receipt's signature with the same secret used at issuance.
    Returns True iff signature matches the canonical payload (everything
    except the `signature` field itself)."""
    if not isinstance(receipt, dict):
        return False
    sig = receipt.get("signature")
    if not isinstance(sig, str) or not sig.startswith("hmac-sha256:"):
        return False
    expected_payload = {k: v for k, v in receipt.items() if k != "signature"}
    expected_sig = _sign_hmac_sha256(expected_payload, secret)
    # Constant-time compare
    return hmac.compare_digest(sig, expected_sig)


# === Issuance ===

def issue_receipt(
    *,
    claim,
    evidence,
    verifier_id: str,
    verifier_method: str,
    verdict: str,
    confidence: float,
    reason_codes: list[str],
    secret: bytes,
    issued_by: str = DEFAULT_ISSUER,
    kid: str = DEFAULT_KID,
    policy_or_oracle_refs: list[str] | None = None,
    caller_context: dict | None = None,
) -> dict:
    """Build, sign, and return a verify_action_receipt.v0.

    The raw claim/evidence are NOT included in the receipt — only their
    SHA-256 hashes. Consumers re-hash to verify the receipt covers
    a particular {claim, evidence} pair.

    `kid` is the key id used to sign this receipt. Verifiers pass it through
    a key resolver to obtain the right secret. v0 ships with a single
    `v0-default` kid; operators rotating keys MUST emit a fresh kid value.

    Caller is responsible for legacy-verdict translation if needed (use
    LEGACY_VERDICT_MAP).
    """
    if verdict not in VERDICTS:
        raise ValueError(f"verdict {verdict!r} not in {VERDICTS}")
    if not (0.0 <= float(confidence) <= 1.0):
        raise ValueError(f"confidence {confidence!r} must be 0..1")
    if not isinstance(reason_codes, list):
        raise ValueError("reason_codes must be a list")
    if not isinstance(verifier_id, str) or "@" not in verifier_id:
        raise ValueError("verifier_id must be 'name@major.minor.patch'")
    if not isinstance(kid, str) or not kid or len(kid) > 64:
        raise ValueError("kid must be a non-empty string up to 64 chars")
    if verifier_method not in ALLOWED_VERIFIER_METHODS:
        # Don't raise — log a warning. v0 enum is reference, not enforced.
        pass

    payload = {
        "schema": SCHEMA_FULL,
        "claim_hash": claim_hash(claim),
        "evidence_manifest_hash": evidence_manifest_hash(evidence),
        "verifier_id": verifier_id,
        "verifier_method": verifier_method,
        "verdict": verdict,
        "confidence": round(float(confidence), 4),
        "reason_codes": list(reason_codes),
        "policy_or_oracle_refs": list(policy_or_oracle_refs or []),
        "caller_context": dict(caller_context or {}),
        "issued_at": _utc_iso(),
        "issued_by": issued_by,
        "kid": kid,
    }
    signature = _sign_hmac_sha256(payload, secret)
    payload["signature"] = signature
    return payload


# === Validation ===

REQUIRED_FIELDS = (
    "schema", "claim_hash", "evidence_manifest_hash", "verifier_id",
    "verifier_method", "verdict", "confidence", "reason_codes",
    "issued_at", "issued_by", "kid", "signature",
)


def validate_receipt(receipt) -> tuple[bool, list[str]]:
    """Structurally validate a receipt. Returns (ok, list_of_errors).
    Does NOT verify the signature (use verify_receipt_signature for that)."""
    errors: list[str] = []
    if not isinstance(receipt, dict):
        return False, ["receipt must be a dict"]
    for f in REQUIRED_FIELDS:
        if f not in receipt:
            errors.append(f"missing required field: {f}")
    schema = receipt.get("schema")
    if schema != SCHEMA_FULL:
        errors.append(f"schema must be {SCHEMA_FULL!r}, got {schema!r}")
    verdict = receipt.get("verdict")
    if verdict is not None and verdict not in VERDICTS:
        errors.append(f"verdict must be one of {VERDICTS}, got {verdict!r}")
    conf = receipt.get("confidence")
    if conf is not None:
        try:
            cf = float(conf)
            if cf < 0 or cf > 1:
                errors.append(f"confidence must be 0..1, got {cf!r}")
        except (TypeError, ValueError):
            errors.append(f"confidence must be a number, got {conf!r}")
    rc = receipt.get("reason_codes")
    if rc is not None and not isinstance(rc, list):
        errors.append("reason_codes must be a list")
    sig = receipt.get("signature")
    if sig is not None and not (isinstance(sig, str) and sig.startswith(("hmac-sha256:", "ed25519:"))):
        errors.append(f"signature must be 'hmac-sha256:...' or 'ed25519:...', got {sig!r}")
    ch = receipt.get("claim_hash")
    if ch is not None and not (isinstance(ch, str) and ch.startswith("sha256:") and len(ch) == 71):
        errors.append(f"claim_hash must be 'sha256:<64-hex>', got {ch!r}")
    eh = receipt.get("evidence_manifest_hash")
    if eh is not None and not (isinstance(eh, str) and eh.startswith("sha256:") and len(eh) == 71):
        errors.append(f"evidence_manifest_hash must be 'sha256:<64-hex>', got {eh!r}")
    kid = receipt.get("kid")
    if kid is not None and not (isinstance(kid, str) and 1 <= len(kid) <= 64):
        errors.append(f"kid must be a non-empty string up to 64 chars, got {kid!r}")
    return (len(errors) == 0), errors
