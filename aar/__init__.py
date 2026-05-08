"""AAR (Agent Action Receipts) — receipt schema, signing, validation.

This module produces signed verification receipts for AI agent actions.
The schema is the canonical artifact; the in-process verifier is one
reference implementation among potentially many.
"""
from aar.schema import (
    SCHEMA_NAME,
    SCHEMA_VERSION,
    VERDICTS,
    ALLOWED_VERIFIER_METHODS,
    issue_receipt,
    validate_receipt,
    verify_receipt_signature,
)

__all__ = [
    "SCHEMA_NAME",
    "SCHEMA_VERSION",
    "VERDICTS",
    "ALLOWED_VERIFIER_METHODS",
    "issue_receipt",
    "validate_receipt",
    "verify_receipt_signature",
]
