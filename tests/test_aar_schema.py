"""Tests for AAR receipt schema."""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aar import schema


class TestSchemaConstants(unittest.TestCase):
    def test_schema_full(self):
        self.assertEqual(schema.SCHEMA_FULL, "verify_action_receipt.v0")

    def test_4_verdicts(self):
        self.assertEqual(len(schema.VERDICTS), 4)
        self.assertIn("verified", schema.VERDICTS)
        self.assertIn("contradicted", schema.VERDICTS)
        self.assertIn("insufficient_evidence", schema.VERDICTS)
        self.assertIn("unsafe_to_verify", schema.VERDICTS)

    def test_legacy_verdict_map_complete(self):
        for legacy in ("ok", "mismatch", "uncertain", "rejected"):
            self.assertIn(legacy, schema.LEGACY_VERDICT_MAP)
            self.assertIn(schema.LEGACY_VERDICT_MAP[legacy], schema.VERDICTS)

    def test_defaults_are_self_describing_not_fake_domain(self):
        # Guard: the previous default was "did:web:toa.example". We intentionally
        # removed the fake domain because consumers cannot resolve it. The new
        # default must be self-describing.
        self.assertNotIn("toa.example", schema.DEFAULT_ISSUER)
        self.assertEqual(schema.DEFAULT_ISSUER, "aar:reference-impl@v0")
        self.assertEqual(schema.DEFAULT_KID, "v0-default")

    def test_kid_is_required_field(self):
        self.assertIn("kid", schema.REQUIRED_FIELDS)


class TestHashing(unittest.TestCase):
    def test_string_hash_deterministic(self):
        h1 = schema.claim_hash("Deleted user 12345")
        h2 = schema.claim_hash("Deleted user 12345")
        self.assertEqual(h1, h2)
        self.assertTrue(h1.startswith("sha256:"))
        self.assertEqual(len(h1), 71)  # "sha256:" + 64 hex

    def test_dict_hash_canonical(self):
        # Same dict in different key order should produce same hash.
        d1 = {"a": 1, "b": 2, "c": [3, 4]}
        d2 = {"c": [3, 4], "b": 2, "a": 1}
        self.assertEqual(schema.evidence_manifest_hash(d1), schema.evidence_manifest_hash(d2))

    def test_different_evidence_different_hash(self):
        h1 = schema.evidence_manifest_hash({"x": 1})
        h2 = schema.evidence_manifest_hash({"x": 2})
        self.assertNotEqual(h1, h2)


class TestIssueReceipt(unittest.TestCase):
    SECRET = b"test-secret-bytes-for-aar-tests-32"

    def _basic(self, **overrides):
        kwargs = dict(
            claim="Deleted user 12345",
            evidence={"before_count": 100, "after_count": 99,
                      "operation": "DELETE FROM users WHERE id=12345"},
            verifier_id="verify-action-mcp@0.2.0",
            verifier_method="rule_based.db_op",
            verdict="verified",
            confidence=0.86,
            reason_codes=["row_count_match", "id_match"],
            secret=self.SECRET,
        )
        kwargs.update(overrides)
        return schema.issue_receipt(**kwargs)

    def test_issue_basic(self):
        r = self._basic()
        ok, errs = schema.validate_receipt(r)
        self.assertTrue(ok, f"validation errors: {errs}")
        self.assertEqual(r["schema"], "verify_action_receipt.v0")
        self.assertEqual(r["verdict"], "verified")
        self.assertTrue(r["claim_hash"].startswith("sha256:"))
        self.assertTrue(r["signature"].startswith("hmac-sha256:"))

    def test_issue_caller_context_included(self):
        r = self._basic(caller_context={"payment_type": "agent_wallet",
                                         "caller_type": "autonomous_agent",
                                         "wallet_provider": "x402"})
        self.assertEqual(r["caller_context"]["payment_type"], "agent_wallet")

    def test_invalid_verdict_raises(self):
        with self.assertRaises(ValueError):
            self._basic(verdict="bogus")

    def test_invalid_confidence_raises(self):
        with self.assertRaises(ValueError):
            self._basic(confidence=1.5)
        with self.assertRaises(ValueError):
            self._basic(confidence=-0.1)

    def test_invalid_verifier_id_raises(self):
        with self.assertRaises(ValueError):
            self._basic(verifier_id="bad-no-at-version")

    def test_invalid_reason_codes_raises(self):
        with self.assertRaises(ValueError):
            self._basic(reason_codes="not a list")  # type: ignore[arg-type]

    def test_default_kid_is_present(self):
        r = self._basic()
        self.assertEqual(r["kid"], "v0-default")

    def test_explicit_kid_round_trips(self):
        r = self._basic(kid="v0-2026-05")
        self.assertEqual(r["kid"], "v0-2026-05")
        self.assertTrue(schema.verify_receipt_signature(r, self.SECRET))

    def test_kid_is_signed(self):
        # Tampering with kid after issuance must invalidate the signature.
        r = self._basic()
        r["kid"] = "attacker-kid"
        self.assertFalse(schema.verify_receipt_signature(r, self.SECRET))

    def test_empty_kid_raises(self):
        with self.assertRaises(ValueError):
            self._basic(kid="")

    def test_oversize_kid_raises(self):
        with self.assertRaises(ValueError):
            self._basic(kid="x" * 65)


class TestSignatureVerify(unittest.TestCase):
    SECRET = b"test-secret-bytes-for-aar-tests-32"
    OTHER = b"completely-different-secret-32-by"

    def _r(self):
        return schema.issue_receipt(
            claim="Deleted user 12345",
            evidence={"before_count": 100, "after_count": 99},
            verifier_id="verify-action-mcp@0.2.0",
            verifier_method="rule_based.db_op",
            verdict="verified",
            confidence=0.86,
            reason_codes=["row_count_match"],
            secret=self.SECRET,
        )

    def test_verify_with_same_secret(self):
        r = self._r()
        self.assertTrue(schema.verify_receipt_signature(r, self.SECRET))

    def test_verify_fails_with_other_secret(self):
        r = self._r()
        self.assertFalse(schema.verify_receipt_signature(r, self.OTHER))

    def test_tampered_verdict_fails(self):
        r = self._r()
        r["verdict"] = "contradicted"  # tamper
        self.assertFalse(schema.verify_receipt_signature(r, self.SECRET))

    def test_tampered_claim_hash_fails(self):
        r = self._r()
        r["claim_hash"] = "sha256:" + "0" * 64
        self.assertFalse(schema.verify_receipt_signature(r, self.SECRET))

    def test_missing_signature(self):
        r = self._r()
        del r["signature"]
        self.assertFalse(schema.verify_receipt_signature(r, self.SECRET))

    def test_constant_time_compare(self):
        # Just exercise the path; we can't easily measure timing in unit tests.
        r = self._r()
        # Replace signature with something that has the right prefix length but wrong bytes
        r["signature"] = "hmac-sha256:" + "A" * 43
        self.assertFalse(schema.verify_receipt_signature(r, self.SECRET))


class TestValidate(unittest.TestCase):
    def test_missing_field(self):
        ok, errs = schema.validate_receipt({"schema": "verify_action_receipt.v0"})
        self.assertFalse(ok)
        self.assertGreater(len(errs), 0)

    def test_wrong_schema(self):
        r = {f: "x" for f in schema.REQUIRED_FIELDS}
        r["schema"] = "wrong.v9"
        ok, errs = schema.validate_receipt(r)
        self.assertFalse(ok)
        self.assertTrue(any("schema must be" in e for e in errs))

    def test_invalid_verdict_value(self):
        r = {f: "x" for f in schema.REQUIRED_FIELDS}
        r["schema"] = "verify_action_receipt.v0"
        r["verdict"] = "bogus"
        r["confidence"] = 0.5
        r["reason_codes"] = []
        r["claim_hash"] = "sha256:" + "0" * 64
        r["evidence_manifest_hash"] = "sha256:" + "0" * 64
        r["kid"] = "v0-default"
        r["signature"] = "hmac-sha256:abcdef"
        ok, errs = schema.validate_receipt(r)
        self.assertFalse(ok)
        self.assertTrue(any("verdict must be" in e for e in errs))

    def test_kid_oversize_in_validate(self):
        r = {f: "x" for f in schema.REQUIRED_FIELDS}
        r["schema"] = "verify_action_receipt.v0"
        r["verdict"] = "verified"
        r["confidence"] = 0.5
        r["reason_codes"] = []
        r["claim_hash"] = "sha256:" + "0" * 64
        r["evidence_manifest_hash"] = "sha256:" + "0" * 64
        r["kid"] = "x" * 65
        r["signature"] = "hmac-sha256:abcdef"
        ok, errs = schema.validate_receipt(r)
        self.assertFalse(ok)
        self.assertTrue(any("kid must be" in e for e in errs))

    def test_not_a_dict(self):
        ok, errs = schema.validate_receipt("not a dict")
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
