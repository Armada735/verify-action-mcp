"""Server-level tests for _do_verify (response shape + receipt + AAR verdict)."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server
from aar import schema as aar_schema


class TestDoVerifyResponseShape(unittest.TestCase):
    def _call(self, claim, evidence, kind=None, caller_context=None):
        return server._do_verify(
            claim=claim,
            evidence=evidence,
            kind=kind,
            context=None,
            caller_context=caller_context or {},
            ip_hash="deadbeef00000000",
            ua="test",
            headers={},
        )

    def test_dual_verdict_present(self):
        r = self._call(
            "Deleted user 12345",
            {"before_count": 100, "after_count": 99,
             "operation": "DELETE FROM users WHERE id=12345",
             "affected_rows": 1},
            kind="db_op",
        )
        self.assertIn("verdict", r)
        self.assertIn("aar_verdict", r)
        self.assertIn(r["verdict"], ("ok", "mismatch", "uncertain", "rejected"))
        self.assertIn(r["aar_verdict"], aar_schema.VERDICTS)

    def test_receipt_has_kid_and_signature(self):
        r = self._call(
            "Deleted user 12345",
            {"before_count": 100, "after_count": 99,
             "operation": "DELETE FROM users WHERE id=12345"},
            kind="db_op",
        )
        receipt = r["receipt"]
        self.assertEqual(receipt["schema"], "verify_action_receipt.v0")
        self.assertEqual(receipt["kid"], server.AAR_KID)
        self.assertEqual(receipt["issued_by"], server.AAR_ISSUED_BY)
        self.assertTrue(aar_schema.verify_receipt_signature(receipt, server.AAR_SECRET))

    def test_exception_path_maps_to_unsafe_to_verify(self):
        # When the verifier raises, _do_verify must emit aar_verdict=unsafe_to_verify
        # (the verifier could not complete) — distinct from insufficient_evidence
        # (the verifier examined evidence and was inconclusive).
        import verifier as v
        original = v.verify
        try:
            v.verify = lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom"))
            r = self._call("x", {"y": 1})
            self.assertEqual(r["kind_dispatched"], "exception")
            self.assertEqual(r["aar_verdict"], "unsafe_to_verify")
            self.assertEqual(r["receipt"]["verdict"], "unsafe_to_verify")
        finally:
            v.verify = original

    def test_legacy_verdict_map_completes(self):
        # All legacy verdicts the verifier may emit must map to a valid AAR verdict.
        for legacy in ("ok", "mismatch", "uncertain", "rejected"):
            self.assertIn(aar_schema.LEGACY_VERDICT_MAP[legacy], aar_schema.VERDICTS)

    def test_caller_context_optional_no_rejection(self):
        # caller_context omitted → still verifies, no error.
        r = self._call(
            "Deleted user 12345",
            {"before_count": 100, "after_count": 99,
             "operation": "DELETE FROM users WHERE id=12345"},
            kind="db_op",
            caller_context=None,
        )
        self.assertNotIn("error", r)
        self.assertIn("aar_verdict", r)

    def test_caller_context_normalized(self):
        # _normalize_caller_context: caps to 8 keys, 64-char strings, no rejection.
        big = {f"k{i}": "v" * 100 for i in range(20)}
        out = server._normalize_caller_context(big)
        self.assertLessEqual(len(out), 8)
        for v in out.values():
            if isinstance(v, str):
                self.assertLessEqual(len(v), 64)

    def test_caller_context_garbage_returns_empty(self):
        self.assertEqual(server._normalize_caller_context("not a dict"), {})
        self.assertEqual(server._normalize_caller_context(123), {})
        self.assertEqual(server._normalize_caller_context(None), {})


class TestSpecDoc(unittest.TestCase):
    def test_no_landscape_endpoint(self):
        spec = server._spec_doc()
        self.assertNotIn("landscape_endpoint", spec)
        self.assertNotIn("caller_context_required", spec)

    def test_kid_in_required_fields(self):
        spec = server._spec_doc()
        self.assertIn("kid", spec["aar_receipt_required_fields"])

    def test_aar_4_verdicts_advertised(self):
        spec = server._spec_doc()
        self.assertEqual(len(spec["aar_verdict_values"]), 4)


if __name__ == "__main__":
    unittest.main()
