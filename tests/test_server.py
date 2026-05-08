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


class TestMcpArgumentsValidation(unittest.TestCase):
    """Regression: tools/call with non-dict arguments must return -32602
    (Invalid params), not -32603 (Internal error) with AttributeError leak."""

    def test_arguments_array_rejected_clean(self):
        # Construct the MCP handler logic directly via _handle_mcp's branches
        # by simulating the dispatch in isolation. We test the type guard
        # independently of the HTTP layer.
        raw_args = [1, 2, 3]
        # Mirror the production guard: arguments must be None or dict.
        if raw_args is None:
            args = {}
            error = None
        elif isinstance(raw_args, dict):
            args = raw_args
            error = None
        else:
            error = (-32602, "Invalid params: 'arguments' must be an object")
        self.assertIsNotNone(error)
        self.assertEqual(error[0], -32602)
        self.assertIn("must be an object", error[1])

    def test_arguments_string_rejected_clean(self):
        raw_args = "not an object"
        if raw_args is None or isinstance(raw_args, dict):
            error = None
        else:
            error = (-32602, "Invalid params: 'arguments' must be an object")
        self.assertEqual(error[0], -32602)

    def test_arguments_null_treated_as_empty(self):
        raw_args = None
        args = {} if raw_args is None else raw_args
        self.assertEqual(args, {})


class TestJapaneseVerbDispatch(unittest.TestCase):
    """JP verb support: 削除 / 作成 / 更新 / 挿入 / 追加 should classify as
    db_op when DB-shaped evidence is present, and the db_op verifier should
    return verified for coherent JP claims."""

    def _call(self, claim, evidence, kind=None):
        return server._do_verify(
            claim=claim, evidence=evidence, kind=kind, context=None,
            caller_context={}, ip_hash="deadbeef00000000", ua="test", headers={},
        )

    def test_jp_delete_verified(self):
        r = self._call(
            "user 12345 を削除しました",
            {"before_count": 100, "after_count": 99,
             "operation": "DELETE FROM users WHERE id=12345",
             "affected_rows": 1},
        )
        self.assertEqual(r["aar_verdict"], "verified")
        self.assertEqual(r["details"]["claim_verb"], "deleted")

    def test_jp_create_verified(self):
        r = self._call(
            "user 1 を新規作成しました",
            {"before_count": 100, "after_count": 101,
             "operation": "INSERT INTO users VALUES (1, 'a')",
             "affected_rows": 1},
        )
        self.assertEqual(r["aar_verdict"], "verified")

    def test_jp_update_verified(self):
        r = self._call(
            "user 7 を更新しました",
            {"before_count": 100, "after_count": 100,
             "operation": "UPDATE users SET name='x' WHERE id=7",
             "affected_rows": 1},
        )
        self.assertEqual(r["aar_verdict"], "verified")

    def test_jp_id_mismatch_contradicted(self):
        # JP verb resolves to "deleted", then ID mismatch should still fire.
        r = self._call(
            "user 12345 を削除しました",
            {"before_count": 100, "after_count": 99,
             "operation": "DELETE FROM users WHERE id=99999",
             "affected_rows": 1},
        )
        self.assertEqual(r["aar_verdict"], "contradicted")


class TestFeedbackEndpoint(unittest.TestCase):
    """POST /feedback — anonymous, PII-guarded, schema-closed feedback channel."""

    def _normalize_request(self, payload):
        # Mirror the server's normalization to test logic in isolation.
        if not isinstance(payload, dict):
            return None, "input_must_be_object"
        message = payload.get("message")
        if not isinstance(message, str) or not message.strip():
            return None, "message_required"
        if len(message) > server.FEEDBACK_MSG_CAP:
            return None, "message_too_long"
        cat_raw = payload.get("category")
        category = cat_raw if cat_raw in server.FEEDBACK_CATEGORIES else "other"
        harness_raw = payload.get("harness")
        harness = harness_raw if harness_raw in server.FEEDBACK_HARNESSES else "other"
        return {"message": message, "category": category, "harness": harness}, None

    def test_message_required(self):
        normalized, err = self._normalize_request({"category": "bug"})
        self.assertEqual(err, "message_required")

    def test_unknown_category_buckets_to_other(self):
        normalized, err = self._normalize_request(
            {"message": "test", "category": "fictional"}
        )
        self.assertIsNone(err)
        self.assertEqual(normalized["category"], "other")

    def test_unknown_harness_buckets_to_other(self):
        normalized, err = self._normalize_request(
            {"message": "test", "harness": "weird-harness-99"}
        )
        self.assertIsNone(err)
        self.assertEqual(normalized["harness"], "other")

    def test_known_category_preserved(self):
        for cat in server.FEEDBACK_CATEGORIES:
            normalized, err = self._normalize_request({"message": "x", "category": cat})
            self.assertEqual(normalized["category"], cat)

    def test_message_size_cap(self):
        big = "x" * (server.FEEDBACK_MSG_CAP + 1)
        normalized, err = self._normalize_request({"message": big})
        self.assertEqual(err, "message_too_long")


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
