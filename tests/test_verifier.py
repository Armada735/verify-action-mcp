"""Unit tests for verify_action.

Run from candidate dir:
    python3 -m unittest discover tests -v
"""
from __future__ import annotations

import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import verifier  # noqa: E402
from verifiers import code_diff, db_op, file_op, api_call, generic  # noqa: E402


# ====== code_diff tests ======

DIFF_NULL_CHECK = """diff --git a/src/user.py b/src/user.py
index 1234567..abcdefg 100644
--- a/src/user.py
+++ b/src/user.py
@@ -42,3 +42,5 @@
 def get_email(user):
+    if user is None:
+        return None
     return user.email
"""

DIFF_MULTI_FILE_SCOPE_CREEP = """diff --git a/src/user.py b/src/user.py
--- a/src/user.py
+++ b/src/user.py
@@ -1,2 +1,3 @@
+x=1
 a
 b
diff --git a/src/auth.py b/src/auth.py
--- a/src/auth.py
+++ b/src/auth.py
@@ -1,2 +1,3 @@
+y=2
 c
 d
diff --git a/src/handlers.py b/src/handlers.py
--- a/src/handlers.py
+++ b/src/handlers.py
@@ -1,2 +1,3 @@
+z=3
 e
 f
"""


class TestCodeDiff(unittest.TestCase):
    def test_coherent_null_check(self):
        r = code_diff.verify(
            "Added a null check for user.email in src/user.py",
            {"diff": DIFF_NULL_CHECK},
        )
        self.assertEqual(r["verdict"], "ok", f"Got: {r}")
        self.assertGreaterEqual(r["confidence"], 0.6)

    def test_scope_creep_detected(self):
        r = code_diff.verify(
            "Added a tiny one-liner to src/user.py",
            {"diff": DIFF_MULTI_FILE_SCOPE_CREEP},
        )
        # Should be mismatch or uncertain; "ok" is the wrong answer
        self.assertNotEqual(r["verdict"], "ok",
                            f"Scope-creep should not be 'ok': {r}")

    def test_no_diff_uncertain(self):
        r = code_diff.verify("Added a fix", {})
        self.assertEqual(r["verdict"], "uncertain")

    def test_path_mismatch(self):
        r = code_diff.verify(
            "Added null check in src/auth.py",
            {"diff": DIFF_NULL_CHECK},
        )
        # claim says auth.py, diff is user.py
        self.assertEqual(r["verdict"], "mismatch", f"Got: {r}")


# ====== db_op tests ======

class TestDbOp(unittest.TestCase):
    def test_delete_coherent(self):
        r = db_op.verify(
            "Deleted user with id=12345",
            {
                "before_count": 1500,
                "after_count": 1499,
                "operation": "DELETE FROM users WHERE id=12345",
                "affected_rows": 1,
            },
        )
        self.assertEqual(r["verdict"], "ok", f"Got: {r}")

    def test_insert_coherent(self):
        r = db_op.verify(
            "Inserted a new user with id=999",
            {
                "before_count": 100,
                "after_count": 101,
                "operation": "INSERT INTO users(id, name) VALUES(999, 'X')",
                "affected_rows": 1,
            },
        )
        self.assertEqual(r["verdict"], "ok", f"Got: {r}")

    def test_delete_but_count_unchanged(self):
        r = db_op.verify(
            "Deleted user 12345",
            {
                "before_count": 1500,
                "after_count": 1500,
                "operation": "DELETE FROM users WHERE id=12345",
                "affected_rows": 0,
            },
        )
        self.assertEqual(r["verdict"], "mismatch", f"Got: {r}")

    def test_update_then_count_unchanged(self):
        r = db_op.verify(
            "Updated user 12345's email",
            {
                "before_count": 1500,
                "after_count": 1500,
                "operation": "UPDATE users SET email='x@y' WHERE id=12345",
                "affected_rows": 1,
            },
        )
        self.assertEqual(r["verdict"], "ok", f"Got: {r}")

    def test_id_mismatch(self):
        r = db_op.verify(
            "Deleted user 12345",
            {
                "before_count": 100,
                "after_count": 99,
                "operation": "DELETE FROM users WHERE id=99999",
                "affected_rows": 1,
            },
        )
        # The IDs don't match between claim and SQL
        self.assertEqual(r["verdict"], "mismatch", f"Got: {r}")


# ====== file_op tests ======

class TestFileOp(unittest.TestCase):
    def test_create_coherent(self):
        r = file_op.verify(
            "Created a new file at /tmp/report.txt with 200 lines",
            {
                "path": "/tmp/report.txt",
                "exists_before": False,
                "exists_after": True,
                "line_count": 200,
                "size_bytes": 12000,
            },
        )
        self.assertEqual(r["verdict"], "ok", f"Got: {r}")

    def test_create_but_already_existed(self):
        r = file_op.verify(
            "Created /tmp/x.txt",
            {"path": "/tmp/x.txt", "exists_before": True, "exists_after": True},
        )
        self.assertEqual(r["verdict"], "mismatch", f"Got: {r}")

    def test_delete_coherent(self):
        r = file_op.verify(
            "Deleted /tmp/old.log",
            {"path": "/tmp/old.log", "exists_before": True, "exists_after": False},
        )
        self.assertEqual(r["verdict"], "ok", f"Got: {r}")

    def test_line_count_mismatch(self):
        r = file_op.verify(
            "Created /tmp/r.txt with 200 lines",
            {
                "path": "/tmp/r.txt",
                "exists_before": False,
                "exists_after": True,
                "line_count": 5,
            },
        )
        self.assertEqual(r["verdict"], "mismatch", f"Got: {r}")

    def test_no_evidence_uncertain(self):
        r = file_op.verify("Created some file", {})
        self.assertEqual(r["verdict"], "uncertain")


# ====== api_call tests ======

class TestApiCall(unittest.TestCase):
    def test_success_coherent(self):
        r = api_call.verify(
            "Successfully sent email to user@example.com",
            {
                "request": {"to": "user@example.com", "subject": "Hi"},
                "response_status": 200,
                "response_body": {"id": "msg_123", "status": "sent"},
            },
        )
        self.assertEqual(r["verdict"], "ok", f"Got: {r}")

    def test_success_but_4xx(self):
        r = api_call.verify(
            "Successfully sent email to a@b.com",
            {
                "request": {"to": "a@b.com"},
                "response_status": 422,
                "response_body": {"error": "invalid email"},
            },
        )
        self.assertEqual(r["verdict"], "mismatch", f"Got: {r}")

    def test_email_target_mismatch(self):
        r = api_call.verify(
            "Sent email to alice@x.com",
            {
                "request": {"to": "bob@y.com"},
                "response_status": 200,
                "response_body": {"status": "sent"},
            },
        )
        self.assertEqual(r["verdict"], "mismatch", f"Got: {r}")

    def test_failure_with_5xx(self):
        r = api_call.verify(
            "API call failed",
            {"response_status": 502, "response_body": {"error": "upstream"}},
        )
        self.assertEqual(r["verdict"], "ok", f"Got: {r}")


# ====== generic fallback ======

class TestGeneric(unittest.TestCase):
    def test_no_signals_uncertain(self):
        r = generic.verify("I did some work", {"output": "stuff happened"})
        self.assertEqual(r["verdict"], "uncertain")

    def test_entity_match_pos(self):
        r = generic.verify(
            "Processed user 12345 and sent to user@example.com",
            {"processed_id": 12345, "destination": "user@example.com"},
        )
        # Should produce 'ok' or 'uncertain' (not 'mismatch')
        self.assertNotEqual(r["verdict"], "mismatch")


# ====== dispatcher / top-level ======

class TestDispatcher(unittest.TestCase):
    def test_kind_inference_diff(self):
        r = verifier.verify(
            "Added null check",
            {"diff": DIFF_NULL_CHECK},
        )
        self.assertEqual(r["kind_dispatched"], "code_diff")

    def test_kind_inference_db(self):
        r = verifier.verify(
            "Deleted user 12345",
            {"before_count": 100, "after_count": 99, "operation": "DELETE FROM users WHERE id=12345"},
        )
        self.assertEqual(r["kind_dispatched"], "db_op")

    def test_kind_inference_file(self):
        r = verifier.verify(
            "Created /tmp/x.txt",
            {"path": "/tmp/x.txt", "exists_before": False, "exists_after": True},
        )
        self.assertEqual(r["kind_dispatched"], "file_op")

    def test_kind_inference_api(self):
        r = verifier.verify(
            "Sent email",
            {"response_status": 200, "response_body": {"status": "sent"}},
        )
        self.assertEqual(r["kind_dispatched"], "api_call")

    def test_explicit_kind_override(self):
        r = verifier.verify(
            "Did something",
            {"diff": DIFF_NULL_CHECK},
            kind="generic",
        )
        self.assertEqual(r["kind_dispatched"], "generic")

    def test_empty_claim(self):
        r = verifier.verify("", {})
        self.assertEqual(r["verdict"], "uncertain")

    def test_invalid_kind_falls_back_to_generic(self):
        r = verifier.verify("X", {}, kind="nonsense_kind")
        self.assertEqual(r["kind_dispatched"], "generic")


if __name__ == "__main__":
    unittest.main()
