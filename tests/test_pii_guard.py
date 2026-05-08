"""Tests for pii_guard module."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pii_guard


class TestEmailDetection(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(pii_guard.detect_pii("alice@example.com"), ["email"])

    def test_jp_tld(self):
        self.assertIn("email", pii_guard.detect_pii("taro.yamada@example.jp"))

    def test_subdomain(self):
        self.assertIn("email", pii_guard.detect_pii("u@a.b.example.org"))

    def test_no_email_in_url(self):
        # Plain URL with @ but not email-shaped (no dot in domain) — not flagged
        self.assertEqual(pii_guard.detect_pii("see https://example.com/path"), [])


class TestPhoneDetection(unittest.TestCase):
    def test_jp_phone(self):
        self.assertIn("phone", pii_guard.detect_pii("Call 090-1234-5678"))

    def test_jp_phone_no_dash(self):
        self.assertIn("phone", pii_guard.detect_pii("phone 03 1234 5678"))

    def test_intl(self):
        self.assertIn("phone", pii_guard.detect_pii("+81-90-1234-5678"))

    def test_not_phone_pure_id(self):
        # 10 consecutive digits without separator — not phone-shaped
        self.assertNotIn("phone", pii_guard.detect_pii("ID 1234567890 stored"))


class TestMyNumber(unittest.TestCase):
    def test_basic_12_digits(self):
        self.assertIn("my_number_or_12digit", pii_guard.detect_pii("123456789012"))

    def test_with_spaces(self):
        self.assertIn("my_number_or_12digit", pii_guard.detect_pii("1234 5678 9012"))

    def test_with_dashes(self):
        self.assertIn("my_number_or_12digit", pii_guard.detect_pii("1234-5678-9012"))

    def test_eleven_digits_now_caught(self):
        # Policy change: MY_NUMBER_RE widened from exact-12 to 11-13 digit range.
        self.assertIn("my_number_or_12digit", pii_guard.detect_pii("12345678901"))


class TestPassportJP(unittest.TestCase):
    def test_basic(self):
        self.assertIn("passport_jp", pii_guard.detect_pii("Passport: TZ1234567"))

    def test_lowercase_not_caught(self):
        self.assertNotIn("passport_jp", pii_guard.detect_pii("tz1234567"))


class TestCreditCard(unittest.TestCase):
    def test_visa_test_luhn_valid(self):
        # 4111-1111-1111-1111 is the canonical Visa test card (Luhn-valid)
        result = pii_guard.detect_pii("Card: 4111-1111-1111-1111")
        # Either credit_card OR my_number_or_12digit (12-digit prefix matches first)
        # — both are blockers, so functional outcome is reject either way.
        self.assertTrue(
            "credit_card" in result or "my_number_or_12digit" in result,
            f"expected credit_card or my_number, got {result}",
        )

    def test_random_16_digits_no_longer_requires_luhn(self):
        # Policy change (audit fix): any 13-19 digit run now flags credit_card,
        # even if Luhn-invalid. Privacy > convenience: shapes that *look* like
        # CC numbers are blocked regardless of checksum validity.
        # 1111222233334445 (last digit 5): Luhn invalid, but still PII-shaped.
        result = pii_guard.detect_pii("Random: 1111222233334445")
        self.assertIn("credit_card", result)

    def test_thirteen_digit_id_caught(self):
        # 13-digit national-id-shape (e.g. KR RRN) — flagged as credit_card
        # under the broadened CC_SHAPE_RE (13-19 digits).
        result = pii_guard.detect_pii("RRN: 1234567890123")
        self.assertIn("credit_card", result)

    def test_eleven_digit_my_number_caught(self):
        # MY_NUMBER_RE widened to 11-13 digits. 11-digit standalone now flags.
        result = pii_guard.detect_pii("ID: 12345678901")
        self.assertIn("my_number_or_12digit", result)


class TestAddressJP(unittest.TestCase):
    def test_tokyo_address(self):
        self.assertIn("address_jp", pii_guard.detect_pii("住所: 東京都港区六本木1-1-1"))

    def test_postal_code(self):
        self.assertIn("postal_code_jp", pii_guard.detect_pii("〒100-0001 千代田区"))


class TestCleanPayload(unittest.TestCase):
    def test_db_op_claim(self):
        text = "Deleted user 12345 from users table"
        # 12345 is 5 digits, not 12 — should not trigger my_number
        result = pii_guard.detect_pii(text)
        self.assertEqual(result, [])

    def test_code_diff_claim(self):
        text = "Added null check for user.email in src/user.py"
        # "user.email" is a property access, not a real email
        # Although "user.email" technically pattern-matches partial — let's test reality
        result = pii_guard.detect_pii(text)
        # This is borderline; the regex requires foo@bar.tld so it shouldn't match
        # "user.email" alone (no @)
        self.assertEqual(result, [])

    def test_sql_op(self):
        text = "DELETE FROM users WHERE id=99999"
        self.assertEqual(pii_guard.detect_pii(text), [])


class TestPayloadScanRecursive(unittest.TestCase):
    def test_email_in_nested_dict(self):
        payload = {"claim": "ok", "evidence": {"request": {"to": "alice@example.com"}}}
        cats = pii_guard.scan_payload(payload)
        self.assertIn("email", cats)

    def test_email_in_list(self):
        payload = {"claim": "ok", "evidence": [{"x": 1}, {"y": "alice@example.com"}]}
        cats = pii_guard.scan_payload(payload)
        self.assertIn("email", cats)

    def test_clean_nested(self):
        payload = {
            "claim": "Deleted user 12345",
            "evidence": {
                "before_count": 100,
                "after_count": 99,
                "operation": "DELETE FROM users WHERE id=12345",
                "affected_rows": 1,
            },
        }
        cats = pii_guard.scan_payload(payload)
        self.assertEqual(cats, [])

    def test_blocking_categories_all_blocked(self):
        # Every category we detect should be in BLOCKING_CATEGORIES
        # (i.e., we don't detect things we wouldn't reject)
        for c in [
            "email", "phone", "postal_code_jp", "address_jp",
            "my_number_or_12digit", "passport_jp", "credit_card",
        ]:
            self.assertIn(c, pii_guard.BLOCKING_CATEGORIES, f"{c} should be blocking")


class TestRejectMessage(unittest.TestCase):
    def test_message_includes_category_human_name(self):
        msg = pii_guard.reject_reason(["email"])
        self.assertIn("email", msg.lower())

    def test_empty_no_message(self):
        self.assertEqual(pii_guard.reject_reason([]), "")


if __name__ == "__main__":
    unittest.main()
