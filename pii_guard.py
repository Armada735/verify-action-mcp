"""PII guard for verify_action.

Detects email / phone / postal code / マイナンバー / credit card / passport
in submitted claim/evidence/context. Returns a list of detected categories,
or [] if clean.

Design choices:
- Conservative: prefer false-positive over false-negative (rejecting a legit
  request is annoying; storing a マイナンバー is a regulatory violation).
- Stdlib only.
- Returns category names (not the actual matched values), so error responses
  can tell the user *what* category was detected without echoing PII back.
"""
from __future__ import annotations

import base64 as _base64
import re
import unicodedata


# ===== Cyrillic→Latin homoglyph fold =====
# Cyrillic letters that look identical to Latin letters can defeat NFKC and
# punctuation-based regex anchoring (e.g., "fоо@bar.com" with Cyrillic 'о').
# We fold the most common confusables to their Latin equivalents before regex.
_CYRILLIC_TO_LATIN = str.maketrans({
    "а": "a", "А": "A",
    "е": "e", "Е": "E",
    "о": "o", "О": "O",
    "р": "p", "Р": "P",
    "с": "c", "С": "C",
    "у": "y", "У": "Y",
    "х": "x", "Х": "X",
    "Ь": "b", "В": "B",
    "Н": "H", "К": "K", "М": "M", "Т": "T",
    "і": "i", "І": "I",
    "ј": "j", "Ј": "J",
    "ѕ": "s", "Ѕ": "S",
    "ԁ": "d",
})


# ===== Regex patterns =====
# Anchors and word-boundaries chosen so embedded matches are caught,
# but typical noise (timestamps, ID hashes, etc.) is not.

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

# JP phone: 0X-XXXX-XXXX or 0XX-XXXX-XXXX or 0XXX-XX-XXXX patterns. Total 10-11 digits.
# Two alternatives:
#  (a) WITH separator (any of dash / space / dot): traditional form
#  (b) WITHOUT separator: 11-digit JP mobile (090/070/080) or 10-digit landline.
#      Bounded by non-digit / non-hyphen on both sides to avoid eating IDs.
PHONE_JP_RE = re.compile(
    r"(?<![\d\-])"
    r"(?:"
    r"0\d{1,4}[\-\s\.]\d{1,4}[\-\s\.]\d{3,4}"
    r"|0[789]0\d{8}"      # mobile no-separator: 09012345678
    r"|0\d{9,10}"         # landline no-separator: 10-11 digits starting with 0
    r")"
    r"(?![\d\-])"
)
# International: +CC...
PHONE_INTL_RE = re.compile(r"\+\d{1,3}[\-\s\.]\d{1,4}[\-\s\.]\d{3,4}[\-\s\.]?\d{3,4}")

# JP postal code: 〒123-4567 or "123-4567" near "東京都" / "Tokyo" etc.
# Pure 3-4 split is extremely common in version numbers, so require 〒 or
# proximity to a place-name kanji block / "Japan".
POSTAL_JP_RE = re.compile(r"〒\s*\d{3}\s*-\s*\d{4}\b")
# Detect address-like strings (kanji place chars + numbers): heuristic.
ADDRESS_JP_HINT_RE = re.compile(r"(東京都|大阪府|北海道|京都府|[都道府県][^、。\s]{1,15}[市区町村]).{1,50}\d+(-\d+)+")

# マイナンバー-shape (11-13 digit run, optional separators).
# Widened from "exactly 12 digits" to 11-13 digit window after a security
# audit finding that 13-digit national IDs (e.g. KR RRN) and slightly
# shortened forms slipped through. Aggressive on purpose — false-positive
# over false-negative.
MY_NUMBER_RE = re.compile(r"(?<!\d)(?:\d[\-\s]?){10,12}\d(?!\d)")

# JP passport: two uppercase letters + 7 digits.
PASSPORT_JP_RE = re.compile(r"\b[A-Z]{2}\d{7}\b")

# Credit-card-shape: 13-19 digit run with optional separators.
# Luhn validity is NOT required — the audit showed that non-Luhn 16-digit
# numbers (e.g. test cards with one digit perturbed) still constitute
# regulatory PII risk and should be rejected.
CC_SHAPE_RE = re.compile(r"(?<!\d)(?:\d[\-\s]?){12,18}\d(?!\d)")


def _luhn_valid(num_str: str) -> bool:
    """Return True if num_str passes the Luhn check (13-19 digits).

    Standard Luhn: starting from the rightmost digit (the check digit),
    every second digit is doubled. If the doubled value > 9, subtract 9.
    Sum must be divisible by 10.
    """
    digits = [int(c) for c in num_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:  # every second digit from the right
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _normalize(text: str) -> str:
    """NFKC-normalize, fold Cyrillic homoglyphs to Latin, drop zero-width
    characters, and collapse newlines / tabs to spaces (so a regex with `\\b`
    isn't fooled by a newline split inside an email)."""
    if not isinstance(text, str):
        return ""
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_CYRILLIC_TO_LATIN)
    # Strip zero-width / format characters; collapse other whitespace.
    out_chars = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat == "Cf":          # zero-width joiners, BOM, etc. — drop
            continue
        if cat[0] == "C" and ch not in "\n\t\r":
            continue
        if ch in ("\n", "\t", "\r"):
            out_chars.append(" ")
        else:
            out_chars.append(ch)
    return "".join(out_chars)


def _maybe_decode_base64_candidates(text: str) -> str:
    """When text contains a long base64-shaped substring, attempt to decode
    each candidate and append the decoded text for PII scanning. Cap at 4
    candidates and 4KB of decoded text to avoid CPU explosions on adversarial
    input. Failed decodes are silently ignored."""
    if not text:
        return ""
    # base64 candidates: 12+ chars of base64 alphabet (with optional padding).
    # "foo@bar.com" (11 bytes) encodes to 15 alphanum + 1 pad = 16 chars total;
    # the alphanum-only group is 15. Setting threshold to 12 catches that.
    # Limit candidates to 4 and decoded budget to 4KB to keep CPU bounded.
    candidates = re.findall(r"[A-Za-z0-9+/]{12,4000}={0,2}", text)
    if not candidates:
        return ""
    out: list[str] = []
    bytes_left = 4096
    for cand in candidates[:4]:
        try:
            raw = _base64.b64decode(cand, validate=False)
            decoded = raw.decode("utf-8", errors="replace")
        except Exception:
            continue
        if not decoded:
            continue
        chunk = decoded[:bytes_left]
        out.append(chunk)
        bytes_left -= len(chunk)
        if bytes_left <= 0:
            break
    return "\n".join(out)


def _detect_pii_inner(text: str) -> list[str]:
    """Run regex+Luhn on a single (already-normalized) string. Returns
    categories. credit_card is checked BEFORE my_number_or_12digit so a
    Luhn-valid 16-digit prefix is reported as credit_card, not my_number."""
    if not text:
        return []
    found: list[str] = []
    if EMAIL_RE.search(text):
        found.append("email")
    if PHONE_JP_RE.search(text) or PHONE_INTL_RE.search(text):
        found.append("phone")
    if POSTAL_JP_RE.search(text):
        found.append("postal_code_jp")
    if ADDRESS_JP_HINT_RE.search(text):
        found.append("address_jp")
    cc_hit = False
    for _m in CC_SHAPE_RE.finditer(text):
        # Reject any 13-19 digit run regardless of Luhn validity. Privacy
        # posture > convenience: a Luhn-invalid 16-digit string still likely
        # represents a personal-data shape (mistyped card, foreign ID, etc.).
        found.append("credit_card")
        cc_hit = True
        break
    # Only flag the 11-13-digit my_number bucket when there's no CC hit at
    # the same place. CC matches (13-19 digits) overlap the 13-digit upper
    # end of MY_NUMBER_RE; reporting both would be redundant.
    if not cc_hit and MY_NUMBER_RE.search(text):
        found.append("my_number_or_12digit")
    if PASSPORT_JP_RE.search(text):
        found.append("passport_jp")
    return found


def detect_pii(text: str) -> list[str]:
    """Detect PII in a single string. Also tries to base64-decode any embedded
    candidates and scan the decoded text as well — catches naive evasion
    via base64-encoded PII payloads.

    Categories: email, phone, postal_code_jp, address_jp,
    my_number_or_12digit, passport_jp, credit_card.
    """
    if not isinstance(text, str) or not text:
        return []
    norm = _normalize(text)
    found = list(_detect_pii_inner(norm))

    # Also scan base64-decoded candidates (prevents trivial evasion).
    decoded = _maybe_decode_base64_candidates(norm)
    if decoded:
        decoded_norm = _normalize(decoded)
        for c in _detect_pii_inner(decoded_norm):
            if c not in found:
                found.append(c)

    return found


SCAN_MAX_DEPTH = 12


def scan_payload(value, depth: int = 0, _found: set | None = None) -> list[str]:
    """Recursively scan dict/list/string for PII. Returns sorted list of unique
    categories. If the payload nests deeper than SCAN_MAX_DEPTH, a synthetic
    'too_deeply_nested' category is added — this is a blocker, since attackers
    can use deep nesting to hide PII from the scanner."""
    if _found is None:
        _found = set()
    if depth > SCAN_MAX_DEPTH:
        _found.add("too_deeply_nested")
        return sorted(_found)

    if isinstance(value, str):
        for c in detect_pii(value):
            _found.add(c)
    elif isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str):
                for c in detect_pii(k):
                    _found.add(c)
            scan_payload(v, depth + 1, _found)
    elif isinstance(value, list):
        for v in value:
            scan_payload(v, depth + 1, _found)
    return sorted(_found)


# Categories considered hard-blockers (always reject). Currently all categories
# are blockers; kept as a separate list so the policy can be tuned later.
BLOCKING_CATEGORIES = frozenset({
    "email",
    "phone",
    "postal_code_jp",
    "address_jp",
    "my_number_or_12digit",
    "passport_jp",
    "credit_card",
    "too_deeply_nested",
})


def reject_reason(categories: list[str]) -> str:
    """Format a user-facing rejection message for detected categories.
    The categories themselves are NOT echoed back literally — that would turn
    this endpoint into a free PII-shape oracle. We return only a generic
    message + a stable count."""
    if not categories:
        return ""
    return (
        "PII-shaped content or excessive structural nesting detected in the "
        "submitted claim/evidence/context. This service does not accept "
        "personal data. Replace identifying values with placeholders "
        "(e.g. <user_id>, <email>) and flatten deeply nested structures, "
        "then resubmit. See /privacy for details."
    )


def reject_reason_with_categories(categories: list[str]) -> str:
    """Same as reject_reason but also lists the detected categories. Used in
    operator-facing trace logs only — never returned to the API caller."""
    if not categories:
        return ""
    cat_human = {
        "email": "email address",
        "phone": "phone number",
        "postal_code_jp": "Japanese postal code",
        "address_jp": "Japanese address pattern",
        "my_number_or_12digit": "11-13-digit national-id-shaped number",
        "passport_jp": "Japanese passport number",
        "credit_card": "credit-card-shaped number (13-19 digits)",
        "too_deeply_nested": f"structure deeper than {SCAN_MAX_DEPTH} levels",
    }
    listed = ", ".join(cat_human.get(c, c) for c in categories)
    return (
        "PII-shaped values detected in submitted claim/evidence/context: "
        f"{listed}. This service does not accept personal data. "
        "Replace identifying values with placeholders (e.g. <user_id>, <email>) "
        "before resubmitting. See /privacy for details."
    )
