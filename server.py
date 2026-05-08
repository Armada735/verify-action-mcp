#!/usr/bin/env python3
"""verify_action HTTP + MCP server.

- 127.0.0.1:8092 only (Cloudflare Tunnel forwards from edge)
- stdlib only
- Strict path whitelist; 404 for everything else
- Body cap 32KB, per-IP rate-limit, global POST cap
- IPs hashed at receipt; no plaintext IP stored
- POST /verify  — REST: {claim, evidence, kind?, context?} → verdict
- POST /mcp     — MCP JSON-RPC: initialize, tools/list, tools/call(verify_action)
- GET  /about /healthcheck /spec /stats
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import http.server
import json
import os
import pathlib
import secrets
import signal
import sys
import threading
import time
import urllib.parse

import verifier  # local module from Phase A
import pii_guard  # local module: detect/reject PII at receipt
from aar import schema as aar_schema  # AAR receipt issuance


# ====== Configuration ======

HOST = "127.0.0.1"
PORT = 8092
MAX_BODY = 32 * 1024
RATE_LIMIT_WINDOW_SEC = 60.0
RATE_LIMIT_MAX = 60  # 60/min (was 30) — relaxed so HN demo doesn't bounce
GLOBAL_POST_LIMIT_PER_HOUR = 1500  # bumped proportionally
# GET endpoints exempt from rate limiting (public read-only metadata).
RATE_LIMIT_EXEMPT_GETS = frozenset({"/", "/about", "/healthcheck", "/spec", "/stats", "/tos", "/privacy"})

# Per-field caps applied to user-supplied claim/evidence before storage.
PAYLOAD_MAX_DEPTH = 6
PAYLOAD_MAX_KEYS = 50
PAYLOAD_MAX_LIST = 100
PAYLOAD_STR_CAP = 8000
PAYLOAD_LIST_ELT_CAP = 2000
PAYLOAD_KEY_CAP = 200

ROOT = pathlib.Path(__file__).resolve().parent
LOG_DIR = ROOT / "logs"
TRACES_DIR = ROOT / "traces"
STATE_DIR = ROOT / "state"
SALT_FILE = STATE_DIR / "ip_hash_salt"
AAR_SECRET_FILE = STATE_DIR / "aar_signing_secret"

for d in (LOG_DIR, TRACES_DIR, STATE_DIR):
    d.mkdir(exist_ok=True)

if not SALT_FILE.exists():
    SALT_FILE.write_text(secrets.token_hex(32))
    SALT_FILE.chmod(0o600)
SALT = SALT_FILE.read_text().strip()

# AAR signing secret — separate from IP-hashing salt so a leak of one doesn't
# imply forgeable receipts. 64 bytes hex = 32 bytes secret = HMAC-SHA256 keyed.
if not AAR_SECRET_FILE.exists():
    AAR_SECRET_FILE.write_text(secrets.token_hex(32))
    AAR_SECRET_FILE.chmod(0o600)
AAR_SECRET = bytes.fromhex(AAR_SECRET_FILE.read_text().strip())

AAR_VERIFIER_ID = f"verify-action-mcp@{verifier.VERIFIER_VERSION}"
# Operator overrides via env. Defaults are intentionally self-describing
# strings, NOT a fake domain — see SCHEMA_UPGRADES.md for the upgrade path
# to a did:web identifier once a stable domain is provisioned.
AAR_ISSUED_BY = os.environ.get("AAR_ISSUED_BY", aar_schema.DEFAULT_ISSUER)
AAR_KID = os.environ.get("AAR_KID", aar_schema.DEFAULT_KID)

# MCP protocol version we advertise (recent MCP draft as of 2026-05).
MCP_PROTOCOL_VERSION = "2024-11-05"

# Headers we are willing to record in trace JSONL. Everything else is dropped.
# Specifically excludes Authorization, Cookie, and any X-* / custom auth headers.
SAFE_TRACE_HEADERS = frozenset({
    "user-agent",
    "content-type",
    "content-length",
    "accept",
    "cf-ipcountry",
    "cf-ray",
})

# Cloudflare public egress IP ranges (https://www.cloudflare.com/ips-v4 /
# https://www.cloudflare.com/ips-v6, snapshot 2026-05). Connections from these
# ranges to 127.0.0.1 only happen via the configured Cloudflare Tunnel, so we
# trust the CF-Connecting-IP header from these peers. From any other peer, the
# header is attacker-controlled and ignored.
import ipaddress as _ipaddr

_CF_RANGES_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
_CF_RANGES_V6 = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]
_CF_NETS = (
    [_ipaddr.ip_network(c) for c in _CF_RANGES_V4]
    + [_ipaddr.ip_network(c) for c in _CF_RANGES_V6]
)
# Loopback is also "trusted" for local testing convenience (operator-only).
_CF_NETS.append(_ipaddr.ip_network("127.0.0.0/8"))
_CF_NETS.append(_ipaddr.ip_network("::1/128"))


def _peer_in_cloudflare(peer: str) -> bool:
    """Return True if the immediate TCP peer is in a Cloudflare egress range
    (or loopback for local testing)."""
    try:
        ip = _ipaddr.ip_address(peer)
    except (ValueError, TypeError):
        return False
    return any(ip in net for net in _CF_NETS)


# ====== Static content ======

ABOUT_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>verify_action — post-action evidence verification with HMAC-attested receipts</title></head>
<body style="font-family:sans-serif;max-width:760px;margin:2em auto;line-height:1.6;">
<h1>verify_action</h1>
<p>A small, JP-jurisdiction reference verification primitive for AI agent actions.
Submit a claim about what your agent did, plus structured evidence of what actually
happened, and receive an independent integrity check plus an
<strong>HMAC-attested receipt</strong> that downstream tooling, CI gates, and audit
reviewers can reference. Open source, free, no warranty (see <a href="/tos">ToS</a>).</p>

<h2>Why this exists</h2>
<p>Pre-action policy admission control systems (e.g., policy-as-code admission
control with Cedar / Rego, lifecycle hooks) decide <em>"is this action allowed?"</em>
before execution. That is a different problem.</p>
<p>This service answers a complementary question: <em>"after the action ran, does the
evidence support the agent's claim about what it did?"</em>. AI agents commonly assert
success when reality didn't match — rows that weren't deleted, files that weren't
created, emails that bounced, code changes that touched five unrelated files. We
catch that drift with structured evidence comparison and emit a content-addressed
HMAC-attested receipt that can be referenced later.</p>
<p>This is a small reference implementation, not a canonical standard. The receipt
format is forkable; vendors and verifiers may diverge.</p>

<h2>API</h2>
<ul>
<li><code>POST /verify</code> — REST. JSON body <code>{claim, evidence, kind?, context?, caller_context?}</code>.
Returns <code>{verdict, reasoning, confidence, verifier_used, receipt}</code>.
<code>caller_context</code> is <strong>optional</strong> metadata; if provided it is
echoed in the receipt for downstream consumers.</li>
<li><code>POST /mcp</code> — MCP JSON-RPC 2.0. Methods: <code>initialize</code>, <code>tools/list</code>,
<code>tools/call</code> (with <code>name=verify_action</code>). Stateless transport.</li>
<li><code>GET /spec</code> — JSON schema for the verify_action tool and the receipt format.</li>
<li><code>GET /healthcheck</code> — liveness probe.</li>
<li><code>GET /stats</code> — service-internal aggregate counters (verdict distribution, no
per-request data).</li>
</ul>

<h2>The receipt</h2>
<p>Every verification produces an HMAC-attested receipt (<code>verify_action_receipt.v0</code>)
containing: SHA-256 of claim, SHA-256 of evidence manifest, verifier id and version,
key id (<code>kid</code>), verdict (one of <code>verified</code> / <code>contradicted</code> /
<code>insufficient_evidence</code> / <code>unsafe_to_verify</code>), confidence, reason
codes, issuance timestamp, and HMAC-SHA256 signature. Raw claim and evidence are
<strong>not</strong> in the receipt; consumers can re-hash to verify the receipt covers
a particular pair. <strong>Receipts attest issuance and integrity, not factual truth or
legal admissibility</strong> — they prove a single private key signed under our verifier
version, not that the verdict is correct.</p>

<aside style="background:#fffbe6;border-left:4px solid #d97706;padding:0.5em 1em;margin:1.5em 0;font-size:0.95em;">
<strong>v0 trust model.</strong> Receipts are signed with HMAC-SHA256 — a
<em>symmetric</em> primitive. This means the receipt verifies that
<em>this service holds the key that signed it</em>; it is <strong>not a
third-party cryptographic attestation</strong> in the public-key sense.
Treat v0 receipts as a content-addressed log entry from us, not as
non-repudiable proof. Asymmetric (ed25519) signing and multi-issuer
support are on the v1 roadmap — see
<a href="https://github.com/Armada735/verify-action-mcp/blob/main/aar/SCHEMA_UPGRADES.md">aar/SCHEMA_UPGRADES.md</a>.
</aside>

<h2>Who can call this</h2>
<p>Anyone — operators running agents (operator-funded), agents calling on their own
behalf (agent-wallet via x402 / Stripe MPP / etc.), or hybrid setups. Same receipt
regardless. The optional <code>caller_context</code> field is informational metadata for
downstream consumers; it does not gate verification.</p>

<h2>Privacy</h2>
<ul>
<li>IPs are hashed (SHA-256 + salt) at receipt; plaintext IPs are never stored.</li>
<li><strong>Personal data is rejected at receipt</strong> with HTTP 400. Submissions
containing email addresses, phone numbers, postal codes, 12-digit identifiers
(マイナンバー shape), passport numbers, or credit-card-shaped numbers are
refused before any processing. See <a href="/privacy">Privacy Policy</a>.</li>
<li><strong>Raw claim and evidence values are not stored.</strong> Trace logs retain only
metadata: claim length, SHA-256 prefix, evidence type, top-level key count,
byte size. Plaintext values are discarded after the response is sent.</li>
<li>No public aggregate dashboard. Internal counters only (see <code>/stats</code> for
verdict distribution since process start).</li>
</ul>

<h2>Phase 1 limitations</h2>
<p>The verification engine in Phase 1 is rule-based (no LLM call). Specialized
verifiers handle code diffs, DB ops, file ops, and HTTP API calls. A generic
fallback handles arbitrary shapes weakly. Provide a specific <code>kind</code> for the
strongest result. <code>insufficient_evidence</code> is a first-class verdict — refusing
to claim certainty is information, not failure.</p>

<h2>Legal</h2>
<ul>
<li><a href="/tos">Terms of Service</a> (governing law: Japan; jurisdiction: Tokyo)</li>
<li><a href="/privacy">Privacy Policy</a> (PII not accepted; data retention 30 days)</li>
</ul>
<hr/>
<p><em>Open source. Source code and detection rules public. This is a probe — small,
forkable, no warranty. Fork it if useful.</em></p>
</body></html>
"""

TOS_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>verify_action — Terms of Service</title></head>
<body style="font-family:sans-serif;max-width:760px;margin:2em auto;line-height:1.6;">
<h1>Terms of Service / 利用規約</h1>
<p><strong>Last updated</strong>: 2026-05-07</p>

<h2>1. Service / 本サービス</h2>
<p>verify_action ("Service") is a free, no-warranty, third-party verification API
operated by an individual JP-based developer ("Operator"). The Service is in
probe / experimental phase. No SLA, no uptime guarantee, no support.</p>
<p><strong>Intended audience.</strong> The Service is intended for use by software developers,
researchers, and operators of agent-based systems in the course of their business
or professional activity. The Service is <strong>not</strong> intended for, marketed to, or
operated as a service for "consumers" within the meaning of the Japan Consumer
Contract Act (消費者契約法 2 条 1 項). Where Japanese consumer protection law would
mandatorily override these Terms in a B2C relationship, those mandatory provisions
apply only to the extent the law requires; the rest of these Terms remain in
effect.</p>

<h2>2. Prohibited uses / 禁止用途</h2>
<p>You agree not to use the Service for, or in connection with:</p>
<ul>
<li>Financial product transactions, investment advice, or trade execution
(金融商品取引, 投資判断, 取引執行)</li>
<li>Medical diagnosis or treatment decisions (医療診断・治療判断)</li>
<li>Legal advice or judicial decisions (法律助言・司法判断)</li>
<li>Identity verification / KYC (本人確認)</li>
<li>Gambling or betting (賭博)</li>
<li>Election-related decisions (選挙関連判断)</li>
<li>Any use involving children's personal data</li>
<li>Submitting personal data (PII) of any individual — see Privacy Policy</li>
<li>Any use that violates applicable law in your jurisdiction</li>
</ul>
<p>Violations may result in immediate request rejection and IP-hash blacklisting.</p>

<h2>3. No warranty / 無保証</h2>
<p>The Service is provided "AS IS" without warranty of any kind, express or implied.
The Operator disclaims all warranties including but not limited to merchantability,
fitness for a particular purpose, and non-infringement. Verdicts returned by the
Service are heuristic and may be incorrect. Do not rely on them as the sole basis
for any consequential action.</p>

<h2>4. Service limits / 利用制限</h2>
<p>To prevent abuse, the Service enforces:</p>
<ul>
<li><strong>30 requests / minute / source IP</strong> on POST endpoints. Excess
returns HTTP 429 with a <code>Retry-After</code> hint.</li>
<li><strong>1,000 POST requests / hour</strong> globally. Excess returns HTTP 503.</li>
<li><strong>Maximum request body 32 KB</strong>. Larger payloads return HTTP 413.</li>
<li>Repeated abuse may result in IP-hash blocklisting.</li>
</ul>
<p>These limits may be raised or lowered without notice. Sustained heavy use
should be done by self-hosting — the source code is public at
<a href="https://github.com/Armada735/verify-action-mcp">github.com/Armada735/verify-action-mcp</a>.</p>

<h2>5. Limitation of liability / 責任制限</h2>
<p>To the maximum extent permitted by applicable law, the Operator shall not be liable
for any direct, indirect, incidental, consequential, or punitive damages arising
from use of the Service. The Operator's aggregate liability shall not exceed JPY 0
(zero), reflecting the free-of-charge nature of this probe.</p>

<h2>6. Cross-border data transit / 国境を越える通信</h2>
<p>The Service is reachable through Cloudflare, Inc. (US) edge infrastructure.
By submitting a request, you consent to your request transiting through
infrastructure located outside Japan (Cloudflare's global edge network).
Cloudflare's data processing addendum applies to its handling.</p>

<h2>7. Governing law / 準拠法</h2>
<p>These Terms are governed by the laws of Japan. Any dispute arising out of or in
connection with these Terms shall be exclusively subject to the jurisdiction of
the Tokyo District Court (or Tokyo Summary Court for small claims), as the court
of first instance.</p>
<p>本規約は日本法に準拠します。本規約に起因または関連する紛争については、東京地方
裁判所（少額の場合は東京簡易裁判所）を第一審の専属的合意管轄裁判所とします。</p>

<h2>8. Changes / 変更</h2>
<p>The Operator may update these Terms at any time. Material changes will be reflected
in the "Last updated" date above. Continued use after such update constitutes
acceptance.</p>

<h2>9. Contact / 連絡先</h2>
<p>For complaints, deletion requests, takedown requests, or legal correspondence,
contact: <code>hello@armadalab.dev</code>.</p>

<hr/>
<p><a href="/">← back to about</a> | <a href="/privacy">Privacy Policy →</a></p>
</body></html>
"""

PRIVACY_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>verify_action — Privacy Policy</title></head>
<body style="font-family:sans-serif;max-width:760px;margin:2em auto;line-height:1.6;">
<h1>Privacy Policy / プライバシーポリシー</h1>
<p><strong>Last updated</strong>: 2026-05-07</p>

<h2>1. We do not accept personal data / 個人データを受け付けません</h2>
<p>The Service is designed to operate on <strong>non-personal claim/evidence pairs</strong>
(e.g. row counts, file paths, code diffs, API request shapes). Submissions
detected to contain personal data — including but not limited to email
addresses, phone numbers, postal addresses, Japanese postal codes, 12-digit
identifiers (My Number / マイナンバー shape), passport numbers, or
credit-card-shaped numbers — are <strong>rejected at receipt</strong> with HTTP 400.
Operators are responsible for redacting personal data before submission.</p>

<h2>2. What we collect / 取得情報</h2>
<p>For each request, the following metadata is recorded for operational purposes
(rate limiting, abuse prevention, aggregate statistics):</p>
<ul>
<li>SHA-256+salt hash of the source IP (16 hex chars). Plaintext IPs are never stored.</li>
<li>User-Agent header.</li>
<li>Timestamp.</li>
<li>Request kind and verdict (e.g. <code>db_op</code> / <code>ok</code>).</li>
<li>Length and SHA-256 hash (16 hex chars) of the submitted claim. Raw claim
text is <strong>not stored</strong>.</li>
<li>Top-level keys, total byte size, and type of the submitted evidence object.
Raw evidence values are <strong>not stored</strong>.</li>
<li>A small allowlist of HTTP headers (User-Agent, Content-Type, Accept,
Content-Length, CF-IPCountry, CF-Ray). Authorization, Cookie, custom headers,
and any other request headers are <strong>dropped at receipt</strong>.</li>
</ul>

<h2>3. Retention / 保管期間</h2>
<p>Operational logs and trace metadata are retained for <strong>30 days</strong> on rolling
delete. After 30 days, logs are automatically purged. Aggregate statistics
(no per-request data) may be retained indefinitely.</p>

<h2>4. No third-party sharing / 第三者提供しない</h2>
<p>Per-request data is not shared with any third party. Aggregate statistics may
be published openly (e.g. "verdict distribution by kind").</p>

<h2>5. Cross-border transit / 越境通信</h2>
<p>Requests reach the Service through Cloudflare, Inc. (US) edge infrastructure.
By submitting a request, you consent to your request transiting through
infrastructure located outside Japan. Cloudflare's data processing addendum
applies to its handling. Per Japan PIPA Article 28 (外国にある第三者への提供):
the United States is not, as of this writing, designated by the Personal
Information Protection Commission as an equivalent-protection country, so
this consent is required.</p>

<h2>6. Your rights / 利用者の権利</h2>
<p>Under Japan's Act on the Protection of Personal Information (個人情報保護法),
you may request disclosure, correction, deletion, or cessation of processing
of your personal data. Since the Service does not accept personal data and
stores no personally identifiable information by design, such requests
should typically return "no data on file." However, if you believe the Service
has inadvertently retained personal data of yours (e.g. through a regex
false-negative), please contact us and we will investigate and delete.</p>

<h2>7. Contact / 連絡先 / 苦情窓口</h2>
<p>For privacy inquiries, deletion requests, or PIPC-related complaints:
<code>hello@armadalab.dev</code>.</p>

<h2>8. Changes / 変更</h2>
<p>This policy may be updated. Material changes are reflected in the "Last
updated" date.</p>

<hr/>
<p><a href="/">← back to about</a> | <a href="/tos">Terms of Service →</a></p>
</body></html>
"""


def _verify_action_tool_schema() -> dict:
    return {
        "name": "verify_action",
        "description": (
            "Post-action evidence verification with HMAC-attested receipts (AAR). "
            "Submit a claim about what an agent did plus structured evidence. "
            "Returns {verdict: 'verified'|'contradicted'|'insufficient_evidence'|'unsafe_to_verify', "
            "reasoning, confidence, receipt}. The receipt is a content-addressed, "
            "HMAC-attested JSON document that downstream tooling / CI / audit reviewers "
            "can reference. Specialized kinds: code_diff, db_op, file_op, api_call. "
            "Fallback: generic. Stateless. No PII (rejected at receipt). "
            "Receipts attest issuance and integrity, not factual truth or legal admissibility."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "claim": {
                    "type": "string",
                    "description": "Natural-language statement of what the agent claims to have done.",
                },
                "evidence": {
                    "type": "object",
                    "description": (
                        "Structured evidence depending on kind. "
                        "code_diff: {diff: '<unified diff>'}. "
                        "db_op: {before_count, after_count, operation, affected_rows}. "
                        "file_op: {path, exists_before, exists_after, line_count?, size_bytes?}. "
                        "api_call: {request, response_status, response_body}. "
                        "generic: any object."
                    ),
                },
                "kind": {
                    "type": "string",
                    "enum": ["code_diff", "db_op", "file_op", "api_call", "generic"],
                    "description": "Optional kind hint to dispatch the right verifier.",
                },
                "context": {
                    "type": "string",
                    "description": "Optional brief context about the broader task.",
                },
                "caller_context": {
                    "type": "object",
                    "description": (
                        "Optional informational metadata about the caller (payment model, "
                        "caller type, wallet provider, etc.). Echoed in the receipt for "
                        "downstream consumers; not validated, not aggregated, not published. "
                        "Free-form keys/values (max 8 keys, 64-char strings)."
                    ),
                    "additionalProperties": True,
                },
            },
            "required": ["claim", "evidence"],
        },
    }


def _spec_doc() -> dict:
    return {
        "verifier_version": verifier.VERIFIER_VERSION,
        "tool": _verify_action_tool_schema(),
        "verifier_kinds": list(verifier.VERIFIERS.keys()),
        "legacy_verdict_values": ["ok", "mismatch", "uncertain"],
        "aar_verdict_values": list(aar_schema.VERDICTS),
        "aar_legacy_verdict_map": dict(aar_schema.LEGACY_VERDICT_MAP),
        "aar_receipt_schema": aar_schema.SCHEMA_FULL,
        "aar_receipt_required_fields": list(aar_schema.REQUIRED_FIELDS),
        "aar_receipt_signing": "HMAC-SHA256 (symmetric, single-issuer with kid v0); ed25519 + multi-issuer planned in SCHEMA_UPGRADES.md",
        "rest_endpoint": "/verify",
        "mcp_endpoint": "/mcp",
        "mcp_protocol_version": MCP_PROTOCOL_VERSION,
        "caller_context": "optional informational metadata; not validated, not aggregated, not published",
    }


# ====== Rate limiting ======

_rate_lock = threading.Lock()
_rate_buckets: dict = {}

_global_post_lock = threading.Lock()
_global_post_times: list = []


# When the rate-bucket dict grows past this size, we opportunistically GC
# empty (timestamp-pruned) buckets to keep memory bounded.
_RATE_BUCKETS_GC_THRESHOLD = 50_000


def rate_check(key: str) -> bool:
    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW_SEC
    with _rate_lock:
        bucket = _rate_buckets.setdefault(key, [])
        bucket[:] = [t for t in bucket if t > cutoff]
        result = len(bucket) < RATE_LIMIT_MAX
        if result:
            bucket.append(now)
        # Drop the bucket entirely when empty so the dict doesn't accumulate
        # one entry per ever-seen IP. Without this, the dict grows monotonically.
        if not bucket:
            _rate_buckets.pop(key, None)
        # Larger sweep when the dict gets big — guards against worst-case
        # adversarial enumeration of unique IPs.
        if len(_rate_buckets) > _RATE_BUCKETS_GC_THRESHOLD:
            _rate_buckets_gc(cutoff)
    return result


def _rate_buckets_gc(cutoff: float) -> None:
    """Sweep all buckets: prune stale timestamps and drop empty buckets.
    Caller must hold _rate_lock."""
    dead = []
    for k, bucket in _rate_buckets.items():
        bucket[:] = [t for t in bucket if t > cutoff]
        if not bucket:
            dead.append(k)
    for k in dead:
        _rate_buckets.pop(k, None)


def global_post_check() -> bool:
    now = time.monotonic()
    cutoff = now - 3600.0
    with _global_post_lock:
        i = 0
        while i < len(_global_post_times) and _global_post_times[i] < cutoff:
            i += 1
        if i:
            del _global_post_times[:i]
        if len(_global_post_times) >= GLOBAL_POST_LIMIT_PER_HOUR:
            return False
        _global_post_times.append(now)
    return True


# ====== Payload sanitisation (depth/size cap) ======

def _sanitize_payload(value, depth: int = 0):
    if depth > PAYLOAD_MAX_DEPTH:
        return "_too_deep"
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return value[:PAYLOAD_STR_CAP]
    if isinstance(value, dict):
        out = {}
        for k, v in list(value.items())[:PAYLOAD_MAX_KEYS]:
            out[str(k)[:PAYLOAD_KEY_CAP]] = _sanitize_payload(v, depth + 1)
        return out
    if isinstance(value, list):
        return [_sanitize_payload(x, depth + 1) for x in value[:PAYLOAD_MAX_LIST]]
    return str(value)[:PAYLOAD_LIST_ELT_CAP]


# ====== Logging / telemetry ======

def _utc_iso() -> str:
    return _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _today() -> str:
    return _dt.datetime.utcnow().strftime("%Y-%m-%d")


def log_access(record: dict) -> None:
    p = LOG_DIR / f"access-{_today()}.jsonl"
    line = json.dumps(record, default=str, ensure_ascii=False)
    with open(p, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    try:
        p.chmod(0o600)
    except OSError:
        pass


def log_trace(record: dict) -> None:
    p = TRACES_DIR / f"traces-{_today()}.jsonl"
    line = json.dumps(record, default=str, ensure_ascii=False)
    with open(p, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    try:
        p.chmod(0o600)
    except OSError:
        pass


# Aggregate stats (in-memory, since process restart).
_stats_lock = threading.Lock()
_stats = {
    "started_at": _utc_iso(),
    "verify_calls_total": 0,
    "by_kind": {},
    "by_verdict": {"ok": 0, "mismatch": 0, "uncertain": 0},
}


def _bump_stats(kind: str, verdict: str) -> None:
    with _stats_lock:
        _stats["verify_calls_total"] += 1
        _stats["by_kind"][kind] = _stats["by_kind"].get(kind, 0) + 1
        if verdict in _stats["by_verdict"]:
            _stats["by_verdict"][verdict] += 1


def _stats_snapshot() -> dict:
    with _stats_lock:
        return {
            "started_at": _stats["started_at"],
            "verify_calls_total": _stats["verify_calls_total"],
            "by_kind": dict(_stats["by_kind"]),
            "by_verdict": dict(_stats["by_verdict"]),
        }


# ====== caller_context (optional metadata) ======
#
# Optional categorical metadata describing how a call was funded. Used only as
# a convenience field on the receipt for downstream consumers who want to
# attribute their own calls. NOT required, NOT aggregated, NOT published.
#
# Common values (free string, not enforced):
#   payment_type: "agent_wallet" | "operator_prefund" | "hybrid" | "none" | "unspecified"
#   caller_type: "autonomous_agent" | "human_approved" | "ci_pipeline" | "ide_assistant" | "unspecified"
#   wallet_provider: free string; common values include coinbase_cdp / privy /
#                    turnkey / stripe_mpp / x402 / vincent / skyfire / kite_ai /
#                    agentcash / olas / etc. Generic strings like "other" /
#                    "none" / "unspecified" are also fine.
#
# Shape validation only (object, max 8 keys, max 64-char string values, depth
# 1). No enum check, no aggregation, no public dashboard.

_CALLER_CTX_MAX_KEYS = 8
_CALLER_CTX_VAL_CAP = 64


def _normalize_caller_context(raw) -> dict:
    """Optional caller_context. Accepts None / dict; returns sanitized dict
    (possibly empty). Never rejects. Strings capped at 64 chars; max 8 keys.

    The receipt issuance includes whatever caller_context the caller chose to
    provide, as informational metadata. Empty dict if nothing supplied.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        return {}
    out: dict = {}
    for k, v in list(raw.items())[:_CALLER_CTX_MAX_KEYS]:
        if not isinstance(k, str):
            continue
        key = k[:_CALLER_CTX_VAL_CAP]
        if isinstance(v, str):
            out[key] = v[:_CALLER_CTX_VAL_CAP]
        elif isinstance(v, (int, float, bool)) or v is None:
            out[key] = v
        # other types silently dropped
    return out


# ====== Core verify wrapper (used by both REST and MCP) ======

def _payload_metadata(claim: str, evidence, context) -> dict:
    """Compute non-PII-bearing metadata about a payload for trace logging.

    Avoids storing top-level evidence key NAMES verbatim (reviewer C v2: keys
    like "my_number", "passport_no", "card" leak the shape of the data even
    when the values are gone). Instead we store key count + the SHA-256 prefix
    of each sorted key — preserves uniqueness for analytics, reveals nothing.
    """
    claim_str = claim if isinstance(claim, str) else ""
    ctx_str = context if isinstance(context, str) else ""
    ev_key_count = 0
    ev_key_hashes: list[str] = []
    if isinstance(evidence, dict):
        keys = sorted(str(k)[:64] for k in list(evidence.keys())[:50])
        ev_key_count = len(keys)
        ev_key_hashes = [
            hashlib.sha256(k.encode("utf-8", "replace")).hexdigest()[:8]
            for k in keys
        ]
    try:
        ev_size = len(json.dumps(evidence, ensure_ascii=False, default=str)) if evidence is not None else 0
    except Exception:
        ev_size = -1
    return {
        "claim_length": len(claim_str),
        "claim_sha256_16": hashlib.sha256(claim_str.encode("utf-8", "replace")).hexdigest()[:16],
        "evidence_type": type(evidence).__name__,
        "evidence_key_count": ev_key_count,
        "evidence_key_hashes": ev_key_hashes,
        "evidence_size_bytes": ev_size,
        "context_length": len(ctx_str),
    }


def _do_verify(claim, evidence, kind, context, caller_context, ip_hash, ua, headers) -> dict:
    """Run verifier, log trace (PII-free), bump stats. Returns verifier result dict
    augmented with an HMAC-attested AAR receipt.

    PII detection runs on the *raw* payload before any sanitisation, and any
    detection short-circuits to a 400-shaped result dict. Trace logging stores
    only metadata (lengths, hashes, key names) — never raw claim/evidence.

    caller_context is optional informational metadata, normalized via
    `_normalize_caller_context` (capped to 8 keys / 64-char strings).
    """
    # === PII guard at receipt (before any storage) ===
    pii_categories = pii_guard.scan_payload({
        "claim": claim,
        "evidence": evidence,
        "context": context,
    })
    blocking = [c for c in pii_categories if c in pii_guard.BLOCKING_CATEGORIES]
    if blocking:
        # Bump stats with a synthetic verdict to preserve observability.
        _bump_stats("rejected_pii", "rejected")
        # Trace the rejection. We log a count, not the category names — combined
        # with ip_hash this would otherwise leak per-IP "this party submitted a
        # マイナンバー-shaped string on day D" to anyone with read access.
        log_trace({
            "ts": _utc_iso(),
            "ip_hash": ip_hash,
            "user_agent": ua,
            "kind_dispatched": "rejected_pii",
            "kind_requested": kind,
            "verifier_used": "pii_guard",
            "verdict": "rejected",
            "confidence": 1.0,
            "latency_ms": 0,
            "pii_category_count": len(blocking),
            "payload_metadata": _payload_metadata(claim, evidence, context),
            "headers": headers,
        })
        # API response: NEVER echo the matched categories — that would turn
        # this endpoint into a free PII-shape oracle (submit candidate string,
        # learn whether the regex matched). Generic message only.
        return {
            "verdict": "rejected",
            "reasoning": pii_guard.reject_reason(blocking),
            "confidence": 1.0,
            "verifier_used": "pii_guard",
            "kind_dispatched": "rejected_pii",
            "_http_status": 400,
        }

    # === Normal path ===
    safe_claim = ""
    if isinstance(claim, str):
        safe_claim = claim[:PAYLOAD_STR_CAP]
    safe_evidence = _sanitize_payload(evidence)
    safe_context = context if isinstance(context, str) else None
    if isinstance(safe_context, str):
        safe_context = safe_context[:PAYLOAD_STR_CAP]

    t0 = time.monotonic()
    try:
        result = verifier.verify(safe_claim, safe_evidence, kind=kind, context=safe_context)
    except Exception as e:
        result = {
            "verdict": "uncertain",
            "reasoning": f"Verifier raised an exception ({type(e).__name__}); treat as uncertain.",
            "confidence": 0.0,
            "verifier_used": "exception",
            "kind_dispatched": "exception",
        }
    latency_ms = int((time.monotonic() - t0) * 1000)

    kind_actual = result.get("kind_dispatched") or "generic"
    legacy_verdict = result.get("verdict") or "uncertain"
    _bump_stats(kind_actual, legacy_verdict)

    # === AAR receipt issuance ===
    # Exceptions during verification map to `unsafe_to_verify` (the verifier
    # could not complete) rather than `insufficient_evidence` (the verifier
    # examined evidence and was inconclusive). The 4-value semantics matter:
    # consumers gating on receipts may treat the two differently.
    if kind_actual == "exception":
        aar_verdict = "unsafe_to_verify"
    else:
        aar_verdict = aar_schema.LEGACY_VERDICT_MAP.get(legacy_verdict, "unsafe_to_verify")
    aar_method = f"rule_based.{kind_actual}" if kind_actual in ("code_diff","db_op","file_op","api_call","generic") else "rule_based.unknown"
    # reason_codes: for v0 we lift the verifier's own reason codes if any,
    # otherwise reconstruct from reasoning text fragments.
    rcs = result.get("reason_codes")
    if not isinstance(rcs, list):
        # Reconstruct from the reasoning string by splitting on the standard separator.
        reasoning = result.get("reasoning") or ""
        rcs = [s.strip() for s in reasoning.split("|") if s.strip()][:8]
    receipt = aar_schema.issue_receipt(
        claim=safe_claim,
        evidence=safe_evidence,
        verifier_id=AAR_VERIFIER_ID,
        verifier_method=aar_method,
        verdict=aar_verdict,
        confidence=float(result.get("confidence") or 0.0),
        reason_codes=rcs,
        secret=AAR_SECRET,
        issued_by=AAR_ISSUED_BY,
        kid=AAR_KID,
        caller_context=caller_context or {},
    )

    log_trace({
        "ts": _utc_iso(),
        "ip_hash": ip_hash,
        "user_agent": ua,
        "kind_dispatched": kind_actual,
        "kind_requested": kind,
        "verifier_used": result.get("verifier_used"),
        "verdict": legacy_verdict,
        "aar_verdict": aar_verdict,
        "confidence": result.get("confidence"),
        "latency_ms": latency_ms,
        # PII-free metadata only — raw claim/evidence are never stored on disk.
        "payload_metadata": _payload_metadata(safe_claim, safe_evidence, safe_context),
        # caller_context is informational metadata, capped to 8 keys / 64-char strings.
        "caller_context": caller_context or {},
        "receipt_signature_prefix": receipt.get("signature","")[:32],
        "headers": headers,
    })

    # Attach receipt + AAR verdict to top-level result so REST + MCP both
    # expose the canonical 4-value verdict alongside the legacy 3-value one.
    # `verdict` is the legacy 3-value (ok/mismatch/uncertain) for backward
    # compat. `aar_verdict` is the canonical 4-value verify_action_receipt.v0
    # value (verified/contradicted/insufficient_evidence/unsafe_to_verify).
    result["aar_verdict"] = aar_verdict
    result["receipt"] = receipt
    return result


# ====== HTTP handler ======

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = ""
    sys_version = ""
    # Read timeout: BaseHTTPRequestHandler honours `timeout` for blocking
    # reads on slow clients. Combined with the per-connection socket timeout
    # in _ThreadingServer.get_request, this caps slow-loris exposure.
    timeout = 15

    def log_message(self, format, *args):  # noqa: A002
        pass

    def version_string(self) -> str:
        return ""

    def _client_ip(self) -> str:
        peer = self.client_address[0] if self.client_address else ""
        # Only honour CF-Connecting-IP when the immediate TCP peer is itself
        # inside a Cloudflare egress range (or loopback). From anywhere else,
        # the header is attacker-controllable and must be ignored.
        if _peer_in_cloudflare(peer):
            cf_ip = self.headers.get("CF-Connecting-IP")
            if cf_ip:
                return cf_ip
        return peer

    def _ip_hash(self) -> str:
        return hashlib.sha256(
            (SALT + self._client_ip()).encode("utf-8")
        ).hexdigest()[:16]

    def _headers_dict(self) -> dict:
        """Return only headers we trust to log. Sensitive headers
        (Authorization, Cookie, X-*-Token, etc.) are dropped at receipt."""
        return {
            k.lower(): v
            for k, v in self.headers.items()
            if k.lower() in SAFE_TRACE_HEADERS
        }

    def _path(self) -> str:
        p = urllib.parse.urlparse(self.path).path
        if len(p) > 1 and p.endswith("/"):
            p = p.rstrip("/") or "/"
        return p

    def _send(self, code: int, body, content_type: str = "text/html; charset=utf-8") -> None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_json(self, code: int, obj) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._send(code, body, content_type="application/json; charset=utf-8")

    def _send_429(self, retry_after: int = 30) -> None:
        """Send a proper 429 with JSON body and Retry-After header."""
        body = json.dumps({
            "error": "rate_limited",
            "retry_after_seconds": retry_after,
            "message": (
                f"Rate limit exceeded ({RATE_LIMIT_MAX} requests per "
                f"{int(RATE_LIMIT_WINDOW_SEC)} seconds per IP). "
                "Read-only endpoints (/about, /spec, /stats, /healthcheck, /tos, /privacy) "
                "are exempt; use those for browsing."
            ),
        }, ensure_ascii=False).encode("utf-8")
        self.send_response(429)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Retry-After", str(retry_after))
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # ----- GET -----
    def do_GET(self) -> None:
        path = self._path()
        ip_hash = self._ip_hash()
        ua = self.headers.get("User-Agent", "")
        headers = self._headers_dict()

        # Read-only metadata endpoints are rate-limit-exempt: browsing them
        # should never trip the limiter, even from a noisy crawler.
        if path not in RATE_LIMIT_EXEMPT_GETS and not rate_check(ip_hash):
            self._send_429(retry_after=30)
            log_access({"ts": _utc_iso(), "method": "GET", "path": path,
                        "status": 429, "ip_hash": ip_hash,
                        "user_agent": ua, "headers": headers})
            return

        if path == "/about":
            # /about is a permanent redirect to / so the canonical landing
            # is unambiguous; previously both served the same HTML which
            # external reviewers flagged as a possible misconfig.
            self.send_response(301)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            status = 301
        elif path == "/":
            self._send(200, ABOUT_PAGE)
            status = 200
        elif path == "/tos":
            self._send(200, TOS_PAGE)
            status = 200
        elif path == "/privacy":
            self._send(200, PRIVACY_PAGE)
            status = 200
        elif path == "/healthcheck":
            self._send(200, "ok", "text/plain")
            status = 200
        elif path == "/spec":
            self._send_json(200, _spec_doc())
            status = 200
        elif path == "/stats":
            self._send_json(200, _stats_snapshot())
            status = 200
        else:
            self._send(404, "Not Found", "text/plain")
            status = 404

        log_access({"ts": _utc_iso(), "method": "GET", "path": path,
                    "status": status, "ip_hash": ip_hash,
                    "user_agent": ua, "headers": headers})

    # ----- POST -----
    def do_POST(self) -> None:
        path = self._path()
        ip_hash = self._ip_hash()
        ua = self.headers.get("User-Agent", "")
        headers = self._headers_dict()

        if not rate_check(ip_hash):
            self._send_429(retry_after=30)
            log_access({"ts": _utc_iso(), "method": "POST", "path": path,
                        "status": 429, "ip_hash": ip_hash,
                        "user_agent": ua, "headers": headers})
            return

        if not global_post_check():
            self._send(503, "Service temporarily unavailable", "text/plain")
            log_access({"ts": _utc_iso(), "method": "POST", "path": path,
                        "status": 503, "ip_hash": ip_hash,
                        "user_agent": ua, "headers": headers,
                        "reason": "global_rate_limit"})
            return

        if path not in ("/verify", "/mcp"):
            self._send(404, "Not Found", "text/plain")
            log_access({"ts": _utc_iso(), "method": "POST", "path": path,
                        "status": 404, "ip_hash": ip_hash,
                        "user_agent": ua, "headers": headers})
            return

        try:
            cl = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            cl = 0
        if cl > MAX_BODY:
            self._send(413, "Payload too large", "text/plain")
            log_access({"ts": _utc_iso(), "method": "POST", "path": path,
                        "status": 413, "ip_hash": ip_hash,
                        "user_agent": ua, "headers": headers,
                        "content_length": cl})
            return

        try:
            body_bytes = self.rfile.read(cl) if cl > 0 else b""
        except Exception:
            self._send(400, "Bad request", "text/plain")
            return
        body_text = body_bytes.decode("utf-8", "replace")

        try:
            payload = json.loads(body_text) if body_text.strip() else {}
        except Exception:
            self._send_json(400, {"error": "invalid_json"})
            log_access({"ts": _utc_iso(), "method": "POST", "path": path,
                        "status": 400, "ip_hash": ip_hash,
                        "user_agent": ua, "headers": headers,
                        "reason": "invalid_json"})
            return

        if path == "/verify":
            self._handle_verify(payload, ip_hash, ua, headers, cl)
        else:
            self._handle_mcp(payload, ip_hash, ua, headers, cl)

    def _handle_verify(self, payload, ip_hash, ua, headers, cl):
        if not isinstance(payload, dict):
            self._send_json(400, {"error": "input_must_be_object"})
            return
        claim = payload.get("claim")
        evidence = payload.get("evidence")
        kind = payload.get("kind")
        context = payload.get("context")
        # caller_context is optional informational metadata; never rejected.
        caller_context = _normalize_caller_context(payload.get("caller_context"))
        result = _do_verify(claim, evidence, kind, context, caller_context, ip_hash, ua, headers)
        status = int(result.pop("_http_status", 200))
        self._send_json(status, result)
        log_access({"ts": _utc_iso(), "method": "POST", "path": "/verify",
                    "status": status, "ip_hash": ip_hash,
                    "user_agent": ua, "headers": headers,
                    "content_length": cl,
                    "verdict": result.get("verdict"),
                    "kind_dispatched": result.get("kind_dispatched")})

    def _handle_mcp(self, payload, ip_hash, ua, headers, cl):
        # Single JSON-RPC 2.0 request only (notifications & batch unsupported here).
        rpc_id = payload.get("id") if isinstance(payload, dict) else None
        method = payload.get("method") if isinstance(payload, dict) else None

        def _rpc_result(result):
            return {"jsonrpc": "2.0", "id": rpc_id, "result": result}

        def _rpc_error(code, message, data=None):
            err = {"code": code, "message": message}
            if data is not None:
                err["data"] = data
            return {"jsonrpc": "2.0", "id": rpc_id, "error": err}

        log_status = 200
        try:
            if method == "initialize":
                resp = _rpc_result({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "verify-action-mcp",
                        "version": verifier.VERIFIER_VERSION,
                    },
                })
            elif method == "tools/list":
                resp = _rpc_result({"tools": [_verify_action_tool_schema()]})
            elif method == "tools/call":
                params = payload.get("params") or {}
                tool_name = params.get("name")
                args = params.get("arguments") or {}
                if tool_name != "verify_action":
                    resp = _rpc_error(-32601, f"Unknown tool: {tool_name}")
                    log_status = 200  # JSON-RPC errors still 200 HTTP
                else:
                    claim = args.get("claim")
                    evidence = args.get("evidence")
                    kind = args.get("kind")
                    context = args.get("context")
                    caller_context = _normalize_caller_context(args.get("caller_context"))
                    result = _do_verify(claim, evidence, kind, context, caller_context, ip_hash, ua, headers)
                    is_rejected = result.pop("_http_status", 200) >= 400
                    resp = _rpc_result({
                        "content": [{
                            "type": "text",
                            "text": json.dumps(result, ensure_ascii=False),
                        }],
                        "isError": is_rejected,
                        "_structured_result": result,
                    })
            elif method in ("notifications/initialized", "ping"):
                # Non-result notification: respond with empty result.
                resp = _rpc_result({})
            else:
                resp = _rpc_error(-32601, f"Method not found: {method}")
        except Exception as e:
            resp = _rpc_error(-32603, "Internal error", data=type(e).__name__)
            log_status = 500

        self._send_json(log_status, resp)
        log_access({"ts": _utc_iso(), "method": "POST", "path": "/mcp",
                    "status": log_status, "ip_hash": ip_hash,
                    "user_agent": ua, "headers": headers,
                    "content_length": cl,
                    "mcp_method": method})

    def do_HEAD(self):    self._send(405, "Method Not Allowed", "text/plain")
    def do_PUT(self):     self._send(405, "Method Not Allowed", "text/plain")
    def do_DELETE(self):  self._send(405, "Method Not Allowed", "text/plain")
    def do_PATCH(self):   self._send(405, "Method Not Allowed", "text/plain")
    def do_OPTIONS(self): self._send(405, "Method Not Allowed", "text/plain")


# ====== Main ======

class _ThreadingServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    # Listen backlog: stdlib default is 5 which is too low; the kernel logs
    # "Possible SYN flooding" once that fills under modest concurrency. 128
    # is a common ceiling on Linux without sysctl tuning.
    request_queue_size = 128
    # Per-connection socket timeout — defeats slow-loris by capping how long
    # a single client can hold a connection without sending data.
    socket_timeout = 15.0

    def get_request(self):
        sock, addr = super().get_request()
        try:
            sock.settimeout(self.socket_timeout)
        except OSError:
            pass
        return sock, addr


def _shutdown(_signum, _frame):
    sys.exit(0)


def main() -> None:
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    server = _ThreadingServer((HOST, PORT), Handler)
    print(f"verify_action: listening on http://{HOST}:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
