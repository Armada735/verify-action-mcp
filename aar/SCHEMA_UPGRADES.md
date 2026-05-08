# AAR receipt schema — upgrade path

This document is the deliberate place to look when planning changes to
`verify_action_receipt.v0`. It exists because chisiki q043 + multiple
reviewers flagged that without a documented migration path, schema changes
become breaking changes by accident.

The schema today (v0) is intentionally minimal. Anything not specified
here is out of scope for v0 and will be addressed in a future version.

---

## v0 (current) — HMAC-SHA256 + kid envelope

**Status**: shipped. Reference implementation only — not a canonical
inter-vendor standard.

**Properties**:
- Symmetric HMAC-SHA256 signature; single issuer per deployment.
- Every receipt carries a `kid` (key id). v0 ships with `kid="v0-default"`;
  operators rotating the signing secret SHOULD emit a fresh kid (e.g.
  `v0-2026-05`) so verifiers can pick the right secret.
- 4-value verdict: `verified` / `contradicted` / `insufficient_evidence`
  / `unsafe_to_verify`.
- `issued_by` defaults to the self-describing string `aar:reference-impl@v0`.
  Operators MAY override per deployment (e.g. once a stable domain is
  provisioned, switch to a `did:web:<domain>` identifier — but no fake
  domain placeholder is shipped).
- Content-addressed: raw claim and evidence are NOT in the receipt; only
  their SHA-256 hashes (`claim_hash`, `evidence_manifest_hash`).
- Required fields are enumerated in `schema.REQUIRED_FIELDS`; missing
  fields fail `validate_receipt`.

**What v0 is NOT**:
- Not a multi-issuer / federated trust system.
- Not asymmetric (no public key verification by external parties without
  the symmetric secret).
- Not a registry of `verifier_id` / `verifier_method` values — `verifier_id`
  is shape-checked (`name@version`) but not allow-listed.
- Not a legal authority claim. The receipt attests issuance and integrity,
  not factual truth or legal admissibility.

---

## v1 (planned) — ed25519 + multi-issuer + reason-code registry

**When**: triggered by **any** of the following — not by calendar time:

1. A second issuer wants to sign receipts under the same schema (e.g. a
   partner running their own AAR reference instance).
2. A consumer asks to verify a receipt without holding the symmetric
   secret (asymmetric verification).
3. `kill_criteria.S1` (3+ frameworks integrated) is met — at that point
   the schema becomes load-bearing for downstream and breaking changes
   become expensive.

**Planned changes**:

- **Signing**: ed25519 alongside HMAC-SHA256. `signature` field
  prefix becomes `ed25519:<base64>`. `verify_receipt_signature` already
  accepts both prefixes for forward compatibility; v1 will document the
  resolver.
- **Multi-issuer**: `issued_by` becomes a verifiable identifier (did:web,
  did:key, or a stable URL of a JWKS-equivalent). `kid` resolves against
  the issuer's published key set.
- **Verdict semantics**: unchanged (4-value). Reviewers explicitly asked us
  not to add a fifth verdict; ambiguity should be expressed via
  `confidence` and `reason_codes`, not new verdicts.
- **Reason-code catalogue**: v0 leaves `reason_codes` free-form. v1 will
  publish a registry under `aar/reason_codes/` with stable strings per
  verifier kind. Free-form codes remain valid; registered codes get a
  `aar:` prefix for unambiguous lookup.
- **Receipt schema string**: `verify_action_receipt.v1`. Consumers MUST
  reject unknown schema strings, so v0 receipts continue to validate
  against the v0 schema and v1 receipts validate against v1.

**What v1 is NOT** (deliberately deferred to v2 or later):
- Not a revocation list. Receipts are content-addressed and not revocable
  — once issued, integrity is fixed. v1 documents this property
  explicitly so consumers do not over-trust.
- Not a verdict-change protocol. If a verifier later changes its mind,
  it issues a new receipt; consumers compare timestamps and decide.
- Not a settlement / payment layer. AAR is post-action verification, not
  a marketplace primitive.

---

## v2+ — speculative

These are explicitly NOT planned for v1. They are listed here so that
future-us does not introduce them piecemeal under v1.

- Revocation lists (per-issuer revoked-receipt registries).
- Receipt chaining (cause-and-effect receipt graphs).
- Confidential receipts (encrypted claim/evidence with selective
  disclosure).
- Aggregation receipts (one receipt summarizing many).

---

## Compatibility rules

These rules are part of the schema contract:

1. **No silent breakage**: changing field semantics requires a new
   `schema` version string. Adding optional fields is a minor change but
   must be announced in this file.
2. **Required-field additions are major**: adding a new required field
   bumps the schema version. v0 receipts MUST continue to validate.
3. **kid is forever**: once a kid is used to sign receipts, the
   corresponding key MUST remain resolvable for as long as those
   receipts are referenced downstream. Operators rotating keys
   MUST keep old keys in their resolver.
4. **Schema strings are reserved**: `verify_action_receipt.v0`,
   `.v1`, `.v2`, etc., are reserved by this reference implementation.
   Forks MAY use a different prefix (`fork-aar-receipt.v0`) or namespace
   their own schemas to avoid collision.

---

## Change log

| Date | Schema | Change | Reason |
|---|---|---|---|
| 2026-05-07 | v0 | Initial release with HMAC-SHA256 + kid envelope | reference impl |
| 2026-05-07 | v0 | Removed `did:web:toa.example` placeholder; default `issued_by = "aar:reference-impl@v0"` | placeholder was misleading; reviewers flagged |
| 2026-05-07 | v0 | Added `kid` as required field (signed-over) | rotation envelope without v1 break |
