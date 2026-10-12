# Production Admission Service v0.1 — Implementation Contract

Status: DRAFT / NOT PRODUCTION READY
Base: core main at 0c554e9 (PR #13)

## Scope
A single-instance Node 24 HTTP service in `packages/service/` wrapping the public `@synthsara/core` API. Never expose `calculateWorth` or the legacy replay engine. Preserve consent and governance checks; do not claim distributed consensus or blockchain minting.

## Planned routes
- `POST /v1/admit`: authenticate caller, validate bounded contribution JSON, enforce recipient consent and ledger admission, then return the admitted receipt. Require `Idempotency-Key`.
- `POST /v1/revoke-consent`: authenticate caller, validate a canonical signed consent-withdrawal request against the existing ledger contract, persist the tombstone.
- `GET /v1/verify/:actionId`: authenticated, privacy-minimal **local** admission status; no claim of independently verifiable cryptographic proof until receipt signing is implemented.

## Hard invariants
1. Authentication is not authorization or recipient consent. Enforce all independently.
2. Validate strict request schemas and signature domains; reject unknown fields, oversized bodies (64 KiB maximum), and malformed identifiers.
3. Idempotency keys must be scoped to authenticated principal and endpoint and bound to a canonical request digest. Same key/different digest -> 409. Never return a prior caller's receipt to a different principal.
4. **Do not** commit admission and idempotency in unrelated transactions. A lost response after admission commit must not turn a retry into a replay failure. Design one SQLite transaction spanning both writes, or implement a crash-safe recovery protocol before enabling `POST /v1/admit`.
5. Never treat socket disconnect as proof of rollback. Return stored outcome for same authorized request on retry.
6. `/verify` reports local state only. Do not expose contributor identity, raw evidence, or other private payloads.
7. Bound request rate, request lifetime, JSON nesting, and response size; fail closed for unavailable authorization/ledger dependencies.
8. Use constant-time comparisons for static API credentials; keep secrets out of logs, error messages, and source control.

## Required core integration review before implementation
- `UdsRuntimePipeline.submit()` currently commits through `SqliteGovernanceLedger.accept()`; it does not accept a caller-supplied SQLite transaction. The service **cannot** honestly promise atomic idempotency simply by writing a second table after `submit()`. Add a reviewed transaction-capable core API or a rigorously tested recovery design on a separate commit.
- Confirm `revokeConsent()` argument types, signature verification, and persistent action lookup in the current core. Do not assume `processed_actions` stores timestamps or signed admission receipts.
- Keep the existing core root-export whitelist unchanged unless a narrowly reviewed public capability is necessary.

## Acceptance tests
- Missing/invalid credentials -> 401; valid credentials without recipient authorization -> rejected.
- Forged signature and invalid canonical domain -> rejected without admission.
- Revocation and admission races -> only serializable, consent-compliant outcomes.
- Identical authorized idempotent retry after simulated lost HTTP response -> same receipt, one admission.
- Same idempotency key with altered body or principal -> rejected.
- Crash/restart around SQLite COMMIT -> no duplicate and no unrecoverable admitted-but-unrecorded response.
- Oversize/malformed JSON and rate limit -> bounded failure.
- Verification endpoint -> privacy-safe local status, no distributed-proof claims.
- Existing 34 core tests remain passing; new service integration suite, TypeScript build and audit pass in CI.

## Merge gate
Draft PR only until working implementation, adversarial tests, clean CI and independent Termux verification. No merge authorization is implied.
