# ADR-001: Atomic admission and idempotency

Status: PROPOSED — implementation blocked pending transactional core refactor
Branch: feat/service-v0.1-admission-daemon

## Observed source behavior
`UdsRuntimePipeline.submit(contribution,evaluationTime)` computes a score and calls `SqliteGovernanceLedger.accept(contribution,consent,evaluationTime)`.
`accept` validates signatures and external consent asynchronously, then enters a synchronous SQLite `BEGIN IMMEDIATE`, checks persisted grants, revocations and replay, inserts into `accepted_contributions`, `processed_actions` and `processed_signatures`, and commits. There is no transaction callback, idempotency key, receipt storage or public receipt lookup. `isActionRecorded` exposes only a boolean.

## Decision
Implement a **single SQLite transaction** for accepted contribution, action/signature replay rows and idempotency outcome. Do not put the idempotency write in a service-level transaction that occurs after `accept()`.

The authoritative write API should be a narrowly reviewed method of the existing `SqliteGovernanceLedger`, invoked by the public `UdsRuntimePipeline` facade; no direct public root export of the standalone scoring engine.

## Schema proposal
```sql
CREATE TABLE IF NOT EXISTS admission_idempotency (
  principal_hash TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  contribution_id TEXT NOT NULL REFERENCES accepted_contributions(contribution_id),
  receipt_payload TEXT NOT NULL,
  committed_at INTEGER NOT NULL,
  PRIMARY KEY (principal_hash, endpoint, idempotency_key)
);
```

Never store raw Bearer tokens, raw contribution payloads or recipient secrets. Use an authenticated principal identifier and a collision-resistant digest of canonicalized, validated request bytes including domain and API version. Compare the stored digest on retries. Same scoped key and different digest -> 409; same key from a different principal must not reveal a receipt.

## Transaction flow
1. Authenticate caller, validate body size/schema and key format; compute scoped digest.
2. Check whether a matching committed outcome exists. Do **not** use this preliminary read to authorize access or skip credential checks.
3. For a new request, verify signed evidence and external consent; compute bounded score privately.
4. Enter `BEGIN IMMEDIATE`. Re-check scoped idempotency key under the write lock. If present, require exact digest match and return the persisted receipt after commit/rollback as appropriate; do not re-run replay inserts.
5. If absent, re-check persisted consent withdrawal, grants, epoch and replay constraints **inside the same transaction**. Insert contribution/action/signature rows and the immutable receipt JSON into `admission_idempotency`. `COMMIT` once.
6. Only after the commit return the receipt. After a crash, a retry sees either the whole committed outcome or no outcome. A lost HTTP response does not undo the commit.

## Security caveats
- Cached receipt access is authorized for the same authenticated principal and matching request digest; evaluate whether current revocation policy requires withholding cached receipt detail, while preserving an honest historical admission status.
- Never accept an arbitrary score from an HTTP caller. The runtime computes it; ledger co-commits its receipt.
- Do not re-verify time-sensitive signatures as though a historical successful submission were a new submission. Verify the cached request digest and access rights instead.
- `Date.now()` drift and active grant windows are evaluated at **original admission**; replay returns historical state, not a fresh admission.
- If an idempotency key is absent, fail closed for the HTTP endpoint.
- A signed recipient action already present in the core is evidence authorization for that action; do not claim an additional independently signed service-consent object exists until explicitly specified.

## Test matrix before implementation is accepted
- New admission -> 201 and one durable action; identical retry -> 200 and identical receipt.
- Same key/different canonical body -> 409, no second admission.
- Same key/different principal -> no cross-principal disclosure.
- Two concurrent requests with same key -> one commit and identical outcomes.
- Crash immediately before commit -> no admission or receipt.
- Crash after commit but before HTTP reply -> retry returns committed receipt.
- Consent withdrawal or grant revocation before write lock -> admission rejected, no receipt.
- Forged signatures -> no admission or idempotency record.
- Restart and open new ledger instance -> same historical receipt.
- Existing 34 core tests remain green.

## Scope limitation
This ADR is a design and test contract, not implemented transactional behavior. Do not advertise the HTTP daemon or idempotent admission as complete.
