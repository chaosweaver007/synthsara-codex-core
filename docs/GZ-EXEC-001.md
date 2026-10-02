# GZ-EXEC-001: governance to execution bridge

No Spiral without Authority. No Authority without Consent. No State Change
without Witness. No Witness without Provenance.

This version is a reviewable reference boundary, not a deployment claim.
`GateZeroContract` compiles trusted deterministic policy outcomes into a decision
and an Ed25519 authorization. RTME verifies the decision, signed context, actual
request, current policy and state before dispatching a registered handler.
Continuity Ledger audits the entire signed lineage against externally trusted
genesis roots and an expected receipt head.

## Trusted policy inputs

Configure the issuer's `policy(request)` callback inside the trusted governance
service. It must resolve authoritative consent records, actor, capability scopes,
purpose, recipient, revocation, expiry and the five rule IDs. It returns a mapping
from rule ID to `PASS`, `FAIL` or `INDETERMINATE`. A missing result is indeterminate;
any failure denies issuance. Raw prompts and model-generated booleans are not a
policy authority. `epistemic_verified=True` alone cannot pass the trusted policy.

`explicit_granted` is only an ALLOW candidate. Denied or revoked consent denies;
unclear, absent or disputed consent remains unresolved unless another rule fails.
`not_applicable` requires an explicit trusted exemption outcome, scoped to the
particular request. It does not manufacture a consent grant.

The request is JSON with `actor_id`, `adapter_id`, `parent_record_hash`, sorted
unique `capability_scope`, `purpose`, `recipient`, and `parameters`. Its complete
hash binds parameter values as well as context. Policy should require and resolve
a consent reference as appropriate for its domain. These contracts enforce
policy results; they do not algorithmically establish philosophical truth.

## Wire profile

The three schemas use JSON Schema Draft 2020-12. Nested objects disallow extra
properties. Runtime validation enforces format and timezone checks even when
optional jsonschema format dependencies are absent.

Canonical payloads are UTF-8 sorted-key compact JSON, prefixed with the domain
`SYNTHSARA:GZ-EXEC-001:<kind>` and a NUL byte. Values are objects, arrays, strings,
integers, booleans or null; floats are rejected. This is a restricted Python JSON
profile, not general RFC 8785. Arrays retain their order. Issuers sort and deduplicate
scopes. Every field is authenticated except the object's own hash and signature.
Authorization IDs are signed, and delimiter characters cannot alias fields.

The authorization signature commits to the decision hash. That commits to the
entire decision, including the exact rule trace. No separate unauthenticated ID
lookup substitutes for the decision object. The same wire module and schemas are
vendored into all three repositories; update them together and compare bytes.

## Persistence and limits

RTME initializes durable SQLite tables when its verifier starts. Nonce,
authorization ID and authorization hash are unique. A durable PENDING journal
reservation is committed before the handler runs; successful signed receipts and
head updates are committed together. Multiple wrappers sharing the same database
serialize state-changing execution. UNKNOWN outcomes record exception type only,
leave the recovery barrier in place, and never retry automatically.

External effects and a database commit cannot be made one atomic transaction.
A crash after effects but before sealing leaves a pending reservation requiring
operator reconciliation. An invalid handler result likewise leaves the durable
reservation. Do not delete the journal or clear nonces to retry. Reconciliation
and signed recovery events are future work.

SQLite is not physically immutable. Hashes and signatures provide tamper evidence;
independent genesis and head checkpoints detect prefix/suffix removal. Database
access controls, key isolation, sandboxing, consent-store transactions and a trusted
state reader are deployment responsibilities. The adapter signs its observations;
a signature alone does not prove that a dishonest adapter observed real effects.

## Integration

Core: `python -m pip install -r requirements-boundary.txt`, then import
`GateZeroContract`. Require a trusted policy callback; retain the resulting
decision alongside the authorization.

RTME: install `.[boundary]`, then import `AuthorizationVerifier` and
`ExecutionWrapper` from `rtme_harmonic.authorization_verifier` and
`rtme_harmonic.execution_wrapper`. Configure pinned public keys, an access-controlled
durable database, a live `current_policy(decision, request)` callback, a trusted
state reader and a registry of capability handlers. Handlers receive only the
verified request and return `(mutations, external_effects)`; the state reader
computes the resulting root. Policies must be coordinated with consent revocation
and outside writes. Arbitrary application code is not sandboxed by Python callbacks.

This new API is explicit opt-in. Existing RTME HMAC `action_gate.py` and the web
inference routes remain compatible and do not automatically use this bridge.
Do not label an existing deployment Ed25519-protected until all relevant action
entry points are routed through the configured wrapper and bypasses are removed.

Ledger: install `requirements-boundary.txt` and run
`python scripts/verify_receipt_chain.py tests/fixtures/boundary-bundle.json tests/fixtures/boundary-trust.json`.
Trust files must come from an independent source; receiving both bundle and keys
from the same untrusted sender does not establish provenance.

The fixture uses publicly reproducible TEST signing keys and two successful
transitions. It is for schema/interoperability/audit tests only; its authorization
window will expire. Never use those keys or fixture trust anchors in production.

## Verification

Core: `python -m pytest tests -q`.
RTME: `python -m pip install -e '.[test,mvp,boundary]'`, then
`python -m pytest tests -q`.
Ledger: `python -m pytest tests -q` and `python scripts/check_examples.py`.
The SCR-001 audit schema and its historical examples remain compatible. The new
execution receipt is a separate linked artifact; it does not relabel older audit
entries as cryptographic execution evidence.
