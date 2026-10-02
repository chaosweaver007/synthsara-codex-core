"""Trusted policy service: policy outcomes never come from a raw prompt.

The injected policy must resolve active scoped consent, purpose, recipient,
revocation and capability allowance against authoritative records. It returns
five deterministic rule outcomes, including an explicitly evaluated exemption.
Missing outcomes fail closed. This contract does not infer ethics from text.
"""
from datetime import timedelta
import secrets
from gate_zero_wire import (RULES, SecurityException, canonical, consent_mapping,
                            digest, seal, timestamp, utcnow, verify_decision)


class GateZeroContract:
    def __init__(self, signing_key, policy, *, ttl_seconds=300):
        if not 0 < ttl_seconds <= 300:
            raise ValueError('ttl_seconds must be in (0, 300]')
        self.signing_key = signing_key
        self.policy = policy
        self.ttl_seconds = ttl_seconds

    def evaluate_request(self, *, request_hash, actor_id, target_adapter,
                         claim_layer, epistemic_verified, consent_state,
                         parent_record_hash, requested_scopes, request):
        import json
        request = json.loads(canonical(request))
        scopes = sorted(set(requested_scopes))
        if not scopes or len(scopes) != len(requested_scopes):
            raise SecurityException('empty-or-duplicate-scope')
        if digest(request) != request_hash:
            raise SecurityException('request-hash-mismatch')
        # These values are in the request hash as well as the signed token.
        for field, expected in [('actor_id', actor_id), ('adapter_id', target_adapter),
                                ('parent_record_hash', parent_record_hash),
                                ('capability_scope', scopes)]:
            if request.get(field) != expected:
                raise SecurityException('request-context-mismatch:' + field)
        consent_status, policy_path = consent_mapping(consent_state)
        outcomes = self.policy(request)
        if digest(request) != request_hash:
            raise SecurityException('policy-mutated-request')
        statuses = {rule: outcomes.get(rule, 'INDETERMINATE') for rule in RULES}
        if any(v not in ('PASS', 'FAIL', 'INDETERMINATE') for v in statuses.values()):
            raise SecurityException('invalid-policy-outcome')
        # Denial/ambiguity cannot be overridden by the policy or model.
        if consent_state != 'not_applicable' and consent_status != 'PASS':
            statuses[RULES[1]] = consent_status
        if not epistemic_verified:
            statuses[RULES[2]] = 'FAIL'
        # The verified flag describes the actual trusted rule outcome.
        verified = statuses[RULES[2]] == 'PASS'
        verdict = ('DENY' if 'FAIL' in statuses.values() else
                   'UNRESOLVED' if 'INDETERMINATE' in statuses.values() else 'ALLOW')
        decision = seal('decision', {
            'decision_id': 'gzd_' + secrets.token_hex(8),
            'timestamp': timestamp(utcnow()), 'request_hash': request_hash,
            'actor_id': actor_id, 'target_adapter': target_adapter,
            'epistemic_validation': {'claim_layer': claim_layer, 'verified': verified},
            'consent_evaluation': {'state': consent_state, 'policy_path': policy_path},
            'verdict': verdict,
            'rule_trace': [{'rule_id': r, 'status': statuses[r]} for r in RULES],
        })
        # Explicitly granted consent still requires policy confirmation.
        # verify_decision allows FAIL/INDETERMINATE for granted only below.
        verify_decision(decision)
        if verdict != 'ALLOW':
            return decision, None
        issued_at = utcnow()
        authorization = seal('authorization', {
            'authorization_id': 'auth_' + secrets.token_hex(8),
            'decision_id': decision['decision_id'], 'decision_hash': decision['decision_hash'],
            'request_hash': request_hash, 'parent_record_hash': parent_record_hash,
            'adapter_id': target_adapter, 'capability_scope': scopes,
            'issued_at': timestamp(issued_at),
            'valid_until': timestamp(issued_at + timedelta(seconds=self.ttl_seconds)),
            'nonce': secrets.token_hex(16), 'max_uses': 1,
        }, self.signing_key)
        return decision, authorization
