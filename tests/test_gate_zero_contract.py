import pytest
from nacl.signing import SigningKey
from gate_zero_contract import GateZeroContract
from gate_zero_wire import RULES, SecurityException, digest, verify


def evaluate(state, outcomes=None):
    key=SigningKey.generate()
    request={'actor_id':'test','adapter_id':'rtme','parent_record_hash':'sha256:'+'a'*64,
             'capability_scope':['rtme:manifest:stream'],'purpose':'test','recipient':'test',
             'parameters':{'text':'hello'}}
    if outcomes is None:
        outcomes={r:'PASS' for r in RULES}
    gate=GateZeroContract(key,lambda req:outcomes)
    dec,auth=gate.evaluate_request(request_hash=digest(request),actor_id='test',target_adapter='rtme',
        claim_layer='L3_COVENANT',epistemic_verified=True,consent_state=state,
        parent_record_hash=request['parent_record_hash'],requested_scopes=request['capability_scope'],
        request=request)
    if auth:
        verify('authorization',auth,key.verify_key)
        assert auth['decision_hash']==dec['decision_hash']
    return dec,auth


@pytest.mark.parametrize('state,verdict',[('explicit_granted','ALLOW'),('explicit_denied','DENY'),
    ('revoked','DENY'),('unclear','UNRESOLVED'),('absent','UNRESOLVED'),('disputed','UNRESOLVED')])
def test_consent_truth_table(state,verdict):
    dec,auth=evaluate(state)
    assert dec['verdict']==verdict
    assert (auth is not None)==(verdict=='ALLOW')


def test_missing_policy_results_never_authorize():
    dec,auth=evaluate('explicit_granted',{})
    assert dec['verdict']=='UNRESOLVED' and auth is None


def test_not_applicable_requires_explicit_policy_evaluation():
    outcomes={r:'PASS' for r in RULES if r!=RULES[1]}
    dec,auth=evaluate('not_applicable',outcomes)
    assert dec['verdict']=='UNRESOLVED' and auth is None
    assert evaluate('not_applicable')[1] is not None


@pytest.mark.parametrize('rule',RULES)
def test_each_policy_failure_blocks_token(rule):
    outcomes={r:'PASS' for r in RULES};outcomes[rule]='FAIL'
    dec,auth=evaluate('explicit_granted',outcomes)
    assert dec['verdict']=='DENY' and auth is None


def test_unknown_consent_rejected():
    with pytest.raises(SecurityException,match='unknown-consent-state'):
        evaluate('invented')
