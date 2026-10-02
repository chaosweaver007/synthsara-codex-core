"""GZ-EXEC-001 wire format. Identical vendored file in all three repositories.

Canonical bytes are domain-separated UTF-8 sorted-key JSON (no floats).
All fields except the object's own hash/signature are authenticated.
This restricted profile is not a claim of general RFC 8785 conformance.
"""
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone
from jsonschema import Draft202012Validator, FormatChecker
from nacl.exceptions import BadSignatureError


class SecurityException(PermissionError):
    pass


HASH_FIELDS = {
    'decision': ('decision_hash', None),
    'authorization': ('authorization_hash', 'gatekeeper_signature'),
    'receipt': ('receipt_hash', 'adapter_signature'),
}
SCHEMAS = {
    'decision': 'gate-zero-decision.schema.json',
    'authorization': 'capability-authorization.schema.json',
    'receipt': 'execution_receipt.schema.json',
}


def canonical(value):
    def check(v):
        if v is None or type(v) in (str, bool, int):
            return
        if type(v) is list:
            for item in v:
                check(item)
            return
        if type(v) is dict and all(type(k) is str for k in v):
            for item in v.values():
                check(item)
            return
        raise SecurityException('unsupported-canonical-type')
    check(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def digest(value):
    return 'sha256:' + hashlib.sha256(canonical(value)).hexdigest()


def payload(kind, doc):
    excluded = set(HASH_FIELDS[kind])
    body = {k: v for k, v in doc.items() if k not in excluded}
    return b'SYNTHSARA:GZ-EXEC-001:' + kind.encode() + b'\x00' + canonical(body)


def validate(kind, doc):
    schema = json.loads((Path(__file__).parent / 'schemas' / SCHEMAS[kind]).read_text())
    errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(doc))
    if errors:
        raise SecurityException('schema-invalid:' + errors[0].json_path)
    for field in ('timestamp', 'execution_start', 'issued_at', 'valid_until'):
        if field in doc:
            try:
                parse_time(doc[field])
            except SecurityException as exc:
                raise SecurityException('schema-invalid:' + field) from exc
    canonical(doc)


def seal(kind, doc, key=None):
    result = json.loads(canonical(doc))
    hash_field, sig_field = HASH_FIELDS[kind]
    raw = payload(kind, result)
    result[hash_field] = 'sha256:' + hashlib.sha256(raw).hexdigest()
    if sig_field:
        result[sig_field] = 'ed25519:' + key.sign(raw).signature.hex()
    validate(kind, result)
    return result


def verify(kind, doc, key=None):
    validate(kind, doc)
    hash_field, sig_field = HASH_FIELDS[kind]
    raw = payload(kind, doc)
    if doc[hash_field] != 'sha256:' + hashlib.sha256(raw).hexdigest():
        raise SecurityException(kind + '-hash-mismatch')
    if sig_field:
        try:
            key.verify(raw, bytes.fromhex(doc[sig_field][8:]))
        except (BadSignatureError, ValueError, TypeError) as exc:
            raise SecurityException(kind + '-signature-invalid') from exc


def utcnow():
    return datetime.now(timezone.utc)


def timestamp(value):
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def parse_time(value):
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if result.tzinfo is None:
            raise ValueError('timezone required')
        return result.astimezone(timezone.utc)
    except (ValueError, TypeError) as exc:
        raise SecurityException('invalid-time') from exc


RULES = (
    'GZ-RULE-001-COERCION-CHECK',
    'GZ-RULE-002-CONSENT-AFFIRMATION',
    'GZ-RULE-003-EPISTEMIC-FIREWALL',
    'GZ-RULE-004-WORTH-SOVEREIGNTY',
    'GZ-RULE-005-HUMILITY-ANTI-DEIFICATION',
)


def verify_decision(dec):
    verify('decision', dec)
    trace = dec['rule_trace']
    if sorted(r['rule_id'] for r in trace) != sorted(RULES):
        raise SecurityException('incomplete-or-duplicate-rule-trace')
    statuses = {r['rule_id']: r['status'] for r in trace}
    state = dec['consent_evaluation']['state']
    status, path = consent_mapping(state)
    if state in ('not_applicable', 'explicit_granted'):
        # Exemption is an explicit trusted policy outcome, never automatic.
        status = statuses[RULES[1]]
    if dec['consent_evaluation']['policy_path'] != path or statuses[RULES[1]] != status:
        raise SecurityException('consent-mapping-mismatch')
    if (statuses[RULES[2]] == 'PASS') != dec['epistemic_validation']['verified']:
        raise SecurityException('epistemic-rule-mismatch')
    expected = ('DENY' if 'FAIL' in statuses.values() else
                'UNRESOLVED' if 'INDETERMINATE' in statuses.values() else 'ALLOW')
    if dec['verdict'] != expected:
        raise SecurityException('verdict-rule-mismatch')


def consent_mapping(state):
    if state == 'explicit_granted':
        return 'PASS', 'CONSENT_REQUIRED_GRANTED'
    if state in ('explicit_denied', 'revoked'):
        return 'FAIL', 'CONSENT_REQUIRED_DENIED'
    if state in ('unclear', 'absent', 'disputed'):
        return 'INDETERMINATE', 'CONSENT_AMBIGUOUS_UNRESOLVED'
    if state == 'not_applicable':
        return 'INDETERMINATE', 'EXEMPT_POLICY_EVALUATED'
    raise SecurityException('unknown-consent-state')
