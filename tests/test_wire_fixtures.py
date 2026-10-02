import json
from pathlib import Path
from nacl.signing import VerifyKey
from gate_zero_wire import verify, verify_decision


def test_three_schema_objects_and_real_signatures():
    root=Path(__file__).parent/'fixtures'
    bundle=json.loads((root/'boundary-bundle.json').read_text())
    trust=json.loads((root/'boundary-trust.json').read_text())
    for decision in bundle['decisions'].values():
        verify_decision(decision)
    for authorization in bundle['authorizations'].values():
        verify('authorization',authorization,VerifyKey(bytes.fromhex(trust['gatekeeper_pubkey_hex'])))
    for receipt in bundle['receipts']:
        verify('receipt',receipt,VerifyKey(bytes.fromhex(trust['adapter_pubkeys'][receipt['adapter_id']])))
