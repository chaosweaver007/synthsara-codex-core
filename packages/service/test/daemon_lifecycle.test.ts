/** Real consent authority over HTTP: valid evidence must fail after withdrawal. */
import {describe,it,expect} from 'vitest';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import * as ed from '@noble/ed25519';
import {SqliteGovernanceLedger,canonicalizeConsentRevocation,type WorthContribution} from '@synthsara/core';
import {AdmissionServer} from '../src/server.js';
import {DurableConsentAuthority} from '../src/consent.js';

const hex=(b:Uint8Array)=>Buffer.from(b).toString('hex');
const enc=new TextEncoder();
const token='daemon_lifecycle_test_token_123456789';
const headers={'authorization':'Bearer '+token,'content-type':'application/json'};

describe('production consent withdrawal over HTTP',()=>{
 it('rejects freshly and correctly signed evidence for a withdrawn action',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'uds-consent-wire-'));
  const root=ed.utils.randomPrivateKey(),attester=ed.utils.randomPrivateKey(),recipient=ed.utils.randomPrivateKey();
  const rootPub=hex(await ed.getPublicKeyAsync(root));
  const attPub=hex(await ed.getPublicKeyAsync(attester));
  const recPub=hex(await ed.getPublicKeyAsync(recipient));
  const now=Date.now();
  const ledger=new SqliteGovernanceLedger({dbPath:join(dir,'ledger.sqlite'),rootAnchorPublicKey:rootPub,activeEpoch:1});
  const server=new AdmissionServer({ledger,consent:new DurableConsentAuthority(ledger),authTokens:new Set([token])});
  try{
   const grant={attesterPublicKey:attPub,authorizedDomains:['CARE_WORK' as const],validFrom:now-1000,validUntil:now+100000,nonce:'grant_lifecycle_123'};
   const grantMessage=enc.encode(JSON.stringify(['SYNTHSARA:UDS:GRANT:v1',grant.attesterPublicKey.toLowerCase(),[...grant.authorizedDomains].sort(),grant.validFrom,grant.validUntil,grant.nonce]));
   await ledger.registerGrant({grant,authoritySignature:hex(await ed.signAsync(grantMessage,root))});
   const actionId='withdrawn_action_001';
   const signedContribution=async(id:string):Promise<WorthContribution>=>{
    const action={actionId,domain:'CARE_WORK' as const,timestamp:now,recipientPublicKey:recPub,recipientSignature:''};
    action.recipientSignature=hex(await ed.signAsync(enc.encode(JSON.stringify(['SYNTHSARA:UDS:ACTION:v1',id,'contributor',actionId,'CARE_WORK',now,recPub])),recipient));
    const signature=hex(await ed.signAsync(enc.encode(JSON.stringify(['SYNTHSARA:UDS:ATTEST:v1',id,'contributor',[[actionId,'CARE_WORK',now,recPub,action.recipientSignature]]])),attester));
    return {contributionId:id,contributorHash:'contributor',verifiedActions:[action],communityAttestations:[{attesterPublicKey:attPub,signature}]};
   };
   await server.listen(0,'127.0.0.1');
   const address=server.address();
   if(!address||typeof address==='string')throw new Error('Missing bound address');
   const base='http://127.0.0.1:'+address.port;
   const submit=(contribution:WorthContribution,key:string)=>fetch(base+'/v1/admit',{method:'POST',headers:{...headers,'idempotency-key':key},body:JSON.stringify({contribution})});
   const first=await submit(await signedContribution('consent_wire_c1'),'consent_wire_key_001');
   expect(first.status).toBe(201);
   expect(await first.json()).toMatchObject({contributionId:'consent_wire_c1',admitted:true});
   const before=await fetch(base+'/v1/verify/'+actionId,{headers});
   expect(before.status).toBe(200);
   expect(await before.json()).toEqual({actionId,admitted:true,consentRevoked:false});
   const revocation={recipientPublicKey:recPub,actionId,revokedAt:now,revocationNonce:'consent_wire_rev_001'};
   const recipientSignature=hex(await ed.signAsync(canonicalizeConsentRevocation(revocation),recipient));
   const withdrawal=await fetch(base+'/v1/revoke-consent',{method:'POST',headers,body:JSON.stringify({...revocation,recipientSignature})});
   expect(withdrawal.status).toBe(200);
   const after=await fetch(base+'/v1/verify/'+actionId,{headers});
   expect(after.status).toBe(200);
   expect(await after.json()).toEqual({actionId,admitted:false,consentRevoked:true});
   const second=await signedContribution('consent_wire_c2');
   const rejected=await submit(second,'consent_wire_key_002');
   expect(rejected.status).toBe(403);
   expect(await rejected.json()).toEqual({error:{code:'CONSENT_DENIED'}});
   expect(ledger.isActionRecorded(actionId)).toBe(true); // original receipt persists; status is revoked
   const unwithdrawn=await signedContribution('consent_wire_control_c3');
   // The same action ID remains withdrawn regardless of fresh, valid signatures.
   expect(await new DurableConsentAuthority(ledger).isAuthorized(unwithdrawn,Date.now())).toBe(false);
  }finally{
   await server.close().catch(()=>{});
   ledger.close();
   rmSync(dir,{recursive:true,force:true});
  }
 });
});
