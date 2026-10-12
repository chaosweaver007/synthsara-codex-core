import {describe,it,expect} from 'vitest';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import * as ed from '@noble/ed25519';
import {SqliteGovernanceLedger,canonicalizeConsentRevocation,type WorthContribution,type ConsentAuthority} from '@synthsara/core';
import {AdmissionServer} from '../src/server.js';
import {DurableConsentAuthority} from '../src/consent.js';
const hex=(b:Uint8Array)=>Buffer.from(b).toString('hex');
const enc=new TextEncoder();
const token='integration_test_token_123456789';
const otherToken='alternate_token_123456789';
const allow:ConsentAuthority={isAuthorized:async()=>true};
async function fixture(){
 const root=ed.utils.randomPrivateKey(),attester=ed.utils.randomPrivateKey(),recipient=ed.utils.randomPrivateKey();
 const rootPub=hex(await ed.getPublicKeyAsync(root)),attPub=hex(await ed.getPublicKeyAsync(attester)),recPub=hex(await ed.getPublicKeyAsync(recipient));
 const now=Date.now();
 const grant={attesterPublicKey:attPub,authorizedDomains:['CARE_WORK' as const],validFrom:now-1000,validUntil:now+100000,nonce:'grant_service_123'};
 const grantMessage=enc.encode(JSON.stringify(['SYNTHSARA:UDS:GRANT:v1',grant.attesterPublicKey.toLowerCase(),[...grant.authorizedDomains].sort(),grant.validFrom,grant.validUntil,grant.nonce]));
 const contribution=async(id:string,actionId:string):Promise<WorthContribution>=>{
  const action={actionId,domain:'CARE_WORK' as const,timestamp:now,recipientPublicKey:recPub,recipientSignature:''};
  action.recipientSignature=hex(await ed.signAsync(enc.encode(JSON.stringify(['SYNTHSARA:UDS:ACTION:v1',id,'contributor',actionId,'CARE_WORK',now,recPub])),recipient));
  const signature=hex(await ed.signAsync(enc.encode(JSON.stringify(['SYNTHSARA:UDS:ATTEST:v1',id,'contributor',[[actionId,'CARE_WORK',now,recPub,action.recipientSignature]]])),attester));
  return {contributionId:id,contributorHash:'contributor',verifiedActions:[action],communityAttestations:[{attesterPublicKey:attPub,signature}]};
 };
 return {rootPub,recPub,recipient,now,signed:{grant,authoritySignature:hex(await ed.signAsync(grantMessage,root))},contribution};
}
async function setup(run:(ctx:{base:string;ledger:SqliteGovernanceLedger;f:Awaited<ReturnType<typeof fixture>>})=>Promise<void>,rateLimitPerMinute=60){
 const dir=mkdtempSync(join(tmpdir(),'uds-wire-'));const f=await fixture();
 const ledger=new SqliteGovernanceLedger({dbPath:join(dir,'ledger.sqlite'),rootAnchorPublicKey:f.rootPub,activeEpoch:1});
 const server=new AdmissionServer({ledger,consent:allow,authTokens:new Set([token,otherToken]),rateLimitPerMinute});
 try{
  await server.listen(0);
  const address=server.address();
  if(!address||typeof address==='string')throw new Error('Missing server address');
  await run({base:'http://127.0.0.1:'+address.port,ledger,f});
 }finally{await server.close();ledger.close();rmSync(dir,{recursive:true,force:true});}
}
const headers={'authorization':'Bearer '+token,'content-type':'application/json'};
describe('service v0.1 HTTP ingress',()=>{
 it('rejects missing and invalid bearer tokens',async()=>setup(async({base})=>{
  for(const authorization of [undefined,'Bearer invalid_token_value']){
   const response=await fetch(base+'/v1/admit',{method:'POST',headers:authorization?{authorization}:{}});
   expect(response.status).toBe(401);
  }
 }));
 it('commits one admission and returns durable replay and digest conflict',async()=>setup(async({base,ledger,f})=>{
  await ledger.registerGrant(f.signed);
  const contribution=await f.contribution('wire_c1','wire_a1');
  const body=JSON.stringify({contribution});
  const send=(payload:string)=>fetch(base+'/v1/admit',{method:'POST',headers:{...headers,'idempotency-key':'wire_key_123'},body:payload});
  const first=await send(body);expect(first.status).toBe(201);
  const receipt=await first.json();expect(receipt).toMatchObject({contributionId:'wire_c1',admitted:true});
  const retry=await send(body);expect(retry.status).toBe(200);expect(retry.headers.get('x-idempotent-replay')).toBe('true');
  expect(await retry.json()).toEqual(receipt);
  const conflict=await send(JSON.stringify({contribution:{...contribution,contributionId:'changed'}}));
  expect(conflict.status).toBe(409);
  expect(ledger.isActionRecorded('wire_a1')).toBe(true);
 }));
 it('persists signed consent withdrawal and exposes minimal verification',async()=>setup(async({base,ledger,f})=>{
  const revocation={recipientPublicKey:f.recPub,actionId:'withdrawn_1',revokedAt:f.now,revocationNonce:'withdrawal_123'};
  const signature=hex(await ed.signAsync(canonicalizeConsentRevocation(revocation),f.recipient));
  const response=await fetch(base+'/v1/revoke-consent',{method:'POST',headers,body:JSON.stringify({...revocation,recipientSignature:signature})});
  expect(response.status).toBe(200);
  expect(ledger.isConsentRevoked(f.recPub,'withdrawn_1')).toBe(true);
  const verify=await fetch(base+'/v1/verify/withdrawn_1',{headers});
  expect(verify.status).toBe(404); // unowned action existence must not be disclosed
 }));
 it('scopes verification to the submitting principal and invalidates admitted actions on recipient withdrawal',async()=>setup(async({base,ledger,f})=>{
  await ledger.registerGrant(f.signed);
  const contribution=await f.contribution('verify_c1','verify_a1');
  const admitted=await fetch(base+'/v1/admit',{method:'POST',headers:{...headers,'idempotency-key':'verify_key_001'},body:JSON.stringify({contribution})});
  expect(admitted.status).toBe(201);
  const before=await fetch(base+'/v1/verify/verify_a1',{headers});
  expect(before.status).toBe(200);
  expect(await before.json()).toEqual({actionId:'verify_a1',admitted:true,consentRevoked:false});
  const other=await fetch(base+'/v1/verify/verify_a1',{headers:{authorization:'Bearer '+otherToken}});
  expect(other.status).toBe(404);
  const revocation={recipientPublicKey:f.recPub,actionId:'verify_a1',revokedAt:f.now,revocationNonce:'verify_withdrawal_001'};
  const recipientSignature=hex(await ed.signAsync(canonicalizeConsentRevocation(revocation),f.recipient));
  const withdrawn=await fetch(base+'/v1/revoke-consent',{method:'POST',headers,body:JSON.stringify({...revocation,recipientSignature})});
  expect(withdrawn.status).toBe(200);
  const after=await fetch(base+'/v1/verify/verify_a1',{headers});
  expect(after.status).toBe(200);
  expect(await after.json()).toEqual({actionId:'verify_a1',admitted:false,consentRevoked:true});
 }));
 it('enforces rate limits and malformed body boundaries',async()=>setup(async({base})=>{
  const one=await fetch(base+'/v1/admit',{method:'POST',headers:{...headers,'idempotency-key':'wire_key_456'},body:'{'});
  expect(one.status).toBe(400);
  const two=await fetch(base+'/v1/verify/a',{headers});
  expect(two.status).toBe(429);
 },1));
});

describe('service v0.1 adversarial durability',()=>{
 it('replays a committed receipt after server and SQLite restart',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'uds-restart-'));
  const dbPath=join(dir,'ledger.sqlite');
  const f=await fixture();
  const contribution=await f.contribution('restart_c1','restart_a1');
  const body=JSON.stringify({contribution});
  const requestHeaders={...headers,'idempotency-key':'restart_key_001'};
  const openLedger=()=>new SqliteGovernanceLedger({dbPath,rootAnchorPublicKey:f.rootPub,activeEpoch:1});
  let ledger=openLedger();
  let server=new AdmissionServer({ledger,consent:allow,authTokens:new Set([token])});
  try{
   await ledger.registerGrant(f.signed);
   await server.listen(0);
   let address=server.address();
   if(!address||typeof address==='string')throw new Error('Missing server address');
   const first=await fetch('http://127.0.0.1:'+address.port+'/v1/admit',{method:'POST',headers:requestHeaders,body});
   expect(first.status).toBe(201);
   const receipt=await first.json();
   await server.close();
   ledger.close();
   ledger=openLedger();
   server=new AdmissionServer({ledger,consent:allow,authTokens:new Set([token])});
   await server.listen(0);
   address=server.address();
   if(!address||typeof address==='string')throw new Error('Missing restarted address');
   const replay=await fetch('http://127.0.0.1:'+address.port+'/v1/admit',{method:'POST',headers:requestHeaders,body});
   expect(replay.status).toBe(200);
   expect(replay.headers.get('x-idempotent-replay')).toBe('true');
   expect(await replay.json()).toEqual(receipt);
   expect(ledger.isActionRecorded('restart_a1')).toBe(true);
  }finally{
   await server.close().catch(()=>{});
   ledger.close();
   rmSync(dir,{recursive:true,force:true});
  }
 });
 it('serializes simultaneous same-key HTTP requests to one admission',async()=>setup(async({base,ledger,f})=>{
  await ledger.registerGrant(f.signed);
  const contribution=await f.contribution('parallel_c1','parallel_a1');
  const body=JSON.stringify({contribution});
  const send=()=>fetch(base+'/v1/admit',{method:'POST',headers:{...headers,'idempotency-key':'parallel_key_001'},body});
  const responses=await Promise.all([send(),send()]);
  expect(responses.map(r=>r.status).sort()).toEqual([200,201]);
  const receipts=await Promise.all(responses.map(r=>r.json()));
  expect(receipts[0]).toEqual(receipts[1]);
  expect(responses.map(r=>r.headers.get('x-idempotent-replay')).sort()).toEqual(['false','true']);
  expect(ledger.isActionRecorded('parallel_a1')).toBe(true);
 }));
});

describe('production consent authority',()=>{
 it('accepts canonical signed evidence and fails closed after durable withdrawal or malformed proof',async()=>setup(async({base,ledger,f})=>{
  await ledger.registerGrant(f.signed);
  const consent=new DurableConsentAuthority(ledger);
  const contribution=await f.contribution('consent_c1','consent_a1');
  expect(await consent.isAuthorized(contribution,Date.now())).toBe(true);
  const forged={...contribution,verifiedActions:[{...contribution.verifiedActions[0],recipientSignature:'0'.repeat(128)}]};
  // Tombstone policy does not replace core Ed25519 signature verification.
  const attempted=await fetch(base+'/v1/admit',{method:'POST',headers:{...headers,'idempotency-key':'forged_key_001'},body:JSON.stringify({contribution:forged})});
  expect(attempted.status).not.toBe(201);
  expect(ledger.isActionRecorded('consent_a1')).toBe(false);
  const revocation={recipientPublicKey:f.recPub,actionId:'consent_a1',revokedAt:f.now,revocationNonce:'consent_revocation_001'};
  await ledger.revokeConsent({...revocation,recipientSignature:hex(await ed.signAsync(canonicalizeConsentRevocation(revocation),f.recipient))});
  expect(await consent.isAuthorized(contribution,Date.now())).toBe(false);
  expect(await consent.isAuthorized({...contribution,verifiedActions:[]},Date.now())).toBe(false);
  expect(ledger.isActionRecorded('consent_a1')).toBe(false);
 }));
});
