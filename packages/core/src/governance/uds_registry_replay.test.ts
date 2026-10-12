import {describe,it,expect} from 'vitest';
import * as ed from '@noble/ed25519';
import {SovereignKeyRegistry, AtomicReplayLedger, grantMessage, revocationMessage,
  type CapabilityGrant, type ConsentAuthority} from './uds_registry_replay.js';
import type {WorthContribution} from './uds_worth_engine.js';
const hex=(b:Uint8Array)=>Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('');
const enc=new TextEncoder();
async function fixture(){
 const root=ed.utils.randomPrivateKey(),attester=ed.utils.randomPrivateKey(),recipient=ed.utils.randomPrivateKey();
 const rootPub=hex(await ed.getPublicKeyAsync(root)),attPub=hex(await ed.getPublicKeyAsync(attester));
 const recPub=hex(await ed.getPublicKeyAsync(recipient));
 const registry=new SovereignKeyRegistry(rootPub), now=Date.now();
 const grant:CapabilityGrant={attesterPublicKey:attPub,authorizedDomains:['CARE_WORK'],validFrom:now-1000,validUntil:now+100000,nonce:'nonce_12345678'};
 await registry.registerGrant({grant,authoritySignature:hex(await ed.signAsync(grantMessage(grant),root))});
 const contribution=async(id:string, actionId:string):Promise<WorthContribution>=>{
   const action={actionId,domain:'CARE_WORK' as const,timestamp:now,recipientPublicKey:recPub,recipientSignature:''};
   action.recipientSignature=hex(await ed.signAsync(enc.encode(JSON.stringify(['SYNTHSARA:UDS:ACTION:v1',id,'contributor',actionId,'CARE_WORK',now,recPub])),recipient));
   const att=hex(await ed.signAsync(enc.encode(JSON.stringify(['SYNTHSARA:UDS:ATTEST:v1',id,'contributor',[[actionId,'CARE_WORK',now,recPub,action.recipientSignature]]])),attester));
   return {contributionId:id,contributorHash:'contributor',verifiedActions:[action],communityAttestations:[{attesterPublicKey:attPub,signature:att}]};
 };
 return {root,attPub,registry,grant,now,contribution};
}
const allow:ConsentAuthority={isAuthorized:async()=>true};
describe('Issue #6: registry and atomic replay',()=>{
 it('rejects unknown, forged, and out-of-scope grants',async()=>{
  const f=await fixture();
  expect(()=>f.registry.verifyAuthority(f.attPub,'ECOSYSTEM_BUILD',f.now)).toThrow(/AUTHORITY/);
  const other=ed.utils.randomPrivateKey();
  const unknown=hex(await ed.getPublicKeyAsync(other));
  expect(()=>f.registry.verifyAuthority(unknown,'CARE_WORK',f.now)).toThrow(/AUTHORITY/);
  await expect(f.registry.registerGrant({grant:{...f.grant,attesterPublicKey:unknown,nonce:'nonce_99999999'},authoritySignature:'00'.repeat(64)})).rejects.toThrow();
 });
 it('rejects overwrite, duplicate nonce, and preserves monotonic revocation',async()=>{
  const f=await fixture();
  const signed={grant:f.grant,authoritySignature:hex(await ed.signAsync(grantMessage(f.grant),f.root))};
  await expect(f.registry.registerGrant(signed)).rejects.toThrow(/AUTHORITY/);
  const rev={targetPublicKey:f.attPub,revokedAt:f.now,reason:'COMPROMISED'};
  await f.registry.revokeKey({...rev,authoritySignature:hex(await ed.signAsync(revocationMessage(rev),f.root))});
  expect(()=>f.registry.verifyAuthority(f.attPub,'CARE_WORK',f.now)).toThrow(/revoked/);
  await expect(f.registry.registerGrant(signed)).rejects.toThrow(/AUTHORITY/);
 });
 it('accepts authentic consented contribution and blocks duplicate',async()=>{
  const f=await fixture(),ledger=new AtomicReplayLedger();
  const c=await f.contribution('c1','a1');
  await ledger.accept(c,f.registry,allow,f.now);
  expect(ledger.isActionRecorded('a1')).toBe(true);
  await expect(ledger.accept(c,f.registry,allow,f.now)).rejects.toThrow(/replay/);
 });
 it('rejects absent consent and leaves no replay state',async()=>{
  const f=await fixture(),ledger=new AtomicReplayLedger(),c=await f.contribution('c1','a1');
  await expect(ledger.accept(c,f.registry,{isAuthorized:async()=>false},f.now)).rejects.toThrow(/CONSENT/);
  expect(ledger.isActionRecorded('a1')).toBe(false);
  await ledger.accept(c,f.registry,allow,f.now);
 });
 it('rejects forged evidence without consuming action ID',async()=>{
  const f=await fixture(),ledger=new AtomicReplayLedger(),c=await f.contribution('c1','a1');
  const forged={...c,verifiedActions:[{...c.verifiedActions[0]!,recipientSignature:'00'.repeat(64)}]};
  await expect(ledger.accept(forged,f.registry,allow,f.now)).rejects.toThrow();
  expect(ledger.isActionRecorded('a1')).toBe(false);
  await ledger.accept(c,f.registry,allow,f.now);
 });
 it('rejects timestamp drift without state mutation',async()=>{
  const f=await fixture(),ledger=new AtomicReplayLedger(1000),c=await f.contribution('c1','a1');
  await expect(ledger.accept(c,f.registry,allow,f.now+2000)).rejects.toThrow(/drift/);
  expect(ledger.isActionRecorded('a1')).toBe(false);
 });
 it('concurrent identical submissions admit exactly one',async()=>{
  const f=await fixture(),ledger=new AtomicReplayLedger(),c=await f.contribution('c1','a1');
  const results=await Promise.allSettled([ledger.accept(c,f.registry,allow,f.now),ledger.accept(c,f.registry,allow,f.now)]);
  expect(results.filter(x=>x.status==='fulfilled')).toHaveLength(1);
  expect(results.filter(x=>x.status==='rejected')).toHaveLength(1);
 });
});
