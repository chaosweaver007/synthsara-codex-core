import {describe,it,expect} from 'vitest';
import * as ed from '@noble/ed25519';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {SqliteGovernanceLedger,canonicalizeConsentRevocation} from '../governance/uds_sqlite_authority.js';
import {grantMessage,type ConsentAuthority} from '../governance/uds_registry_replay.js';
import type {WorthContribution} from '../governance/uds_worth_engine.js';
import {UdsRuntimePipeline} from './uds_runtime_pipeline.js';
const hex=(b:Uint8Array)=>Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('');
const enc=new TextEncoder();
async function fixture(){
 const root=ed.utils.randomPrivateKey(),att=ed.utils.randomPrivateKey(),rec=ed.utils.randomPrivateKey();
 const rootPub=hex(await ed.getPublicKeyAsync(root)),attPub=hex(await ed.getPublicKeyAsync(att)),recPub=hex(await ed.getPublicKeyAsync(rec));
 const now=Date.now();
 const grant={attesterPublicKey:attPub,authorizedDomains:['CARE_WORK' as const],validFrom:now-1000,validUntil:now+100000,nonce:'runtime_nonce_123'};
 const signed={grant,authoritySignature:hex(await ed.signAsync(grantMessage(grant),root))};
 const contribution=async(id:string,actionId:string):Promise<WorthContribution>=>{
  const action={actionId,domain:'CARE_WORK' as const,timestamp:now,recipientPublicKey:recPub,recipientSignature:''};
  action.recipientSignature=hex(await ed.signAsync(enc.encode(JSON.stringify(['SYNTHSARA:UDS:ACTION:v1',id,'contributor',actionId,'CARE_WORK',now,recPub])),rec));
  const signature=hex(await ed.signAsync(enc.encode(JSON.stringify(['SYNTHSARA:UDS:ATTEST:v1',id,'contributor',[[actionId,'CARE_WORK',now,recPub,action.recipientSignature]]])),att));
  return {contributionId:id,contributorHash:'contributor',verifiedActions:[action],communityAttestations:[{attesterPublicKey:attPub,signature}]};
 };
 const withdraw=async(actionId:string)=>{
  const entry={recipientPublicKey:recPub,actionId,revokedAt:now,revocationNonce:'runtime_withdraw_123'};
  return {...entry,recipientSignature:hex(await ed.signAsync(canonicalizeConsentRevocation(entry),rec))};
 };
 return {rootPub,now,signed,contribution,withdraw};
}
const allow:ConsentAuthority={isAuthorized:async()=>true};
async function withLedger(fn:(ledger:SqliteGovernanceLedger,f:Awaited<ReturnType<typeof fixture>>)=>Promise<void>){
 const dir=mkdtempSync(join(tmpdir(),'uds-runtime-'));const f=await fixture();
 const ledger=new SqliteGovernanceLedger({dbPath:join(dir,'ledger.sqlite'),rootAnchorPublicKey:f.rootPub,activeEpoch:1});
 try{await fn(ledger,f);}finally{ledger.close();rmSync(dir,{recursive:true,force:true});}
}
describe('UDS runtime admission wiring',()=>{
 it('emits bounded score only after durable admission',async()=>withLedger(async(ledger,f)=>{
  await ledger.registerGrant(f.signed);
  const receipt=await new UdsRuntimePipeline(ledger,allow).submit(await f.contribution('c1','a1'),f.now);
  expect(receipt).toEqual({contributionId:'c1',admitted:true,score:expect.any(Number)});
  expect(receipt.score).toBeGreaterThan(0);
  expect(receipt.score).toBeLessThanOrEqual(100);
  expect(ledger.isActionRecorded('a1')).toBe(true);
 }));
 it('does not emit a score without a registered attester grant',async()=>withLedger(async(ledger,f)=>{
  await expect(new UdsRuntimePipeline(ledger,allow).submit(await f.contribution('c1','a1'),f.now)).rejects.toThrow(/grant/);
  expect(ledger.isActionRecorded('a1')).toBe(false);
 }));
 it('does not emit a score after recipient withdrawal',async()=>withLedger(async(ledger,f)=>{
  await ledger.registerGrant(f.signed);
  await ledger.revokeConsent(await f.withdraw('a1'));
  await expect(new UdsRuntimePipeline(ledger,allow).submit(await f.contribution('c1','a1'),f.now)).rejects.toThrow(/CONSENT/);
  expect(ledger.isActionRecorded('a1')).toBe(false);
 }));
 it('does not emit a score on missing consent or replay',async()=>withLedger(async(ledger,f)=>{
  await ledger.registerGrant(f.signed);
  const c=await f.contribution('c1','a1');
  await expect(new UdsRuntimePipeline(ledger,{isAuthorized:async()=>false}).submit(c,f.now)).rejects.toThrow(/CONSENT/);
  expect(ledger.isActionRecorded('a1')).toBe(false);
  const pipeline=new UdsRuntimePipeline(ledger,allow);
  await pipeline.submit(c,f.now);
  await expect(pipeline.submit(c,f.now)).rejects.toThrow();
 }));
 it('rejects forged evidence without committing an action',async()=>withLedger(async(ledger,f)=>{
  await ledger.registerGrant(f.signed);
  const c=await f.contribution('c1','a1');
  const forged={...c,verifiedActions:[{...c.verifiedActions[0],recipientSignature:'00'.repeat(64)}]};
  await expect(new UdsRuntimePipeline(ledger,allow).submit(forged,f.now)).rejects.toThrow();
  expect(ledger.isActionRecorded('a1')).toBe(false);
 }));
});
