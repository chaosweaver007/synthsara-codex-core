import {describe,it,expect} from 'vitest';
import * as ed from '@noble/ed25519';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {SqliteGovernanceLedger,canonicalizeConsentRevocation} from './uds_sqlite_authority.js';
import {grantMessage,revocationMessage,type CapabilityGrant,type ConsentAuthority} from './uds_registry_replay.js';
import type {WorthContribution} from './uds_worth_engine.js';
const hex=(b:Uint8Array)=>Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('');
const enc=new TextEncoder(),allow:ConsentAuthority={isAuthorized:async()=>true};
async function fixture(){
 const root=ed.utils.randomPrivateKey(),attester=ed.utils.randomPrivateKey(),recipient=ed.utils.randomPrivateKey();
 const rootPub=hex(await ed.getPublicKeyAsync(root)),attPub=hex(await ed.getPublicKeyAsync(attester)),recPub=hex(await ed.getPublicKeyAsync(recipient));
 const now=Date.now();
 const grant:CapabilityGrant={attesterPublicKey:attPub,authorizedDomains:['CARE_WORK'],validFrom:now-1000,validUntil:now+100000,nonce:'nonce_12345678'};
 const signed={grant,authoritySignature:hex(await ed.signAsync(grantMessage(grant),root))};
 const contribution=async(id:string,actionId:string):Promise<WorthContribution>=>{
  const action={actionId,domain:'CARE_WORK' as const,timestamp:now,recipientPublicKey:recPub,recipientSignature:''};
  action.recipientSignature=hex(await ed.signAsync(enc.encode(JSON.stringify(['SYNTHSARA:UDS:ACTION:v1',id,'contributor',actionId,'CARE_WORK',now,recPub])),recipient));
  const signature=hex(await ed.signAsync(enc.encode(JSON.stringify(['SYNTHSARA:UDS:ATTEST:v1',id,'contributor',[[actionId,'CARE_WORK',now,recPub,action.recipientSignature]]])),attester));
  return {contributionId:id,contributorHash:'contributor',verifiedActions:[action],communityAttestations:[{attesterPublicKey:attPub,signature}]};
 };
 const revocation=async()=>{const entry={targetPublicKey:attPub,revokedAt:now,reason:'COMPROMISED'};
  return {...entry,authoritySignature:hex(await ed.signAsync(revocationMessage(entry),root))};};
 const consentRevocation=async(actionId:string,nonce:string,privateKey=recipient)=>{
  const entry={recipientPublicKey:recPub,actionId,revokedAt:now,revocationNonce:nonce};
  return {...entry,recipientSignature:hex(await ed.signAsync(canonicalizeConsentRevocation(entry),privateKey))};
 };
 return {rootPub,attPub,recPub,now,signed,contribution,revocation,consentRevocation};
}
async function withDb(run:(path:string)=>Promise<void>){
 const dir=mkdtempSync(join(tmpdir(),'uds-authority-'));
 try{await run(join(dir,'ledger.sqlite'));}finally{rmSync(dir,{recursive:true,force:true});}
}
describe('Issue #6 stage 2 durable authority',()=>{
 it('persists grants and accepts canonical evidence after restart',async()=>withDb(async path=>{
  const f=await fixture(),a=new SqliteGovernanceLedger({dbPath:path,rootAnchorPublicKey:f.rootPub,activeEpoch:1});
  await a.registerGrant(f.signed);a.close();
  const b=new SqliteGovernanceLedger({dbPath:path,rootAnchorPublicKey:f.rootPub,activeEpoch:1});
  try{await b.accept(await f.contribution('c1','a1'),allow,f.now);expect(b.isActionRecorded('a1')).toBe(true);}
  finally{b.close();}
 }));
 it('revocation is durable, monotonic, and prevents regrant',async()=>withDb(async path=>{
  const f=await fixture(),a=new SqliteGovernanceLedger({dbPath:path,rootAnchorPublicKey:f.rootPub,activeEpoch:1});
  await a.registerGrant(f.signed);await a.revokeKey(await f.revocation());a.close();
  const b=new SqliteGovernanceLedger({dbPath:path,rootAnchorPublicKey:f.rootPub,activeEpoch:1});
  try{
   expect(b.isKeyRevoked(f.attPub)).toBe(true);
   await expect(b.registerGrant(f.signed)).rejects.toThrow();
   await expect(b.accept(await f.contribution('c1','a1'),allow,f.now)).rejects.toThrow(/revoked/);
   expect(b.isActionRecorded('a1')).toBe(false);
  }finally{b.close();}
 }));
 it('revocation on independent connection before admission rejects atomically',async()=>withDb(async path=>{
  const f=await fixture();
  const a=new SqliteGovernanceLedger({dbPath:path,rootAnchorPublicKey:f.rootPub,activeEpoch:1});
  const b=new SqliteGovernanceLedger({dbPath:path,rootAnchorPublicKey:f.rootPub,activeEpoch:1});
  try{
   await a.registerGrant(f.signed);
   const c=await f.contribution('c1','a1');
   await b.revokeKey(await f.revocation());
   await expect(a.accept(c,allow,f.now)).rejects.toThrow(/revoked/);
   expect(a.isActionRecorded('a1')).toBe(false);
  }finally{a.close();b.close();}
 }));
 it('deterministic mid-flight revocation during async consent gate rejects before transaction',async()=>withDb(async path=>{
  const f=await fixture();
  const a=new SqliteGovernanceLedger({dbPath:path,rootAnchorPublicKey:f.rootPub,activeEpoch:1});
  const b=new SqliteGovernanceLedger({dbPath:path,rootAnchorPublicKey:f.rootPub,activeEpoch:1});
  try{
   await a.registerGrant(f.signed);
   const c=await f.contribution('midflight','action_midflight');
   let callbackInvoked=false;
   const consent:ConsentAuthority={isAuthorized:async()=>{
    callbackInvoked=true;
    // Called after canonical signature verification, before A obtains its SQLite write lock.
    await b.revokeKey(await f.revocation());
    return true;
   }};
   await expect(a.accept(c,consent,f.now)).rejects.toThrow(/revoked at commit/);
   expect(callbackInvoked).toBe(true);
   expect(a.isActionRecorded('action_midflight')).toBe(false);
  }finally{a.close();b.close();}
 }));
 it('recipient-signed withdrawal survives restart and blocks valid admission',async()=>withDb(async path=>{
  const f=await fixture();
  const a=new SqliteGovernanceLedger({dbPath:path,rootAnchorPublicKey:f.rootPub,activeEpoch:1});
  await a.registerGrant(f.signed);
  const withdrawal=await f.consentRevocation('a1','nonce_consent_123');
  await a.revokeConsent(withdrawal);
  expect(a.isConsentRevoked(f.recPub,'a1')).toBe(true);
  await expect(a.revokeConsent(withdrawal)).rejects.toThrow(/CONSENT/);
  a.close();
  const b=new SqliteGovernanceLedger({dbPath:path,rootAnchorPublicKey:f.rootPub,activeEpoch:1});
  try{
   expect(b.isConsentRevoked(f.recPub,'a1')).toBe(true);
   await expect(b.accept(await f.contribution('c1','a1'),allow,f.now)).rejects.toThrow(/CONSENT/);
   expect(b.isActionRecorded('a1')).toBe(false);
   await b.accept(await f.contribution('c2','a2'),allow,f.now);
   expect(b.isActionRecorded('a2')).toBe(true);
  }finally{b.close();}
 }));
 it('rejects forged consent withdrawals and replayed nonce',async()=>withDb(async path=>{
  const f=await fixture(),a=new SqliteGovernanceLedger({dbPath:path,rootAnchorPublicKey:f.rootPub,activeEpoch:1});
  try{
   const valid=await f.consentRevocation('a1','nonce_consent_234');
   await expect(a.revokeConsent({...valid,actionId:'a2'})).rejects.toThrow(/CONSENT/);
   expect(a.isConsentRevoked(f.recPub,'a2')).toBe(false);
   await a.revokeConsent(valid);
   await expect(a.revokeConsent(await f.consentRevocation('a2','nonce_consent_234'))).rejects.toThrow(/CONSENT/);
   expect(a.isConsentRevoked(f.recPub,'a2')).toBe(false);
  }finally{a.close();}
 }));
 it('withdrawal committed during async consent checkpoint aborts admission',async()=>withDb(async path=>{
  const f=await fixture();
  const a=new SqliteGovernanceLedger({dbPath:path,rootAnchorPublicKey:f.rootPub,activeEpoch:1});
  const b=new SqliteGovernanceLedger({dbPath:path,rootAnchorPublicKey:f.rootPub,activeEpoch:1});
  try{
   await a.registerGrant(f.signed);
   const c=await f.contribution('c1','a1');
   const consent:ConsentAuthority={isAuthorized:async()=>{
    await b.revokeConsent(await f.consentRevocation('a1','nonce_consent_345'));
    return true;
   }};
   await expect(a.accept(c,consent,f.now)).rejects.toThrow(/CONSENT/);
   expect(a.isActionRecorded('a1')).toBe(false);
  }finally{a.close();b.close();}
 }));
 it('rejects wrong root/epoch and absent consent',async()=>withDb(async path=>{
  const f=await fixture(),a=new SqliteGovernanceLedger({dbPath:path,rootAnchorPublicKey:f.rootPub,activeEpoch:1});
  try{
   await a.registerGrant(f.signed);
   await expect(a.accept(await f.contribution('c1','a1'),{isAuthorized:async()=>false},f.now)).rejects.toThrow(/CONSENT/);
   expect(a.isActionRecorded('a1')).toBe(false);
   expect(()=>new SqliteGovernanceLedger({dbPath:path,rootAnchorPublicKey:f.rootPub,activeEpoch:2})).toThrow(/epoch mismatch/);
  }finally{a.close();}
 }));
});
