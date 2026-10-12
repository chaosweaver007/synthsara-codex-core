import {describe,it,expect} from 'vitest';
import * as ed from '@noble/ed25519';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {SqliteReplayLedger} from './uds_sqlite_replay.js';
import {SovereignKeyRegistry,grantMessage,type CapabilityGrant,type ConsentAuthority} from './uds_registry_replay.js';
import type {WorthContribution} from './uds_worth_engine.js';

const hex=(b:Uint8Array)=>Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('');
const enc=new TextEncoder();
const allow:ConsentAuthority={isAuthorized:async()=>true};
async function fixture() {
  const root=ed.utils.randomPrivateKey(),attester=ed.utils.randomPrivateKey(),recipient=ed.utils.randomPrivateKey();
  const rootPub=hex(await ed.getPublicKeyAsync(root)),attPub=hex(await ed.getPublicKeyAsync(attester));
  const recPub=hex(await ed.getPublicKeyAsync(recipient));
  const registry=new SovereignKeyRegistry(rootPub),now=Date.now();
  const grant:CapabilityGrant={attesterPublicKey:attPub,authorizedDomains:['CARE_WORK'],
    validFrom:now-1000,validUntil:now+100000,nonce:'nonce_12345678'};
  await registry.registerGrant({grant,authoritySignature:hex(await ed.signAsync(grantMessage(grant),root))});
  const contribution=async(id:string,actionId:string):Promise<WorthContribution>=>{
    const action={actionId,domain:'CARE_WORK' as const,timestamp:now,recipientPublicKey:recPub,recipientSignature:''};
    action.recipientSignature=hex(await ed.signAsync(enc.encode(JSON.stringify(
      ['SYNTHSARA:UDS:ACTION:v1',id,'contributor',actionId,'CARE_WORK',now,recPub])),recipient));
    const sig=hex(await ed.signAsync(enc.encode(JSON.stringify(
      ['SYNTHSARA:UDS:ATTEST:v1',id,'contributor',[[actionId,'CARE_WORK',now,recPub,action.recipientSignature]]])),attester));
    return {contributionId:id,contributorHash:'contributor',verifiedActions:[action],
      communityAttestations:[{attesterPublicKey:attPub,signature:sig}]};
  };
  return {registry,now,contribution};
}
async function withDb(run:(path:string)=>Promise<void>) {
  const dir=mkdtempSync(join(tmpdir(),'uds-sqlite-'));
  try { await run(join(dir,'ledger.sqlite')); } finally { rmSync(dir,{recursive:true,force:true}); }
}
describe('Issue #6 SQLite durable replay',()=>{
  it('persists across close/reopen and rejects replay',async()=>withDb(async path=>{
    const f=await fixture(),c=await f.contribution('c1','a1');
    const first=new SqliteReplayLedger({dbPath:path});
    await first.accept(c,f.registry,allow,f.now);
    first.close();
    const reopened=new SqliteReplayLedger({dbPath:path});
    try {
      expect(reopened.isActionRecorded('a1')).toBe(true);
      expect(reopened.isSignatureRecorded(c.verifiedActions[0]!.recipientSignature)).toBe(true);
      await expect(reopened.accept(c,f.registry,allow,f.now)).rejects.toThrow(/Duplicate/);
    } finally {reopened.close();}
  }));
  it('rolls back an entire contribution when a signature collides',async()=>withDb(async path=>{
    const f=await fixture(),ledger=new SqliteReplayLedger({dbPath:path});
    try {
      const c1=await f.contribution('c1','a1');
      await ledger.accept(c1,f.registry,allow,f.now);
      const c2=await f.contribution('c2','a2');
      const collision={...c2,communityAttestations:c1.communityAttestations};
      // Forged attestation must be rejected before transaction.
      await expect(ledger.accept(collision,f.registry,allow,f.now)).rejects.toThrow();
      expect(ledger.isActionRecorded('a2')).toBe(false);
      await ledger.accept(c2,f.registry,allow,f.now);
    } finally {ledger.close();}
  }));
  it('rejects absent consent without writing replay records',async()=>withDb(async path=>{
    const f=await fixture(),ledger=new SqliteReplayLedger({dbPath:path});
    try {
      const c=await f.contribution('c1','a1');
      await expect(ledger.accept(c,f.registry,{isAuthorized:async()=>false},f.now)).rejects.toThrow(/CONSENT/);
      expect(ledger.isActionRecorded('a1')).toBe(false);
      await ledger.accept(c,f.registry,allow,f.now);
    } finally {ledger.close();}
  }));
  it('two independent SQLite connections admit exactly one duplicate',async()=>withDb(async path=>{
    const f=await fixture(),c=await f.contribution('c1','a1');
    const first=new SqliteReplayLedger({dbPath:path}),second=new SqliteReplayLedger({dbPath:path});
    try {
      const results=await Promise.allSettled([
        first.accept(c,f.registry,allow,f.now),second.accept(c,f.registry,allow,f.now)]);
      expect(results.filter(r=>r.status==='fulfilled')).toHaveLength(1);
      expect(results.filter(r=>r.status==='rejected')).toHaveLength(1);
      expect(second.isActionRecorded('a1')).toBe(true);
    } finally {first.close();second.close();}
  }));
  it('rejects forged recipient evidence without reserving action ID',async()=>withDb(async path=>{
    const f=await fixture(),ledger=new SqliteReplayLedger({dbPath:path});
    try {
      const c=await f.contribution('c1','a1');
      const forged={...c,verifiedActions:[{...c.verifiedActions[0]!,recipientSignature:'00'.repeat(64)}]};
      await expect(ledger.accept(forged,f.registry,allow,f.now)).rejects.toThrow();
      expect(ledger.isActionRecorded('a1')).toBe(false);
      await ledger.accept(c,f.registry,allow,f.now);
    } finally {ledger.close();}
  }));
});
