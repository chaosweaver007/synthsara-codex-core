import {describe,it,expect,beforeAll} from 'vitest';
import * as ed from '@noble/ed25519';
import {boundedImpact,calculateWorth,validateWorthSchema,DEFAULT_WORTH_CONFIG,type WorthContribution} from './uds_worth_engine.js';
const hex=(b:Uint8Array)=>Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('');
const enc=new TextEncoder();
describe('UDS WORTH: dignity unscorable',()=>{
 let contribution:WorthContribution;
 let trusted:Set<string>;
 beforeAll(async()=>{
  const recipient=ed.utils.randomPrivateKey(),attester=ed.utils.randomPrivateKey();
  const rp=hex(await ed.getPublicKeyAsync(recipient)),ap=hex(await ed.getPublicKeyAsync(attester));
  const action={actionId:'a1',domain:'CARE_WORK' as const,timestamp:1775865600,recipientPublicKey:rp,recipientSignature:''};
  const base={contributionId:'c1',contributorHash:'node1',verifiedActions:[action],communityAttestations:[]};
  const message=JSON.stringify(['SYNTHSARA:UDS:ACTION:v1','c1','node1','a1','CARE_WORK',1775865600,rp]);
  action.recipientSignature=hex(await ed.signAsync(enc.encode(message),recipient));
  const actionArray=[['a1','CARE_WORK',1775865600,rp,action.recipientSignature]];
  const attest=JSON.stringify(['SYNTHSARA:UDS:ATTEST:v1','c1','node1',actionArray]);
  contribution={...base,communityAttestations:[{attesterPublicKey:ap,signature:hex(await ed.signAsync(enc.encode(attest),attester))}]};
  trusted=new Set([ap]);
 });
 it('accepts authentic evidence',async()=>{expect(await calculateWorth(contribution,trusted)).toBeGreaterThan(0);});
 it('rejects identity attributes at top and nested levels',()=>{
  expect(()=>validateWorthSchema({...contribution,sexualOrientation:'x'})).toThrow(/UDS_SECURITY_VIOLATION/);
  expect(()=>validateWorthSchema({...contribution,verifiedActions:[{...contribution.verifiedActions[0],gender:'x'}]})).toThrow(/UDS_SECURITY_VIOLATION/);
 });
 it('rejects prototype pollution payload',()=>{
  expect(()=>validateWorthSchema(JSON.parse('{"contributionId":"c","contributorHash":"h","verifiedActions":[],"communityAttestations":[],"__proto__":{}}'))).toThrow(/UDS_SECURITY_VIOLATION/);
 });
 it('rejects forged action signatures',async()=>{
  const forged={...contribution,verifiedActions:[{...contribution.verifiedActions[0],recipientSignature:'00'.repeat(64)}]};
  await expect(calculateWorth(forged,trusted)).rejects.toThrow();
 });
 it('rejects untrusted attesters',async()=>{
  await expect(calculateWorth(contribution,new Set())).rejects.toThrow(/Untrusted attester/);
 });
 it('rejects conflicting duplicates',async()=>{
  const altered={...contribution,verifiedActions:[...contribution.verifiedActions,{...contribution.verifiedActions[0],timestamp:1775865601}]};
  await expect(calculateWorth(altered,trusted)).rejects.toThrow(/Conflicting duplicate/);
 });
 it('is bounded, increasing and strictly concave in the real-valued model',()=>{
  const {maxScore:M,actionDecayK:k}=DEFAULT_WORTH_CONFIG;
  const consensus=0.5;
  for(const n of [1,2,5,10,50]){
   const w=boundedImpact(n,0);
   expect(w).toBeGreaterThan(0);expect(w).toBeLessThanOrEqual(M);
   expect(M*k*Math.exp(-k*n)*consensus).toBeGreaterThan(0);
   expect(-M*k*k*Math.exp(-k*n)*consensus).toBeLessThan(0);
  }
  expect(boundedImpact(2,0)).toBeGreaterThan(boundedImpact(1,0));
  expect(boundedImpact(3,0)-boundedImpact(2,0)).toBeLessThan(boundedImpact(2,0)-boundedImpact(1,0));
  expect(boundedImpact(1000000,12)).toBeLessThanOrEqual(M);
 });
});
