/** Issue #6 Stage 2: durable root-signed attester authority and atomic replay admission.
 * Local SQLite consistency only; not cross-node consensus.
 */
import {DatabaseSync} from 'node:sqlite';
import * as ed from '@noble/ed25519';
import {validateWorthSchema,verifyContributionSignatures,type WorthContribution,type DomainScope} from './uds_worth_engine.js';
import {grantMessage,revocationMessage,type SignedCapabilityGrant,type RevocationEntry,type ConsentAuthority} from './uds_registry_replay.js';

const keyRe=/^[0-9a-fA-F]{64}$/,sigRe=/^[0-9a-fA-F]{128}$/;
const scopes=new Set<DomainScope>(['CARE_WORK','COMMUNITY_HEALING','SHADOW_INTEGRATION','ECOSYSTEM_BUILD']);
const fail=(reason:string):never=>{throw new Error('[UDS_AUTHORITY_ERROR]: '+reason);};
export interface ConsentRevocationEntry {
 readonly recipientPublicKey:string;
 readonly actionId:string;
 readonly revokedAt:number;
 readonly revocationNonce:string;
 readonly recipientSignature:string;
}
export function canonicalizeConsentRevocation(entry:Omit<ConsentRevocationEntry,'recipientSignature'>):Uint8Array {
 return new TextEncoder().encode(JSON.stringify([
  'SYNTHSARA:UDS:CONSENT_REVOCATION:v1',
  entry.recipientPublicKey.toLowerCase(),entry.actionId,entry.revokedAt,entry.revocationNonce
 ]));
}
const consentFail=(reason:string):never=>{throw new Error('[UDS_CONSENT_ERROR]: '+reason);};
export interface SqliteGovernanceConfig {readonly dbPath:string;readonly rootAnchorPublicKey:string;readonly activeEpoch:number;readonly maxDriftMs?:number;}
export interface IdempotencyScope {
 readonly principalHash:string;
 readonly endpoint:string;
 readonly idempotencyKey:string;
 readonly requestDigest:string;
}
export interface AdmissionReceipt {
 readonly contributionId:string;
 readonly score:number;
 readonly admitted:true;
}
export interface IdempotentAdmissionResult {
 readonly receipt:AdmissionReceipt;
 readonly isReplay:boolean;
}
const idemFail=(reason:string):never=>{throw new Error('[UDS_IDEMPOTENCY_CONFLICT]: '+reason);};
export class SqliteGovernanceLedger {
 private readonly db:DatabaseSync;
 private readonly root:string;
 private readonly epoch:number;
 private readonly drift:number;
 constructor(config:SqliteGovernanceConfig) {
  if(!config||!keyRe.test(config.rootAnchorPublicKey)||!config.dbPath?.trim()||
     !Number.isSafeInteger(config.activeEpoch)||config.activeEpoch<=0)
    fail('Invalid root, database path or epoch');
  const drift=config.maxDriftMs??86_400_000;
  if(!Number.isSafeInteger(drift)||drift<=0)fail('Invalid timestamp drift');
  this.root=config.rootAnchorPublicKey.toLowerCase();this.epoch=config.activeEpoch;this.drift=drift;
  this.db=new DatabaseSync(config.dbPath);
  try {
   this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;');
   // Same replay tables as Stage 1. Existing Stage 1 receipts remain authoritative.
   this.db.exec(`
    CREATE TABLE IF NOT EXISTS accepted_contributions(contribution_id TEXT PRIMARY KEY,committed_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS processed_actions(action_id TEXT PRIMARY KEY,contributor_hash TEXT NOT NULL,action_timestamp INTEGER NOT NULL,contribution_id TEXT NOT NULL REFERENCES accepted_contributions(contribution_id));
    CREATE TABLE IF NOT EXISTS processed_signatures(signature TEXT PRIMARY KEY,signature_type TEXT NOT NULL,contribution_id TEXT NOT NULL REFERENCES accepted_contributions(contribution_id));
    CREATE TABLE IF NOT EXISTS authority_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),root_key TEXT NOT NULL,epoch INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS capability_grants(attester_public_key TEXT PRIMARY KEY,authorized_domains TEXT NOT NULL,valid_from INTEGER NOT NULL,valid_until INTEGER NOT NULL,nonce TEXT NOT NULL UNIQUE,authority_epoch INTEGER NOT NULL,authority_signature TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS used_grant_nonces(nonce TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS revocations(target_public_key TEXT PRIMARY KEY,revoked_at INTEGER NOT NULL,reason TEXT NOT NULL,authority_epoch INTEGER NOT NULL,authority_signature TEXT NOT NULL);
    -- Reserved for a future transaction-integrated admission API.
    -- This table alone does not make admission idempotent.
    CREATE TABLE IF NOT EXISTS admission_idempotency(
     principal_hash TEXT NOT NULL,
     endpoint TEXT NOT NULL,
     idempotency_key TEXT NOT NULL,
     request_digest TEXT NOT NULL,
     contribution_id TEXT NOT NULL REFERENCES accepted_contributions(contribution_id),
     receipt_payload TEXT NOT NULL,
     committed_at INTEGER NOT NULL,
     PRIMARY KEY(principal_hash,endpoint,idempotency_key)
    );
    CREATE TABLE IF NOT EXISTS consent_revocations(
     recipient_public_key TEXT NOT NULL,
     action_id TEXT NOT NULL,
     revoked_at INTEGER NOT NULL,
     revocation_nonce TEXT NOT NULL UNIQUE,
     recipient_signature TEXT NOT NULL,
     PRIMARY KEY(recipient_public_key,action_id)
    );
    CREATE TRIGGER IF NOT EXISTS prevent_consent_revocation_update
     BEFORE UPDATE ON consent_revocations BEGIN SELECT RAISE(ABORT,'consent revocation is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS prevent_consent_revocation_delete
     BEFORE DELETE ON consent_revocations BEGIN SELECT RAISE(ABORT,'consent revocation is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS prevent_revoked_grant BEFORE INSERT ON capability_grants
     WHEN EXISTS(SELECT 1 FROM revocations WHERE target_public_key=NEW.attester_public_key)
     BEGIN SELECT RAISE(ABORT,'revoked attester'); END;
   `);
   this.db.exec('BEGIN IMMEDIATE');
   try {
    this.db.prepare('INSERT OR IGNORE INTO authority_meta(singleton,root_key,epoch) VALUES(1,?,?)').run(this.root,this.epoch);
    const meta=this.db.prepare('SELECT root_key,epoch FROM authority_meta WHERE singleton=1').get() as {root_key:string;epoch:number};
    if(meta.root_key!==this.root||meta.epoch!==this.epoch)fail('Root or epoch mismatch with persisted authority');
    this.db.exec('COMMIT');
   }catch(e){this.db.exec('ROLLBACK');throw e;}
  }catch(e){this.db.close();throw e;}
 }
 async registerGrant(s:SignedCapabilityGrant):Promise<void>{
  const g=s?.grant;
  if(!g)fail('Malformed grant');
  if(!keyRe.test(g.attesterPublicKey)||!sigRe.test(s.authoritySignature)||
   !Number.isSafeInteger(g.validFrom)||!Number.isSafeInteger(g.validUntil)||
   g.validFrom<=0||g.validFrom>=g.validUntil||!/^[a-zA-Z0-9_-]{8,128}$/.test(g.nonce)||
   !Array.isArray(g.authorizedDomains)||!g.authorizedDomains.length||
   new Set(g.authorizedDomains).size!==g.authorizedDomains.length||
   !g.authorizedDomains.every(d=>scopes.has(d)))fail('Malformed grant');
  // Stage 2 retains the existing v1 root signature format; epoch is bound by persistent database metadata.
  if(!await ed.verifyAsync(s.authoritySignature,grantMessage(g),this.root))fail('Invalid root grant signature');
  this.db.exec('BEGIN IMMEDIATE');
  try{
   this.db.prepare('INSERT INTO used_grant_nonces(nonce) VALUES(?)').run(g.nonce);
   this.db.prepare('INSERT INTO capability_grants VALUES(?,?,?,?,?,?,?)').run(
    g.attesterPublicKey.toLowerCase(),JSON.stringify([...g.authorizedDomains].sort()),
    g.validFrom,g.validUntil,g.nonce,this.epoch,s.authoritySignature.toLowerCase());
   this.db.exec('COMMIT');
  }catch(e){this.db.exec('ROLLBACK');fail('Grant conflict, revoked key or reused nonce');}
 }
 async revokeKey(r:RevocationEntry):Promise<void>{
  if(!r||!keyRe.test(r.targetPublicKey)||!sigRe.test(r.authoritySignature)||
   !Number.isSafeInteger(r.revokedAt)||r.revokedAt<=0||
   typeof r.reason!=='string'||r.reason.length<1||r.reason.length>256)fail('Malformed revocation');
  if(!await ed.verifyAsync(r.authoritySignature,revocationMessage(r),this.root))fail('Invalid root revocation signature');
  this.db.exec('BEGIN IMMEDIATE');
  try{
   this.db.prepare('INSERT INTO revocations VALUES(?,?,?,?,?)').run(
    r.targetPublicKey.toLowerCase(),r.revokedAt,r.reason,this.epoch,r.authoritySignature.toLowerCase());
   this.db.prepare('DELETE FROM capability_grants WHERE attester_public_key=?').run(r.targetPublicKey.toLowerCase());
   this.db.exec('COMMIT');
  }catch(e){this.db.exec('ROLLBACK');fail('Duplicate or invalid revocation');}
 }
 async revokeConsent(entry:ConsentRevocationEntry):Promise<void>{
  if(!entry||!keyRe.test(entry.recipientPublicKey)||!sigRe.test(entry.recipientSignature)||
     typeof entry.actionId!=='string'||entry.actionId.length===0||entry.actionId.length>256||
     entry.actionId.trim()!==entry.actionId||
     !Number.isSafeInteger(entry.revokedAt)||entry.revokedAt<=0||
     typeof entry.revocationNonce!=='string'||!/^[a-zA-Z0-9_-]{8,128}$/.test(entry.revocationNonce))
   consentFail('Malformed consent revocation');
  const key=entry.recipientPublicKey.toLowerCase();
  const payload=canonicalizeConsentRevocation({
   recipientPublicKey:key,actionId:entry.actionId,revokedAt:entry.revokedAt,revocationNonce:entry.revocationNonce
  });
  if(!await ed.verifyAsync(entry.recipientSignature,payload,key))
   consentFail('Invalid recipient revocation signature');
  this.db.exec('BEGIN IMMEDIATE');
  try{
   this.db.prepare('INSERT INTO consent_revocations VALUES(?,?,?,?,?)').run(
    key,entry.actionId,entry.revokedAt,entry.revocationNonce,entry.recipientSignature.toLowerCase());
   this.db.exec('COMMIT');
  }catch(e){this.db.exec('ROLLBACK');consentFail('Duplicate withdrawal or reused nonce');}
 }
 isConsentRevoked(recipientPublicKey:string,actionId:string):boolean{
  if(!keyRe.test(recipientPublicKey))consentFail('Malformed recipient key');
  return this.db.prepare('SELECT 1 FROM consent_revocations WHERE recipient_public_key=? AND action_id=?')
   .get(recipientPublicKey.toLowerCase(),actionId)!==undefined;
 }
 async accept(c:WorthContribution,consent:ConsentAuthority,evaluationTime=Date.now()):Promise<void>{
  await this.acceptInternal(c,consent,evaluationTime);
 }
 /** Atomic admission and receipt storage; caller authentication and digest derivation occur at the service boundary. */
 async acceptWithIdempotency(c:WorthContribution,consent:ConsentAuthority,evaluationTime:number,scope:IdempotencyScope,score:number):Promise<IdempotentAdmissionResult>{
  if(!scope||!/^[0-9a-f]{64}$/.test(scope.principalHash)||!/^[0-9a-f]{64}$/.test(scope.requestDigest)||
   !/^[a-z0-9/_-]{1,80}$/.test(scope.endpoint)||!/^[A-Za-z0-9_-]{8,128}$/.test(scope.idempotencyKey)||
   !Number.isFinite(score)||score<0)idemFail('Invalid idempotency scope or score');
  const result=await this.acceptInternal(c,consent,evaluationTime,scope,score);
  if(!result)throw new Error('[UDS_IDEMPOTENCY_ERROR]: Missing committed receipt');
  return result;
 }
 /** Read-only preflight after transport authentication; never creates admission state. */
 lookupIdempotency(scope:IdempotencyScope):AdmissionReceipt|undefined{
  if(!scope||!/^[0-9a-f]{64}$/.test(scope.principalHash)||!/^[0-9a-f]{64}$/.test(scope.requestDigest)||
   !/^[a-z0-9/_-]{1,80}$/.test(scope.endpoint)||!/^[A-Za-z0-9_-]{8,128}$/.test(scope.idempotencyKey))
   idemFail('Invalid idempotency scope');
  return this.cached(scope);
 }
 private cached(scope:IdempotencyScope):AdmissionReceipt|undefined{
  const row=this.db.prepare('SELECT request_digest,receipt_payload FROM admission_idempotency WHERE principal_hash=? AND endpoint=? AND idempotency_key=?')
   .get(scope.principalHash,scope.endpoint,scope.idempotencyKey) as {request_digest:string;receipt_payload:string}|undefined;
  if(!row)return undefined;
  if(row.request_digest!==scope.requestDigest)idemFail('Key reused with different request');
  const receipt=JSON.parse(row.receipt_payload) as AdmissionReceipt;
  if(!receipt||receipt.admitted!==true||typeof receipt.contributionId!=='string'||!Number.isFinite(receipt.score))
   idemFail('Invalid persisted receipt');
  return Object.freeze(receipt);
 }
 private async acceptInternal(c:WorthContribution,consent:ConsentAuthority,evaluationTime:number,scope?:IdempotencyScope,score?:number):Promise<IdempotentAdmissionResult|undefined>{
  // Historical replay is resolved before time-dependent new-admission checks.
  if(scope){
   const previous=this.cached(scope);
   if(previous)return {receipt:previous,isReplay:true};
  }
  validateWorthSchema(c);
  if(!Number.isSafeInteger(evaluationTime)||evaluationTime<=0||!c.verifiedActions.length||!c.communityAttestations.length)
   fail('Invalid evaluation time or missing evidence');
  for(const a of c.verifiedActions)if(Math.abs(evaluationTime-a.timestamp)>this.drift)fail('Timestamp drift');
  // The canonical WORTH verifier checks domain-separated signed payloads.
  const trusted=new Set(c.communityAttestations.map(a=>a.attesterPublicKey.toLowerCase()));
  await verifyContributionSignatures(c,trusted);
  if(!await consent.isAuthorized(c,evaluationTime))throw new Error('[UDS_CONSENT_ERROR]: Consent absent or revoked');
  // No awaits from this point through COMMIT. All authority mutations use the same database lock.
  this.db.exec('BEGIN IMMEDIATE');
  try{
   // Re-check under BEGIN IMMEDIATE to close the concurrent retry window.
   if(scope){
    const previous=this.cached(scope);
    if(previous){this.db.exec('COMMIT');return {receipt:previous,isReplay:true};}
   }
   const now=Date.now();
   const grant=this.db.prepare('SELECT authorized_domains,valid_from,valid_until,authority_epoch FROM capability_grants WHERE attester_public_key=?');
   const revoked=this.db.prepare('SELECT 1 FROM revocations WHERE target_public_key=?');
   const domains=new Set(c.verifiedActions.map(a=>a.domain));
   const withdrawn=this.db.prepare('SELECT 1 FROM consent_revocations WHERE recipient_public_key=? AND action_id=?');
   for(const a of c.verifiedActions){
    if(withdrawn.get(a.recipientPublicKey.toLowerCase(),a.actionId))
     consentFail('Recipient consent withdrawn for action '+a.actionId);
   }
   for(const a of c.verifiedActions)if(Math.abs(now-a.timestamp)>this.drift)fail('Timestamp drift at commit');
   for(const a of c.communityAttestations){
    const id=a.attesterPublicKey.toLowerCase();
    if(revoked.get(id))fail('Attester revoked at commit');
    const g=grant.get(id) as {authorized_domains:string;valid_from:number;valid_until:number;authority_epoch:number}|undefined;
    if(!g)throw new Error('[UDS_AUTHORITY_ERROR]: Missing attester grant');
    if(g.authority_epoch!==this.epoch||now<g.valid_from||now>g.valid_until)fail('Inactive or stale attester grant');
    const authorized=JSON.parse(g.authorized_domains) as DomainScope[];
    if(!Array.isArray(authorized)||[...domains].some(d=>!authorized.includes(d)))fail('Out-of-scope attester');
   }
   this.db.prepare('INSERT INTO accepted_contributions VALUES(?,?)').run(c.contributionId,now);
   const action=this.db.prepare('INSERT INTO processed_actions VALUES(?,?,?,?)');
   const signature=this.db.prepare('INSERT INTO processed_signatures VALUES(?,?,?)');
   for(const a of c.verifiedActions){
    action.run(a.actionId,c.contributorHash,a.timestamp,c.contributionId);
    signature.run(a.recipientSignature.toLowerCase(),'RECIPIENT',c.contributionId);
   }
   for(const a of c.communityAttestations)signature.run(a.signature.toLowerCase(),'ATTESTER',c.contributionId);
   let receipt:AdmissionReceipt|undefined;
   if(scope){
    receipt=Object.freeze({contributionId:c.contributionId,score:score!,admitted:true as const});
    this.db.prepare('INSERT INTO admission_idempotency(principal_hash,endpoint,idempotency_key,request_digest,contribution_id,receipt_payload,committed_at) VALUES(?,?,?,?,?,?,?)')
     .run(scope.principalHash,scope.endpoint,scope.idempotencyKey,scope.requestDigest,c.contributionId,JSON.stringify(receipt),now);
   }
   this.db.exec('COMMIT');
   return receipt?{receipt,isReplay:false}:undefined;
  }catch(e){if(this.db.isTransaction)this.db.exec('ROLLBACK');throw e;}
 }
 isKeyRevoked(key:string):boolean{return this.db.prepare('SELECT 1 FROM revocations WHERE target_public_key=?').get(key.toLowerCase())!==undefined;}
 isActionRecorded(id:string):boolean{return this.db.prepare('SELECT 1 FROM processed_actions WHERE action_id=?').get(id)!==undefined;}
 close():void{this.db.close();}
}
