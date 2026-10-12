/** Issue #6 Stage 2: durable root-signed attester authority and atomic replay admission.
 * Local SQLite consistency only; not cross-node consensus or durable recipient consent.
 */
import {DatabaseSync} from 'node:sqlite';
import * as ed from '@noble/ed25519';
import {validateWorthSchema,verifyContributionSignatures,type WorthContribution,type DomainScope} from './uds_worth_engine.js';
import {grantMessage,revocationMessage,type SignedCapabilityGrant,type RevocationEntry,type ConsentAuthority} from './uds_registry_replay.js';

const keyRe=/^[0-9a-fA-F]{64}$/,sigRe=/^[0-9a-fA-F]{128}$/;
const scopes=new Set<DomainScope>(['CARE_WORK','COMMUNITY_HEALING','SHADOW_INTEGRATION','ECOSYSTEM_BUILD']);
const fail=(reason:string):never=>{throw new Error('[UDS_AUTHORITY_ERROR]: '+reason);};
export interface SqliteGovernanceConfig {readonly dbPath:string;readonly rootAnchorPublicKey:string;readonly activeEpoch:number;readonly maxDriftMs?:number;}
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
 async accept(c:WorthContribution,consent:ConsentAuthority,evaluationTime=Date.now()):Promise<void>{
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
   const now=Date.now();
   const grant=this.db.prepare('SELECT authorized_domains,valid_from,valid_until,authority_epoch FROM capability_grants WHERE attester_public_key=?');
   const revoked=this.db.prepare('SELECT 1 FROM revocations WHERE target_public_key=?');
   const domains=new Set(c.verifiedActions.map(a=>a.domain));
   for(const a of c.verifiedActions)if(Math.abs(now-a.timestamp)>this.drift)fail('Timestamp drift at commit');
   for(const a of c.communityAttestations){
    const id=a.attesterPublicKey.toLowerCase();
    if(revoked.get(id))fail('Attester revoked at commit');
    const g=grant.get(id) as {authorized_domains:string;valid_from:number;valid_until:number;authority_epoch:number}|undefined;
    if(!g||g.authority_epoch!==this.epoch||now<g.valid_from||now>g.valid_until)fail('Inactive or stale attester grant');
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
   this.db.exec('COMMIT');
  }catch(e){this.db.exec('ROLLBACK');throw e;}
 }
 isKeyRevoked(key:string):boolean{return this.db.prepare('SELECT 1 FROM revocations WHERE target_public_key=?').get(key.toLowerCase())!==undefined;}
 isActionRecorded(id:string):boolean{return this.db.prepare('SELECT 1 FROM processed_actions WHERE action_id=?').get(id)!==undefined;}
 close():void{this.db.close();}
}
