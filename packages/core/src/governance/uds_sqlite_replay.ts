/**
 * UDS Issue #6, stage 1: local durable replay admission.
 * SQLite is a single-host transactional authority, NOT distributed consensus.
 * Never expose a raw insert method to unverified callers.
 */
import { DatabaseSync } from 'node:sqlite';
import { verifyContributionSignatures, validateWorthSchema, type WorthContribution } from './uds_worth_engine.js';
import { type ConsentAuthority, SovereignKeyRegistry } from './uds_registry_replay.js';

const fail = (reason: string): never => { throw new Error('[UDS_INTEGRITY_VIOLATION]: ' + reason); };
export interface SqliteReplayConfig {
  readonly dbPath: string;
  readonly maxDriftMs?: number;
}
export class SqliteReplayLedger {
  private readonly db: DatabaseSync;
  private readonly maxDriftMs: number;
  constructor(config: SqliteReplayConfig) {
    if (!config || typeof config.dbPath !== 'string' || !config.dbPath.trim())
      throw new Error('[UDS_CONFIG_ERROR]: dbPath required');
    const drift = config.maxDriftMs ?? 86_400_000;
    if (!Number.isSafeInteger(drift) || drift <= 0)
      throw new Error('[UDS_CONFIG_ERROR]: Invalid timestamp drift bound');
    this.maxDriftMs = drift;
    this.db = new DatabaseSync(config.dbPath);
    try {
      this.db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = 5000;');
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS accepted_contributions (
          contribution_id TEXT PRIMARY KEY,
          committed_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS processed_actions (
          action_id TEXT PRIMARY KEY,
          contributor_hash TEXT NOT NULL,
          action_timestamp INTEGER NOT NULL,
          contribution_id TEXT NOT NULL REFERENCES accepted_contributions(contribution_id)
        );
        CREATE TABLE IF NOT EXISTS processed_signatures (
          signature TEXT PRIMARY KEY,
          signature_type TEXT NOT NULL,
          contribution_id TEXT NOT NULL REFERENCES accepted_contributions(contribution_id)
        );
      `);
    } catch (error) { this.db.close(); throw error; }
  }

  /** Validate evidence, authority and consent BEFORE entering the synchronous SQLite transaction. */
  async accept(c: WorthContribution, registry: SovereignKeyRegistry,
    consent: ConsentAuthority, evaluationTime = Date.now()): Promise<void> {
    validateWorthSchema(c);
    if (!Number.isSafeInteger(evaluationTime) || evaluationTime <= 0)
      fail('Invalid evaluation time');
    if (!c.verifiedActions.length || !c.communityAttestations.length)
      fail('Evidence and attestation required');
    const domains = new Set(c.verifiedActions.map(a => a.domain));
    for (const a of c.communityAttestations)
      for (const domain of domains) registry.verifyAuthority(a.attesterPublicKey, domain, evaluationTime);
    for (const a of c.verifiedActions) {
      if (Math.abs(evaluationTime - a.timestamp) > this.maxDriftMs)
        fail('Timestamp drift');
    }
    await verifyContributionSignatures(c, registry.trustedKeys());
    if (!await consent.isAuthorized(c, evaluationTime))
      throw new Error('[UDS_CONSENT_ERROR]: Consent absent or revoked');
    // Recheck after async work. Durable revocation/consent synchronization is a later milestone.
    const commitTime = Date.now();
    for (const a of c.communityAttestations)
      for (const domain of domains) registry.verifyAuthority(a.attesterPublicKey, domain, commitTime);
    for (const a of c.verifiedActions) {
      if (Math.abs(commitTime - a.timestamp) > this.maxDriftMs)
        fail('Timestamp drift at commit');
    }
    // No await or external callback within this transaction. Unique constraints
    // provide all-or-nothing replay rejection across processes sharing this file.
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.prepare('INSERT INTO accepted_contributions (contribution_id, committed_at) VALUES (?, ?)')
        .run(c.contributionId, commitTime);
      const action = this.db.prepare(
        'INSERT INTO processed_actions (action_id, contributor_hash, action_timestamp, contribution_id) VALUES (?, ?, ?, ?)');
      const signature = this.db.prepare(
        'INSERT INTO processed_signatures (signature, signature_type, contribution_id) VALUES (?, ?, ?)');
      for (const a of c.verifiedActions) {
        action.run(a.actionId, c.contributorHash, a.timestamp, c.contributionId);
        signature.run(a.recipientSignature.toLowerCase(), 'RECIPIENT', c.contributionId);
      }
      for (const a of c.communityAttestations)
        signature.run(a.signature.toLowerCase(), 'ATTESTER', c.contributionId);
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      fail('Duplicate contribution, action or signature; transaction rolled back');
    }
  }
  isActionRecorded(actionId: string): boolean {
    return this.db.prepare('SELECT 1 FROM processed_actions WHERE action_id = ?')
      .get(actionId) !== undefined;
  }
  isSignatureRecorded(signature: string): boolean {
    return this.db.prepare('SELECT 1 FROM processed_signatures WHERE signature = ?')
      .get(signature.toLowerCase()) !== undefined;
  }
  close(): void { this.db.close(); }
}
