/** UDS Issue #6: capability authority and replay defense.
 * In-memory reference implementation, NOT durable/distributed production storage.
 * Dignity is never scored; only verified contributions are recognized.
 */
import * as ed from '@noble/ed25519';
import { verifyContributionSignatures, validateWorthSchema, type DomainScope, type WorthContribution } from './uds_worth_engine.js';

const keyRe = /^[0-9a-fA-F]{64}$/;
const sigRe = /^[0-9a-fA-F]{128}$/;
const domains = new Set<DomainScope>(['CARE_WORK', 'COMMUNITY_HEALING', 'SHADOW_INTEGRATION', 'ECOSYSTEM_BUILD']);
const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const fail = (code: string, reason: string): never => { throw new Error(`[${code}]: ${reason}`); };
const validKey = (key: string) => typeof key === 'string' && keyRe.test(key);
const validSignature = (sig: string) => typeof sig === 'string' && sigRe.test(sig);
const finiteTime = (time: number) => Number.isSafeInteger(time) && time > 0;

export interface CapabilityGrant {
  readonly attesterPublicKey: string;
  readonly authorizedDomains: readonly DomainScope[];
  readonly validFrom: number;
  readonly validUntil: number;
  readonly nonce: string;
}
export interface SignedCapabilityGrant {
  readonly grant: CapabilityGrant;
  readonly authoritySignature: string;
}
export interface RevocationEntry {
  readonly targetPublicKey: string;
  readonly revokedAt: number;
  readonly reason: string;
  readonly authoritySignature: string;
}
export const grantMessage = (grant: CapabilityGrant): Uint8Array =>
  encode(['SYNTHSARA:UDS:GRANT:v1', grant.attesterPublicKey.toLowerCase(),
    [...grant.authorizedDomains].sort(), grant.validFrom, grant.validUntil, grant.nonce]);
export const revocationMessage = (revocation: Omit<RevocationEntry, 'authoritySignature'>): Uint8Array =>
  encode(['SYNTHSARA:UDS:REVOKE:v1', revocation.targetPublicKey.toLowerCase(),
    revocation.revokedAt, revocation.reason]);

/** Root-key verification protects mutation. Root-key custody and persistence are external. */
export class SovereignKeyRegistry {
  private readonly grants = new Map<string, CapabilityGrant>();
  private readonly revocations = new Set<string>();
  private readonly nonces = new Set<string>();
  private readonly root: string;
  constructor(rootAnchorPublicKey: string) {
    if (!validKey(rootAnchorPublicKey)) fail('UDS_REGISTRY_ERROR', 'Invalid root public key');
    this.root = rootAnchorPublicKey.toLowerCase();
  }
  async registerGrant(signed: SignedCapabilityGrant): Promise<void> {
    const g = signed.grant;
    if (!g || !validKey(g.attesterPublicKey) || !validSignature(signed.authoritySignature) ||
        !finiteTime(g.validFrom) || !finiteTime(g.validUntil) || g.validFrom >= g.validUntil ||
        typeof g.nonce !== 'string' || !/^[a-zA-Z0-9_-]{8,128}$/.test(g.nonce) ||
        !Array.isArray(g.authorizedDomains) || g.authorizedDomains.length === 0 ||
        new Set(g.authorizedDomains).size !== g.authorizedDomains.length ||
        !g.authorizedDomains.every(d => domains.has(d)))
      fail('UDS_AUTHORITY_ERROR', 'Invalid grant');
    const id = g.attesterPublicKey.toLowerCase();
    if (this.revocations.has(id) || this.grants.has(id) || this.nonces.has(g.nonce))
      fail('UDS_AUTHORITY_ERROR', 'Grant overwrite, revocation or nonce reuse');
    if (!await ed.verifyAsync(signed.authoritySignature, grantMessage(g), this.root))
      fail('UDS_CRYPTO_ERROR', 'Invalid root grant signature');
    // Recheck after async verification, before synchronous mutation.
    if (this.revocations.has(id) || this.grants.has(id) || this.nonces.has(g.nonce))
      fail('UDS_AUTHORITY_ERROR', 'Concurrent grant conflict');
    this.grants.set(id, Object.freeze({...g, attesterPublicKey: id,
      authorizedDomains: Object.freeze([...g.authorizedDomains])}));
    this.nonces.add(g.nonce);
  }
  async revokeKey(entry: RevocationEntry): Promise<void> {
    if (!entry || !validKey(entry.targetPublicKey) || !validSignature(entry.authoritySignature) ||
        !finiteTime(entry.revokedAt) || typeof entry.reason !== 'string' ||
        entry.reason.length < 1 || entry.reason.length > 256)
      fail('UDS_AUTHORITY_ERROR', 'Invalid revocation');
    if (!await ed.verifyAsync(entry.authoritySignature, revocationMessage(entry), this.root))
      fail('UDS_CRYPTO_ERROR', 'Invalid root revocation signature');
    const id = entry.targetPublicKey.toLowerCase();
    if (this.revocations.has(id)) fail('UDS_AUTHORITY_ERROR', 'Already revoked');
    this.revocations.add(id);
    this.grants.delete(id);
  }
  verifyAuthority(publicKey: string, domain: DomainScope, at = Date.now()): void {
    if (!validKey(publicKey) || !finiteTime(at)) fail('UDS_AUTHORITY_ERROR', 'Invalid authority query');
    const id = publicKey.toLowerCase();
    if (this.revocations.has(id)) fail('UDS_AUTHORITY_ERROR', 'Attester revoked');
    const g = this.grants.get(id);
    if (!g || at < g.validFrom || at > g.validUntil || !g.authorizedDomains.includes(domain))
      fail('UDS_AUTHORITY_ERROR', 'Missing, expired or out-of-scope capability');
  }
  trustedKeys(): ReadonlySet<string> { return new Set(this.grants.keys()); }
}

export interface ConsentAuthority {
  /** Must fail closed; false means consent is absent or revoked. */
  isAuthorized(contribution: WorthContribution, evaluationTime: number): Promise<boolean>;
}
export class AtomicReplayLedger {
  private readonly actionKeys = new Set<string>();
  private readonly signatures = new Set<string>();
  private readonly contributionIds = new Set<string>();
  constructor(readonly maxDriftMs = 86_400_000) {
    if (!Number.isSafeInteger(maxDriftMs) || maxDriftMs <= 0)
      fail('UDS_CONFIG_ERROR', 'Invalid timestamp drift bound');
  }
  /** Single-process atomic commit. Do not call before all cryptographic checks. */
  private commit(c: WorthContribution, now: number): void {
    const actions = new Set<string>();
    const signatures = new Set<string>();
    if (this.contributionIds.has(c.contributionId))
      fail('UDS_INTEGRITY_VIOLATION', 'Contribution replay');
    for (const a of c.verifiedActions) {
      if (Math.abs(now - a.timestamp) > this.maxDriftMs)
        fail('UDS_INTEGRITY_VIOLATION', 'Timestamp drift');
      // Action ID is global across contributors and epochs to prevent cross-epoch reuse.
      const actionId = a.actionId;
      if (this.actionKeys.has(actionId) || actions.has(actionId))
        fail('UDS_INTEGRITY_VIOLATION', 'Action replay');
      actions.add(actionId);
      const signature = a.recipientSignature.toLowerCase();
      if (this.signatures.has(signature) || signatures.has(signature))
        fail('UDS_INTEGRITY_VIOLATION', 'Recipient signature replay');
      signatures.add(signature);
    }
    for (const a of c.communityAttestations) {
      const signature = a.signature.toLowerCase();
      if (this.signatures.has(signature) || signatures.has(signature))
        fail('UDS_INTEGRITY_VIOLATION', 'Attestation signature replay');
      signatures.add(signature);
    }
    // No await between checking and mutating. All-or-nothing in one JS process.
    this.contributionIds.add(c.contributionId);
    for (const key of actions) this.actionKeys.add(key);
    for (const sig of signatures) this.signatures.add(sig);
  }
  async accept(c: WorthContribution, registry: SovereignKeyRegistry,
    consent: ConsentAuthority, now = Date.now()): Promise<void> {
    validateWorthSchema(c);
    if (!finiteTime(now)) fail('UDS_INTEGRITY_VIOLATION', 'Invalid evaluation time');
    if (!c.verifiedActions.length || !c.communityAttestations.length)
      fail('UDS_INTEGRITY_VIOLATION', 'Evidence and attestation required');
    const scopedDomains = new Set(c.verifiedActions.map(a => a.domain));
    for (const a of c.communityAttestations)
      for (const domain of scopedDomains) registry.verifyAuthority(a.attesterPublicKey, domain, now);
    await verifyContributionSignatures(c, registry.trustedKeys());
    if (!await consent.isAuthorized(c, now)) fail('UDS_CONSENT_ERROR', 'Consent absent or revoked');
    // Recheck after awaits to close revocation races in the same process.
    for (const a of c.communityAttestations)
      for (const domain of scopedDomains) registry.verifyAuthority(a.attesterPublicKey, domain, Date.now());
    this.commit(c, now);
  }
  isActionRecorded(actionId: string): boolean { return this.actionKeys.has(actionId); }
  isSignatureRecorded(signature: string): boolean { return this.signatures.has(signature.toLowerCase()); }
}
