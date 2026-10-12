/**
 * UDS Axiom IV.IV — Sacred Order protects difference without scoring identity.
 * This metric recognizes verified contribution; it never represents human dignity.
 */
import * as ed from '@noble/ed25519';

export type DomainScope = 'CARE_WORK' | 'COMMUNITY_HEALING' | 'SHADOW_INTEGRATION' | 'ECOSYSTEM_BUILD';
export interface VerifiedAction {
  readonly actionId: string;
  readonly domain: DomainScope;
  readonly timestamp: number;
  readonly recipientPublicKey: string;
  readonly recipientSignature: string;
}
export interface CommunityAttestation {
  readonly attesterPublicKey: string;
  readonly signature: string;
}
export interface WorthContribution {
  readonly contributionId: string;
  readonly contributorHash: string;
  readonly verifiedActions: readonly VerifiedAction[];
  readonly communityAttestations: readonly CommunityAttestation[];
}
export interface WorthConfig {
  readonly maxScore: number;
  readonly actionDecayK: number;
  readonly maxAttestations: number;
}
export const DEFAULT_WORTH_CONFIG: Readonly<WorthConfig> = Object.freeze({
  maxScore: 100, actionDecayK: 0.15, maxAttestations: 12
});
const domains = new Set<DomainScope>(['CARE_WORK','COMMUNITY_HEALING','SHADOW_INTEGRATION','ECOSYSTEM_BUILD']);
const keyPattern = /^[0-9a-fA-F]{64}$/;
const sigPattern = /^[0-9a-fA-F]{128}$/;
const enc = new TextEncoder();
function fail(message: string): never { throw new Error(message); }
function record(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype)
    return fail('[UDS_SECURITY_VIOLATION]: Invalid plain object: ' + label);
  const obj = value as Record<string, unknown>;
  const actual = Reflect.ownKeys(obj);
  if (actual.some(k => typeof k !== 'string' || !keys.includes(k)))
    return fail('[UDS_SECURITY_VIOLATION]: Unexpected attribute in ' + label);
  if (actual.length !== keys.length || keys.some(k => !Object.prototype.hasOwnProperty.call(obj, k)))
    return fail('[UDS_SCHEMA_ERROR]: Missing required attribute in ' + label);
  for (const k of keys) {
    const desc = Object.getOwnPropertyDescriptor(obj, k);
    if (!desc || !('value' in desc)) return fail('[UDS_SECURITY_VIOLATION]: Accessor rejected');
  }
  return obj;
}
function nonempty(x: unknown): x is string {
  return typeof x === 'string' && x.length > 0 && x.trim() === x && x.length <= 256;
}
function key(x: unknown): x is string { return typeof x === 'string' && keyPattern.test(x); }
function signature(x: unknown): x is string { return typeof x === 'string' && sigPattern.test(x); }
export function validateWorthConfig(c: WorthConfig): void {
  if (!Number.isFinite(c.maxScore) || c.maxScore <= 0 ||
      !Number.isFinite(c.actionDecayK) || c.actionDecayK <= 0 ||
      !Number.isSafeInteger(c.maxAttestations) || c.maxAttestations <= 0)
    fail('[UDS_CONFIG_ERROR]: Invalid scoring configuration');
}
export function validateWorthSchema(input: unknown): asserts input is WorthContribution {
  const p = record(input, ['contributionId','contributorHash','verifiedActions','communityAttestations'], 'contribution');
  if (!nonempty(p.contributionId) || !nonempty(p.contributorHash))
    fail('[UDS_SCHEMA_ERROR]: Invalid contribution identifiers');
  if (!Array.isArray(p.verifiedActions) || !Array.isArray(p.communityAttestations) ||
      p.verifiedActions.length > 10000 || p.communityAttestations.length > 1000)
    fail('[UDS_SCHEMA_ERROR]: Invalid or oversized evidence arrays');
  for (const value of p.verifiedActions) {
    const a = record(value, ['actionId','domain','timestamp','recipientPublicKey','recipientSignature'], 'action');
    if (!nonempty(a.actionId) || !domains.has(a.domain as DomainScope) ||
        !Number.isSafeInteger(a.timestamp) || (a.timestamp as number) <= 0 ||
        !key(a.recipientPublicKey) || !signature(a.recipientSignature))
      fail('[UDS_SCHEMA_ERROR]: Malformed action evidence');
  }
  for (const value of p.communityAttestations) {
    const a = record(value, ['attesterPublicKey','signature'], 'attestation');
    if (!key(a.attesterPublicKey) || !signature(a.signature))
      fail('[UDS_SCHEMA_ERROR]: Malformed attestation evidence');
  }
}
function actionMessage(c: WorthContribution, a: VerifiedAction): Uint8Array {
  return enc.encode(JSON.stringify(['SYNTHSARA:UDS:ACTION:v1',c.contributionId,c.contributorHash,a.actionId,a.domain,a.timestamp,a.recipientPublicKey.toLowerCase()]));
}
function attestationMessage(c: WorthContribution): Uint8Array {
  const actions = c.verifiedActions.map(a => [a.actionId,a.domain,a.timestamp,a.recipientPublicKey.toLowerCase(),a.recipientSignature.toLowerCase()])
    .sort((a,b) => String(a[0]).localeCompare(String(b[0])));
  return enc.encode(JSON.stringify(['SYNTHSARA:UDS:ATTEST:v1',c.contributionId,c.contributorHash,actions]));
}
export async function verifyContributionSignatures(c: WorthContribution, trustedAttesters: ReadonlySet<string>): Promise<void> {
  validateWorthSchema(c);
  for (const a of c.verifiedActions) {
    const ok = await ed.verifyAsync(a.recipientSignature,actionMessage(c,a),a.recipientPublicKey);
    if (!ok) fail('[UDS_CRYPTO_ERROR]: Invalid recipient signature');
  }
  for (const a of c.communityAttestations) {
    if (!trustedAttesters.has(a.attesterPublicKey.toLowerCase()))
      fail('[UDS_CRYPTO_ERROR]: Untrusted attester');
    const ok = await ed.verifyAsync(a.signature,attestationMessage(c),a.attesterPublicKey);
    if (!ok) fail('[UDS_CRYPTO_ERROR]: Invalid community attestation');
  }
}
function uniqueCounts(c: WorthContribution): {actions:number;attesters:number} {
  const actions = new Map<string,string>();
  for (const a of c.verifiedActions) {
    const fingerprint = JSON.stringify([a.domain,a.timestamp,a.recipientPublicKey.toLowerCase(),a.recipientSignature.toLowerCase()]);
    const old = actions.get(a.actionId);
    if (old !== undefined && old !== fingerprint)
      fail('[UDS_INTEGRITY_VIOLATION]: Conflicting duplicate actionId');
    actions.set(a.actionId,fingerprint);
  }
  const attesters = new Map<string,string>();
  for (const a of c.communityAttestations) {
    const id = a.attesterPublicKey.toLowerCase(), sig = a.signature.toLowerCase();
    const old = attesters.get(id);
    if (old !== undefined && old !== sig)
      fail('[UDS_INTEGRITY_VIOLATION]: Conflicting attestation by signer');
    attesters.set(id,sig);
  }
  return {actions:actions.size,attesters:attesters.size};
}
/** Pure, bounded mathematical kernel; NOT a signature-verification bypass. */
export function boundedImpact(actionCount: number, attesterCount: number, config: WorthConfig = DEFAULT_WORTH_CONFIG): number {
  validateWorthConfig(config);
  if (!Number.isSafeInteger(actionCount) || actionCount < 0 ||
      !Number.isSafeInteger(attesterCount) || attesterCount < 0)
    fail('[UDS_CONFIG_ERROR]: Invalid counts');
  if (!actionCount) return 0;
  const consensus = (1 + Math.min(attesterCount,config.maxAttestations)/config.maxAttestations)/2;
  return Math.min(config.maxScore,config.maxScore * -Math.expm1(-config.actionDecayK*actionCount) * consensus);
}
/** Requires trusted attester registry. Caller must verify key ownership and consent authority separately. */
export async function calculateWorth(c: WorthContribution, trustedAttesters: ReadonlySet<string>,
  config: WorthConfig = DEFAULT_WORTH_CONFIG): Promise<number> {
  validateWorthConfig(config);
  validateWorthSchema(c);
  const counts = uniqueCounts(c);
  await verifyContributionSignatures(c,trustedAttesters);
  return Number(boundedImpact(counts.actions,counts.attesters,config).toFixed(4));
}
