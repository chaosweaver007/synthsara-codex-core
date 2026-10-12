/** Runtime admission boundary: only return an admitted score after durable governance commit.
 * calculateWorth remains a standalone analytical function, not an admission receipt.
 */
import {calculateWorth,DEFAULT_WORTH_CONFIG,type WorthContribution,type WorthConfig} from '../governance/uds_worth_engine.js';
import {SqliteGovernanceLedger,type IdempotencyScope,type IdempotentAdmissionResult} from '../governance/uds_sqlite_authority.js';
import type {ConsentAuthority} from '../governance/uds_registry_replay.js';

export interface AdmittedWorthReceipt {
 readonly contributionId:string;
 readonly score:number;
 readonly admitted:true;
}
/** The only score-emitting method in this runtime facade. Does not expose uncommitted scores. */
export class UdsRuntimePipeline {
 constructor(private readonly ledger:SqliteGovernanceLedger,private readonly consent:ConsentAuthority,
  private readonly config:WorthConfig=DEFAULT_WORTH_CONFIG){}
 async submitIdempotent(contribution:WorthContribution,scope:IdempotencyScope,evaluationTime=Date.now()):Promise<IdempotentAdmissionResult>{
  // Score is computed internally, never supplied by the HTTP caller.
  // Ledger resolves historical idempotent retries before new-admission replay checks.
  const previous=this.ledger.lookupIdempotency(scope);
  if(previous)return {receipt:previous,isReplay:true};
  const trusted=new Set(contribution.communityAttestations.map(a=>a.attesterPublicKey.toLowerCase()));
  const score=await calculateWorth(contribution,trusted,this.config);
  return this.ledger.acceptWithIdempotency(contribution,this.consent,evaluationTime,scope,score);
 }
 async submit(contribution:WorthContribution,evaluationTime=Date.now()):Promise<AdmittedWorthReceipt>{
  // Compute privately before admission; no score is returned on any failed check.
  // Ledger.accept independently verifies signatures and persisted authority under its write lock.
  const trusted=new Set(contribution.communityAttestations.map(a=>a.attesterPublicKey.toLowerCase()));
  const score=await calculateWorth(contribution,trusted,this.config);
  await this.ledger.accept(contribution,this.consent,evaluationTime);
  return Object.freeze({contributionId:contribution.contributionId,score,admitted:true as const});
 }
}
