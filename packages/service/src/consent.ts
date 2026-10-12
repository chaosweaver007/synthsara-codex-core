/** Fail-closed durable consent policy. Signature verification is performed by the
 * canonical core verifier before this authority is consulted, and the ledger
 * rechecks withdrawal tombstones inside the admission transaction.
 */
import {SqliteGovernanceLedger,type ConsentAuthority,type WorthContribution} from '@synthsara/core';

export class DurableConsentAuthority implements ConsentAuthority {
 constructor(private readonly ledger:SqliteGovernanceLedger){}
 async isAuthorized(contribution:WorthContribution,_evaluationTime:number):Promise<boolean>{
  if(!Array.isArray(contribution?.verifiedActions)||contribution.verifiedActions.length===0)return false;
  try{
   for(const action of contribution.verifiedActions){
    if(!action||typeof action.actionId!=='string'||typeof action.recipientPublicKey!=='string'||
       typeof action.recipientSignature!=='string'||!/^[0-9a-fA-F]{128}$/.test(action.recipientSignature)||
       this.ledger.isConsentRevoked(action.recipientPublicKey,action.actionId))return false;
   }
   return true;
  }catch{return false;}
 }
}
