/** Milestone 50: compiled daemon OS-process, graceful shutdown, and durable admission proof.
 * Run after npm run build; no external SQLite dependency is required.
 */
import {describe,it,expect} from 'vitest';
import {spawn,type ChildProcess} from 'node:child_process';
import {createServer} from 'node:net';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {DatabaseSync} from 'node:sqlite';
import * as ed from '@noble/ed25519';
import {SqliteGovernanceLedger,type WorthContribution} from '@synthsara/core';

const hex=(bytes:Uint8Array)=>Buffer.from(bytes).toString('hex');
const enc=new TextEncoder();
const token='daemon_process_test_token_123456789';
const script=fileURLToPath(new URL('../dist/daemon.js',import.meta.url));
const pause=(ms:number)=>new Promise<void>(resolve=>setTimeout(resolve,ms));

async function availablePort():Promise<number>{
 return await new Promise((resolve,reject)=>{
  const socket=createServer();
  socket.once('error',reject);
  socket.listen(0,'127.0.0.1',()=>{
   const address=socket.address();
   if(!address||typeof address==='string'){socket.close();reject(new Error('No loopback port'));return;}
   socket.close(error=>error?reject(error):resolve(address.port));
  });
 });
}
function processFinished(child:ChildProcess):boolean{
 return child.exitCode!==null||child.signalCode!==null;
}
async function awaitExit(child:ChildProcess,ms:number):Promise<{code:number|null;signal:NodeJS.Signals|null}>{
 if(processFinished(child))return {code:child.exitCode,signal:child.signalCode};
 return await new Promise((resolve,reject)=>{
  const timeout=setTimeout(()=>{cleanup();reject(new Error('Timed out waiting for daemon exit'));},ms);
  const done=(code:number|null,signal:NodeJS.Signals|null)=>{cleanup();resolve({code,signal});};
  const failed=(error:Error)=>{cleanup();reject(error);};
  const cleanup=()=>{clearTimeout(timeout);child.off('exit',done);child.off('error',failed);};
  child.once('exit',done);child.once('error',failed);
 });
}
async function terminate(child:ChildProcess):Promise<void>{
 if(processFinished(child))return;
 child.kill('SIGTERM');
 try{await awaitExit(child,2000);}
 catch{
  if(!processFinished(child))child.kill('SIGKILL');
  await awaitExit(child,2000).catch(()=>{});
 }
}
async function ready(base:string,child:ChildProcess,diagnostics:()=>string):Promise<void>{
 const deadline=Date.now()+5000;
 while(Date.now()<deadline){
  if(processFinished(child))throw new Error('Daemon exited before readiness: '+diagnostics());
  try{
   const response=await fetch(base+'/healthz',{signal:AbortSignal.timeout(350)});
   if(response.status===200)return;
  }catch{/* Process may not yet be listening. */}
  await pause(50);
 }
 throw new Error('Daemon readiness timeout: '+diagnostics());
}

describe('Milestone 50 compiled daemon process',()=>{
 it('admits signed evidence, exits on SIGTERM, and preserves valid SQLite state',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'uds-daemon-os-'));
  const dbPath=join(dir,'governance.sqlite');
  let child:ChildProcess|undefined;
  let stdout='',stderr='';
  const diagnostics=()=>JSON.stringify({exitCode:child?.exitCode,signalCode:child?.signalCode,stdout,stderr});
  try{
   const root=ed.utils.randomPrivateKey();
   const attester=ed.utils.randomPrivateKey();
   const recipient=ed.utils.randomPrivateKey();
   const rootPub=hex(await ed.getPublicKeyAsync(root));
   const attPub=hex(await ed.getPublicKeyAsync(attester));
   const recPub=hex(await ed.getPublicKeyAsync(recipient));
   const now=Date.now();
   const grant={attesterPublicKey:attPub,authorizedDomains:['CARE_WORK' as const],validFrom:now-1000,validUntil:now+100000,nonce:'grant_daemon_os_001'};
   const grantBytes=enc.encode(JSON.stringify(['SYNTHSARA:UDS:GRANT:v1',attPub,['CARE_WORK'],grant.validFrom,grant.validUntil,grant.nonce]));
   const ledger=new SqliteGovernanceLedger({dbPath,rootAnchorPublicKey:rootPub,activeEpoch:1});
   try{
    await ledger.registerGrant({grant,authoritySignature:hex(await ed.signAsync(grantBytes,root))});
   }finally{ledger.close();}

   const port=await availablePort();
   const base='http://127.0.0.1:'+port;
   child=spawn(process.execPath,[script],{
    env:{...process.env,HOST:'127.0.0.1',PORT:String(port),DB_PATH:dbPath,ROOT_ANCHOR_PUBLIC_KEY:rootPub,AUTH_TOKENS:token,ACTIVE_EPOCH:'1'},
    stdio:['ignore','pipe','pipe']
   });
   child.stdout?.on('data',(data:Buffer)=>{stdout=(stdout+data.toString()).slice(-8192);});
   child.stderr?.on('data',(data:Buffer)=>{stderr=(stderr+data.toString()).slice(-8192);});
   await ready(base,child,diagnostics);

   const contributionId='daemon_os_contribution_50';
   const actionId='daemon_os_action_50';
   const contributorHash='contributor';
   const timestamp=Date.now();
   const recipientSig=hex(await ed.signAsync(enc.encode(JSON.stringify([
    'SYNTHSARA:UDS:ACTION:v1',contributionId,contributorHash,actionId,'CARE_WORK',timestamp,recPub
   ])),recipient));
   const attesterSig=hex(await ed.signAsync(enc.encode(JSON.stringify([
    'SYNTHSARA:UDS:ATTEST:v1',contributionId,contributorHash,[[actionId,'CARE_WORK',timestamp,recPub,recipientSig]]
   ])),attester));
   const contribution:WorthContribution={
    contributionId,contributorHash,
    verifiedActions:[{actionId,domain:'CARE_WORK',timestamp,recipientPublicKey:recPub,recipientSignature:recipientSig}],
    communityAttestations:[{attesterPublicKey:attPub,signature:attesterSig}]
   };
   const headers={'authorization':'Bearer '+token,'content-type':'application/json','idempotency-key':'daemon_os_key_001'};
   const admitted=await fetch(base+'/v1/admit',{
    method:'POST',headers,body:JSON.stringify({contribution}),signal:AbortSignal.timeout(3000)
   });
   const admissionBody=await admitted.json();
   expect(admitted.status,diagnostics()).toBe(201);
   expect(admissionBody).toMatchObject({contributionId,admitted:true});
   expect(typeof admissionBody.score).toBe('number');

   const verified=await fetch(base+'/v1/verify/'+actionId,{
    headers:{authorization:'Bearer '+token},signal:AbortSignal.timeout(3000)
   });
   expect(verified.status).toBe(200);
   expect(await verified.json()).toEqual({actionId,admitted:true,consentRevoked:false});

   const exiting=awaitExit(child,5000);
   expect(child.kill('SIGTERM')).toBe(true);
   const result=await exiting;
   expect(result,diagnostics()).toEqual({code:0,signal:null});

   // Offline independent handle: no checkpoint command is used to manufacture durability.
   const db=new DatabaseSync(dbPath,{readOnly:true});
   try{
    const integrity=db.prepare('PRAGMA integrity_check').all() as Array<{integrity_check:string}>;
    expect(integrity.map(row=>row.integrity_check)).toEqual(['ok']);
    expect(db.prepare('SELECT 1 AS found FROM processed_actions WHERE action_id=?').get(actionId)).toEqual({found:1});
    expect(db.prepare('SELECT 1 AS found FROM accepted_contributions WHERE contribution_id=?').get(contributionId)).toEqual({found:1});
    expect(db.prepare('SELECT 1 AS found FROM admission_idempotency WHERE idempotency_key=?').get('daemon_os_key_001')).toEqual({found:1});
   }finally{db.close();}
  }catch(error){
   throw new Error('Milestone 50 process proof failed: '+String(error)+'; '+diagnostics(),{cause:error});
  }finally{
   if(child)await terminate(child);
   rmSync(dir,{recursive:true,force:true});
  }
 },20000);
});
