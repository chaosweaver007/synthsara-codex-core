/** Explicit daemon entrypoint. Library imports never open a listener. */
import {SqliteGovernanceLedger} from '@synthsara/core';
import {AdmissionServer} from './server.js';
import {DurableConsentAuthority} from './consent.js';

function required(name:string):string{
 const value=process.env[name];
 if(!value||!value.trim())throw new Error('[BOOTSTRAP_ERROR]: Missing '+name);
 return value.trim();
}
function integer(name:string,fallback:string,min:number,max:number):number{
 const raw=process.env[name]??fallback;
 if(!/^(0|[1-9][0-9]*)$/.test(raw))throw new Error('[BOOTSTRAP_ERROR]: Invalid '+name);
 const value=Number(raw);
 if(!Number.isSafeInteger(value)||value<min||value>max)throw new Error('[BOOTSTRAP_ERROR]: Invalid '+name);
 return value;
}
async function main():Promise<void>{
 const host=process.env.HOST??'127.0.0.1';
 if(host!=='127.0.0.1'&&host!=='::1'&&host!=='localhost'){
  // External binding is disabled until a separate authenticated TLS edge is reviewed.
  throw new Error('[BOOTSTRAP_ERROR]: Non-loopback binding is disabled in service v0.1');
 }
 const port=integer('PORT','8080',1,65535);
 const epoch=integer('ACTIVE_EPOCH','1',1,Number.MAX_SAFE_INTEGER);
 const dbPath=required('DB_PATH');
 const rootAnchorPublicKey=required('ROOT_ANCHOR_PUBLIC_KEY');
 const rawTokens=required('AUTH_TOKENS').split(',').map(x=>x.trim());
 if(rawTokens.some(x=>x.length<16)||new Set(rawTokens).size!==rawTokens.length)
  throw new Error('[BOOTSTRAP_ERROR]: Invalid or duplicate AUTH_TOKENS');
 const ledger=new SqliteGovernanceLedger({dbPath,rootAnchorPublicKey,activeEpoch:epoch});
 const server=new AdmissionServer({ledger,consent:new DurableConsentAuthority(ledger),authTokens:new Set(rawTokens)});
 let stopping=false;
 const shutdown=async(signal:string)=>{
  if(stopping)return;
  stopping=true;
  // server.close() stops accepting connections and drains active requests.
  // SQLite close() releases its WAL resources; this is not a crash-recovery guarantee.
  try{
   await server.close();
   ledger.close();
   console.log('[SYNTHSARA_DAEMON]: Stopped after '+signal);
   process.exitCode=0;
  }catch(e){
   console.error('[SYNTHSARA_DAEMON]: Shutdown failed',e);
   process.exitCode=1;
  }
 };
 try{
  await server.listen(port,host);
 }catch(e){ledger.close();throw e;}
 process.on('SIGINT',()=>{void shutdown('SIGINT');});
 process.on('SIGTERM',()=>{void shutdown('SIGTERM');});
 console.log('[SYNTHSARA_DAEMON]: Listening on '+host+':'+port);
}
main().catch(e=>{console.error('[BOOTSTRAP_FATAL]',e);process.exitCode=1;});
