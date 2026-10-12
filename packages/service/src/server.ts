/** Authenticated local-node admission transport. No listener starts on import. */
import {createServer,type Server,type IncomingMessage,type ServerResponse} from 'node:http';
import {createHash,timingSafeEqual} from 'node:crypto';
import {UdsRuntimePipeline,SqliteGovernanceLedger,type ConsentAuthority,type WorthContribution} from '@synthsara/core';

export interface ServiceConfig {
 readonly ledger:SqliteGovernanceLedger;
 readonly consent:ConsentAuthority;
 readonly authTokens:ReadonlySet<string>;
 readonly maxBodyBytes?:number;
 readonly rateLimitPerMinute?:number;
}
export const sha256Hex=(value:string|Uint8Array):string=>createHash('sha256').update(value).digest('hex');
const json=(res:ServerResponse,status:number,payload:unknown,headers:Record<string,string>={})=>{
 res.writeHead(status,{'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff',...headers});
 res.end(JSON.stringify(payload));
};
const error=(res:ServerResponse,status:number,code:string)=>json(res,status,{error:{code}});
const canonical=(value:unknown):string=>{
 if(value===null||typeof value!=='object')return JSON.stringify(value);
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical((value as Record<string,unknown>)[k])).join(',')+'}';
};
export class AdmissionServer {
 private readonly server:Server;
 private readonly pipeline:UdsRuntimePipeline;
 private readonly limit:number;
 private readonly maxBytes:number;
 private readonly counters=new Map<string,{minute:number,count:number}>();
 constructor(private readonly config:ServiceConfig){
  if(!config.authTokens.size||[...config.authTokens].some(t=>t.length<16))throw new Error('Strong authentication tokens required');
  this.maxBytes=config.maxBodyBytes??65536;
  this.limit=config.rateLimitPerMinute??60;
  if(!Number.isSafeInteger(this.maxBytes)||this.maxBytes<1024||!Number.isSafeInteger(this.limit)||this.limit<1)throw new Error('Invalid service limits');
  this.pipeline=new UdsRuntimePipeline(config.ledger,config.consent);
  this.server=createServer((req,res)=>{void this.handle(req,res).catch(()=>{if(!res.headersSent)error(res,500,'INTERNAL_ERROR');else res.destroy();});});
 }
 listen(port:number,host='127.0.0.1'):Promise<void>{
  return new Promise((resolve,reject)=>{
   const onError=(e:Error)=>{this.server.off('listening',onListen);reject(e);};
   const onListen=()=>{this.server.off('error',onError);resolve();};
   this.server.once('error',onError);this.server.once('listening',onListen);this.server.listen(port,host);
  });
 }
 address(){return this.server.address();}
 close():Promise<void>{return new Promise((resolve,reject)=>this.server.close(e=>e?reject(e):resolve()));}
 private authenticate(req:IncomingMessage):string|undefined{
  const header=req.headers.authorization;
  if(typeof header!=='string'||!/^Bearer [^\s]+$/.test(header))return;
  const token=header.slice(7);
  const candidate=Buffer.from(sha256Hex(token),'hex');
  let valid=0;
  for(const known of this.config.authTokens){
   const expected=Buffer.from(sha256Hex(known),'hex');
   valid|=Number(timingSafeEqual(candidate,expected));
  }
  return valid?sha256Hex(token):undefined;
 }
 private async body(req:IncomingMessage):Promise<unknown>{
  if(req.headers['content-type']?.split(';')[0]?.trim().toLowerCase()!=='application/json')throw new Error('CONTENT_TYPE');
  if(Number(req.headers['content-length']??0)>this.maxBytes)throw new Error('PAYLOAD_TOO_LARGE');
  const chunks:Buffer[]=[];let size=0;
  for await(const chunk of req){
   const b=Buffer.isBuffer(chunk)?chunk:Buffer.from(chunk);
   size+=b.length;
   if(size>this.maxBytes)throw new Error('PAYLOAD_TOO_LARGE');
   chunks.push(b);
  }
  try{return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;}catch{throw new Error('MALFORMED_JSON');}
 }
 private async handle(req:IncomingMessage,res:ServerResponse):Promise<void>{
  const pathname=new URL(req.url??'/', 'http://localhost').pathname;
  if(req.method==='GET'&&pathname==='/healthz'){json(res,200,{status:'HEALTHY'});return;}
  const principalHash=this.authenticate(req);
  if(!principalHash){error(res,401,'UNAUTHORIZED');return;}
  const minute=Math.floor(Date.now()/60000),counter=this.counters.get(principalHash);
  const count=counter?.minute===minute?counter.count+1:1;
  this.counters.set(principalHash,{minute,count});
  if(this.counters.size>10000)for(const [k,v] of this.counters)if(v.minute!==minute)this.counters.delete(k);
  if(count>this.limit){error(res,429,'RATE_LIMITED');return;}
  if(req.method==='GET'&&pathname.startsWith('/v1/verify/')){
   const actionId=pathname.slice('/v1/verify/'.length);
   if(!/^[A-Za-z0-9_-]{1,256}$/.test(actionId)){error(res,400,'INVALID_ACTION_ID');return;}
   const status=this.config.ledger.verifyActionForPrincipal(principalHash,actionId);
   if(!status){error(res,404,'NOT_FOUND');return;}
   json(res,200,status);
   return;
  }
  if(req.method!=='POST'||!['/v1/admit','/v1/revoke-consent'].includes(pathname)){error(res,404,'NOT_FOUND');return;}
  let payload:unknown;
  try{payload=await this.body(req);}catch(e){
   const code=e instanceof Error?e.message:'MALFORMED_JSON';
   error(res,code==='PAYLOAD_TOO_LARGE'?413:code==='CONTENT_TYPE'?415:400,code);return;
  }
  if(!payload||typeof payload!=='object'||Array.isArray(payload)){error(res,400,'INVALID_BODY');return;}
  const obj=payload as Record<string,unknown>;
  if(pathname==='/v1/revoke-consent'){
   if(Object.keys(obj).sort().join(',')!==['actionId','recipientPublicKey','recipientSignature','revocationNonce','revokedAt'].sort().join(',')){
    error(res,400,'INVALID_REVOCATION');return;
   }
   try{
    await this.config.ledger.revokeConsent(obj as unknown as Parameters<SqliteGovernanceLedger['revokeConsent']>[0]);
    json(res,200,{status:'CONSENT_REVOKED',actionId:obj.actionId});
   }catch{error(res,400,'INVALID_REVOCATION');}
   return;
  }
  const key=req.headers['idempotency-key'];
  if(typeof key!=='string'||!/^[A-Za-z0-9_-]{8,128}$/.test(key)){error(res,400,'INVALID_IDEMPOTENCY_KEY');return;}
  if(Object.keys(obj).length!==1||!obj.contribution||typeof obj.contribution!=='object'||Array.isArray(obj.contribution)){
   error(res,400,'INVALID_CONTRIBUTION');return;
  }
  const digest=sha256Hex(canonical(obj));
  try{
   const result=await this.pipeline.submitIdempotent(obj.contribution as WorthContribution,{
    principalHash,endpoint:'v1/admit',idempotencyKey:key,requestDigest:digest
   });
   json(res,result.isReplay?200:201,result.receipt,{'x-idempotent-replay':String(result.isReplay)});
  }catch(e){
   const message=e instanceof Error?e.message:'';
   if(message.includes('IDEMPOTENCY_CONFLICT'))error(res,409,'IDEMPOTENCY_CONFLICT');
   else if(message.includes('CONSENT'))error(res,403,'CONSENT_DENIED');
   else if(message.includes('AUTHORITY'))error(res,403,'AUTHORITY_DENIED');
   else error(res,400,'ADMISSION_REJECTED');
  }
 }
}
export function createAdmissionServer(config:ServiceConfig):AdmissionServer{return new AdmissionServer(config);}
