/** Service v0.1 scaffold. No network listener is exposed until authentication, consent and route tests are complete. */
import {createServer,type Server} from 'node:http';

export function createAdmissionServer():Server {
 return createServer((_request,response)=>{
  response.writeHead(503,{'content-type':'application/json','cache-control':'no-store'});
  response.end(JSON.stringify({error:'SERVICE_NOT_READY'}));
 });
}
