'use strict';
const wire=require('./wire.cjs');
const profiles=require('./client-profile.cjs');
// Client endpoints observed in the pinned official worker; download/upload DCs
// and caller-provided arbitrary URLs are not allowed.
const ENDPOINTS=Object.freeze(['hasan.eitaa.ir','hosna.eitaa.com','armita.eitaa.com','majid.eitaa.com','alireza.eitaa.com','mostafa.eitaa.com','sajad.eitaa.ir','bagher.eitaa.ir','sadegh.eitaa.ir','kazem.eitaa.ir'].map(host=>'https://'+host+'/eitaa/'));
class ApiError extends Error{constructor(reason,status){super('Eitaa API '+reason);this.reason=reason;if(status!==undefined)this.statusCode=status;}}
async function bounded(response){
 const size=response.headers.get('content-length');
 if(size!==null&&(!/^\d+$/.test(size)||Number(size)>wire.MAX)){await response.body?.cancel().catch(()=>{});throw new ApiError('response_too_large');}
 const reader=response.body?.getReader();if(!reader)throw new ApiError('invalid_response');let sizeRead=0;const chunks=[];
 try{while(true){const {done,value}=await reader.read();if(done)break;sizeRead+=value.length;if(sizeRead>wire.MAX)throw new ApiError('response_too_large');chunks.push(Buffer.from(value));}}
 catch(e){await reader.cancel().catch(()=>{});throw e;}finally{reader.releaseLock();}
 return Buffer.concat(chunks,sizeRead);
}
class Transport{
 #fetch;#server;#pending;#closed=false;#profile;
 constructor({fetchImpl=globalThis.fetch,server,protocolProfile='web'}={}){try{this.#profile=profiles.mode(protocolProfile);}catch{throw new ApiError('invalid_client_profile');}server??=this.#profile===profiles.ANDROID?profiles.ANDROID_ENDPOINT:ENDPOINTS[0];if(!(this.#profile===profiles.ANDROID?server===profiles.ANDROID_ENDPOINT:ENDPOINTS.includes(server)))throw new ApiError('invalid_server');this.#fetch=fetchImpl;this.#server=server;}
 assertOpen(){if(this.#closed)throw new ApiError('closed');}
 async post(body,{timeout=10000}={}){
  if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw new ApiError('tls_verification_disabled');
  if(this.#closed)throw new ApiError('closed');if(this.#pending)throw new ApiError('account_busy');
  if(!Number.isInteger(timeout)||timeout<1||timeout>30000)throw new ApiError('invalid_request');
  if(!(body instanceof Uint8Array)||!body.length||body.length>wire.MAX)throw new ApiError('invalid_request');
  const controller=new AbortController();this.#pending=controller;const timer=setTimeout(()=>controller.abort(),timeout);
  try{
   const response=await this.#fetch(this.#server,{method:'POST',body,headers:this.#profile===profiles.ANDROID?{'content-type':'text/stream'}:{'content-type':'application/octet-stream',origin:'https://web.eitaa.com',referer:'https://web.eitaa.com/'},redirect:'error',cache:'no-store',signal:controller.signal});
   if(controller.signal.aborted||this.#closed)throw new ApiError(this.#closed?'closed':'timeout');
   if(response.status!==200){await response.body?.cancel().catch(()=>{});throw new ApiError(response.status===429?'rate_limited':'http_error',response.status);}
   const result=await bounded(response);if(controller.signal.aborted||this.#closed)throw new ApiError(this.#closed?'closed':'timeout');return result;
  }catch(e){if(e instanceof ApiError||e instanceof wire.WireError)throw e;throw new ApiError(this.#closed?'closed':controller.signal.aborted?'timeout':'network_error');}
  finally{clearTimeout(timer);if(this.#pending===controller)this.#pending=null;}
 }
 close(){this.#closed=true;this.#pending?.abort();}
}
class HttpClient{
 #transport;
 constructor(options){this.#transport=new Transport(options);}
 // Read-only anonymous probe only. No phone, OTP, token, or login RPC accepted.
 async ping(options={}){this.#transport.assertOpen();const id=wire.pingId(),start=performance.now();let result=wire.response(await this.#transport.post(wire.envelope(wire.ping(id),{imei:wire.deviceId()}),options));this.#transport.assertOpen();if(result.type==='rpc_result')result=result.result;if(result.type==='service_error')throw new ApiError('service_rejected');if(result.type!=='pong'||result.pingId!==id)throw new ApiError('ping_mismatch');return {pong:true,elapsedMs:Math.round(performance.now()-start)};}
 close(){this.#transport.close();}
}
module.exports={HttpClient,Transport,ApiError,ENDPOINTS};
