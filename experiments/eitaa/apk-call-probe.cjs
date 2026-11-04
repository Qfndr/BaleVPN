// Explicit read-only protocol probe for the pinned official Android wrapper.
// This does not relabel, persist, register or replace the supplied Web session.
'use strict';
const wire=require('./wire.cjs'),codec=require('./call-wire.cjs');
const {ApiError}=require('./http-client.cjs'),{serviceError}=require('./account-client.cjs');
const ENDPOINT='https://armita.eitaa.com/eitaa/index.php';
const {apkEnvelope,socketEnvelope,credentials,CONSTRUCTOR,LAYER,BUILD}=require('./android-envelope.cjs');
const APK='android-apk-7.1.8',SOCKET='android-socket-7.1.8';
async function bounded(response){
 const length=response.headers.get('content-length');if(length!==null&&(!/^\d+$/.test(length)||Number(length)>wire.MAX)){await response.body?.cancel().catch(()=>{});throw new ApiError('response_too_large');}
 const reader=response.body?.getReader();if(!reader)throw new ApiError('invalid_response');const chunks=[];let count=0;
 try{while(true){const {done,value}=await reader.read();if(done)break;count+=value.length;if(count>wire.MAX)throw new ApiError('response_too_large');chunks.push(Buffer.from(value));}}
 catch(e){await reader.cancel().catch(()=>{});throw e;}finally{reader.releaseLock();}
 return Buffer.concat(chunks,count);
}
class ApkCallProbe{
 #record;#fetch;#pending;#closed=false;#language;#profile;
 constructor({record,fetchImpl=globalThis.fetch,language='fa',envelopeProfile=APK}={}){this.#record=credentials(record);if(typeof fetchImpl!=='function'||!['fa','en','ar'].includes(language)||![APK,SOCKET].includes(envelopeProfile))throw new ApiError('invalid_request');this.#fetch=fetchImpl;this.#language=language;this.#profile=envelopeProfile;}
 async getDhConfig({timeout=10000}={}){
  if(this.#closed)throw new ApiError('closed');if(this.#pending)throw new ApiError('account_busy');if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw new ApiError('tls_verification_disabled');if(!Number.isInteger(timeout)||timeout<1||timeout>30000)throw new ApiError('invalid_request');
  const packed=codec.method('messages.getDhConfig',{version:0,random_length:256}),options={record:{provider:'eitaa',...this.#record},language:this.#language};
  const body=this.#profile===SOCKET?socketEnvelope(packed,options):apkEnvelope(packed,options);
  const controller=this.#pending=new AbortController(),timer=setTimeout(()=>controller.abort(),timeout);
  try{
   const response=await this.#fetch(ENDPOINT,{method:'POST',headers:{'content-type':'text/stream'},body,redirect:'error',cache:'no-store',signal:controller.signal});
   if(this.#closed||controller.signal.aborted)throw new ApiError(this.#closed?'closed':'timeout');
   if(response.status!==200){await response.body?.cancel().catch(()=>{});throw new ApiError(response.status===429?'rate_limited':'http_error',response.status);}
   const bytes=await bounded(response);if(this.#closed||controller.signal.aborted)throw new ApiError(this.#closed?'closed':'timeout');let result=codec.response(bytes,'messages.getDhConfig');if(result?._==='rpc_result')result=result.result;
   if(['error','eitta_error'].includes(result?._))throw serviceError(result);
   if(['eitaa_updates_expire_token','eitaa_token_updating'].includes(result?._))throw new ApiError('session_refresh_required');
   if(result?._!=='messages.dhConfig'||!(result.p instanceof Uint8Array)||result.p.length!==256||!(result.random instanceof Uint8Array)||result.random.length!==256||!Number.isInteger(result.g)||result.g<2||result.g>7||!Number.isInteger(result.version)||result.version<0)throw new ApiError('invalid_dh_config');
   // The caller must still use CallKeyExchange's existing safe-prime and public
   // key validation before any call. A structurally valid reply is no shortcut.
   return result;
  }catch(e){if(e instanceof ApiError||e instanceof wire.WireError)throw e;throw new ApiError(this.#closed?'closed':controller.signal.aborted?'timeout':'network_error');}
  finally{clearTimeout(timer);if(this.#pending===controller)this.#pending=null;body.fill(0);}
 }
 close(){this.#closed=true;this.#pending?.abort();this.#record.token='';this.#record.imei='';}
}
module.exports={ApkCallProbe,apkEnvelope,socketEnvelope,ENDPOINT,CONSTRUCTOR,LAYER,BUILD,APK,SOCKET};
