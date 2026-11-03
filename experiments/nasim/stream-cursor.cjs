// Read only the initial conversation-page cursor used by the official client.
// No history pagination, message persistence, public metadata, or token logging.
'use strict';
const crypto=require('node:crypto');
const {ApiError}=require('./http-client.cjs');
const MAX=256*1024;
async function initialCursor(session,{fetchImpl=globalThis.fetch,signal}={}){
 if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw new ApiError('tls_verification_disabled');
 if(typeof session?.token!=='string'||! /^[\x21-\x7e]{32,16384}$/.test(session.token))throw new ApiError('invalid_saved_session');
 const controller=new AbortController(),abort=()=>controller.abort();signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)controller.abort();
 const timer=setTimeout(abort,10000);let encrypted,plain,key;
 try{
  if(controller.signal.aborted)throw new ApiError('closed');
  const response=await fetchImpl('https://api.gaplication.com/groupList?page=reset',{method:'GET',headers:{project:'nasimrezvan',APPVERSION:'web','Accept-Language':'fa','X-VERSION':'6.1.1','X-Token':session.token,origin:'https://web.nasimrezvan.com',referer:'https://web.nasimrezvan.com/'},redirect:'error',cache:'no-store',signal:controller.signal});
  if(response.status===401)throw new ApiError('not_authorized');if(response.status!==200)throw new ApiError('cursor_request_failed');
  const length=response.headers.get('content-length');if(length&&(!/^\d+$/.test(length)||Number(length)>MAX)){await response.body?.cancel().catch(()=>{});throw new ApiError('response_too_large');}
  const reader=response.body?.getReader();if(!reader)throw new ApiError('invalid_cursor_response');const chunks=[];let total=0;
  try{while(true){const part=await reader.read();if(part.done)break;total+=part.value.length;if(total>MAX)throw new ApiError('response_too_large');chunks.push(Buffer.from(part.value));}encrypted=Buffer.concat(chunks,total);}catch(e){await reader.cancel().catch(()=>{});throw e;}finally{for(const chunk of chunks)chunk.fill(0);reader.releaseLock();}
  if(controller.signal.aborted)throw new ApiError('closed');
  let decoded;try{
   const text=new TextDecoder('utf-8',{fatal:true}).decode(encrypted);
   if(text.trimStart().startsWith('{'))decoded=JSON.parse(text);
   else{if(text.length<40||! /^[\x20-\x7e]{16}[A-Za-z0-9+/]+={0,2}$/.test(text))throw Error();key=Buffer.from(session.token).subarray(0,32);const cipher=crypto.createDecipheriv('aes-256-cbc',key,Buffer.from(text.slice(0,16)));plain=Buffer.concat([cipher.update(Buffer.from(text.slice(16),'base64')),cipher.final()]);decoded=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain));}
  }catch{throw new ApiError('invalid_cursor_response');}
  const groups=decoded?.data?.groups;if(decoded?.status==='error'||!Array.isArray(groups)||groups.length>256)throw new ApiError('invalid_cursor_response');
  if(!groups.length)return '0';const id=groups[0]?.lastMessage?.messageID;
  if(typeof id==='number'&&!Number.isSafeInteger(id)||!['number','string'].includes(typeof id)||! /^(?:0|[1-9]\d{0,19})$/.test(String(id)))throw new ApiError('invalid_cursor_response');
  return String(id);
 }catch(e){if(e instanceof ApiError)throw e;throw new ApiError(controller.signal.aborted?'closed':'cursor_request_failed');}
 finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);encrypted?.fill(0);plain?.fill(0);key?.fill(0);}
}
module.exports={initialCursor};
