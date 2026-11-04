// Narrow HTTP/SSE adapter for the pinned vendor call controller.
'use strict';
const {isDeepStrictEqual}=require('node:util');
const wire=require('./wire.cjs'),codec=require('./call-codec.cjs');
const ENDPOINT='https://api.gaplication.com/',ORIGIN='https://web.nasimrezvan.com';
const MAX=64*1024,MAX_EVENTS=64,MAX_EVENT_BYTES=512*1024;
const TYPES=new Set(['callRequest','accept','offer','answer','ice','bye','reject','busy']);
const fail=reason=>Object.assign(new Error('Official Nasim transport '+reason),{reason});
function decode(bytes,token){
 let plain;try{plain=wire.decryptBytes(bytes,token);return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain));}
 catch{throw fail('invalid_call_packet');}finally{plain?.fill(0);}
}
async function bounded(response){
 const size=response.headers.get('content-length');
 if(size!==null&&(!/^\d+$/.test(size)||Number(size)>MAX)){await response.body?.cancel().catch(()=>{});throw fail('response_too_large');}
 const reader=response.body?.getReader();if(!reader)throw fail('invalid_call_response');
 const parts=[];let count=0;
 try{while(true){const {value,done}=await reader.read();if(done)break;
  count+=value.length;if(count>MAX)throw fail('response_too_large');parts.push(Buffer.from(value));
 }if(!count)throw fail('invalid_call_response');return Buffer.concat(parts,count);}
 catch(error){await reader.cancel().catch(()=>{});throw error;}
 finally{for(const part of parts)part.fill(0);reader.releaseLock();}
}
class OfficialCallTransport{
 #accounts;#gate;#journal;#fetch;#deliver;#media;#abort=new AbortController();#events=[];#eventBytes=0;#deliveryReady=false;#eventQueue=Promise.resolve();
 constructor({accounts,gate,journal,fetchImpl,deliver,mediaGuard=null}){
  if(!accounts?.get(1)||!accounts.get(2)||!gate||!journal||typeof fetchImpl!=='function'||typeof deliver!=='function')throw fail('invalid_options');
  this.#accounts=accounts;this.#gate=gate;this.#journal=journal;this.#fetch=fetchImpl;this.#deliver=deliver;this.#media=mediaGuard;
 }
 #guard(){if(this.#abort.signal.aborted)throw fail('closed');if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw fail('tls_verification_disabled');}
 #account(slot){if(![1,2].includes(slot))throw fail('invalid_slot');return this.#accounts.get(slot).exportSession();}
 #sameAccount(slot,record){
  const current=this.#account(slot);
  if(['provider','userId','clientId','deviceId','token'].some(key=>current[key]!==record[key]))throw fail('account_binding_changed');
 }
 async forward(slot,{url,method,headers,body}){
  this.#guard();const account=this.#account(slot),peer=this.#account(3-slot);
  if(url!==ENDPOINT||method!=='POST'||!Buffer.isBuffer(body)||body.length<1||body.length>MAX||
   headers?.['api-version']!=='v2.5'||headers['x-token']!==account.token||headers['x-clientid']!==account.clientId||
   headers['project']!=='nasimrezvan'||headers['content-type']!=='application/json')throw fail('request_denied');
  const packet=decode(body,account.token),signal=packet?.data;
  if(!TYPES.has(signal?.type))throw fail('signal_denied');
  const expected=codec.outgoing(signal,account.userId,peer.userId);
  if(headers['x-topic']!==expected.topic||!isDeepStrictEqual(packet,expected.body))throw fail('request_denied');
  // Clone before awaiting the gate so the bytes forwarded cannot be replaced.
  const frame=Buffer.from(body);let raw;
  try{
   await this.#media?.checkSignal(slot,signal);
   await this.#gate.outgoing(slot,signal);this.#guard();this.#sameAccount(slot,account);this.#sameAccount(3-slot,peer);
   const response=await this.#fetch(ENDPOINT,{method:'POST',headers:{'accept-language':'fa','app-version':'web','api-version':'v2.5',
    'x-clientid':account.clientId,os:'web','x-token':account.token,'x-topic':expected.topic,'content-type':'application/json',
    project:'nasimrezvan',origin:ORIGIN,referer:ORIGIN+'/'},body:frame,redirect:'error',cache:'no-store',
    signal:AbortSignal.any([this.#abort.signal,AbortSignal.timeout(10000)])});
   raw=await bounded(response);
   if(signal.type==='callRequest'){
    const intent=await this.#journal.load();if(intent?.phase!=='requested'||intent.callerSlot!==slot)throw fail('call_intent_missing');
    await this.#journal.stageResponse(intent.operationId,raw,response.status);
   }
   this.#guard();this.#sameAccount(slot,account);this.#sameAccount(3-slot,peer);
   if(response.status<200||response.status>=300)throw fail('call_rejected');
   const decoded=decode(raw,account.token);
   if(!decoded||typeof decoded!=='object'||Array.isArray(decoded)||decoded.status==='error'||decoded.error)throw fail('call_rejected');
   if(signal.type==='callRequest')await this.#gate.bindResponse(slot,decoded);
   if(signal.type==='bye'&&decoded.status==='success')await this.#gate.acknowledgeTerminal(slot,{acknowledged:true,
    terminalAcknowledgement:{type:'bye',callUUID:signal.callUUID,peerId:peer.userId}});
   let iceServers;
   if(this.#media&&decoded.type==='msgGroupCall'&&decoded.data?.type==='config'){
    const checked=await this.#gate.incoming(slot,decoded);
    if(checked.defer||checked.drop)throw fail('unexpected_config');
    this.#media.checkServers(checked.event.iceServers);iceServers=checked.event.iceServers;
   }
   return {status:response.status,body:Buffer.from(raw),...iceServers?{iceServers}:{}};
  }finally{frame.fill(0);raw?.fill(0);}
 }
 async recoverResponse(slot){
  this.#guard();const account=this.#account(slot),intent=await this.#journal.load();
  if(intent?.phase!=='requested'||intent.callerSlot!==slot)return false;
  const archived=await this.#journal.loadResponse(intent.operationId);if(!archived)return false;
  try{
   this.#sameAccount(slot,account);if(archived.status<200||archived.status>=300)throw fail('call_rejected');
   const decoded=decode(archived.body,account.token);
   if(!decoded||typeof decoded!=='object'||Array.isArray(decoded)||decoded.status==='error'||decoded.error)throw fail('call_rejected');
   await this.#gate.bindResponse(slot,decoded);return true;
  }finally{archived.body.fill(0);}
 }
 async endKnownCall(slot){
  this.#guard();const intent=await this.#journal.load();if(intent?.phase!=='bound')throw fail('call_not_bound');
  const account=this.#account(slot),peer=this.#account(3-slot);
  const encoded=codec.outgoing({type:'bye',callUUID:intent.callUUID,callData:null},account.userId,peer.userId);
  const plain=Buffer.from(JSON.stringify(encoded.body));let frame,response;
  try{
   frame=wire.encryptBytes(plain,account.token);
   response=await this.forward(slot,{url:ENDPOINT,method:'POST',headers:{'api-version':'v2.5','x-token':account.token,
    'x-clientid':account.clientId,'x-topic':encoded.topic,project:'nasimrezvan','content-type':'application/json'},body:frame});
   return {status:response.status};
  }finally{plain.fill(0);frame?.fill(0);response?.body.fill(0);}
 }
 #eventsWork(action){const task=this.#eventQueue.then(action);this.#eventQueue=task.catch(()=>{});return task;}
 async #dispatch(slot,message){
  let checked;try{checked=await this.#gate.incoming(slot,message);}catch(error){
   if(['call_uuid_mismatch','wrong_peer','wrong_client'].includes(error.reason))return false;
   throw error;
  }
  if(checked.defer||checked.drop)return false;
  await this.#media?.checkSignal(3-slot,checked.event);
  if(checked.event.type==='bye')await this.#gate.terminalEvent(slot,message);
  await this.#deliver(slot,message);return true;
 }
 incoming(slot,message){return this.#eventsWork(async()=>{
  this.#guard();if(message?.type!=='msgGroupCall'||!this.#gate.state.pending)return false;
  if(this.#deliveryReady)return this.#dispatch(slot,message);
  const checked=await this.#gate.incoming(slot,message);if(checked.drop)return false;
  const bytes=Buffer.byteLength(JSON.stringify(message));
  if(this.#events.length>=MAX_EVENTS||bytes>MAX||this.#eventBytes+bytes>MAX_EVENT_BYTES)throw fail('deferred_event_limit');
  this.#events.push({slot,message:structuredClone(message)});this.#eventBytes+=bytes;return false;
 });}
 releaseEvents(){return this.#eventsWork(async()=>{
  this.#guard();if(!this.#gate.state.uuidKnown)throw fail('call_not_bound');
  this.#deliveryReady=true;const events=this.#events;this.#events=[];this.#eventBytes=0;
  for(const {slot,message}of events)await this.#dispatch(slot,message);
 });}
 close(){this.#abort.abort();this.#gate.stop();this.#events=[];this.#eventBytes=0;}
}
module.exports={OfficialCallTransport,ENDPOINT,ORIGIN};
