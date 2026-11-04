const {HttpClient,ApiError}=require('./http-client.cjs');
const wire=require('./wire.cjs');
const codec=require('./call-codec.cjs');
const {SSEParser}=require('./sse-parser.cjs');
const {initialCursor}=require('./stream-cursor.cjs');
const MAX_REPLY=256*1024+28;
const DOMAINS=['gaplication.com','gap.im','nasimrezvan.com'];
function serverBase(value){
 if(typeof value!=='string'||value.length>512)throw new ApiError('invalid_stream_server');
 let url;try{url=new URL(value);}catch{throw new ApiError('invalid_stream_server');}
 if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash||url.port||
  !['/','/sse'].includes(url.pathname)||!DOMAINS.some(domain=>url.hostname===domain||url.hostname.endsWith('.'+domain)))throw new ApiError('invalid_stream_server');
 return url.origin+(url.pathname==='/'?'':url.pathname);
}
async function bounded(response){
 const length=response.headers.get('content-length');
 if(length&&(!/^\d+$/.test(length)||Number(length)>MAX_REPLY))throw new ApiError('response_too_large');
 const reader=response.body?.getReader();if(!reader)throw new ApiError('invalid_response');
 const chunks=[];let total=0;
 try{while(true){const {done,value}=await reader.read();if(done)break;total+=value.length;
  if(total>MAX_REPLY)throw new ApiError('response_too_large');chunks.push(Buffer.from(value));}}
 catch(error){await reader.cancel().catch(()=>{});throw error;}
 return Buffer.concat(chunks,total);
}
class SignalingConnection{
 #session;
 #api;
 #fetch;
 #onEvent;
 #abort=new AbortController();
 #reader;
 #parser;
 #phase='connecting';
 #reason=null;
 #cursor=0n;
 #frames=0;
 #calls=0;
 #ignored=0;
 #invalid=0;
 #replayed=0;
 #historyGaps=0;
 #awaitingFreshEvent=false;
 #pending=new Set();
 #unbind;
 static async open(session,{fetchImpl=globalThis.fetch,onEvent=()=>{},cursor='0',signal}={}){
  if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw new ApiError('tls_verification_disabled');
  if(session?.provider!=='nasim'||typeof session.token!=='string'||! /^[\x21-\x7e]{16,16384}$/.test(session.token)||
   typeof session.deviceId!=='string'||! /^web\.[a-z0-9.-]{12,80}$/.test(session.deviceId)||
   typeof onEvent!=='function'||typeof cursor!=='string'||! /^(?:0|[1-9]\d{0,19})$/.test(cursor))throw new ApiError('invalid_saved_session');
  if(signal?.aborted)throw new ApiError('closed');
  if(signal&&(typeof signal.addEventListener!=='function'||typeof signal.removeEventListener!=='function'||typeof signal.aborted!=='boolean'))throw new ApiError('invalid_request');
  let self,client;try{self=codec.userId(session.userId);client=codec.clientId(session.clientId);}catch{throw new ApiError('invalid_saved_session');}
  const connection=new SignalingConnection();
  connection.#session={provider:'nasim',token:session.token,userId:self,clientId:client,deviceId:session.deviceId};
  connection.#cursor=BigInt(cursor);connection.#fetch=fetchImpl;connection.#onEvent=onEvent;
  connection.#api=new HttpClient({deviceId:session.deviceId,fetchImpl});
  if(signal){const close=()=>connection.close();signal.addEventListener('abort',close,{once:true});connection.#unbind=()=>signal.removeEventListener('abort',close);}
  try{await connection.#start();return connection;}catch(error){const reason=connection.#phase==='closed'?'closed':error instanceof ApiError?error.reason:'stream_connect_failed';connection.#fail(reason);throw new ApiError(reason,error instanceof ApiError?error.statusCode:undefined,['cursor_cipher','cursor_groups','cursor_message_id'].includes(error?.serviceType)?error.serviceType:undefined);}
 }
 #headers(){return {'accept-language':'fa','app-version':'web','api-version':'v2.8',
  clientid:this.#session.clientId,duid:this.#session.deviceId,os:'web',token:this.#session.token,
  project:'nasimrezvan','content-type':'application/octet-stream',origin:'https://web.nasimrezvan.com',referer:'https://web.nasimrezvan.com/'};}
 async #start(){
  if(this.#cursor===0n)this.#cursor=BigInt(await initialCursor(this.#session,{fetchImpl:this.#fetch,signal:this.#abort.signal}));
  if(this.#abort.signal.aborted)throw new ApiError('closed');
  const config=await this.#api.request('/message/get/config',{}, {token:this.#session.token,clientId:this.#session.clientId});
  if(this.#abort.signal.aborted)throw new ApiError('closed');
  const base=serverBase(config?.SSEServerAddress);
  let timedOut=false;const timer=setTimeout(()=>{timedOut=true;this.#abort.abort();},10000);let response;
  try{response=await this.#fetch(base+'/message/get',{method:'GET',headers:{...this.#headers(),lastEventTime:this.#cursor.toString()},
   redirect:'error',cache:'no-store',signal:this.#abort.signal});}
  catch{throw new ApiError(timedOut?'stream_connect_timeout':this.#abort.signal.aborted?'closed':'stream_connect_failed');}
  finally{clearTimeout(timer);}
  if(this.#abort.signal.aborted)throw new ApiError('closed');
  if(response.status===401)throw new ApiError('not_authorized');
  if(response.status!==200||response.headers.get('content-type')?.split(';')[0].trim().toLowerCase()!=='text/event-stream')throw new ApiError('invalid_event_stream');
  this.#reader=response.body?.getReader();if(!this.#reader)throw new ApiError('invalid_event_stream');
  this.#parser=new SSEParser(this.#session.token);this.#phase='connected';
  this.#pump().catch(error=>this.#fail(error instanceof ApiError?error.reason:'invalid_event_stream'));
 }
 async #pump(){
  const reader=this.#reader;
  try{while(!this.#abort.signal.aborted){
   const chunk=await reader.read();if(this.#abort.signal.aborted)return;
   if(chunk.done){this.#parser.finish();throw new ApiError('stream_ended');}
   const frames=this.#parser.push(chunk.value);
   for(const frame of frames){
    if(this.#abort.signal.aborted)return;this.#frames++;
    if(frame.event==='cleanSession'){
     // The official worker keeps reading after this notice. Chat clients
     // reload their conversation list; a call-only consumer instead discards
     // any stale call state and continues receiving fresh live events.
     this.#historyGaps++;this.#awaitingFreshEvent=true;
     try{await this.#onEvent({provider:'nasim',type:'streamReset',lastEventId:this.#cursor.toString()});}
     catch{throw new ApiError('event_handler_failed');}
     continue;
    }
    if(frame.event!=='message')continue;
    const cursor=BigInt(frame.id);if(cursor<=this.#cursor){this.#replayed++;continue;}
    const messages=frame.data?.messages;
    if(!Array.isArray(messages)||messages.length>1024)throw new ApiError('invalid_event_batch');
    for(const message of messages){
     if(this.#abort.signal.aborted)return;
     if(message?.type!=='msgGroupCall'){this.#ignored++;continue;}
     let event;try{event=codec.incoming(message,this.#session.userId);}catch{this.#invalid++;continue;}
     try{await this.#onEvent(event);}catch{throw new ApiError('event_handler_failed');}
     this.#calls++;
    }
    this.#cursor=cursor;this.#awaitingFreshEvent=false;
   }
  }}finally{reader.releaseLock();}
 }
 async send(signal,{peerId,timeout=10000}={}){
  if(this.#phase!=='connected'||!this.#session)throw new ApiError('not_connected');
  if(this.#pending.size>=8)throw new ApiError('too_many_requests');
  if(!Number.isInteger(timeout)||timeout<1||timeout>30000)throw new ApiError('invalid_request');
  let request;try{request=codec.outgoing(signal,this.#session.userId,peerId);}catch{throw new ApiError('invalid_call_signal');}
  const controller=new AbortController();this.#pending.add(controller);
  const timer=setTimeout(()=>controller.abort(),timeout),token=this.#session.token;let plain,body;
  try{
   plain=Buffer.from(JSON.stringify(request.body));body=wire.encryptBytes(plain,token);plain.fill(0);plain=null;
   const response=await this.#fetch('https://api.gaplication.com/',{method:'POST',headers:{
    'accept-language':'fa','app-version':'web','api-version':'v2.5','x-clientid':this.#session.clientId,
    os:'web','x-token':token,'x-topic':request.topic,'content-type':'application/json',project:'nasimrezvan',
    origin:'https://web.nasimrezvan.com',referer:'https://web.nasimrezvan.com/'},
    body,redirect:'error',cache:'no-store',signal:controller.signal});
   const bytes=await bounded(response);
   if(this.#abort.signal.aborted||controller.signal.aborted)throw new ApiError(this.#abort.signal.aborted?'closed':'timeout');
   if(response.status===401)throw new ApiError('not_authorized');
   if(response.status<200||response.status>=300)throw new ApiError('call_rejected',response.status);
   let result;try{plain=wire.decryptBytes(bytes,token);result=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain));}
   catch{throw new ApiError('invalid_call_response');}finally{plain?.fill(0);plain=null;}
   if(!result||typeof result!=='object'||Array.isArray(result)||result.status==='error'||result.error)throw new ApiError('call_rejected');
   let reply=null;
   // Some acknowledgments carry a full local call event; no raw service result
   // (including chat/user metadata) is returned when that shape is absent.
   if(result.data?.type&&result.data?.callUUID){
    try{reply=codec.incoming({...result,type:'msgGroupCall'},this.#session.userId);}catch{throw new ApiError('invalid_call_response');}
   }
   return {acknowledged:true,reply,...signal.type==='bye'&&result.status==='success'?{
    terminalAcknowledgement:{type:'bye',callUUID:signal.callUUID,peerId:String(peerId)}}:{}};
  }catch(error){if(error instanceof ApiError){if(error.reason==='not_authorized')this.#fail('not_authorized');throw error;}
   throw new ApiError(this.#abort.signal.aborted?'closed':controller.signal.aborted?'timeout':'call_transport_failed');}
  finally{clearTimeout(timer);plain?.fill(0);body?.fill(0);this.#pending.delete(controller);}
 }
 #fail(reason){if(['closed','failed'].includes(this.#phase))return;
  this.#phase='failed';this.#reason=reason;this.#dispose();}
 #dispose(){this.#unbind?.();this.#unbind=null;this.#abort.abort();this.#api?.close();for(const pending of this.#pending)pending.abort();
  this.#reader?.cancel().catch(()=>{});this.#parser?.close();this.#session=null;}
 close(){if(this.#phase==='closed')return;this.#phase='closed';this.#reason=null;this.#dispose();}
 get state(){return {provider:'nasim',phase:this.#phase,reason:this.#reason,lastEventId:this.#cursor.toString(),
  receivedFrames:this.#frames,callEvents:this.#calls,ignoredMessages:this.#ignored,invalidCallMessages:this.#invalid,
  replayedFrames:this.#replayed,historyGaps:this.#historyGaps,awaitingFreshEvent:this.#awaitingFreshEvent,
  pendingRequests:this.#pending.size,liveCallVerified:false,tunnelReady:false,billingVerified:false};}
}
module.exports={SignalingConnection,serverBase};
