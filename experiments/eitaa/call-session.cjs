// Private, account-bound two-party signaling controller. Media callbacks are
// private and do not imply a working provider relay, proxy or discounted tariff.
'use strict';
const {CallClient}=require('./call-client.cjs'),{CallKeyExchange}=require('./call-key.cjs');
const profiles=require('./client-profile.cjs');
const {SignalingCipher,MAX_PAYLOAD,validateSignal}=require('./call-signaling.cjs'),codec=require('./call-wire.cjs');
class CallError extends Error{constructor(reason){super('Eitaa call '+reason);this.reason=reason;}}
const fail=reason=>{throw new CallError(reason);};
const id=v=>typeof v==='bigint'&&v>0n&&v<2n**63n;
const hash=v=>typeof v==='bigint'&&v!==0n&&v>=-(2n**63n)&&v<2n**63n;
const uint=v=>Number.isInteger(v)&&v>=0&&v<=0x7fffffff;
const isBytes=(v,n)=>v instanceof Uint8Array&&v.length===n;
const SAFE=new Set(['closed','timeout','network_error','http_error','rate_limited','session_refresh_required','service_rejected',
 'unexpected_acknowledgement','unsafe_public_key','commitment_mismatch','fingerprint_mismatch','unsafe_group','invalid_group',
 'invalid_key_bytes','group_validation_busy','group_validation_failed','key_generation_failed','key_derivation_failed',
 'invalid_signal_authentication','signal_replayed','signal_too_old','invalid_signal_counter','invalid_signal_json','invalid_signal_payload',
 'invalid_signal_size','invalid_signal_key','signal_counter_exhausted','signal_crypto_failed','unsupported_signal_type']);
function protocol(v){return v?._==='phoneCallProtocol'&&v.udp_reflector===true&&uint(v.min_layer)&&uint(v.max_layer)&&v.min_layer<=92&&v.max_layer>=92&&Array.isArray(v.library_versions)&&v.library_versions.includes('4.0.0');}
function cursor(v){if(v?._!=='updates.state'||!['pts','qts','date','seq','unread_count'].every(k=>uint(v[k])))fail('invalid_update_cursor');return {pts:v.pts,qts:v.qts,date:v.date,seq:v.seq};}
function signalCopy(value){validateSignal(value);const text=JSON.stringify(value);if(Buffer.byteLength(text)>MAX_PAYLOAD)fail('invalid_signal_size');return JSON.parse(text);}
class CallSession{
 #account;#create;#callbacks;#client;#binding;#allowed;#self;#cursor;
 #phase='idle';#reason=null;#call;#peer;#outgoing=false;#dh;#commitment;#cipher;#early=[];#earlyBytes=0;
 #epoch=0;#queue=[];#queuedBytes=0;#working=false;#timer;#pollQueued=false;#deadline=0;#startedAt=0;#retired=new Set();#ignored=0;#waits=new Set();
 constructor(account,{allowedPeers=[],createClient=options=>new CallClient(options),onSecure=async()=>{},onSignal=async()=>{},onEnd=()=>{}}={}){
  if(!account||typeof createClient!=='function'||![onSecure,onSignal,onEnd].every(v=>typeof v==='function')||!Array.isArray(allowedPeers)||allowedPeers.length>32||allowedPeers.some(v=>typeof v!=='string'||!/^\d{1,19}$/.test(v)||!id(BigInt(v)))||new Set(allowedPeers).size!==allowedPeers.length)fail('invalid_call_options');
  this.#account=account;this.#allowed=new Set(allowedPeers);this.#create=createClient;this.#callbacks={onSecure,onSignal,onEnd};
 }
 #context(){
  const state=this.#account.state;if(state?.provider!=='eitaa'||state.signedIn!==true||state.selfConfirmed!==true)fail('not_authenticated');
  let record;try{record=this.#account.exportSession();}catch{fail('not_authenticated');}
  let mode;try{mode=profiles.fromRecord(record);}catch{fail('invalid_account_binding');}
  if(record?.provider!=='eitaa'||record.userId!==state.userId||typeof record.userId!=='string'||!/^\d{1,19}$/.test(record.userId)||!id(BigInt(record.userId))||typeof record.token!=='string'||!record.token||!profiles.validImei(record.imei,mode))fail('invalid_account_binding');
  if(this.#binding&&(record.token!==this.#binding.token||record.imei!==this.#binding.imei||record.userId!==this.#binding.userId||mode!==profiles.fromRecord(this.#binding)))fail('account_binding_changed');
  return record;
 }
 #guard(epoch){if(epoch!==this.#epoch)fail('call_cancelled');this.#context();}
 #enqueue(action,size=0){
  if(this.#queue.length>=32||this.#queuedBytes+size>256*1024){this.#finish('failed','too_many_call_events',true);return Promise.reject(new CallError('too_many_call_events'));}
  const promise=new Promise((resolve,reject)=>{this.#queue.push({action,size,epoch:this.#epoch,resolve,reject});this.#queuedBytes+=size;});this.#pump();return promise;
 }
 async #pump(){
  if(this.#working)return;this.#working=true;
  try{while(this.#queue.length){const job=this.#queue.shift();this.#queuedBytes-=job.size;
   try{const guard=()=>this.#guard(job.epoch);guard();const value=await job.action(guard);guard();job.resolve(value);}
   catch(e){const error=e instanceof CallError?e:new CallError(SAFE.has(e?.reason)?e.reason:'call_operation_failed');
    if(job.epoch===this.#epoch&&!['call_cancelled','call_busy','call_not_ringing','call_not_secure','call_peer_not_allowed','call_not_listening','invalid_call_peer','invalid_call_options','call_not_started'].includes(error.reason))this.#finish('failed',error.reason,true);
    job.reject(error);
   }
  }}finally{this.#working=false;}
 }
 async #rpc(name,input,guard){guard();if(!this.#client)fail('call_not_started');const result=await this.#client.request(name,input);guard();return result;}
 #peerInput(){return {_:'inputPhoneCall',id:this.#call.id,access_hash:this.#call.access_hash};}
 #resetCall(){
  if(this.#call){this.#retired.add(String(this.#call.id));while(this.#retired.size>128)this.#retired.delete(this.#retired.values().next().value);}
  this.#dh?.close();this.#dh=null;this.#cipher?.close();this.#cipher=null;this.#commitment?.fill(0);this.#commitment=null;
  for(const bytes of this.#early)bytes.fill(0);this.#early=[];this.#earlyBytes=0;this.#call=null;this.#peer=null;this.#outgoing=false;this.#deadline=0;this.#startedAt=0;
  try{Promise.resolve(this.#callbacks.onEnd()).catch(()=>{});}catch{}
 }
 #finish(phase,reason,close){
  this.#epoch++;clearInterval(this.#timer);this.#timer=null;this.#pollQueued=false;
  for(const cancel of this.#waits)cancel();this.#waits.clear();
  this.#resetCall();this.#phase=phase;this.#reason=reason;
  for(const job of this.#queue)job.reject(new CallError('call_cancelled'));this.#queue=[];this.#queuedBytes=0;
  if(close){this.#client?.close();this.#client=null;this.#binding=null;this.#self=null;this.#cursor=null;}
 }
 #checkCall(call,{incoming=false}={}){
  if(!id(call?.id)||!hash(call.access_hash)||!id(call.admin_id)||!id(call.participant_id)||call.admin_id===call.participant_id||call.video===true||!protocol(call.protocol))fail('invalid_call_response');
  const self=BigInt(this.#self),peer=incoming?call.admin_id:this.#outgoing?call.participant_id:call.admin_id;
  if((incoming||!this.#outgoing?call.participant_id:call.admin_id)!==self||!this.#allowed.has(String(peer))||this.#peer&&peer!==this.#peer)fail('call_participant_mismatch');
  if(this.#call&&(call.id!==this.#call.id||call.access_hash!==this.#call.access_hash))fail('call_identity_mismatch');return peer;
 }
 async #generate(guard){
  const config=await this.#rpc('messages.getDhConfig',{},guard);
  if(config?._!=='messages.dhConfig'||!isBytes(config.p,256)||!isBytes(config.random,256)||!uint(config.version))fail('invalid_dh_config');
  const exchange=await CallKeyExchange.create({prime:config.p,generator:config.g});try{guard();return exchange;}catch(e){exchange.close();throw e;}
 }
 async start({pollInterval=0}={}){
  if(!Number.isInteger(pollInterval)||pollInterval!==0&&(pollInterval<1000||pollInterval>30000))fail('invalid_call_options');
  return this.#enqueue(async guard=>{
   if(this.#client)fail('call_busy');const record=this.#context();if(this.#allowed.has(record.userId))fail('invalid_call_options');
   this.#binding={token:record.token,imei:record.imei,userId:record.userId,...record.profile?{profile:{...record.profile}}:{}};this.#self=record.userId;this.#client=this.#create({provider:'eitaa',token:record.token,imei:record.imei,...record.profile?{profile:{...record.profile}}:{}});
   this.#cursor=cursor(await this.#rpc('updates.getState',{},guard));this.#phase='listening';this.#reason=null;
   let next=Date.now()+pollInterval;const timerEpoch=this.#epoch;
   this.#timer=setInterval(()=>{
    if(timerEpoch!==this.#epoch)return;
    try{this.#guard(timerEpoch);if(this.#deadline&&Date.now()>this.#deadline)fail('call_timeout');}
    catch(e){this.#finish('failed',e instanceof CallError?e.reason:'account_binding_changed',true);return;}
    if(pollInterval&&Date.now()>=next&&!this.#pollQueued){next=Date.now()+pollInterval;this.#pollQueued=true;this.pollOnce().catch(()=>{}).finally(()=>{if(timerEpoch===this.#epoch)this.#pollQueued=false;});}
   },250);this.#timer.unref();return {listening:true};
  });
 }
 async dial({userId,accessHash}={}){
  if(typeof userId!=='string'||!/^\d{1,19}$/.test(userId)||!id(BigInt(userId))||!hash(accessHash))fail('invalid_call_peer');
  return this.#enqueue(async guard=>{
   if(!this.#client)fail('call_not_started');if(this.#phase!=='listening')fail('call_not_listening');if(!this.#allowed.has(userId)||userId===this.#self)fail('call_peer_not_allowed');
   this.#outgoing=true;this.#peer=BigInt(userId);this.#phase='dialing';this.#deadline=Date.now()+60000;this.#reason=null;this.#dh=await this.#generate(guard);
   const reply=await this.#rpc('phone.requestCall',{user_id:{_:'inputUser',user_id:this.#peer,access_hash:accessHash},g_a_hash:this.#dh.commitment},guard);
   if(reply?._!=='phone.phoneCall'||reply.phone_call?._!=='phoneCallWaiting')fail('invalid_call_response');
   this.#checkCall(reply.phone_call);if(this.#retired.has(String(reply.phone_call.id)))fail('retired_call');this.#call=reply.phone_call;this.#phase='waiting';return {dialing:true};
  });
 }
 async accept(){
  return this.#enqueue(async guard=>{
   if(this.#phase!=='ringing'||this.#outgoing)fail('call_not_ringing');this.#phase='accepting';this.#deadline=Date.now()+60000;this.#dh=await this.#generate(guard);
   const reply=await this.#rpc('phone.acceptCall',{peer:this.#peerInput(),g_b:this.#dh.publicValue},guard);
   if(reply?._!=='phone.phoneCall'||!['phoneCallWaiting','phoneCallAccepted','phoneCall'].includes(reply.phone_call?._))fail('invalid_call_response');
   this.#checkCall(reply.phone_call);if(reply.phone_call._==='phoneCall')await this.#active(reply.phone_call,guard);return {accepted:true};
  });
 }
 async #secure(call,key,guard){
  try{guard();this.#cipher=new SignalingCipher({key,isOutgoing:this.#outgoing});}finally{key.fill(0);}
  this.#dh?.close();this.#dh=null;this.#commitment?.fill(0);this.#commitment=null;this.#call=call;this.#phase='secure';this.#deadline=0;this.#startedAt=Date.now();
  await this.#notify('onSecure',{direction:this.#outgoing?'outgoing':'incoming',callId:String(call.id),selfId:this.#self,peerId:String(this.#peer),connections:call.connections},guard);
  for(const bytes of this.#early){try{await this.#deliver(bytes,guard);}finally{bytes.fill(0);}}this.#early=[];this.#earlyBytes=0;
 }
 async #accepted(call,guard){
  if(!this.#outgoing||!['waiting','confirming','secure'].includes(this.#phase))return;
  if(this.#phase==='secure')return;if(this.#phase==='confirming')fail('duplicate_call_transition');
  if(!isBytes(call.g_b,256))fail('invalid_call_response');this.#phase='confirming';const ga=this.#dh.publicValue,{key,fingerprint}=this.#dh.derive(call.g_b);
  try{
   const response=await this.#rpc('phone.confirmCall',{peer:this.#peerInput(),g_a:ga,key_fingerprint:fingerprint},guard);
   if(response?._!=='phone.phoneCall'||response.phone_call?._!=='phoneCall')fail('invalid_call_response');const active=response.phone_call;this.#checkCall(active);
   if(active.key_fingerprint!==fingerprint)fail('fingerprint_mismatch');await this.#secure(active,key,guard);
  }finally{ga.fill(0);key.fill(0);}
 }
 async #active(call,guard){
  if(this.#cipher){if(call.key_fingerprint!==this.#call.key_fingerprint)fail('fingerprint_mismatch');return;}if(this.#outgoing||this.#phase!=='accepting'||!this.#dh||!this.#commitment)fail('unexpected_call_confirmation');
  if(!isBytes(call.g_a_or_b,256))fail('invalid_call_response');const {key}=this.#dh.derive(call.g_a_or_b,{expectedCommitment:this.#commitment,expectedFingerprint:call.key_fingerprint});
  await this.#secure(call,key,guard);
 }
 async #onCall(call,guard){
  if(this.#retired.has(String(call?.id))){this.#ignored++;return;}
  if(call?._==='phoneCallRequested'&&!this.#call){
   if(this.#phase!=='listening'||!this.#allowed.has(String(call.admin_id))||call.participant_id!==BigInt(this.#self)){this.#ignored++;return;}
   this.#peer=this.#checkCall(call,{incoming:true});if(!isBytes(call.g_a_hash,32))fail('invalid_call_response');this.#outgoing=false;this.#call=call;this.#commitment=Buffer.from(call.g_a_hash);this.#phase='ringing';this.#deadline=Date.now()+60000;
   if(await this.#rpc('phone.receivedCall',{peer:this.#peerInput()},guard)!==true)fail('call_receipt_not_confirmed');return;
  }
  if(!this.#call||call.id!==this.#call.id){this.#ignored++;return;}
  if(call._==='phoneCallDiscarded'){this.#resetCall();this.#phase='listening';this.#reason='remote_call_ended';return;}
  this.#checkCall(call);
  if(call._==='phoneCallAccepted')await this.#accepted(call,guard);
  else if(call._==='phoneCall')await this.#active(call,guard);
  else if(!['phoneCallWaiting','phoneCallRequested'].includes(call._))fail('invalid_call_response');
 }
 async #deliver(data,guard){
  const signal=this.#cipher.decryptJson(data);await this.#notify('onSignal',signal,guard);
 }
 async #notify(name,value,guard){
  const call=this.#call,cipher=this.#cipher;let active=true,tail=Promise.resolve(),sendError;
  const check=()=>{guard();if(this.#call!==call||this.#cipher!==cipher)fail('call_cancelled');};
  const send=value=>{check();const copy=signalCopy(value);
   if(!active)return this.#enqueue(g=>{check();return this.#sendSignal(copy,g);});
   const next=tail.then(()=>{check();if(sendError)throw sendError;return this.#sendSignal(copy,guard);});tail=next.catch(e=>{sendError??=e;});return next;
  };
  let timer,cancel;
  try{
   await new Promise((resolve,reject)=>{
    cancel=()=>reject(new CallError('call_cancelled'));this.#waits.add(cancel);timer=setTimeout(()=>reject(new CallError('media_callback_timeout')),20000);
    const operation=(async()=>{if(name==='onSecure')await this.#callbacks.onSecure({...value,send});else await this.#callbacks.onSignal(value,{callId:String(call.id),send});await tail;if(sendError)throw sendError;guard();})();
    operation.then(resolve,reject);
   });
  }finally{active=false;clearTimeout(timer);this.#waits.delete(cancel);}
 }
 async #onUpdate(update,guard){
  if(update?._==='updatePhoneCall')return this.#onCall(update.phone_call,guard);
  if(update?._!=='updatePhoneCallSignalingData')return;
  if(!this.#call||update.phone_call_id!==this.#call.id){this.#ignored++;return;}
  const data=update.data;if(!(data instanceof Uint8Array)||data.length<21||data.length>MAX_PAYLOAD+20)fail('invalid_signal_size');
  if(this.#cipher)return this.#deliver(data,guard);
  if(this.#early.length>=16||this.#earlyBytes+data.length>128*1024)fail('too_many_early_signals');this.#early.push(Buffer.from(data));this.#earlyBytes+=data.length;
 }
 async #sendSignal(value,guard){
  guard();if(!this.#cipher||this.#phase!=='secure')fail('call_not_secure');const data=this.#cipher.encryptJson(value);
  try{if(await this.#rpc('phone.sendSignalingData',{peer:this.#peerInput(),data},guard)!==true)fail('signal_not_confirmed');}finally{data.fill(0);}
 }
 sendSignal(value){let copy;try{copy=signalCopy(value);}catch(e){return Promise.reject(new CallError(SAFE.has(e?.reason)?e.reason:'invalid_signal_payload'));}const call=this.#call,cipher=this.#cipher;return this.#enqueue(guard=>{if(this.#call!==call||this.#cipher!==cipher)fail('call_cancelled');return this.#sendSignal(copy,guard);});}
 ingest(update){
  let bytes,copy;try{bytes=codec.object(update);copy=codec.decode(bytes,'Update');}catch{return Promise.reject(new CallError('invalid_call_event'));}
  try{return this.#enqueue(guard=>this.#onUpdate(copy,guard),bytes.length);}finally{bytes.fill(0);}
 }
 pollOnce(){
  return this.#enqueue(async guard=>{
   if(!this.#cursor||!this.#client)fail('call_not_started');const before=this.#cursor;
   const result=await this.#rpc('updates.getDifference',{pts:before.pts,date:before.date,qts:-1},guard);let after;
   if(result?._==='updates.differenceTooLong')fail('update_resync_required');
   if(result?._==='updates.differenceEmpty'){if(!uint(result.date)||!uint(result.seq))fail('invalid_update_cursor');after={...before,date:result.date,seq:result.seq};}
   else if(['updates.difference','updates.differenceSlice'].includes(result?._)){
    after=cursor(result._==='updates.difference'?result.state:result.intermediate_state);if(!Array.isArray(result.other_updates)||result.other_updates.length>256)fail('invalid_call_event');
   }else fail('invalid_update_response');
   if(['pts','qts','date','seq'].some(k=>after[k]<before[k]))fail('update_cursor_regressed');
   for(const update of result.other_updates||[]){await this.#onUpdate(update,guard);guard();}
   guard();this.#cursor=after;return {polled:true,more:result._==='updates.differenceSlice'};
  });
 }
 hangUp(reason='phoneCallDiscardReasonHangup'){
  if(!['phoneCallDiscardReasonHangup','phoneCallDiscardReasonDisconnect','phoneCallDiscardReasonBusy'].includes(reason))fail('invalid_call_options');
  const call=this.#call;return this.#enqueue(async guard=>{
   if(!call)fail('call_not_started');if(call!==this.#call)fail('call_cancelled');const target=call.id,response=await this.#rpc('phone.discardCall',{peer:this.#peerInput(),duration:Math.min(604800,this.#startedAt?Math.floor((Date.now()-this.#startedAt)/1000):0),reason},guard);
   const updates=response?._==='updates'||response?._==='updatesCombined'?response.updates:response?._==='updateShort'?[response.update]:null;
   if(!Array.isArray(updates)||!updates.some(v=>v?._==='updatePhoneCall'&&v.phone_call?._==='phoneCallDiscarded'&&v.phone_call.id===target))fail('call_end_not_confirmed');
   for(const update of updates)await this.#onUpdate(update,guard);return {ended:true};
  });
 }
 stop(){this.#finish('stopped',null,true);}
 close(){this.stop();}
 get state(){return {provider:'eitaa',phase:this.#phase,reason:this.#reason,listening:!!this.#client,callId:this.#call?String(this.#call.id):null,peerId:this.#peer?String(this.#peer):null,
  direction:this.#call?(this.#outgoing?'outgoing':'incoming'):null,keyNegotiated:!!this.#cipher,busy:this.#working,queued:this.#queue.length,ignoredEvents:this.#ignored,
  mediaConnected:false,peerAuthenticated:false,proxyReady:false,providerPathVerified:false,billingVerified:false};}
}
module.exports={CallSession,CallError};
