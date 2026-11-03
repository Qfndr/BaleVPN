// Private single-call controller; no native media, automatic answering/redial,
// or connected-proxy state. All signaling here is opaque protocol ciphertext.
'use strict';
const {CallClient}=require('./call-client.cjs'),codec=require('./call-codec.cjs'),updates=require('./call-updates.cjs');
class CallError extends Error{constructor(reason){super('Rubika call '+reason);this.reason=reason;}}
const fail=reason=>{throw new CallError(reason);};
const id=v=>typeof v==='string'&&/^[A-Za-z0-9_-]{8,128}$/.test(v);
const SAFE=new Set(['not_authenticated','invalid_account_binding','account_binding_changed','not_authorized','rate_limited','registration_required',
 'service_rejected','timeout','network_error','http_error','invalid_dc_server','invalid_dc_response','invalid_response',
 'invalid_encrypted_response','response_too_large','tls_verification_disabled','invalid_call_response','call_identity_mismatch',
 'unsupported_call_protocol','update_account_mismatch','call_operation_failed']);
const LOCAL=new Set(['call_not_started','call_already_started','call_not_listening','call_not_ringing','call_not_accepted','call_peer_not_allowed']);
const rank={Requested:0,Waiting:1,Accepted:2,Discarded:3};
class CallSession{
 #account;#create;#allowed;#profile;#now;#client;#binding;#self;#epoch=0;#busy=false;#closed=false;#ready=false;#timer;
 #phase='idle';#reason=null;#call;#peer;#outgoing=false;#acceptedLocally=false;#deadline=0;#acceptedAt=0;#times=new Map();#latest=0;
 #retired=new Set();#signals=[];#signalBytes=0;#ignored=0;
 constructor(account,{allowedPeers=[],protocol,createClient=a=>new CallClient(a),now=Date.now}={}){
  if(!account||typeof createClient!=='function'||typeof now!=='function'||!Array.isArray(allowedPeers)||allowedPeers.length>32||
   allowedPeers.some(v=>!id(v))||new Set(allowedPeers).size!==allowedPeers.length)fail('invalid_call_options');
  try{if(!protocol||Object.keys(protocol).length!==3||Object.keys(protocol).some(k=>!['min_layer','max_layer','library_versions'].includes(k)))fail('invalid_call_options');codec.validateInput('acceptCall',{call_id:'profile_validation',...protocol});}catch{fail('invalid_call_options');}
  this.#account=account;this.#create=createClient;this.#allowed=new Set(allowedPeers);this.#profile=structuredClone(protocol);this.#now=now;
 }
 #context(){
  const state=this.#account.state;let record;
  if(state?.provider!=='rubika'||state.signedIn!==true||state.selfConfirmed!==true)fail('not_authenticated');
  try{record=this.#account.exportSession();}catch{fail('not_authenticated');}
  if(record?.provider!=='rubika'||!id(record.userId)||record.userId!==state.userId||['auth','privateKey','publicKey'].some(k=>typeof record[k]!=='string'||!record[k]))fail('invalid_account_binding');
  if(this.#binding&&['userId','auth','privateKey','publicKey'].some(k=>record[k]!==this.#binding[k]))fail('account_binding_changed');return record;
 }
 #guard(epoch){
  if(this.#closed||epoch!==this.#epoch)fail('call_cancelled');this.#context();
  if(this.#ready&&this.#client?.state.ready!==true)fail('call_operation_failed');
 }
 #wipeSignals(){for(const bytes of this.#signals)bytes.fill(0);this.#signals=[];this.#signalBytes=0;}
 #clearCall(){
  if(this.#call)this.#retired.add(this.#call.call_id);
  this.#call=null;this.#peer=null;this.#outgoing=false;this.#acceptedLocally=false;this.#deadline=0;this.#acceptedAt=0;
  this.#times.clear();this.#latest=0;this.#wipeSignals();
 }
 #finish(reason){this.#clearCall();this.#phase='listening';this.#reason=reason;}
 #fail(reason){
  this.#epoch++;clearInterval(this.#timer);this.#timer=null;this.#clearCall();this.#ready=false;this.#phase='failed';this.#reason=reason;
  this.#client?.close();this.#client=null;this.#binding=null;this.#self=null;
 }
 #tick(){
  try{this.#guard(this.#epoch);if(this.#deadline&&this.#now()>=this.#deadline)fail('call_timeout');}
  catch(e){this.#fail(SAFE.has(e?.reason)||e?.reason==='call_timeout'?e.reason:'call_operation_failed');}
 }
 async #run(action){
  if(this.#closed)fail('closed');if(this.#busy)fail('call_busy');this.#busy=true;const epoch=this.#epoch;
  try{this.#guard(epoch);if(this.#deadline&&this.#now()>=this.#deadline)fail('call_timeout');const result=await action(()=>this.#guard(epoch));this.#guard(epoch);return result;}
  catch(e){
   if(this.#closed||epoch!==this.#epoch)throw new CallError('call_cancelled');
   const reason=e instanceof CallError||SAFE.has(e?.reason)?e.reason:'call_operation_failed';
   if(!LOCAL.has(reason))this.#fail(reason);throw new CallError(reason);
  }finally{this.#busy=false;}
 }
 #wipeReply(reply){
  if(Array.isArray(reply?.call_signal_data))for(const signal of reply.call_signal_data.slice(0,codec.MAX_BATCH))if(Buffer.isBuffer(signal?.data))signal.data.fill(0);
  if(Array.isArray(reply?.data_list))for(const bytes of reply.data_list.slice(0,codec.MAX_BATCH))if(Buffer.isBuffer(bytes))bytes.fill(0);
 }
 async #rpc(method,input,guard){
  guard();const result=await this.#client.request(method,input);try{guard();return result;}catch(e){this.#wipeReply(result);throw e;}
 }
 #checkPeer(update,peer){
  if(update.call?.call_type!==undefined&&update.call.call_type!=='Voice')fail('unsupported_call_type');
  if(update.object_guid!==undefined&&update.object_guid!==peer)fail('call_participant_mismatch');
  if(update.call?.other_participants?.some(v=>![this.#self,peer].includes(v.object_guid)))fail('call_participant_mismatch');
 }
 #fresh(update){
  // Local policy: timestamps are treated as Unix seconds with 30 seconds of
  // forward skew and a 120-second incoming window. Live clock semantics remain
  // unverified; a stale request is ignored rather than automatically answered.
  const now=Math.floor(this.#now()/1000);return update.timestamp<=now+30&&update.timestamp>=now-120;
 }
 #begin(update,peer,outgoing){
  if(this.#retired.has(update.call_id))fail('retired_call');if(this.#retired.size>=128)fail('call_history_full');
  if(!this.#fresh(update))fail('stale_call');
  if(update.action!=='New'||!update.call||!['Requested','Waiting'].includes(update.call.state))fail('invalid_call_response');
  this.#checkPeer(update,peer);this.#peer=peer;this.#outgoing=outgoing;this.#acceptedLocally=false;
  this.#call={call_id:update.call_id};this.#deadline=this.#now()+60000;this.#apply(update);
 }
 #apply(update){
  if(!this.#call||update.call_id!==this.#call.call_id){this.#ignored++;return;}
  this.#checkPeer(update,this.#peer);
  if(update.action==='Delete'){
   if(update.timestamp<this.#latest){this.#ignored++;return;}this.#finish('remote_call_ended');return;
  }
  const fields=update.action==='Edit'?update.updated_parameters:Object.keys(update.call);
  // Refuse an ambiguous delta rather than overwrite retained state with every
  // default field emitted by a serializer. Null/absent values never invent data.
  if(!Array.isArray(fields))fail('missing_update_parameters');
  const next={...this.#call};let changed=false;
  for(const name of fields){
   if(name==='call_id'||!Object.hasOwn(update.call,name))continue;
   const value=update.call[name];
   const previous=this.#times.get(name)??-1;
   if(update.timestamp<previous||update.timestamp===previous&&!(name==='state'&&rank[value]>rank[next.state]))continue;
   if(name==='state'&&rank[value]<rank[next.state]){this.#ignored++;continue;}
   next[name]=structuredClone(value);this.#times.set(name,update.timestamp);changed=true;
  }
  if(!changed)return;this.#latest=Math.max(this.#latest,update.timestamp);this.#call=next;
  if(next.state==='Discarded'){this.#finish('remote_call_ended');return;}
  if(next.state==='Accepted'){
   if(!this.#outgoing&&!this.#acceptedLocally){this.#finish('call_answered_elsewhere');return;}
   this.#phase='accepted';this.#deadline=0;if(!this.#acceptedAt)this.#acceptedAt=this.#now();
  }else this.#phase=this.#outgoing?'waiting':this.#acceptedLocally?'accepting':'ringing';
 }
 #signal(callId,bytes){
  if(!this.#call||callId!==this.#call.call_id){this.#ignored++;return;}
  if(!Buffer.isBuffer(bytes)||!bytes.length||bytes.length>codec.MAX_SIGNAL||this.#signals.length>=32||this.#signalBytes+bytes.length>codec.MAX_SIGNAL)fail('too_many_call_signals');
  this.#signals.push(Buffer.from(bytes));this.#signalBytes+=bytes.length;
 }
 #onUpdate(update){
  if(this.#retired.has(update.call_id)){this.#ignored++;return;}
  if(this.#call){this.#apply(update);return;}
  if(update.action!=='New'||update.call?.call_type!=='Voice'||update.call?.state!=='Requested'||!this.#allowed.has(update.object_guid)||update.object_guid===this.#self||!this.#fresh(update)){
   this.#ignored++;return;
  }
  this.#begin(update,update.object_guid,false);
 }
 start(){return this.#run(async guard=>{
  if(this.#client)fail('call_already_started');const record=this.#context();if(this.#allowed.has(record.userId))fail('invalid_call_options');
  this.#binding={userId:record.userId,auth:record.auth,privateKey:record.privateKey,publicKey:record.publicKey};this.#self=record.userId;
  this.#client=this.#create(this.#account);const result=await this.#client.start();guard();
  if(result?.ready!==true||result.mediaReady!==false)fail('invalid_call_response');
  this.#ready=true;this.#phase='listening';this.#reason=null;this.#timer=setInterval(()=>this.#tick(),250);this.#timer.unref();return {listening:true,mediaReady:false};
 });}
 dial(peerId){
  if(!id(peerId)||!this.#allowed.has(peerId))return Promise.reject(new CallError('call_peer_not_allowed'));
  return this.#run(async guard=>{
   if(!this.#ready)fail('call_not_started');if(this.#call||this.#phase!=='listening')fail('call_not_listening');if(peerId===this.#self)fail('call_peer_not_allowed');
   this.#phase='dialing';this.#deadline=this.#now()+60000;
   const reply=await this.#rpc('requestCall',{call_type:'Voice',user_guid:peerId,...structuredClone(this.#profile)},guard);
   if(reply?.call_type!=='WebRtc')fail('unsupported_call_protocol');const update=updates.callUpdate(reply.call_update);
   this.#begin(update,peerId,true);return {dialing:true,callId:this.#call.call_id};
  });
 }
 pollOnce(){return this.#run(async guard=>{
  if(!this.#ready)fail('call_not_started');const reply=await this.#rpc('getUpdate',{},guard);
  try{
   if(reply?.user_guid!==this.#self||!Array.isArray(reply.call_updates)||reply.call_updates.length>64||!Array.isArray(reply.call_signal_data)||reply.call_signal_data.length>codec.MAX_BATCH)fail('invalid_call_response');
   // Project all updates before changing state, even with an injected client.
   const calls=reply.call_updates.map(v=>updates.callUpdate(v));for(const update of calls)this.#onUpdate(update);
   for(const signal of reply.call_signal_data)this.#signal(signal.call_id,signal.data);
  }finally{this.#wipeReply(reply);}
  return {polled:true};
 });}
 acknowledge(){return this.#run(async guard=>{
  if(this.#phase!=='ringing'||this.#outgoing)fail('call_not_ringing');const callId=this.#call.call_id;
  const reply=await this.#rpc('receivedCall',{call_id:callId},guard);this.#apply(updates.callUpdate(reply.call_update,{callId}));return {acknowledged:true};
 });}
 accept(){return this.#run(async guard=>{
  if(this.#phase!=='ringing'||this.#outgoing)fail('call_not_ringing');const callId=this.#call.call_id;this.#acceptedLocally=true;this.#phase='accepting';this.#deadline=this.#now()+60000;
  const reply=await this.#rpc('acceptCall',{call_id:callId,...structuredClone(this.#profile)},guard);
  this.#apply(updates.callUpdate(reply.call_update,{callId}));return {accepted:true,mediaReady:false};
 });}
 hangup(reason='Hangup'){
  if(!['Missed','Disconnect','Hangup','Busy'].includes(reason))return Promise.reject(new CallError('invalid_call_options'));
  return this.#run(async guard=>{
  if(!this.#call)fail('call_not_ringing');const callId=this.#call.call_id,duration=this.#acceptedAt?Math.min(2147483647,Math.max(0,Math.floor((this.#now()-this.#acceptedAt)/1000))):0;
  try{codec.validateInput('discardCall',{call_id:callId,duration,reason});}catch{fail('invalid_call_options');}
  const reply=await this.#rpc('discardCall',{call_id:callId,duration,reason},guard);updates.callUpdate(reply.call_update,{callId});
  this.#finish('local_call_ended');return {ended:true};
 });}
 sendOpaqueSignal(bytes){
  let data;try{data=codec.encodeSignal(bytes);}catch{return Promise.reject(new CallError('invalid_call_signal'));}
  return this.#run(async guard=>{
   if(this.#phase!=='accepted')fail('call_not_accepted');const callId=this.#call.call_id;
   await this.#rpc('sendSignalingData',{call_id:callId,data},guard);return {sent:true};
  });
 }
 pollSignals(){return this.#run(async guard=>{
  if(this.#phase!=='accepted')fail('call_not_accepted');const callId=this.#call.call_id,reply=await this.#rpc('getSignalingData',{call_id:callId},guard);
  try{
   if(reply?.call_id!==callId||!Array.isArray(reply.data_list)||reply.data_list.length>codec.MAX_BATCH)fail('invalid_call_response');
   for(const bytes of reply.data_list)this.#signal(callId,bytes);
  }finally{this.#wipeReply(reply);}
  return {polled:true};
 });}
 takeOpaqueSignals(){
  if(this.#closed)fail('closed');this.#tick();if(this.#phase!=='accepted')fail('call_not_accepted');
  const result=this.#signals;this.#signals=[];this.#signalBytes=0;return result;
 }
 // No private media/key export until its native protocol is actually supported.
 close(){if(this.#closed)return;this.#closed=true;this.#fail('closed');this.#phase='closed';}
 get state(){
  if(this.#ready&&!this.#closed)this.#tick();
  return {provider:'rubika',phase:this.#phase,ready:this.#ready,busy:this.#busy,reason:this.#reason,callId:this.#call?.call_id??null,
   peerId:this.#peer??null,direction:this.#call?(this.#outgoing?'outgoing':'incoming'):null,serviceState:this.#call?.state??null,
   serviceDuration:this.#call?.duration??null,
   queuedSignals:this.#signals.length,ignoredEvents:this.#ignored,mediaReady:false,peerAuthenticated:false,providerVerified:false};
 }
}
module.exports={CallSession,CallError};
