// Account-owned two-party call controller. All relay/SDP material stays private.
// There is no automatic dialing, answering, redial or cross-account trust.
const {NativeMediaBridge}=require('./native-media-bridge.cjs');
const {userId,clientId}=require('./call-codec.cjs');
const SAFE=new Set(['timeout','closed','not_authorized','not_connected','call_transport_failed','call_rejected','invalid_call_response',
 'invalid_native_output','operation_timeout','input_closed','process_exited','process_failed','prepare_timeout','invalid_relay',
 'invalid_pairing','invalid_description','negotiation_failed','gather_timeout','no_relay','transport_closed','transport_failed',
 'transport_disconnected','proxy_bind_failed','server_setup_failed','media_setup_failed','unsafe_environment']);
class CallError extends Error {constructor(reason,fatal=false){super('Nasim call '+reason);this.reason=reason;this.fatal=fatal;}}
const error=(reason,fatal=false)=>new CallError(reason,fatal);
function cert(v){return typeof v==='string'&&v.length>=128&&v.length<=16384&&v.length%2===0&&/^[a-f0-9]+$/.test(v);}
function uuid(v){return typeof v==='string'&&/^[-A-Za-z0-9_:]{1,128}$/.test(v);}
class CallSession {
 #account;#executable;#open;#rpc;#self;#client;#allowed=new Set();#bridge;#own;#trusted=[];#options;
 #phase='idle';#direction;#peer;#call;#remote;#config;#localAccepted=false;#remoteAccepted=false;
 #configured=false;#negotiated=false;#offerSeen=false;#answerSeen=false;#earlyOffers=new Map();#early=[];#earlyBytes=0;#ice=[];#iceSeen=new Set();
 #epoch=0;#queue=[];#working=false;#bytes=0;#timer;#deadline=0;#retired=new Set();#ignored=0;#reason=null;
 constructor(account,{executable,open=NativeMediaBridge.open}={}){this.#account=account;this.#executable=executable;this.#open=open;}
 #context(){
  const state=this.#account.state;
  if(state.provider!=='nasim'||!state.signedIn)throw error('not_authenticated',true);
  let self,client,rpc;try{self=userId(state.userId);client=clientId(state.clientId);rpc=this.#account.signalConnection;if(typeof rpc?.send!=='function')throw Error();}catch{throw error('event_stream_not_connected',true);}
  if(this.#rpc&&(rpc!==this.#rpc||self!==this.#self||client!==this.#client))throw error('call_connection_changed',true);
  this.#rpc=rpc;this.#self=self;this.#client=client;return rpc;
 }
 #guard(epoch){if(epoch!==this.#epoch)throw error('call_cancelled');this.#context();}
 #enqueue(action,bytes=0){
  if(this.#queue.length>=32||this.#bytes+bytes>2*1024*1024){this.#finish('failed','too_many_call_events',true);return Promise.reject(error('too_many_call_events'));}
  const promise=new Promise((resolve,reject)=>{this.#queue.push({action,bytes,resolve,reject,epoch:this.#epoch});this.#bytes+=bytes;});
  this.#pump();return promise;
 }
 async #pump(){
  if(this.#working)return;this.#working=true;
  try{while(this.#queue.length){const job=this.#queue.shift();this.#bytes-=job.bytes;
   try{this.#guard(job.epoch);const result=await job.action(()=>this.#guard(job.epoch));this.#guard(job.epoch);job.resolve(result);}
   catch(e){const failure=e instanceof CallError?e:error('call_operation_failed',true);
    if(job.epoch===this.#epoch&&failure.fatal)this.#finish('uncertain',failure.reason,true);
    job.reject(failure);
   }
  }}finally{this.#working=false;}
 }
 async #io(work,guard){
  guard();try{const value=await work();guard();return value;}
  catch(e){if(e instanceof CallError)throw e;throw error(SAFE.has(e?.reason)?e.reason:'call_operation_failed',true);}
 }
 async #send(type,callData,guard){
  const signal={type,callData,...type==='callRequest'?{}:{callUUID:this.#call}};
  const response=await this.#io(()=>this.#rpc.send(signal,{peerId:this.#peer}),guard);
  if(response?.reply)this.handleEvent(response.reply);
 }
 #arm(active=true){
  this.#deadline=active?Date.now()+60000:0;clearInterval(this.#timer);
  this.#timer=setInterval(()=>{
   try{this.#context();const media=this.#bridge?.state;
    if(media&&['failed','closed'].includes(media.phase))throw error(SAFE.has(media.reason)?media.reason:'transport_closed',true);
    if(this.#negotiated&&this.#localAccepted&&this.#remoteAccepted&&this.#mediaReady(media))this.#phase='connected';
    if(this.#deadline&&this.#phase!=='connected'&&Date.now()>this.#deadline)throw error('call_timeout',true);
   }catch(e){this.#finish('uncertain',e instanceof CallError?e.reason:'call_connection_changed',true);}
  },1000);this.#timer.unref();
 }
 #mediaReady(media){return media?.mediaConnected===true&&media.relayPair===true&&media.peerAuthenticated===true&&
  (this.#options?.role==='server'?media.phase==='connected':media.proxyReady===true);}
 #finish(phase,reason=null,disconnect=false){
  this.#epoch++;if(this.#call){this.#retired.add(this.#call);while(this.#retired.size>128)this.#retired.delete(this.#retired.values().next().value);}
  clearInterval(this.#timer);this.#timer=null;this.#bridge?.close();this.#bridge=null;this.#own=null;this.#trusted=[];
  this.#config=null;this.#earlyOffers.clear();this.#early=[];this.#earlyBytes=0;this.#ice=[];this.#iceSeen.clear();this.#configured=this.#negotiated=false;
  this.#offerSeen=this.#answerSeen=this.#localAccepted=this.#remoteAccepted=false;this.#phase=phase;this.#reason=reason;
  this.#call=null;this.#remote=null;
  for(const job of this.#queue)job.reject(error('call_cancelled'));this.#queue=[];this.#bytes=0;
  if(disconnect){
   // Never tear down a newer account subscription when invalidating the one
   // this controller actually pinned. Old HTTP requests still get cancelled.
   let current;try{current=this.#account.signalConnection;}catch{}
   if(this.#rpc&&current===this.#rpc)this.#account.disconnectSignals();else this.#rpc?.close?.();
   this.#rpc=null;this.#self=null;this.#client=null;this.#allowed.clear();
  }
 }
 setAllowedPeers(peers){
  this.#context();if(!['idle','prepared','ready','ended'].includes(this.#phase)||this.#working)throw error('call_busy');
  if(!Array.isArray(peers)||peers.length>16)throw error('invalid_call_peers');
  let values;try{values=peers.map(userId);}catch{throw error('invalid_call_peers');}
  if(new Set(values).size!==values.length||values.includes(this.#self))throw error('invalid_call_peers');this.#allowed=new Set(values);
 }
 async prepare({role,socksPort=1089,throughput=false}={}){
  return this.#enqueue(async guard=>{
   if(!['idle','ended'].includes(this.#phase)||this.#bridge)throw error('call_busy');
   if(!['client','server'].includes(role)||!Number.isInteger(socksPort)||socksPort<0||socksPort>65535||socksPort>0&&socksPort<1024||typeof throughput!=='boolean')throw error('invalid_media_options');
   this.#phase='preparing';this.#reason=null;
   const bridge=await this.#io(async()=>{
    const bridge=await this.#open(this.#executable);try{guard();return bridge;}catch(e){bridge.close();throw e;}
   },guard);
   this.#bridge=bridge;this.#own=bridge.publicCertificate;this.#options={role,socksPort,throughput};this.#phase='prepared';this.#arm(false);return {publicCertificate:this.#own};
  });
 }
 trustCertificate(certificate){
  this.#context();if(this.#phase!=='prepared'||this.#working)throw error('call_busy');
  if(!cert(certificate)||certificate===this.#own)throw error('invalid_pairing');this.#trusted=[certificate];this.#phase='ready';
 }
 async dial(peerId){
  try{peerId=userId(peerId);}catch{throw error('invalid_call_peer');}
  return this.#enqueue(async guard=>{
   if(this.#phase!=='ready')throw error('call_not_ready');if(peerId===this.#self||!this.#allowed.has(peerId))throw error('call_peer_not_allowed');
   this.#peer=peerId;this.#direction='caller';this.#phase='dialing';this.#localAccepted=true;this.#arm();
   await this.#send('callRequest',{method:'audio'},guard);this.#phase='outgoing';return {requested:true};
  });
 }
 async #configure(guard){
  if(this.#configured)return;
  if(!this.#config||!this.#bridge||!this.#trusted.length)throw error('call_not_ready',true);
  await this.#io(()=>this.#bridge.configure({provider:'nasim',callUUID:this.#call,selfId:this.#self,peerId:this.#peer,
   iceServers:this.#config.iceServers},{...this.#options,trustedCertificates:this.#trusted}),guard);this.#configured=true;
 }
 async accept(){
  return this.#enqueue(async guard=>{
   if(this.#phase!=='incoming'||this.#direction!=='callee')throw error('no_incoming_call');
   await this.#configure(guard);this.#localAccepted=true;this.#phase='negotiating';
   await this.#send('accept',{},guard);
   const offer=await this.#io(()=>this.#bridge.offer(),guard);this.#offerSeen=true;
   await this.#send('offer',offer,guard);return {accepted:true};
  });
 }
 async #offer(event,guard){
  if(this.#direction!=='caller'||this.#offerSeen)return;
  if(!this.#remoteAccepted){if(this.#earlyOffers.size<4||this.#earlyOffers.has(event.senderClientId))this.#earlyOffers.set(event.senderClientId,event);else this.#ignored++;return;}
  if(event.senderClientId!==this.#remote){this.#ignored++;return;}
  this.#offerSeen=true;await this.#configure(guard);this.#phase='negotiating';
  const answer=await this.#io(()=>this.#bridge.answer(event.description),guard);
  await this.#send('answer',{...answer,clientID:this.#remote,participantData:{isCameraEnabled:false,isMicrophoneMuted:false}},guard);
  this.#negotiated=true;await this.#flushIce(guard);
 }
 async #flushIce(guard){
  if(!this.#negotiated)return;
  for(const candidate of this.#ice.splice(0))await this.#io(()=>this.#bridge.addCandidate(candidate),guard);
 }
 handleEvent(event){
  if(event?.provider!=='nasim'){this.#ignored++;return false;}
  if(event.type==='streamReset'){
   if(this.#call||['dialing','outgoing','incoming','negotiating','connected'].includes(this.#phase))this.#finish('uncertain','call_stream_reset',true);
   return true;
  }
  if(!this.#bridge){this.#ignored++;return false;}
  if(!uuid(event.callUUID)||this.#retired.has(event.callUUID)){this.#ignored++;return false;}
  let bytes;try{bytes=Buffer.byteLength(JSON.stringify(event));}catch{this.#ignored++;return false;}
  if(bytes>192*1024){this.#ignored++;return false;}
  this.#enqueue(guard=>this.#event(event,guard),bytes).catch(()=>{});return true;
 }
 async #event(event,guard){
  if(this.#retired.has(event.callUUID)){this.#ignored++;return;}
  if(event.type==='config'){
   if(this.#call===event.callUUID){this.#ignored++;return;}
   if(!this.#trusted.length||!this.#allowed.has(event.peerId)||!Array.isArray(event.participantIds)||event.participantIds.length!==2||
    !event.participantIds.includes(this.#self)||!event.participantIds.includes(event.peerId)||event.peerId===this.#self||
    ![this.#self,event.peerId].includes(event.invitedUserId)||event.method!=='audio'){this.#ignored++;return;}
   try{clientId(event.senderClientId);}catch{this.#ignored++;return;}
   if(event.invitedUserId===this.#self){
    if(this.#phase!=='ready'){this.#ignored++;return;}
    this.#direction='callee';this.#peer=event.peerId;this.#remote=event.senderClientId;this.#phase='incoming';this.#arm();
   }else{
    if(this.#phase!=='outgoing'||this.#peer!==event.peerId||event.senderClientId!==this.#client){this.#ignored++;return;}
   }
   this.#call=event.callUUID;this.#config=event;
   const early=this.#early;this.#early=[];this.#earlyBytes=0;
   for(const pending of early){guard();if(pending.callUUID===this.#call)await this.#event(pending,guard);else this.#ignored++;}
   return;
  }
  if(!this.#call){
   if(this.#direction==='caller'&&['dialing','outgoing'].includes(this.#phase)&&event.senderId===this.#peer&&
    ['accept','offer','ice','bye','reject','busy'].includes(event.type)){
    try{clientId(event.senderClientId);}catch{this.#ignored++;return;}
    const bytes=Buffer.byteLength(JSON.stringify(event));
    if(this.#early.length<16&&this.#earlyBytes+bytes<=256*1024){this.#early.push(event);this.#earlyBytes+=bytes;return;}
   }
   this.#ignored++;return;
  }
  if(event.callUUID!==this.#call){this.#ignored++;return;}
  if(event.type==='callLog'){
   // Official Web treats callLog as history metadata, including the initial
   // not_answered placeholder. It is not a bye/reject/busy control message.
   this.#ignored++;
   return;
  }
  try{clientId(event.senderClientId);}catch{this.#ignored++;return;}
  if(event.senderId===this.#self&&event.senderClientId!==this.#client&&['accept','bye','reject','busy'].includes(event.type)){
   this.#finish('ended','call_handled_on_other_device');return;
  }
  if(event.senderId!==this.#peer){this.#ignored++;return;}
  if(this.#remote&&event.senderClientId!==this.#remote){this.#ignored++;return;}
  if(event.type==='accept'){
   if(this.#direction!=='caller')return;this.#remote=event.senderClientId;this.#remoteAccepted=true;
   const offer=this.#earlyOffers.get(this.#remote);this.#earlyOffers.clear();if(offer)await this.#offer(offer,guard);return;
  }
  if(event.type==='offer'){await this.#offer(event,guard);return;}
  if(event.type==='answer'){
   if(this.#direction!=='callee'||!this.#localAccepted||!this.#offerSeen||this.#answerSeen||event.targetClientId!==this.#client){this.#ignored++;return;}
   this.#answerSeen=true;await this.#io(()=>this.#bridge.setAnswer(event.description),guard);this.#remoteAccepted=true;this.#negotiated=true;await this.#flushIce(guard);return;
  }
  if(event.type==='ice'){
   const c=event.candidate;
   if(!this.#remote||!c||c.clientID!==null&&c.clientID!==this.#client||typeof c.sdpCandidate!=='string'||c.sdpCandidate.split(/\s+/)[7]!=='relay'){this.#ignored++;return;}
   if(this.#iceSeen.has(c.sdpCandidate))return;if(this.#iceSeen.size>=64){this.#ignored++;return;}this.#iceSeen.add(c.sdpCandidate);
   this.#ice.push({candidate:c.sdpCandidate,sdpMid:c.sdpMid,sdpMLineIndex:c.sdpMLineIndex});await this.#flushIce(guard);return;
  }
  if(['bye','reject','busy'].includes(event.type)){
   if(!this.#remote&&this.#direction==='caller')this.#remote=event.senderClientId;
   this.#finish('ended');return;
  }
  this.#ignored++;
 }
 async end(){
  const rpc=this.#rpc,peer=this.#peer,call=this.#call,epoch=this.#epoch;
  const type=this.#direction==='callee'&&!this.#localAccepted?'reject':'bye';
  // Close media immediately, even if an earlier operation still awaits HTTP.
  this.#finish('ended',null,!call&&['dialing','outgoing'].includes(this.#phase));
  if(!rpc||!peer||!call)return {ended:true};
  try{if(this.#account.signalConnection!==rpc)throw error('call_connection_changed');await rpc.send({type,callUUID:call,callData:null},{peerId:peer});}
  catch(e){if(this.#epoch===epoch+1)this.#reason=SAFE.has(e?.reason)?e.reason:'call_end_uncertain';throw error('call_end_uncertain');}
  return {ended:true};
 }
 reset(){this.#finish('idle',null,true);this.#peer=null;this.#direction=null;}
 get state(){
  const media=this.#bridge?.state||null;
  const phase=this.#phase==='negotiating'&&this.#negotiated&&this.#localAccepted&&this.#remoteAccepted&&this.#mediaReady(media)?'connected':this.#phase;
  return {provider:'nasim',phase,busy:this.#working||this.#queue.length>0,direction:this.#direction||null,peerId:this.#peer||null,callUUID:this.#call||null,
   selfId:this.#self||null,remoteClientId:this.#remote||null,localAccepted:this.#localAccepted,remoteAccepted:this.#remoteAccepted,
   pairingSet:this.#trusted.length>0,ignoredEvents:this.#ignored,queuedEvents:this.#queue.length,reason:this.#reason,media,
   liveCallVerified:false,providerPathVerified:false,billingVerified:false,internationalOutageVerified:false};
 }
}
module.exports={CallSession,CallError};
