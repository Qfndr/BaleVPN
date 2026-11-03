// Private media owner for a CallSession. A signaling key alone cannot make a
// proxy ready: relay-route + independent pinned QUIC identity are mandatory.
'use strict';
function createCallMedia({provider,label,NativeMediaBridge,relayServers,fromDescription,toDescription,validateSignal,MAX_PAYLOAD,id}){
class MediaError extends Error{constructor(reason){super(label+' media '+reason);this.reason=reason;}}
const fail=reason=>{throw new MediaError(reason);};
const cert=v=>typeof v==='string'&&v.length>=128&&v.length<=16384&&v.length%2===0&&/^[a-f0-9]+$/.test(v);
const SAFE=new Set(['invalid_relay','invalid_pairing','invalid_description','invalid_native_output','prepare_timeout','operation_timeout','input_closed','process_exited','process_failed',
 'negotiation_failed','gather_timeout','no_relay','connect_timeout','transport_closed','transport_failed','transport_disconnected','proxy_bind_failed','server_setup_failed','media_setup_failed',
 'non_relay_candidate','candidate_context_mismatch','invalid_candidate','invalid_audio','invalid_media_signal','unsupported_media','no_relay_candidate',
 'invalid_media_context','duplicate_initial_setup','too_many_candidates']);
class CallMedia{
 #executable;#open;#failure;#options;#bridge;#trusted;#certificate;#call;#direction;#initial;#candidates=[];#candidateBytes=0;#candidateCount=0;#seen=new Set();#negotiated=false;
 #phase='idle';#reason=null;#epoch=0;#busy=false;#timer;
 constructor({executable,role,socksPort=1089,throughput=false,open=NativeMediaBridge.open,onFailure=()=>{}}={}){
  if(typeof executable!=='string'||!['client','server'].includes(role)||!Number.isInteger(socksPort)||socksPort<0||socksPort>65535||socksPort>0&&socksPort<1024||typeof throughput!=='boolean'||typeof open!=='function'||typeof onFailure!=='function')fail('invalid_media_options');
  this.#executable=executable;this.#open=open;this.#failure=onFailure;this.#options={role,socksPort,throughput};
 }
 #guard(epoch){if(epoch!==this.#epoch)fail('media_cancelled');}
 #failed(reason){
  if(['failed','closed'].includes(this.#phase))return;this.#epoch++;this.#phase='failed';this.#reason=SAFE.has(reason)?reason:'media_operation_failed';
  clearInterval(this.#timer);this.#bridge?.close();this.#bridge=null;this.#clear();try{Promise.resolve(this.#failure(this.#reason)).catch(()=>{});}catch{}
 }
 #clear(){this.#trusted=null;this.#call=null;this.#initial=null;this.#candidates=[];this.#candidateBytes=this.#candidateCount=0;this.#seen.clear();this.#negotiated=false;}
 async #run(work){
  if(this.#busy)fail('media_busy');this.#busy=true;const epoch=this.#epoch,guard=()=>this.#guard(epoch);
  try{guard();const result=await work(guard);guard();return result;}
  catch(e){const reason=e instanceof MediaError?e.reason:SAFE.has(e?.reason)?e.reason:'media_operation_failed';if(epoch===this.#epoch&&!['media_not_prepared','media_not_paired','media_busy'].includes(reason))this.#failed(reason);throw new MediaError(reason);}
  finally{if(epoch===this.#epoch)this.#busy=false;}
 }
 async prepare(){
  return this.#run(async guard=>{
   if(this.#phase!=='idle')fail('media_not_prepared');this.#phase='preparing';const bridge=await this.#open(this.#executable);
   try{guard();}catch(e){bridge.close();throw e;}this.#bridge=bridge;this.#certificate=bridge.publicCertificate;if(!cert(this.#certificate))fail('invalid_pairing');
   this.#phase='prepared';const epoch=this.#epoch;this.#timer=setInterval(()=>{if(epoch===this.#epoch&&this.#bridge?.state.phase==='failed')this.#failed(this.#bridge.state.reason);},250);this.#timer.unref();return {publicCertificate:this.#certificate};
  });
 }
 trustCertificate(value){
  if(this.#phase!=='prepared'||this.#busy)fail('media_not_prepared');if(!cert(value)||value===this.#certificate)fail('invalid_pairing');this.#trusted=value;this.#phase='paired';
 }
 async onSecure(context){
  return this.#run(async guard=>{
   if(this.#phase!=='paired'||!this.#bridge)fail('media_not_paired');
   if(!id(context?.callId)||!id(context.selfId)||!id(context.peerId)||context.selfId===context.peerId||!['outgoing','incoming'].includes(context.direction)||typeof context.send!=='function')fail('invalid_media_context');
   const servers=relayServers(context.connections);this.#call=context.callId;this.#direction=context.direction;this.#phase='configuring';
   await this.#bridge.configure({provider,callUUID:this.#call,selfId:context.selfId,peerId:context.peerId,iceServers:servers},{...this.#options,trustedCertificates:[this.#trusted]});guard();
   this.#phase='awaiting_remote';if(this.#direction==='outgoing'){const offer=await this.#bridge.offer();guard();await this.#sendDescription(offer,context.send,guard);}
  });
 }
 async #sendDescription(description,send,guard){
  const converted=fromDescription(description);await send(converted.initialSetup);guard();for(const message of converted.candidateMessages){await send(message);guard();}
 }
 async onSignal(signal,context){
  let value;try{validateSignal(signal);const text=JSON.stringify(signal);if(Buffer.byteLength(text)>MAX_PAYLOAD)fail('invalid_signal_size');value=JSON.parse(text);}catch{this.#failed('invalid_media_signal');fail('invalid_media_signal');}
  return this.#run(async guard=>{
   if(!this.#bridge||!this.#call||context?.callId!==this.#call||typeof context.send!=='function')fail('invalid_media_context');
   if(value['@type']==='InitialSetup'){if(this.#initial)fail('duplicate_initial_setup');this.#initial=value;}
   else if(value['@type']==='Candidates'){
    const size=Buffer.byteLength(JSON.stringify(value));if(this.#candidates.length>=8||this.#candidateCount+value.candidates.length>64||this.#candidateBytes+size>128*1024)fail('too_many_candidates');
    this.#candidates.push(value);this.#candidateCount+=value.candidates.length;this.#candidateBytes+=size;
   }else fail('invalid_media_signal');
   if(!this.#initial||!this.#candidateCount)return;
   const type=this.#direction==='outgoing'?'answer':'offer',remote=toDescription(this.#initial,this.#candidates,{type});
   const candidates=remote.sdp.split('\r\n').filter(line=>line.startsWith('a=candidate:')).map(line=>line.slice(2));
   if(!this.#negotiated){
    this.#phase='negotiating';if(type==='offer'){const answer=await this.#bridge.answer(remote);guard();await this.#sendDescription(answer,context.send,guard);}else{await this.#bridge.setAnswer(remote);guard();}
    this.#negotiated=true;this.#phase='connecting';for(const candidate of candidates)this.#seen.add(candidate);
   }else for(const candidate of candidates)if(!this.#seen.has(candidate)){await this.#bridge.addCandidate({candidate,sdpMid:'0',sdpMLineIndex:0,usernameFragment:this.#initial.ufrag});guard();this.#seen.add(candidate);}
  });
 }
 close(){
  if(['closed','failed'].includes(this.#phase))return;this.#epoch++;clearInterval(this.#timer);this.#bridge?.close();this.#bridge=null;this.#clear();this.#busy=false;this.#phase='closed';
 }
 get state(){
  const state=this.#bridge?.state,relay=state?.relayPair===true&&state.mediaConnected===true,authenticated=relay&&state.peerAuthenticated===true,
   ready=this.#negotiated&&authenticated&&(this.#options.role==='server'?state.phase==='connected':state.proxyReady===true),proxyReady=ready&&this.#options.role==='client';
  return {provider,phase:state?.phase==='failed'?'failed':ready?'connected':this.#phase,reason:state?.phase==='failed'?state.reason:this.#reason,role:this.#options.role,callId:this.#call||null,
   mediaConnected:!!relay,relayPair:!!relay,peerAuthenticated:!!authenticated,ready:!!ready,serverReady:!!ready&&this.#options.role==='server',proxyReady:!!proxyReady,socksAddress:proxyReady?state.socksAddress||null:null,
   receivedBytes:state?.receivedBytes||0,sentBytes:state?.sentBytes||0,quic:state?.quic?{...state.quic}:null,providerPathVerified:false,billingVerified:false,internationalOutageVerified:false};
 }
}
return {CallMedia,MediaError};
}
module.exports={createCallMedia};
