// Private exclusive owner joining an accepted CallSession to explicit legacy
// media. No login, auto-answer/redial or public API. Provider/billing stay false.
'use strict';
const {CallMedia}=require('./call-media.cjs'),{LegacySignalCipher,MAX_PAYLOAD}=require('./legacy-signal-cipher.cjs');
const {validateSignal}=require('./media-description.cjs');
class AccountMediaError extends Error{constructor(reason){super('Rubika account media '+reason);this.reason=reason;}}
const fail=reason=>{throw new AccountMediaError(reason);};
const SAFE=new Set(['not_authenticated','account_binding_changed','invalid_account_binding','call_cancelled','call_not_accepted','unsupported_media_profile',
 'invalid_media_parameters','media_lease_already_issued','media_lease_expired','media_lease_consumed','ambiguous_media_update','invalid_signal_size','invalid_signal_authentication','signal_too_old','signal_replayed',
 'invalid_signal_counter','invalid_signal_payload','unsupported_signal_type','invalid_relay','invalid_pairing','invalid_media_context','duplicate_initial_setup',
 'too_many_candidates','invalid_media_signal','media_cancelled','media_operation_failed','transport_disconnected','transport_failed','network_error','timeout',
 'rate_limited','not_authorized','registration_required','service_rejected','call_operation_failed','media_not_ready']);
const LOCAL=new Set(['media_not_prepared','media_not_paired','media_not_attached','invalid_call_options']);
class AccountMedia{
 #session;#media;#lease;#cipher;#context;#phase='idle';#reason=null;#busy=false;#epoch=0;#timer;#started=false;#discarded=0;
 constructor(session,options={}){
  if(!session||!['issueLegacyMedia','takeOpaqueSignals','pollOnce','pollSignals','hangup','close'].every(k=>typeof session[k]==='function'))fail('invalid_media_options');
  this.#session=session;this.#media=new CallMedia(options);
 }
 #cleanup(phase,reason,{closeSession=true}={}){
  this.#epoch++;clearInterval(this.#timer);this.#timer=null;this.#media.close();this.#cipher?.close();this.#cipher=null;this.#context=null;this.#lease=null;
  this.#phase=phase;this.#reason=reason;if(closeSession)this.#session.close();
 }
 #guard(epoch){if(epoch!==this.#epoch||['closed','failed','ended'].includes(this.#phase))fail('media_cancelled');this.#lease?.assertCurrent();if(this.#media.state.phase==='failed')fail(this.#media.state.reason);}
 async #run(action){
  if(['closed','failed','ended'].includes(this.#phase))fail('media_cancelled');if(this.#busy)fail('media_busy');this.#busy=true;const epoch=this.#epoch;
  try{this.#guard(epoch);const result=await action(()=>this.#guard(epoch));if(this.#phase==='ended'&&result?.ended===true)return result;this.#guard(epoch);return result;}
  catch(e){const reason=SAFE.has(e?.reason)||LOCAL.has(e?.reason)?e.reason:'account_media_failed';if(epoch===this.#epoch&&!LOCAL.has(reason))this.#cleanup('failed',reason);throw new AccountMediaError(epoch!==this.#epoch&&['closed','ended'].includes(this.#phase)?'media_cancelled':reason);}
  finally{this.#busy=false;}
 }
 prepare(){return this.#run(async guard=>{if(this.#phase!=='idle')fail('media_not_prepared');const result=await this.#media.prepare();guard();this.#phase='prepared';return result;});}
 trustCertificate(certificate){if(this.#phase!=='prepared'||this.#busy)fail('media_not_prepared');this.#media.trustCertificate(certificate);this.#phase='paired';}
 async #send(value,guard){
  guard();validateSignal(value);const raw=Buffer.from(JSON.stringify(value));let packet;
  try{if(raw.length>MAX_PAYLOAD)fail('invalid_signal_size');packet=this.#cipher.encryptRaw(raw);await this.#lease.send(packet);guard();}
  finally{raw.fill(0);packet?.fill(0);}
 }
 async #drain(guard){
  guard();const packets=this.#session.takeOpaqueSignals();
  try{for(const packet of packets){
   guard();let raw;
   try{
    try{raw=this.#cipher.decryptRaw(packet);}catch(e){if(['signal_replayed','signal_too_old'].includes(e?.reason)){this.#discarded=Math.min(2147483647,this.#discarded+1);continue;}throw e;}
    let value;try{value=JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(raw));}catch{fail('invalid_media_signal');}
    validateSignal(value);await this.#media.onSignal(value,{callId:this.#context.callId,send:v=>this.#send(v,guard)});guard();
   }finally{raw?.fill(0);}
  }}finally{for(const packet of packets)packet.fill(0);}
 }
 async #reportStarted(guard){
  guard();if(this.#started||this.#media.state.ready!==true)return;
  await this.#lease.markStarted(this.#media.state);guard();this.#started=true;this.#phase='connected';
 }
 attachAccepted(){return this.#run(async guard=>{
  if(this.#phase!=='paired')fail('media_not_paired');this.#lease=this.#session.issueLegacyMedia();const context=this.#lease.consumeContext();
  try{this.#cipher=new LegacySignalCipher({key:context.key,isOutgoing:context.direction==='outgoing',libraryVersion:context.libraryVersion,protocolLayer:context.protocolLayer});}
  finally{context.key.fill(0);delete context.key;}
  this.#context={callId:context.callId};this.#phase='connecting';
  await this.#media.onSecure({...context,send:v=>this.#send(v,guard)});guard();await this.#drain(guard);await this.#reportStarted(guard);
  const epoch=this.#epoch;this.#timer=setInterval(()=>{
   try{this.#guard(epoch);if(this.#media.state.phase==='failed')fail(this.#media.state.reason);}
   catch(e){if(epoch===this.#epoch)this.#cleanup('failed',SAFE.has(e?.reason)?e.reason:'account_media_failed');return;}
   if(!this.#busy&&!this.#started&&this.#media.state.ready)this.#run(g=>this.#reportStarted(g)).catch(()=>{});
  },250);this.#timer.unref();return {attached:true};
 });}
 pollOnce({pollSignals=false}={}){return this.#run(async guard=>{
  if(!this.#lease)fail('media_not_attached');
  await this.#session.pollOnce();
  const state=this.#session.state;
  if(state.phase!=='accepted'||state.callId!==this.#context.callId){this.#cleanup('ended','call_ended',{closeSession:false});return {ended:true};}
  guard();if(pollSignals)await this.#session.pollSignals();guard();await this.#drain(guard);await this.#reportStarted(guard);return {polled:true};
 });}
 async hangup(reason='Hangup'){
  if(!['Missed','Disconnect','Hangup','Busy'].includes(reason))fail('invalid_call_options');
  if(['closed','failed','ended'].includes(this.#phase))fail('media_cancelled');if(this.#busy)fail('media_busy');this.#busy=true;
  try{await this.#session.hangup(reason);this.#cleanup('ended','local_call_ended',{closeSession:false});return {ended:true};}
  catch(e){this.#cleanup('failed',SAFE.has(e?.reason)?e.reason:'account_media_failed');throw new AccountMediaError(SAFE.has(e?.reason)?e.reason:'account_media_failed');}
  finally{this.#busy=false;}
 }
 close(){if(['closed','ended','failed'].includes(this.#phase))return;this.#cleanup('closed','closed');}
 get state(){
  if(this.#lease)try{this.#lease.assertCurrent();}catch(e){this.#cleanup('failed',SAFE.has(e?.reason)?e.reason:'account_media_failed');}
  if(!['closed','ended','failed'].includes(this.#phase)&&this.#media.state.phase==='failed')this.#cleanup('failed',SAFE.has(this.#media.state.reason)?this.#media.state.reason:'account_media_failed');
  const media=this.#media.state,ready=this.#phase==='connected'&&this.#started&&media.ready===true;
  return {...media,phase:['ended','failed','closed'].includes(this.#phase)?this.#phase:ready?'connected':this.#phase==='connected'?'connecting':this.#phase,reason:this.#reason,
   ready,serverReady:ready&&media.serverReady,proxyReady:ready&&media.proxyReady,socksAddress:ready?media.socksAddress:null,
   callStartedAcknowledged:this.#started,discardedSignals:this.#discarded,busy:this.#busy,providerPathVerified:false,billingVerified:false,internationalOutageVerified:false};
 }
}
module.exports={AccountMedia,AccountMediaError};
