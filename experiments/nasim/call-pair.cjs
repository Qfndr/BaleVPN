// Local two-account laboratory orchestration. Trust is exchanged in-process,
// never accepted from browser SDP or automatically sent through the messenger.
const {CallSession,CallError}=require('./call-session.cjs');
const {ApiError}=require('./http-client.cjs');
// Only fixed protocol reasons may cross the laboratory boundary. Never retain
// provider error text, response bodies, stream addresses or authentication data.
const PREPARE_REASONS=new Set(['closed','not_authenticated','not_authorized','account_busy',
 'stream_connect_timeout','stream_connect_failed','stream_ended','invalid_event_stream',
 'invalid_stream_server','invalid_event_batch','event_handler_failed','too_many_events',
 'cursor_request_failed','invalid_cursor_response','invalid_response','invalid_saved_session','response_too_large',
 'timeout','transport_failed','access_denied','rate_limited','rejected','invalid_encrypted_response','tls_verification_disabled']);
class CallPair {
 #accounts;#calls;#available;#preparing=false;#epoch=0;#phase='idle';#clientSlot=1;#reason=null;
 constructor(accounts,{executable,open}={}){
  this.#accounts=accounts;this.#available=!!executable;
  this.#calls=new Map([1,2].map(slot=>[slot,new CallSession(accounts.get(slot),{executable,...open?{open}:{}})]));
 }
 async connectEvents(slot){
  return this.#accounts.get(slot).connectSignals({onEvent:event=>this.#calls.get(slot).handleEvent(event)});
 }
 reset(){this.#epoch++;this.#preparing=false;this.#phase='idle';this.#reason=null;
  for(const call of this.#calls.values())call.reset();
  for(const account of this.#accounts.values())account.disconnectSignals();
 }
 invalidate(){this.reset();this.#phase='ended';}
 async prepare({clientSlot=1,socksPort=1089,throughput=true}={}){
  if(!this.#available)throw new CallError('native_bridge_unavailable');
  if(this.#preparing||[...this.#calls.values()].some(c=>!['idle','ended'].includes(c.state.phase)||c.state.busy))throw new CallError('call_busy');
  if(![1,2].includes(clientSlot)||!Number.isInteger(socksPort)||socksPort<1024||socksPort>65535||typeof throughput!=='boolean')throw new CallError('invalid_media_options');
  const states=[...this.#accounts.values()].map(a=>a.state);
  if(states.some(a=>!a.signedIn))throw new CallError('both_accounts_required');
  if(states[0].userId===states[1].userId)throw new CallError('distinct_accounts_required');
  const epoch=++this.#epoch;this.#preparing=true;this.#phase='preparing';this.#reason=null;
  const guard=()=>{if(epoch!==this.#epoch)throw new CallError('call_cancelled');};
  try{
   // A completed call can still pin its old event subscription. Retire those
   // bindings before establishing fresh subscriptions for an explicit attempt.
   for(const call of this.#calls.values())call.reset();
   const connections=await Promise.allSettled([1,2].map(async slot=>{
    if(this.#accounts.get(slot).state.events?.phase!=='connected')await this.connectEvents(slot);
    guard();
   }));guard();const connectionError=connections.find(r=>r.status==='rejected');if(connectionError)throw connectionError.reason;
   for(const slot of [1,2])this.#calls.get(slot).setAllowedPeers([this.#accounts.get(3-slot).state.userId]);
   const prepared=await Promise.allSettled([1,2].map(slot=>this.#calls.get(slot).prepare({role:slot===clientSlot?'client':'server',socksPort,throughput})));
   guard();const failed=prepared.find(r=>r.status==='rejected');if(failed)throw failed.reason;
   for(const slot of [1,2])this.#calls.get(slot).trustCertificate(prepared[2-slot].value.publicCertificate);
   this.#clientSlot=clientSlot;this.#phase='ready';return {prepared:true};
  }catch(e){
   if(epoch!==this.#epoch)throw new CallError('call_cancelled');
   const failure=e instanceof CallError?e:new CallError(e instanceof ApiError&&PREPARE_REASONS.has(e.reason)?e.reason:'call_prepare_failed');
   this.reset();this.#phase='failed';this.#reason=failure.reason;
   throw failure;
  }finally{if(epoch===this.#epoch)this.#preparing=false;}
 }
 async dial(slot=this.#clientSlot){if(this.#preparing||![1,2].includes(slot))throw new CallError('call_busy');
  if(this.#phase!=='ready')throw new CallError('call_not_ready');
  return this.#calls.get(slot).dial(this.#accounts.get(3-slot).state.userId);
 }
 async accept(slot){if(this.#preparing||![1,2].includes(slot))throw new CallError('call_busy');return this.#calls.get(slot).accept();}
 async end(slot=this.#clientSlot){if(![1,2].includes(slot))throw new CallError('invalid_call_target');
  if(this.#preparing){this.reset();return {ended:true};}
  const ending=this.#calls.get(slot).end();this.#calls.get(3-slot).reset();this.#epoch++;this.#phase='ended';
  return ending;
 }
 getCall(slot){return this.#calls.get(slot).state;}
 get state(){return {available:this.#available,phase:this.#phase,busy:this.#preparing,clientSlot:this.#clientSlot,reason:this.#reason,
  accounts:[1,2].map(slot=>({slot,...this.#calls.get(slot).state})),liveCallVerified:false,providerPathVerified:false,billingVerified:false,internationalOutageVerified:false};}
}
module.exports={CallPair};
