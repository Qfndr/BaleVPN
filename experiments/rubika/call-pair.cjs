// Explicit two-account local call lab. Both helpers are locally owned, so their
// fresh QUIC identities can be paired in-process. No remote blind pin exchange.
'use strict';
const {diagnostic}=require('./call-diagnostic.cjs');
const {CallSession,CallError}=require('./call-session.cjs'),{AccountMedia,AccountMediaError}=require('./account-media.cjs'),{ApiError}=require('./http-client.cjs');
const fail=reason=>{throw new CallError(reason);};
const typed=e=>e instanceof CallError||e instanceof AccountMediaError||e instanceof ApiError;
function binding(account){
 const state=account?.state;let record;
 if(state?.provider!=='rubika'||state.signedIn!==true||state.selfConfirmed!==true)fail('not_authenticated');
 try{record=account.exportSession();}catch{fail('not_authenticated');}
 if(record?.provider!=='rubika'||record.userId!==state.userId||typeof record.userId!=='string'||! /^[A-Za-z0-9_-]{8,128}$/.test(record.userId)||['auth','privateKey','publicKey'].some(k=>typeof record[k]!=='string'||!record[k]))fail('invalid_account_binding');
 return {userId:record.userId,auth:record.auth,privateKey:record.privateKey,publicKey:record.publicKey};
}
const same=(a,b)=>['userId','auth','privateKey','publicKey'].every(k=>a[k]===b[k]);
class CallPair{
 #accounts;#executable;#open;#factory;#interval;#records;#calls=new Map();#owners=new Map();#attached=false;#epoch=0;#busy=false;#timer;#phase='idle';#reason=null;#clientSlot=1;#diagnostic=null;
 constructor(accounts,{executable,open,createClient,pollInterval=2000}={}){
  if(!(accounts instanceof Map)||!Number.isInteger(pollInterval)||pollInterval!==0&&(pollInterval<1000||pollInterval>30000))fail('invalid_call_options');
  this.#accounts=accounts;this.#executable=executable;this.#open=open;this.#factory=createClient;this.#interval=pollInterval;
 }
 #guard(epoch){if(epoch!==this.#epoch)fail('call_cancelled');if(this.#records)for(const [slot,record]of this.#records)if(!same(record,binding(this.#accounts.get(slot))))fail('account_binding_changed');}
 #clear(phase,reason=null,detail=null){
  this.#epoch++;clearInterval(this.#timer);this.#timer=null;for(const owner of this.#owners.values())owner.close();for(const call of this.#calls.values())call.close();
  this.#calls.clear();this.#owners.clear();this.#records=null;this.#attached=false;this.#busy=false;this.#phase=phase;this.#reason=reason;this.#diagnostic=detail?diagnostic(detail):null;
 }
 reset(){this.#clear('idle');}
 invalidate(){this.#clear('ended');}
 async prepare({clientSlot=1,socksPort=1092,throughput=true}={}){
  if(!this.#executable)fail('native_bridge_unavailable');if(this.#busy||this.#calls.size)fail('call_busy');
  if(![1,2].includes(clientSlot)||!Number.isInteger(socksPort)||socksPort<0||socksPort>65535||socksPort>0&&socksPort<1024||typeof throughput!=='boolean')fail('invalid_media_options');
  const records=new Map([1,2].map(slot=>[slot,binding(this.#accounts.get(slot))]));if(records.get(1).userId===records.get(2).userId)fail('distinct_accounts_required');
  const epoch=++this.#epoch,calls=new Map(),owners=new Map();this.#records=records;this.#calls=calls;this.#owners=owners;this.#busy=true;this.#phase='preparing';this.#reason=null;this.#diagnostic=null;this.#clientSlot=clientSlot;
  try{
   for(const slot of [1,2]){
    const call=new CallSession(this.#accounts.get(slot),{allowedPeers:[records.get(3-slot).userId],protocol:{min_layer:92,max_layer:92,library_versions:['6.0.0']},...this.#factory?{createClient:this.#factory}:{}});calls.set(slot,call);
    owners.set(slot,new AccountMedia(call,{executable:this.#executable,role:slot===clientSlot?'client':'server',socksPort,throughput,libraryVersion:'6.0.0',protocolLayer:92,...this.#open?{open:this.#open}:{}}));
   }
   const prepared=await Promise.allSettled([1,2].map(slot=>owners.get(slot).prepare()));this.#guard(epoch);const failed=prepared.find(v=>v.status==='rejected');if(failed)throw failed.reason;
   for(const slot of [1,2])owners.get(slot).trustCertificate(prepared[2-slot].value.publicCertificate);
   const listening=await Promise.allSettled([1,2].map(slot=>calls.get(slot).start()));this.#guard(epoch);const failure=listening.find(v=>v.status==='rejected');if(failure)throw failure.reason;
   this.#phase='ready';if(this.#interval){this.#timer=setInterval(()=>{if(epoch===this.#epoch&&!this.#busy)this.pollOnce().catch(()=>{});},this.#interval);this.#timer.unref();}return {prepared:true};
  }catch(e){if(epoch===this.#epoch)this.#clear('failed',typed(e)?e.reason:'call_prepare_failed',e);throw typed(e)?e:new CallError('call_prepare_failed');}
  finally{if(epoch===this.#epoch)this.#busy=false;}
 }
 async #operate(slot,action){
  if(![1,2].includes(slot))fail('invalid_call_target');if(this.#busy)fail('call_busy');if(!this.#calls.has(slot))fail('call_not_prepared');
  const epoch=this.#epoch;this.#busy=true;
  try{this.#guard(epoch);const result=await action(()=>this.#guard(epoch));if(result?.ended===true&&this.#phase==='ended')return result;this.#guard(epoch);return result;}
  catch(e){if(epoch===this.#epoch&&!['call_busy','media_busy','call_not_ringing','call_not_listening'].includes(e?.reason))this.#clear('failed',typed(e)?e.reason:'call_operation_failed',e);throw typed(e)?e:new CallError('call_operation_failed');}
  finally{if(epoch===this.#epoch)this.#busy=false;}
 }
 async #poll(slot,guard){
  if(this.#attached){const owner=this.#owners.get(slot);if(!owner.state.busy)await owner.pollOnce();}else await this.#calls.get(slot).pollOnce();guard();
 }
 async #attach(guard){
  if(this.#attached||![1,2].every(slot=>this.#calls.get(slot).state.legacyMediaAvailable))return;
  const order=[1,2].sort((a,b)=>(this.#calls.get(a).state.direction==='outgoing'?1:0)-(this.#calls.get(b).state.direction==='outgoing'?1:0));
  for(const slot of order){await this.#owners.get(slot).attachAccepted();guard();}this.#attached=true;this.#phase='negotiating';
  for(const slot of order){await this.#poll(slot,guard);}
 }
 dial(slot=this.#clientSlot){return this.#operate(slot,async guard=>{const result=await this.#calls.get(slot).dial(this.#records.get(3-slot).userId);guard();await this.#poll(3-slot,guard);return result;});}
 accept(slot){return this.#operate(slot,async guard=>{const result=await this.#calls.get(slot).accept();guard();await this.#poll(3-slot,guard);await this.#attach(guard);return result;});}
 pollOnce(){return this.#operate(1,async guard=>{
  for(const slot of [1,2]){await this.#poll(slot,guard);if(this.#attached&&this.#owners.get(slot).state.phase==='ended'){this.#clear('ended');return {ended:true};}}
  await this.#attach(guard);return {polled:true};
 });}
 async end(slot=this.#clientSlot){
  if(![1,2].includes(slot))fail('invalid_call_target');
  const call=this.#calls.get(slot);if(this.#busy||!call?.state.callId){const uncertain=this.#busy&&!!call;this.#clear(uncertain?'uncertain':'ended',uncertain?'call_end_uncertain':null);return {ended:true,remoteConfirmed:false};}
  this.#busy=true;const epoch=this.#epoch;
  try{if(this.#attached)await this.#owners.get(slot).hangup();else await call.hangup();this.#guard(epoch);this.#clear('ended');return {ended:true,remoteConfirmed:true};}
  catch(e){if(epoch===this.#epoch)this.#clear('uncertain','call_end_uncertain');throw new CallError('call_end_uncertain');}
 }
 getCall(slot){
  const call=this.#calls.get(slot)?.state,media=this.#owners.get(slot)?.state;
  const phase=!call?this.#phase==='idle'?'idle':'ended':media?.phase==='failed'||call.phase==='failed'?'failed':media?.phase==='ended'||media?.phase==='closed'?'ended':media?.ready?'connected':call.phase==='listening'?'ready':call.phase==='accepted'?'negotiating':call.phase;
  return {provider:'rubika',slot,phase,signalingPhase:call?.phase||null,busy:!!call?.busy||!!media?.busy,callId:call?.callId||null,reason:media?.reason||call?.reason||null,media:media||null};
 }
 get state(){
  if(this.#records)try{this.#guard(this.#epoch);}catch(e){this.#clear('failed',typed(e)?e.reason:'call_operation_failed');}
  const accounts=[1,2].map(slot=>this.getCall(slot));return {available:!!this.#executable,canPrepare:!this.#busy&&this.#calls.size===0,phase:accounts.every(a=>a.phase==='connected')?'connected':accounts.some(a=>a.phase==='failed')?'failed':this.#phase,
   busy:this.#busy,reason:this.#reason,diagnostic:this.#diagnostic?{...this.#diagnostic}:null,clientSlot:this.#clientSlot,accounts,profile:'6.0.0/layer-92',liveCallVerified:false,providerPathVerified:false,billingVerified:false,internationalOutageVerified:false};
 }
}
module.exports={CallPair};
