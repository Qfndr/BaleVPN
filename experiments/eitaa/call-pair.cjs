// Explicit local two-account lab. Pairing identities stay inside this process;
// access hashes come from the calling account's protected target lookup.
'use strict';
const {createHash}=require('node:crypto');
const {CallSession,CallError,confirmsTerminal}=require('./call-session.cjs'),{CallClient}=require('./call-client.cjs'),{CallMedia}=require('./call-media.cjs'),{TargetResolver,binding}=require('./target-resolver.cjs');
const profiles=require('./client-profile.cjs');
const fail=reason=>{throw new CallError(reason);};
const same=(a,b)=>a.userId===b.userId&&a.token===b.token&&a.imei===b.imei&&profiles.fromRecord(a)===profiles.fromRecord(b);
const fingerprint=record=>createHash('sha256').update(JSON.stringify([record.userId,record.token,record.imei,profiles.fromRecord(record)])).digest('hex');
class CallPair{
 #accounts;#executable;#open;#clientFactory;#resolver;#calls=new Map();#media=new Map();#records;#targets;#epoch=0;#busy=false;#phase='idle';#reason=null;#clientSlot=1;
 #recovery=null;#recoveryClient=null;
 constructor(accounts,{executable,open,createClient,createAccountClient}={}){
  this.#accounts=accounts;this.#executable=executable;this.#open=open;this.#clientFactory=createClient;
  this.#resolver=new TargetResolver(accounts,{...createClient?{createCallClient:createClient}:{},...createAccountClient?{createAccountClient}:{}});
 }
 #guard(epoch){if(epoch!==this.#epoch)fail('call_cancelled');if(this.#records)for(const [slot,record]of this.#records)if(!same(record,binding(this.#accounts.get(slot))))fail('account_binding_changed');}
 #pending(confirmedId){return [...this.#calls.values()].some(call=>call.remotePending&&(!confirmedId||call.state.callId!==confirmedId));}
 #clear(phase,reason=null,confirmedId){
  const uncertain=this.#phase==='uncertain'||this.#pending(confirmedId);
  this.#recoveryClient?.close();this.#recoveryClient=null;
  this.#epoch++;this.#resolver.close();for(const call of this.#calls.values())call.close();for(const media of this.#media.values())media.close();this.#calls.clear();this.#media.clear();this.#targets=null;this.#records=null;this.#busy=false;
  this.#phase=uncertain?'uncertain':phase;this.#reason=uncertain?'call_end_uncertain':reason;
 }
 reset(){if(this.#busy&&this.#phase!=='preparing')fail('call_busy');if(this.#pending()||this.#phase==='uncertain')fail('call_end_uncertain');this.#clear('idle');}
 invalidate(){this.#clear('ended');}
 async prepare({clientSlot=1,socksPort=1091,throughput=true}={}){
  if(!this.#executable)fail('native_bridge_unavailable');if(this.#phase==='uncertain')fail('call_end_uncertain');if(this.#busy||this.#calls.size)fail('call_busy');
  if(![1,2].includes(clientSlot)||!Number.isInteger(socksPort)||socksPort<1024||socksPort>65535||typeof throughput!=='boolean')fail('invalid_media_options');
  const records=new Map([1,2].map(slot=>[slot,binding(this.#accounts.get(slot))]));if(records.get(1).userId===records.get(2).userId)fail('distinct_accounts_required');
  const epoch=++this.#epoch;this.#records=records;this.#busy=true;this.#phase='preparing';this.#reason=null;this.#clientSlot=clientSlot;
  try{
   const targets=await this.#resolver.resolve();this.#guard(epoch);this.#targets=targets;
   for(const slot of [1,2])this.#media.set(slot,new CallMedia({executable:this.#executable,role:slot===clientSlot?'client':'server',socksPort,throughput,...this.#open?{open:this.#open}:{},onFailure:()=>{if(epoch===this.#epoch)this.#clear('failed','native_media_failed');}}));
   const prepared=await Promise.allSettled([1,2].map(slot=>this.#media.get(slot).prepare()));this.#guard(epoch);const failure=prepared.find(v=>v.status==='rejected');if(failure)throw failure.reason;
   for(const slot of [1,2])this.#media.get(slot).trustCertificate(prepared[2-slot].value.publicCertificate);
   for(const slot of [1,2]){
    const media=this.#media.get(slot);this.#calls.set(slot,new CallSession(this.#accounts.get(slot),{allowedPeers:[records.get(3-slot).userId],...this.#clientFactory?{createClient:this.#clientFactory}:{},onSecure:context=>media.onSecure(context),onSignal:(signal,context)=>media.onSignal(signal,context),onEnd:()=>media.close()}));
   }
   const listening=await Promise.allSettled([1,2].map(slot=>this.#calls.get(slot).start({pollInterval:2000})));this.#guard(epoch);const failed=listening.find(v=>v.status==='rejected');if(failed)throw failed.reason;
   this.#phase='ready';return {prepared:true};
  }catch(e){if(epoch===this.#epoch)this.#clear('failed',e instanceof CallError?e.reason:'call_prepare_failed');throw e instanceof CallError?e:new CallError('call_prepare_failed');}
  finally{if(epoch===this.#epoch)this.#busy=false;}
 }
 async #operate(slot,action){
  if(![1,2].includes(slot))fail('invalid_call_target');if(this.#busy)fail('call_busy');if(!this.#calls.has(slot)||!this.#targets)fail('call_not_prepared');
  const epoch=this.#epoch;this.#guard(epoch);this.#busy=true;
  try{const result=await action(this.#calls.get(slot),()=>this.#guard(epoch));this.#guard(epoch);return result;}
  catch(e){if(epoch===this.#epoch&&['failed','stopped'].includes(this.#calls.get(slot)?.state.phase))this.#clear('failed',e instanceof CallError?e.reason:'call_operation_failed');throw e instanceof CallError?e:new CallError('call_operation_failed');}
  finally{if(epoch===this.#epoch)this.#busy=false;}
 }
 dial(slot=this.#clientSlot){return this.#operate(slot,async(call,guard)=>{if(this.#pending())fail('call_busy');const result=await call.dial(this.#targets.get(slot));guard();await this.#calls.get(3-slot).pollOnce();guard();return result;});}
 accept(slot){return this.#operate(slot,async(call,guard)=>{const result=await call.accept();guard();for(const target of [3-slot,slot,3-slot]){await this.#calls.get(target).pollOnce();guard();}return result;});}
 async end(slot=this.#clientSlot){
  if(![1,2].includes(slot))fail('invalid_call_target');if(this.#busy)fail('call_busy');
  const call=this.#calls.get(slot),callId=call?.state.callId;
  if(!callId){if(this.#pending()||this.#phase==='uncertain')fail('call_end_uncertain');this.#clear('ended');return {ended:true,remoteConfirmed:false};}
  const checkpoint=call.terminalCheckpoint(),bindings=[1,2].map(target=>fingerprint(this.#records.get(target)));
  const epoch=this.#epoch;this.#busy=true;for(const media of this.#media.values())media.close();
  try{await call.hangUp();this.#guard(epoch);this.#clear('ended',null,callId);return {ended:true,remoteConfirmed:true};}
  catch(e){
   if(epoch===this.#epoch){
    const other=this.#calls.get(3-slot);
    if(checkpoint&&(!other?.remotePending||other.state.callId===callId))this.#recovery={slot,checkpoint,bindings};
    this.#clear('uncertain','call_end_uncertain');
   }
   throw e instanceof CallError?e:new CallError('call_end_uncertain');
  }
 }
 async recover(){
  if(this.#busy)fail('call_busy');
  const recovery=this.#recovery;
  if(this.#phase!=='uncertain'||!recovery)fail('call_end_uncertain');
  const epoch=this.#epoch;
  const records=()=>{
   this.#guard(epoch);
   const pair=[1,2].map(slot=>binding(this.#accounts.get(slot)));
   if(pair.some((record,index)=>fingerprint(record)!==recovery.bindings[index]))fail('account_binding_changed');
   return pair;
  };
  const record=records()[recovery.slot-1];
  const client=this.#clientFactory?this.#clientFactory(record):new CallClient(record);
  this.#busy=true;this.#recoveryClient=client;
  try{
   const {pts,date}=recovery.checkpoint.cursor;
   const result=await client.request('updates.getDifference',{pts,date,qts:-1});
   records();
   if(!confirmsTerminal(result,recovery.checkpoint))fail('call_end_uncertain');
   this.#recovery=null;this.#phase='ended';this.#reason=null;
   return {ended:true,remoteConfirmed:true};
  }catch(error){throw error instanceof CallError?error:new CallError('call_end_uncertain');}
  finally{if(epoch===this.#epoch){client.close();this.#recoveryClient=null;this.#busy=false;}}
 }
 getCall(slot){const signaling=this.#calls.get(slot)?.state,media=this.#media.get(slot)?.state;return {provider:'eitaa',slot,phase:!signaling?this.#phase==='idle'?'idle':'ended':media?.phase==='failed'?'failed':media?.phase==='closed'?'ended':media?.ready?'connected':signaling.phase==='listening'?'ready':signaling.phase==='secure'?'negotiating':signaling.phase,signalingPhase:signaling?.phase||null,busy:!!signaling?.busy,callId:signaling?.callId||null,reason:media?.reason||signaling?.reason||null,media:media||null};}
 get state(){const accounts=[1,2].map(slot=>this.getCall(slot));return {available:!!this.#executable,canPrepare:this.#phase!=='uncertain'&&!this.#busy&&this.#calls.size===0,canRecover:this.#phase==='uncertain'&&!!this.#recovery&&!this.#busy,phase:accounts.length===2&&accounts.every(a=>a.phase==='connected')?'connected':accounts.some(a=>a.phase==='failed')?'failed':this.#phase,busy:this.#busy,reason:this.#reason,clientSlot:this.#clientSlot,accounts,liveCallVerified:false,providerPathVerified:false,billingVerified:false,internationalOutageVerified:false};}
}
module.exports={CallPair};
