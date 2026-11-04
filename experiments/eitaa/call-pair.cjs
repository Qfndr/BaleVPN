// Explicit local two-account lab. Pairing identities stay inside this process;
// access hashes come from the calling account's protected target lookup.
'use strict';
const {createHash,randomBytes}=require('node:crypto');
const {CallSession,CallError,confirmsTerminal}=require('./call-session.cjs'),{CallClient}=require('./call-client.cjs'),{CallMedia}=require('./call-media.cjs'),{TargetResolver,binding}=require('./target-resolver.cjs');
const profiles=require('./client-profile.cjs');
const fail=reason=>{throw new CallError(reason);};
const same=(a,b)=>a.userId===b.userId&&a.token===b.token&&a.imei===b.imei&&profiles.fromRecord(a)===profiles.fromRecord(b);
const fingerprint=record=>createHash('sha256').update(JSON.stringify([record.userId,record.token,record.imei,profiles.fromRecord(record)])).digest('hex');
class CallPair{
 #accounts;#executable;#open;#clientFactory;#resolver;#calls=new Map();#media=new Map();#records;#targets;#epoch=0;#busy=false;#phase='idle';#reason=null;#clientSlot=1;
 #recovery=null;#recoveryClient=null;
 #openJournal;#journalTail=Promise.resolve();#intent=null;#journalReadBlocked=false;
 constructor(accounts,{executable,open,createClient,createAccountClient,openJournal}={}){
  this.#accounts=accounts;this.#executable=executable;this.#open=open;this.#clientFactory=createClient;
  this.#openJournal=openJournal;
  this.#resolver=new TargetResolver(accounts,{...createClient?{createCallClient:createClient}:{},...createAccountClient?{createAccountClient}:{}});
 }
 #guard(epoch){if(epoch!==this.#epoch)fail('call_cancelled');if(this.#records)for(const [slot,record]of this.#records)if(!same(record,binding(this.#accounts.get(slot))))fail('account_binding_changed');}
 #journalWork(guard,action){
  const task=this.#journalTail.then(async()=>{
   guard();let journal;
   try{journal=await this.#openJournal();guard();return await action(journal);}
   catch(error){throw error instanceof CallError?error:new CallError(error.reason==='eitaa_call_owner_busy'?'eitaa_call_owner_busy':'call_journal_unavailable');}
   finally{await journal?.close();}
  });
  this.#journalTail=task.catch(()=>{});return task;
 }
 settleJournal(){return this.#journalTail;}
 async loadJournal(){
  if(!this.#openJournal||!this.#executable)return;
  const epoch=this.#epoch,guard=()=>this.#guard(epoch);
  try{
   await this.#journalWork(guard,async journal=>{
    const intent=await journal.load();guard();this.#intent=intent;
    const readBlocked=this.#journalReadBlocked;this.#journalReadBlocked=false;
    if(!intent){
     if(readBlocked){this.#phase='idle';this.#reason=null;}
     return;
    }
    this.#phase='uncertain';this.#reason='call_end_uncertain';
    if(intent.callId)this.#recovery={slot:intent.slot,bindings:intent.bindings,checkpoint:{callId:BigInt(intent.callId),cursor:intent.cursor}};
   });
  }catch(error){
   if(epoch===this.#epoch){
    if(this.#phase!=='uncertain'&&!this.#intent&&!this.#pending())this.#journalReadBlocked=true;
    this.#phase='uncertain';this.#reason=error.reason||'call_journal_unavailable';
   }
   throw error;
  }
 }
 #beginIntent(slot,guard){
  const intent={operationId:randomBytes(16).toString('hex'),bindings:[1,2].map(target=>fingerprint(this.#records.get(target))),
   slot,phase:'requested',callId:null,cursor:null,terminalProof:null};
  return this.#journalWork(guard,async journal=>{
   const existing=await journal.load();guard();
   if(existing){this.#intent=existing;fail('call_end_uncertain');}
   try{await journal.save(intent,null,guard);}
   catch(error){this.#intent=await journal.load().catch(()=>intent);throw error;}
   guard();this.#intent=intent;
  });
 }
 #bindIntent(slot,callId,cursor,guard){
  return this.#journalWork(guard,async journal=>{
   const intent=this.#intent;
   if(intent?.slot!==slot||intent.phase!=='requested')fail('call_end_uncertain');
   const bound={...intent,phase:'bound',callId:String(callId),cursor};
   await journal.save(bound,intent,guard);guard();this.#intent=bound;
  });
 }
 #finishIntent(callId,proof,guard){
  return this.#journalWork(guard,async journal=>{
   const intent=this.#intent;
   if(!intent)return;
   if(intent.phase==='requested'||intent.callId!==String(callId))fail('call_end_uncertain');
   const terminal=intent.phase==='terminal'?intent:{...intent,phase:'terminal',terminalProof:proof};
   if(terminal!==intent){await journal.save(terminal,intent,guard);guard();this.#intent=terminal;}
   await journal.clear(terminal,guard);guard();this.#intent=null;
  });
 }
 #pending(confirmedId){return [...this.#calls.values()].some(call=>call.remotePending&&(!confirmedId||call.state.callId!==confirmedId));}
 #clear(phase,reason=null,confirmedId){
  const uncertain=this.#phase==='uncertain'||!!this.#intent||this.#pending(confirmedId);
  if(this.#intent||this.#pending(confirmedId))this.#journalReadBlocked=false;
  if(this.#recovery){
   const {slot,checkpoint}=this.#recovery,other=this.#calls.get(3-slot);
   if(!uncertain||confirmedId===String(checkpoint.callId)||other?.remotePending&&other.state.callId!==String(checkpoint.callId))
    this.#recovery=null;
  }
  this.#recoveryClient?.close();this.#recoveryClient=null;
  this.#epoch++;this.#resolver.close();for(const call of this.#calls.values())call.close();for(const media of this.#media.values())media.close();this.#calls.clear();this.#media.clear();this.#targets=null;this.#records=null;this.#busy=false;
  this.#phase=uncertain?'uncertain':phase;this.#reason=uncertain?'call_end_uncertain':reason;
 }
 reset(){if(this.#busy&&this.#phase!=='preparing')fail('call_busy');if(this.#intent||this.#pending()||this.#phase==='uncertain')fail('call_end_uncertain');this.#clear('idle');}
 invalidate(){this.#clear('ended');}
 async prepare({clientSlot=1,socksPort=1091,throughput=true}={}){
  if(!this.#executable)fail('native_bridge_unavailable');if(this.#phase==='uncertain')fail('call_end_uncertain');if(this.#busy||this.#calls.size)fail('call_busy');
  if(![1,2].includes(clientSlot)||!Number.isInteger(socksPort)||socksPort<1024||socksPort>65535||typeof throughput!=='boolean')fail('invalid_media_options');
  const records=new Map([1,2].map(slot=>[slot,binding(this.#accounts.get(slot))]));if(records.get(1).userId===records.get(2).userId)fail('distinct_accounts_required');
  const epoch=++this.#epoch;this.#records=records;this.#busy=true;this.#phase='preparing';this.#reason=null;this.#clientSlot=clientSlot;
  try{
   if(this.#openJournal){await this.loadJournal();this.#guard(epoch);if(this.#intent)fail('call_end_uncertain');}
   const targets=await this.#resolver.resolve();this.#guard(epoch);this.#targets=targets;
   for(const slot of [1,2])this.#media.set(slot,new CallMedia({executable:this.#executable,role:slot===clientSlot?'client':'server',socksPort,throughput,...this.#open?{open:this.#open}:{},onFailure:()=>{if(epoch===this.#epoch)this.#clear('failed','native_media_failed');}}));
   const prepared=await Promise.allSettled([1,2].map(slot=>this.#media.get(slot).prepare()));this.#guard(epoch);const failure=prepared.find(v=>v.status==='rejected');if(failure)throw failure.reason;
   for(const slot of [1,2])this.#media.get(slot).trustCertificate(prepared[2-slot].value.publicCertificate);
   for(const slot of [1,2]){
    const guarded=guard=>()=>{guard();this.#guard(epoch);};
    const journalCallbacks=this.#openJournal?{
     beforeRequest:guard=>this.#beginIntent(slot,guarded(guard)),
     beforeBind:(id,cursor,guard)=>this.#bindIntent(slot,id,cursor,guarded(guard)),
     beforeReceipt:id=>{if(this.#intent?.phase!=='bound'||this.#intent.slot===slot||this.#intent.callId!==String(id))fail('call_request_unbound');},
     beforeTerminal:(id,proof,guard)=>this.#finishIntent(id,proof,guarded(guard))
    }:{};
    const media=this.#media.get(slot);this.#calls.set(slot,new CallSession(this.#accounts.get(slot),{allowedPeers:[records.get(3-slot).userId],...this.#clientFactory?{createClient:this.#clientFactory}:{},...journalCallbacks,onSecure:context=>media.onSecure(context),onSignal:(signal,context)=>media.onSignal(signal,context),onEnd:()=>media.close()}));
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
  if(!callId){if(this.#intent||this.#pending()||this.#phase==='uncertain')fail('call_end_uncertain');this.#clear('ended');return {ended:true,remoteConfirmed:false};}
  const checkpoint=call.terminalCheckpoint(),bindings=[1,2].map(target=>fingerprint(this.#records.get(target)));
  // Invalidation may close both sessions before the discard promise settles.
  if(checkpoint)this.#recovery={slot,checkpoint,bindings};
  const epoch=this.#epoch;this.#busy=true;for(const media of this.#media.values())media.close();
  try{await call.hangUp();this.#guard(epoch);this.#clear('ended',null,callId);return {ended:true,remoteConfirmed:true};}
  catch(e){if(epoch===this.#epoch)this.#clear('uncertain','call_end_uncertain');throw e instanceof CallError?e:new CallError('call_end_uncertain');}
 }
 async recover(){
  if(this.#busy)fail('call_busy');
  if(this.#phase!=='uncertain')fail('call_end_uncertain');
  const epoch=this.#epoch;
  this.#busy=true;let client,recovery;
  const records=()=>{
   this.#guard(epoch);
   const pair=[1,2].map(slot=>binding(this.#accounts.get(slot)));
   if(pair.some((record,index)=>fingerprint(record)!==recovery.bindings[index]))fail('account_binding_changed');
   return pair;
  };
  try{
   if(this.#openJournal)await this.loadJournal();
   this.#guard(epoch);recovery=this.#recovery;
   if(!recovery||this.#openJournal&&!this.#intent?.callId)fail('call_end_uncertain');
   const record=records()[recovery.slot-1];
   if(this.#intent?.phase!=='terminal'){
    client=this.#clientFactory?this.#clientFactory(record):new CallClient(record);this.#recoveryClient=client;
    const {pts,date}=recovery.checkpoint.cursor;
    const result=await client.request('updates.getDifference',{pts,date,qts:-1});records();
    if(!confirmsTerminal(result,recovery.checkpoint))fail('call_end_uncertain');
   }
   if(this.#openJournal)await this.#finishIntent(recovery.checkpoint.callId,'event-history',records);
   records();
   this.#recovery=null;this.#phase='ended';this.#reason=null;
   return {ended:true,remoteConfirmed:true};
  }catch(error){throw error instanceof CallError?error:new CallError('call_end_uncertain');}
  finally{if(epoch===this.#epoch){client?.close();this.#recoveryClient=null;this.#busy=false;}}
 }
 getCall(slot){const signaling=this.#calls.get(slot)?.state,media=this.#media.get(slot)?.state;return {provider:'eitaa',slot,phase:!signaling?this.#phase==='idle'?'idle':'ended':media?.phase==='failed'?'failed':media?.phase==='closed'?'ended':media?.ready?'connected':signaling.phase==='listening'?'ready':signaling.phase==='secure'?'negotiating':signaling.phase,signalingPhase:signaling?.phase||null,busy:!!signaling?.busy,callId:signaling?.callId||null,reason:media?.reason||signaling?.reason||null,media:media||null};}
 get state(){const accounts=[1,2].map(slot=>this.getCall(slot));return {available:!!this.#executable,canPrepare:this.#phase!=='uncertain'&&!this.#busy&&this.#calls.size===0,canRecover:this.#phase==='uncertain'&&!!this.#recovery&&!this.#busy,phase:accounts.length===2&&accounts.every(a=>a.phase==='connected')?'connected':accounts.some(a=>a.phase==='failed')?'failed':this.#phase,busy:this.#busy,reason:this.#reason,clientSlot:this.#clientSlot,accounts,liveCallVerified:false,providerPathVerified:false,billingVerified:false,internationalOutageVerified:false};}
}
module.exports={CallPair};
