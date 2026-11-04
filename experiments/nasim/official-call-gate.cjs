// Account-bound admission and recovery policy. No network or vault is opened here.
'use strict';
const crypto=require('node:crypto');
const codec=require('./call-codec.cjs');
const {accountBinding}=require('./cleanup-intent.cjs');
const {SOURCES}=require('./official-web-reference.cjs');
const SOURCE_HASH=crypto.createHash('sha256').update(JSON.stringify(SOURCES)).digest('hex');
const FORMAT='nasim-official-call-intent-v1';
const fail=reason=>Object.assign(new Error('Official Nasim gate '+reason),{reason});
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
function snapshot(account){
 const context=accountBinding(account),record=account.exportSession();
 if(typeof record.deviceId!=='string'||!/^web\.[a-z0-9.-]{12,80}$/.test(record.deviceId))throw fail('invalid_account_binding');
 return {...context,deviceBinding:crypto.createHash('sha256').update(record.deviceId).digest('hex')};
}
function validate(value){
 const fields=['format','operationId','createdAt','sourceHash','accounts','callerSlot','phase','callUUID','terminalEvents'];
 if(!value||typeof value!=='object'||Array.isArray(value)||!equal(Object.keys(value).sort(),fields.sort())||
  value.format!==FORMAT||! /^[a-f0-9]{32}$/.test(value.operationId)||!Number.isSafeInteger(value.createdAt)||value.createdAt<=0||
  value.sourceHash!==SOURCE_HASH||![1,2].includes(value.callerSlot)||!['prepared','requested','bound'].includes(value.phase)||
  !Array.isArray(value.accounts)||value.accounts.length!==2||!Array.isArray(value.terminalEvents)||
  value.terminalEvents.length>2||new Set(value.terminalEvents.map(event=>event?.slot)).size!==value.terminalEvents.length||
  value.terminalEvents.some(event=>!event||!equal(Object.keys(event).sort(),['slot','source'])||
   ![1,2].includes(event.slot)||!['http-ack','peer-bye'].includes(event.source)))throw fail('invalid_intent');
 for(const account of value.accounts){
  if(!account||!equal(Object.keys(account).sort(),['selfId','selfClientId','accountBinding','deviceBinding'].sort())||
   codec.userId(account.selfId)!==account.selfId||codec.clientId(account.selfClientId)!==account.selfClientId||
   !/^[a-f0-9]{64}$/.test(account.accountBinding)||!/^[a-f0-9]{64}$/.test(account.deviceBinding))throw fail('invalid_intent');
 }
 if(value.accounts[0].selfId===value.accounts[1].selfId||
  (value.phase==='bound'?typeof value.callUUID!=='string'||!/^[-A-Za-z0-9_:]{1,128}$/.test(value.callUUID):value.callUUID!==null||value.terminalEvents.length!==0))throw fail('invalid_intent');
 return structuredClone(value);
}
class OfficialCallGate{
 #accounts;#cleanup;#store;#intent=null;#epoch=0;#queue=Promise.resolve();#counts=new Map();#failed=false;#ready=false;#stopped=false;#recovering=false;
 constructor(accounts,cleanup,store){
  if(!accounts?.get(1)||!accounts.get(2)||!cleanup?.get(1)||!cleanup.get(2)||
   !store||!['load','save','clear'].every(key=>typeof store[key]==='function'))throw fail('invalid_options');
  this.#accounts=accounts;this.#cleanup=cleanup;this.#store=store;
 }
 #run(action){const task=this.#queue.then(action);this.#queue=task.catch(()=>{});return task;}
 #bindings(){return [snapshot(this.#accounts.get(1)),snapshot(this.#accounts.get(2))];}
 #guard(intent,epoch){if(this.#stopped||epoch!==this.#epoch)throw fail('cancelled');if(!equal(this.#bindings(),intent.accounts))throw fail('account_binding_changed');}
 async #save(next){
  const previous=this.#intent,epoch=this.#epoch,guard=()=>this.#guard(next,epoch);guard();
  // Keep uncertainty in memory even if a store writes and subsequently rejects.
  this.#intent=next;this.#failed=true;await this.#store.save(structuredClone(next),previous&&structuredClone(previous),guard);guard();
  if(!equal(validate(await this.#store.load()),next))throw fail('intent_save_failed');guard();
  this.#failed=false;
 }
 async #restore(){
  const accounts=this.#bindings(),epoch=this.#epoch,stored=await this.#store.load();this.#guard({accounts},epoch);if(!stored)return false;
  const intent=validate(stored);this.#guard(intent,epoch);this.#intent=intent;this.#failed=false;this.#recovering=true;return true;
 }
 begin(callerSlot=1){return this.#run(async()=>{
  if(![1,2].includes(callerSlot))throw fail('invalid_slot');
  if(this.#intent||await this.#restore())throw fail('cleanup_pending');
  for(const cleanup of this.#cleanup.values())await cleanup.ensureClear();
  await this.#save(validate({format:FORMAT,operationId:crypto.randomBytes(16).toString('hex'),createdAt:Date.now(),sourceHash:SOURCE_HASH,
   accounts:this.#bindings(),callerSlot,phase:'prepared',callUUID:null,terminalEvents:[]}));
 });}
 outgoing(slot,signal){return this.#run(async()=>{
  const intent=this.#intent;if(this.#failed)throw fail('intent_save_failed');if(!intent||![1,2].includes(slot))throw fail('call_not_prepared');this.#guard(intent,this.#epoch);
  const self=intent.accounts[slot-1],peer=intent.accounts[2-slot];
  const encoded=codec.outgoing(signal,self.selfId,peer.selfId);
  if(this.#recovering&&!['bye','reject'].includes(signal.type))throw fail('cleanup_pending');
  if(signal.type==='callRequest'){
   if(slot!==intent.callerSlot||intent.phase!=='prepared')throw fail('duplicate_call_request');
   await this.#save({...intent,phase:'requested'});return encoded;
  }
  if(!this.#ready||intent.phase!=='bound'||signal.callUUID!==intent.callUUID)throw fail('call_uuid_mismatch');
  if(signal.type==='accept'&&slot===intent.callerSlot)throw fail('wrong_call_direction');
  if(signal.type==='answer'&&signal.callData.clientID!==peer.selfClientId)throw fail('wrong_client');
  if(signal.type==='ice'&&signal.callData.clientID!==null&&signal.callData.clientID!==peer.selfClientId)throw fail('wrong_client');
  const key=slot+':'+signal.type,count=this.#counts.get(key)||0,limit=signal.type==='ice'?256:1;
  if(count>=limit)throw fail('signal_limit');this.#counts.set(key,count+1);return encoded;
 });}
 bindResponse(slot,response){return this.#run(async()=>{
  const intent=this.#intent;if(this.#failed)throw fail('intent_save_failed');if(!intent||slot!==intent.callerSlot||!['requested','bound'].includes(intent.phase))throw fail('unexpected_response');
  this.#guard(intent,this.#epoch);
  const callUUID=codec.requestCallUUID(response,intent.accounts[slot-1].selfId,intent.accounts[2-slot].selfId);
  if(!callUUID)throw fail('call_uuid_missing');
  if(intent.callUUID&&intent.callUUID!==callUUID)throw fail('call_uuid_mismatch');
  this.#ready=false;
  if(intent.phase!=='bound')await this.#save({...intent,phase:'bound',callUUID});
  // Persist each existing per-account cleanup record before the caller may
  // deliver the response or buffered SSE messages to vendor JavaScript.
  for(const target of [1,2])if(!intent.terminalEvents.some(event=>event.slot===target))await this.#cleanup.get(target).capture({peerId:intent.accounts[2-target].selfId,callUUID});
  this.#guard(this.#intent,this.#epoch);this.#ready=true;
 });}
 incoming(slot,message){return this.#run(async()=>{
  const intent=this.#intent;if(this.#failed)throw fail('intent_save_failed');if(!intent||![1,2].includes(slot))throw fail('call_not_prepared');this.#guard(intent,this.#epoch);
  const self=intent.accounts[slot-1],peer=intent.accounts[2-slot],event=codec.incoming(message,self.selfId);
  if(['config','callLog'].includes(event.type)){
   if(event.peerId!==peer.selfId)throw fail('wrong_peer');
   if(event.type==='config'&&(event.senderClientId!==intent.accounts[intent.callerSlot-1].selfClientId||
    event.invitedUserId!==intent.accounts[2-intent.callerSlot].selfId))throw fail('wrong_client');
  }else if(event.senderId===self.selfId&&event.senderClientId===self.selfClientId){
   return {defer:false,drop:true};
  }else if(event.senderId!==peer.selfId||event.senderClientId!==peer.selfClientId)throw fail('wrong_peer');
  if(intent.phase!=='bound'||!this.#ready)return {defer:true};
  if(event.callUUID!==intent.callUUID)throw fail('call_uuid_mismatch');
  if(event.type==='answer'&&event.targetClientId!==self.selfClientId)throw fail('wrong_client');
  if(event.type==='ice'&&event.candidate.clientID!==null&&event.candidate.clientID!==self.selfClientId)throw fail('wrong_client');
  return {defer:false,event};
 });}
 acknowledgeTerminal(slot,result){return this.#run(async()=>{
  let intent=this.#intent;if(this.#failed)throw fail('intent_save_failed');if(!intent||intent.phase!=='bound'||![1,2].includes(slot))throw fail('call_not_bound');this.#guard(intent,this.#epoch);
  const peerId=intent.accounts[2-slot].selfId,ack=result?.terminalAcknowledgement;
  if(result?.acknowledged!==true||ack?.type!=='bye'||ack.callUUID!==intent.callUUID||ack.peerId!==peerId)throw fail('cleanup_unconfirmed');
  await this.#finishTerminal(slot,'http-ack');
 });}
 terminalEvent(slot,message){return this.#run(async()=>{
  const intent=this.#intent;if(this.#failed)throw fail('intent_save_failed');
  if(!intent||intent.phase!=='bound'||![1,2].includes(slot))throw fail('call_not_bound');this.#guard(intent,this.#epoch);
  const self=intent.accounts[slot-1],peer=intent.accounts[2-slot],event=codec.incoming(message,self.selfId);
  if(event.type!=='bye'||event.callUUID!==intent.callUUID||event.senderId!==peer.selfId||event.senderClientId!==peer.selfClientId)throw fail('cleanup_unconfirmed');
  await this.#finishTerminal(slot,'peer-bye');
 });}
 async #finishTerminal(slot,source){
  let intent=this.#intent;
  if(!intent.terminalEvents.some(event=>event.slot===slot)){
   await this.#save({...intent,terminalEvents:[...intent.terminalEvents,{slot,source}].sort((a,b)=>a.slot-b.slot)});intent=this.#intent;
  }
  await this.#cleanup.get(slot).peerEnded({peerId:intent.accounts[2-slot].selfId,callUUID:intent.callUUID});
  if(intent.terminalEvents.length!==2||[...this.#cleanup.values()].some(cleanup=>cleanup.state.pending))return;
  const epoch=this.#epoch,guard=()=>this.#guard(intent,epoch);await this.#store.clear(structuredClone(intent),guard);guard();
  const remaining=await this.#store.load();guard();if(remaining)throw fail('cleanup_unconfirmed');
  this.#intent=null;this.#counts.clear();this.#ready=false;this.#recovering=false;
 }
 restore(){return this.#run(async()=>{
  if(!await this.#restore())return false;
  const intent=this.#intent;
  if(intent.phase==='bound'){
   for(const slot of [1,2]){
    const cleanup=this.#cleanup.get(slot),peerId=intent.accounts[2-slot].selfId;
    await cleanup.restore();
    if(intent.terminalEvents.some(event=>event.slot===slot))await cleanup.peerEnded({peerId,callUUID:intent.callUUID});
    else await cleanup.capture({peerId,callUUID:intent.callUUID});
   }
   this.#guard(intent,this.#epoch);this.#ready=true;
  }
  return true;
 });}
 stop(){this.#stopped=true;this.#epoch++;}
 get state(){return {pending:!!this.#intent,phase:this.#intent?.phase||'idle',uuidKnown:!!this.#intent?.callUUID};}
}
module.exports={OfficialCallGate,validateOfficialIntent:validate};
