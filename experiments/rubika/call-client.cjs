// Authenticated account-bound call transport. No retries, media, automatic
// polling or device registration. Incoming data remains private to the caller.
'use strict';
const {diagnostic}=require('./call-diagnostic.cjs');
const {StreamError}=require('./socket-updates.cjs');
const crypto=require('node:crypto'),{HttpClient,ApiError}=require('./http-client.cjs');
const profiles=require('./client-profile.cjs');
const {validateCallRecovery}=require('./call-recovery.cjs');
const codec=require('./call-codec.cjs'),updates=require('./call-updates.cjs');
const SAFE=new Set(['closed','account_busy','invalid_request','invalid_credentials','not_authorized','access_denied','rate_limited',
 'registration_required','service_rejected','timeout','network_error','http_error','invalid_dc_server',
 'invalid_dc_response','invalid_response','invalid_encrypted_response','response_too_large','tls_verification_disabled',
 'recovery_save_failed','recovery_clear_failed','call_recovery_available','invalid_call_recovery','call_recovery_expired']);
const UPDATE_ERRORS=new Set(['invalid_call_response','call_identity_mismatch','unsupported_call_protocol','update_account_mismatch']);
const fail=reason=>{throw new ApiError(reason);};
const accountBinding=record=>crypto.createHash('sha256').update(JSON.stringify([record.userId,record.auth,record.privateKey,record.publicKey,profiles.fromRecord(record)])).digest('hex');
function callResponseOnly(value){
 if(!value||typeof value!=='object'||Array.isArray(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))fail('recovery_save_failed');
 const response=Object.create(null);
 for(const key of ['call_type','call_update']){const field=Object.getOwnPropertyDescriptor(value,key);if(field){if(!Object.hasOwn(field,'value'))fail('recovery_save_failed');response[key]=field.value;}}
 return response;
}
class CallClient{
 #account;#create;#lang;#client;#binding;#epoch=0;#busy=false;#ready=false;#closed=false;#error=null;
 #saveRecovery;#clearRecovery;#pendingRecovery=null;#privateRecovery=null;
 constructor(account,{language='fa',createClient=options=>new HttpClient(options),saveCallRecovery,clearCallRecovery}={}){
  if(!account||typeof createClient!=='function'||!['fa','en'].includes(language))fail('invalid_request');
  if((saveCallRecovery!==undefined||clearCallRecovery!==undefined)&&(typeof saveCallRecovery!=='function'||typeof clearCallRecovery!=='function'))fail('invalid_request');
  this.#account=account;this.#create=createClient;this.#lang=language;
  this.#saveRecovery=saveCallRecovery;this.#clearRecovery=clearCallRecovery;
 }
 #context(){
  const state=this.#account.state;
  if(state?.provider!=='rubika'||state.signedIn!==true||state.selfConfirmed!==true)fail('not_authenticated');
  let record;try{record=this.#account.exportSession();}catch{fail('not_authenticated');}
  if(record?.provider!=='rubika'||record.userId!==state.userId||typeof record.userId!=='string'||! /^[A-Za-z0-9_-]{8,128}$/.test(record.userId)||
   typeof record.auth!=='string'||! /^[A-Za-z0-9]{32}$/.test(record.auth)||typeof record.privateKey!=='string'||record.privateKey.length>16384||typeof record.publicKey!=='string'||record.publicKey.length>8192)fail('invalid_account_binding');
  let profile;try{profile=profiles.fromRecord(record);}catch{fail('invalid_account_binding');}
  if(this.#binding&&(['userId','auth','privateKey','publicKey'].some(k=>record[k]!==this.#binding[k])||profile!==profiles.fromRecord(this.#binding)))fail('account_binding_changed');return record;
 }
 #guard(epoch){if(this.#closed||epoch!==this.#epoch)fail('closed');this.#context();}
 #retainRecovery(candidate,{stored=false,intentStored=false}={}){
  const bytes=Buffer.from(JSON.stringify(candidate));this.#privateRecovery?.fill(0);this.#privateRecovery=bytes;
  this.#pendingRecovery={selfId:candidate.selfId,peerId:candidate.peerId,accountBinding:candidate.accountBinding,capturedAt:candidate.capturedAt,stored,intentStored,callId:null};
 }
 #clearPrivateRecovery(){this.#privateRecovery?.fill(0);this.#privateRecovery=null;this.#pendingRecovery=null;}
 async #savePendingRecovery(guard){
  const pending=this.#pendingRecovery,bytes=this.#privateRecovery;
  const ownerGuard=()=>{guard();if(!pending||this.#pendingRecovery!==pending||this.#privateRecovery!==bytes||pending.accountBinding!==accountBinding(this.#context()))fail('account_binding_changed');};
  ownerGuard();if(!this.#saveRecovery||!bytes)fail('invalid_call_recovery');
  let candidate;try{candidate=validateCallRecovery(JSON.parse(bytes.toString('utf8')));}catch{fail('invalid_call_recovery');}
  try{await this.#saveRecovery(candidate,ownerGuard);}catch{ownerGuard();fail('recovery_save_failed');}ownerGuard();
  pending.stored=true;if(Object.keys(candidate.response).length===0)pending.intentStored=true;
 }
 #retire(){this.#epoch++;this.#ready=false;this.#client?.close();this.#client=null;this.#binding=null;}
 async #run(action,operation='start'){
  if(this.#closed)fail('closed');if(this.#busy)fail('account_busy');this.#busy=true;this.#error=null;const epoch=this.#epoch;
  try{this.#guard(epoch);const result=await action(()=>this.#guard(epoch));this.#guard(epoch);return result;}
  catch(e){
   if(this.#closed||epoch!==this.#epoch)throw new ApiError('closed');
   const reason=e instanceof StreamError?e.reason:e instanceof ApiError&&SAFE.has(e.reason)||e instanceof updates.UpdateError&&UPDATE_ERRORS.has(e.reason)?e.reason:
    ['not_authenticated','invalid_account_binding','account_binding_changed','call_not_started','call_already_started'].includes(e?.reason)?e.reason:'call_operation_failed';
   const detail=diagnostic({...e,operation,...this.#pendingRecovery?{recoveryStored:this.#pendingRecovery.stored===true}:{}});this.#error={reason,...detail};
   if(!['invalid_request','call_not_started','call_already_started'].includes(reason))this.#retire();
   throw Object.assign(new ApiError(reason),detail);
  }finally{this.#busy=false;}
 }
 start(){return this.#run(async guard=>{
  if(this.#client)fail('call_already_started');const record=this.#context();
  // Check key ownership once on start, never on the media hot path.
  try{
   const privateKey=crypto.createPrivateKey(record.privateKey),publicKey=crypto.createPublicKey(record.publicKey);
   if(privateKey.asymmetricKeyType!=='rsa'||publicKey.asymmetricKeyType!=='rsa'||privateKey.asymmetricKeyDetails.modulusLength<2048||publicKey.asymmetricKeyDetails.modulusLength<2048||
    !crypto.createPublicKey(privateKey).export({type:'spki',format:'der'}).equals(publicKey.export({type:'spki',format:'der'})))fail('invalid_account_binding');
  }catch{fail('invalid_account_binding');}
  this.#binding={provider:'rubika',userId:record.userId,auth:record.auth,privateKey:record.privateKey,publicKey:record.publicKey,...record.profile?{profile:{...record.profile}}:{}};
  this.#client=this.#create({language:this.#lang,protocolProfile:profiles.fromRecord(record)});await this.#client.discover();guard();if(typeof this.#client.startUpdates==='function')await this.#client.startUpdates({...this.#binding});guard();this.#ready=true;return {ready:true,mediaReady:false};
 });}
 request(method,value={}){
  // Snapshot before awaiting discovery/network or allowing external mutation.
  let input;try{if(!codec.PROTECTED_METHODS.includes(method))fail('invalid_request');codec.validateInput(method,value);input=structuredClone(value);}catch{return Promise.reject(new ApiError('invalid_request'));}
  return this.#run(async guard=>{
   if(!this.#ready||!this.#client)fail('call_not_started');
   if(method==='requestCall'&&this.#pendingRecovery)fail('call_recovery_available');
   if(method==='requestCall'&&this.#saveRecovery){
    // Persist uncertainty BEFORE the service can create a call. If stopped,
    // locked or crashed during the request, this intent blocks a blind redial.
    const intent=validateCallRecovery({provider:'rubika',operation:'requestCall',selfId:this.#binding.userId,peerId:input.user_guid,
     accountBinding:accountBinding(this.#binding),capturedAt:Date.now(),response:{}});
    this.#retainRecovery(intent);await this.#savePendingRecovery(guard);guard();
   }
   const result=await this.#client.request(method,input,{credentials:{...this.#binding}});guard();
   if(method==='requestCall'&&this.#saveRecovery){
    let candidate;try{candidate=validateCallRecovery({provider:'rubika',operation:'requestCall',selfId:this.#binding.userId,peerId:input.user_guid,
     accountBinding:accountBinding(this.#binding),capturedAt:this.#pendingRecovery.capturedAt,response:callResponseOnly(result)});}catch{fail('recovery_save_failed');}
    this.#retainRecovery(candidate,{intentStored:true});await this.#savePendingRecovery(guard);
   }
   const projected=updates.response(method,result,{selfId:this.#binding.userId,callId:input.call_id});
   if(method==='requestCall'&&this.#pendingRecovery)this.#pendingRecovery.callId=projected.call_update.call_id;
   return projected;
  },method);
 }
 // Called only after the CallSession has adopted the exact parsed call ID.
 // Clearing this diagnostic copy does not acknowledge or accept a remote call.
 acknowledgeRequestCall(callId){return this.#run(async guard=>{
  if(typeof callId!=='string'||!/^[A-Za-z0-9_-]{8,128}$/.test(callId))fail('invalid_call_recovery');
  if(!this.#pendingRecovery)return {acknowledged:true};
  const pending=this.#pendingRecovery;
  if(!this.#clearRecovery||!pending.stored||pending.callId!==callId||pending.accountBinding!==accountBinding(this.#context()))fail('invalid_call_recovery');
  guard();try{await this.#clearRecovery({...pending},guard);}catch{guard();fail('recovery_clear_failed');}guard();
  if(this.#pendingRecovery!==pending)fail('invalid_call_recovery');this.#clearPrivateRecovery();return {acknowledged:true};
 },'requestCall');}
 // Private explicit retry of the same bounded candidate; never repeats a call
 // RPC. A changed/closed owner cannot persist the old account's response.
 retrySaveCallRecovery(){return this.#run(async guard=>{
  await this.#savePendingRecovery(guard);return {saved:true};
 },'requestCall');}
 // Private reparse only: no registration, call RPC, caller admission or removal.
 recoverRequestCall(value){return this.#run(async guard=>{
  const retained=value===undefined;
  let candidate;try{candidate=validateCallRecovery(retained&&this.#privateRecovery?JSON.parse(this.#privateRecovery.toString('utf8')):value);}catch(e){fail(['invalid_call_recovery','call_recovery_expired'].includes(e?.reason)?e.reason:'invalid_call_recovery');}
  const record=this.#context();if(candidate.selfId!==record.userId||candidate.accountBinding!==accountBinding(record))fail('account_binding_changed');
  const result=updates.response('requestCall',candidate.response,{selfId:record.userId});guard();
  const update=result.call_update;
  if(update.object_guid!==candidate.peerId||update.call?.other_participants?.some(p=>![candidate.selfId,candidate.peerId].includes(p.object_guid)))fail('call_identity_mismatch');
  const stored=retained?this.#pendingRecovery?.stored===true:true;
  this.#retainRecovery(candidate,{stored,intentStored:true});this.#pendingRecovery.callId=update.call_id;
  return result;
 },'requestCall');}
 close(){if(this.#closed)return;this.#closed=true;this.#retire();this.#clearPrivateRecovery();}
 get state(){
  if(this.#binding&&!this.#closed)try{this.#context();}catch(e){this.#error={reason:['not_authenticated','invalid_account_binding','account_binding_changed'].includes(e?.reason)?e.reason:'call_operation_failed'};this.#retire();}
  return {provider:'rubika',ready:this.#ready,closed:this.#closed,busy:this.#busy,error:this.#error?{...this.#error}:null,mediaReady:false};
 }
}
module.exports={CallClient};
