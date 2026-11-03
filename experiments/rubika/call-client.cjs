// Authenticated account-bound call transport. No retries, media, automatic
// polling or device registration. Incoming data remains private to the caller.
'use strict';
const {diagnostic}=require('./call-diagnostic.cjs');
const crypto=require('node:crypto'),{HttpClient,ApiError}=require('./http-client.cjs');
const codec=require('./call-codec.cjs'),updates=require('./call-updates.cjs');
const SAFE=new Set(['closed','account_busy','invalid_request','invalid_credentials','not_authorized','rate_limited',
 'registration_required','service_rejected','timeout','network_error','http_error','invalid_dc_server',
 'invalid_dc_response','invalid_response','invalid_encrypted_response','response_too_large','tls_verification_disabled']);
const UPDATE_ERRORS=new Set(['invalid_call_response','call_identity_mismatch','unsupported_call_protocol','update_account_mismatch']);
const fail=reason=>{throw new ApiError(reason);};
class CallClient{
 #account;#create;#lang;#client;#binding;#epoch=0;#busy=false;#ready=false;#closed=false;#error=null;
 constructor(account,{language='fa',createClient=options=>new HttpClient(options)}={}){
  if(!account||typeof createClient!=='function'||!['fa','en'].includes(language))fail('invalid_request');
  this.#account=account;this.#create=createClient;this.#lang=language;
 }
 #context(){
  const state=this.#account.state;
  if(state?.provider!=='rubika'||state.signedIn!==true||state.selfConfirmed!==true)fail('not_authenticated');
  let record;try{record=this.#account.exportSession();}catch{fail('not_authenticated');}
  if(record?.provider!=='rubika'||record.userId!==state.userId||typeof record.userId!=='string'||! /^[A-Za-z0-9_-]{8,128}$/.test(record.userId)||
   typeof record.auth!=='string'||! /^[A-Za-z0-9]{32}$/.test(record.auth)||typeof record.privateKey!=='string'||record.privateKey.length>16384||typeof record.publicKey!=='string'||record.publicKey.length>8192)fail('invalid_account_binding');
  if(this.#binding&&['userId','auth','privateKey','publicKey'].some(k=>record[k]!==this.#binding[k]))fail('account_binding_changed');return record;
 }
 #guard(epoch){if(this.#closed||epoch!==this.#epoch)fail('closed');this.#context();}
 #retire(){this.#epoch++;this.#ready=false;this.#client?.close();this.#client=null;this.#binding=null;}
 async #run(action,operation='start'){
  if(this.#closed)fail('closed');if(this.#busy)fail('account_busy');this.#busy=true;this.#error=null;const epoch=this.#epoch;
  try{this.#guard(epoch);const result=await action(()=>this.#guard(epoch));this.#guard(epoch);return result;}
  catch(e){
   if(this.#closed||epoch!==this.#epoch)throw new ApiError('closed');
   const reason=e instanceof ApiError&&SAFE.has(e.reason)||e instanceof updates.UpdateError&&UPDATE_ERRORS.has(e.reason)?e.reason:
    ['not_authenticated','invalid_account_binding','account_binding_changed','call_not_started','call_already_started'].includes(e?.reason)?e.reason:'call_operation_failed';
   const detail=diagnostic({...e,operation});this.#error={reason,...detail};
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
  this.#binding={provider:'rubika',userId:record.userId,auth:record.auth,privateKey:record.privateKey,publicKey:record.publicKey};
  this.#client=this.#create({language:this.#lang});await this.#client.discover();guard();this.#ready=true;return {ready:true,mediaReady:false};
 });}
 request(method,value={}){
  // Snapshot before awaiting discovery/network or allowing external mutation.
  let input;try{if(!codec.PROTECTED_METHODS.includes(method))fail('invalid_request');codec.validateInput(method,value);input=structuredClone(value);}catch{return Promise.reject(new ApiError('invalid_request'));}
  return this.#run(async guard=>{
   if(!this.#ready||!this.#client)fail('call_not_started');
   const result=await this.#client.request(method,input,{credentials:{...this.#binding}});guard();
   return updates.response(method,result,{selfId:this.#binding.userId,callId:input.call_id});
  },method);
 }
 close(){if(this.#closed)return;this.#closed=true;this.#retire();}
 get state(){
  if(this.#binding&&!this.#closed)try{this.#context();}catch(e){this.#error={reason:['not_authenticated','invalid_account_binding','account_binding_changed'].includes(e?.reason)?e.reason:'call_operation_failed'};this.#retire();}
  return {provider:'rubika',ready:this.#ready,closed:this.#closed,busy:this.#busy,error:this.#error?{...this.#error}:null,mediaReady:false};
 }
}
module.exports={CallClient};
