// PRIVATE bounded first-page call metadata for explicit laboratory cleanup.
// No UI route, persistence, pagination, registration or discard request exists.
'use strict';
const crypto=require('node:crypto'),{types}=require('node:util');
const {HttpClient,ApiError}=require('./http-client.cjs'),profiles=require('./client-profile.cjs');
const MAX_CALLS=128; // Local bound, not a claimed provider page limit.
class CallHistoryError extends Error{constructor(reason){super('Rubika call history '+reason);this.reason=reason;}}
const fail=reason=>{throw new CallHistoryError(reason);};
const id=value=>typeof value==='string'&&/^[A-Za-z0-9_-]{8,128}$/.test(value);
const plain=value=>value&&typeof value==='object'&&!types.isProxy(value)&&!Array.isArray(value)&&[Object.prototype,null].includes(Object.getPrototypeOf(value));
function own(value,key){const item=Object.getOwnPropertyDescriptor(value,key);if(!item)return undefined;if(!Object.hasOwn(item,'value'))fail('invalid_call_history');return item.value;}
function long(value){
 if(Number.isSafeInteger(value)&&value>=0)return String(value);
 if(typeof value==='string'&&/^(0|[1-9]\d{0,18})$/.test(value)&&BigInt(value)<=9223372036854775807n)return value;
 fail('invalid_call_history');
}
function row(value){
 if(!plain(value))fail('invalid_call_history');
 const callId=own(value,'call_id'),callType=own(value,'call_type'),objectGuid=own(value,'object_guid'),requestType=own(value,'request_type');
 if(!id(callId)||!['Voice','Video','CallOut'].includes(callType)||!id(objectGuid)||!['Caller','Receiver'].includes(requestType))fail('invalid_call_history');
 const out={call_id:callId,call_type:callType,object_guid:objectGuid,request_type:requestType,start_time:long(own(value,'start_time'))};
 const participants=own(value,'other_participants');
 if(participants!==undefined){
  if(participants===null)out.other_participants=null;
  else{if(!Array.isArray(participants)||types.isProxy(participants)||participants.length>16)fail('invalid_call_history');const seen=new Set();out.other_participants=participants.map(item=>{
   if(!plain(item)||!id(own(item,'object_guid'))||own(item,'type')!=='User'||seen.has(own(item,'object_guid')))fail('invalid_call_history');
   const guid=own(item,'object_guid');seen.add(guid);return {object_guid:guid,type:'User'};
  });}
 }
 const duration=own(value,'duration');if(duration!==undefined){if(duration!==null&&(!Number.isInteger(duration)||duration<0||duration>2147483647))fail('invalid_call_history');out.duration=duration;}
 const discard=own(value,'discard_reason');if(discard!==undefined){
  if(discard!==null&&typeof discard!=='string')fail('invalid_call_history');
  // Retain only the fixed discard vocabulary already grounded in the APK;
  // unknown strings are not copied as if they were verified enum metadata.
  if(discard===null||['Missed','Disconnect','Hangup','Busy'].includes(discard))out.discard_reason=discard;
 }
 return out;
}
function decodeCallHistory(value){
 if(!plain(value))fail('invalid_call_history');const calls=own(value,'calls'),hasContinue=own(value,'has_continue');
 if(!Array.isArray(calls)||types.isProxy(calls)||calls.length>MAX_CALLS||typeof hasContinue!=='boolean')fail('invalid_call_history');
 const seen=new Set(),projected=calls.map(value=>{const item=row(value);if(seen.has(item.call_id))fail('invalid_call_history');seen.add(item.call_id);return item;});
 // CallAbsObject has no active-state member. start_time is a Java long in
 // the APK; these sources do not prove its unit. Never invent either fact.
 return {calls:projected,hasContinue,timeUnit:'unverified',activeStateAvailable:false};
}
function findCallHistoryCandidates(page,{selfId,peerId}={}){
 if(!id(selfId)||!id(peerId)||selfId===peerId||!plain(page)||!Array.isArray(page.calls)||page.calls.length>MAX_CALLS)fail('invalid_history_selection');
 const candidates=page.calls.map(row).filter(item=>{
  if(item.call_type!=='Voice'||item.request_type!=='Caller'||item.object_guid!==peerId||!Array.isArray(item.other_participants))return false;
  const members=new Set([item.object_guid,...item.other_participants.map(p=>p.object_guid)]);
  return members.size===2&&members.has(selfId)&&members.has(peerId);
 });
 return {candidates,ambiguous:candidates.length>1,timeUnit:'unverified',activeStateAvailable:false,selectedCallId:null};
}
function context(account){
 let state,record;try{state=account.state;record=account.exportSession();}catch{fail('not_authenticated');}
 if(state?.provider!=='rubika'||state.signedIn!==true||state.selfConfirmed!==true||record?.provider!=='rubika'||record.userId!==state.userId||!id(record.userId)||
  typeof record.auth!=='string'||!/^[A-Za-z0-9]{32}$/.test(record.auth)||typeof record.privateKey!=='string'||record.privateKey.length>16384||typeof record.publicKey!=='string'||record.publicKey.length>8192)fail('invalid_account_binding');
 let mode;try{mode=profiles.fromRecord(record);}catch{fail('invalid_account_binding');}
 return {provider:'rubika',userId:record.userId,auth:record.auth,privateKey:record.privateKey,publicKey:record.publicKey,...mode===profiles.ANDROID?{profile:{protocolProfile:mode}}:{}};
}
const binding=record=>crypto.createHash('sha256').update(JSON.stringify([record.userId,record.auth,record.privateKey,record.publicKey,profiles.fromRecord(record)])).digest('hex');
async function readCallHistory(account,{language='fa',createClient=options=>new HttpClient(options)}={}){
 if(!account||typeof createClient!=='function'||!['fa','en'].includes(language))fail('invalid_history_options');
 const record=context(account),fingerprint=binding(record),guard=()=>{if(binding(context(account))!==fingerprint)fail('account_binding_changed');};let client;
 try{
  const privateKey=crypto.createPrivateKey(record.privateKey),publicKey=crypto.createPublicKey(record.publicKey);
  if(privateKey.asymmetricKeyType!=='rsa'||publicKey.asymmetricKeyType!=='rsa'||privateKey.asymmetricKeyDetails.modulusLength<2048||publicKey.asymmetricKeyDetails.modulusLength<2048||
   !crypto.createPublicKey(privateKey).export({type:'spki',format:'der'}).equals(publicKey.export({type:'spki',format:'der'})))fail('invalid_account_binding');
  client=createClient({language,protocolProfile:profiles.fromRecord(record),updatesFactory:null});guard();await client.discover();guard();
  const reply=await client.request('getCalls',{filter_type:'All',sort:'FromMax'},{credentials:record});guard();return decodeCallHistory(reply);
 }catch(error){
  if(error instanceof CallHistoryError)throw error;
  const safe=['not_authorized','access_denied','registration_required','rate_limited','timeout','network_error','http_error','invalid_response','invalid_encrypted_response','response_too_large','tls_verification_disabled'];
  fail(error instanceof ApiError&&safe.includes(error.reason)?error.reason:'history_read_failed');
 }finally{try{client?.close();}catch{}record.auth='';record.privateKey='';record.publicKey='';}
}
module.exports={readCallHistory,decodeCallHistory,findCallHistoryCandidates,CallHistoryError};
