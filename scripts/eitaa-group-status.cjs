// Private existing-group diagnostic. No CLI, production route, default fetch,
// chat listing, session restore, OTP, or create/join/leave/discard operation.
'use strict';
const {types}=require('node:util');
const {groupStatusSchema}=require('./extract-eitaa-schema.cjs');
const {Transport,ApiError,ENDPOINTS}=require('../experiments/eitaa/http-client.cjs');
const {createCodec}=require('../experiments/eitaa/tl-codec.cjs');
const profiles=require('../experiments/eitaa/client-profile.cjs'),wire=require('../experiments/eitaa/wire.cjs');
const SERVER='https://hasan.eitaa.ir/eitaa/',running=new WeakSet();
const SAFE_SERVICE_CODES=new Set(['INVALID_CONSTRUCTOR','GROUPCALL_INVALID','CHANNEL_PRIVATE','CHAT_ID_INVALID']);
const SAFE_TRANSPORT_ERRORS=new Set(['closed','account_busy','timeout','tls_verification_disabled','rate_limited','http_error','network_error','response_too_large']);
class GroupStatusError extends Error{
 constructor(reason,stage,{statusCode,serviceCode}={}){
  super('Eitaa group status '+reason);this.reason=reason;this.stage=stage;
  if(Number.isInteger(statusCode)&&statusCode>=100&&statusCode<=599)this.statusCode=statusCode;
  if(SAFE_SERVICE_CODES.has(serviceCode))this.serviceCode=serviceCode;
 }
}
const long=value=>typeof value==='bigint'&&value>=-(2n**63n)&&value<2n**63n;
const id=value=>long(value)&&value>0n;
function selection(value){
 if(!value||typeof value!=='object'||types.isProxy(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))throw new GroupStatusError('invalid_selection','validate');
 const descriptors=Object.getOwnPropertyDescriptors(value),keys=Reflect.ownKeys(descriptors);
 if(keys.some(key=>!Object.hasOwn(descriptors[key],'value')))throw new GroupStatusError('invalid_selection','validate');
 const {consent,kind,id:groupId,accessHash}=value;
 const expected=kind==='chat'?['consent','kind','id']:['consent','kind','id','accessHash'];
 if(consent!==true||!['chat','channel'].includes(kind)||!id(groupId)||keys.length!==expected.length||keys.some(key=>!expected.includes(key))||
  kind==='channel'&&(!long(accessHash)||accessHash===0n))throw new GroupStatusError('invalid_selection','validate');
 return kind==='chat'?{method:'messages.getFullChat',input:{chat_id:groupId},fullKind:'chatFull',id:groupId}:
  {method:'channels.getFullChannel',input:{channel:{_:'inputChannel',channel_id:groupId,access_hash:accessHash}},fullKind:'channelFull',id:groupId};
}
function snapshot(session){
 const state=session?.state;
 if(!state||state.provider!=='eitaa'||state.signedIn!==true||state.selfConfirmed!==true||state.busy!==false||state.protocolProfile!==profiles.WEB||
  state.hasRecovery||state.hasRefreshRecovery||typeof session.exportSession!=='function')throw new GroupStatusError('verified_web_session_required','validate');
 const record=session.exportSession();
 if(record?.provider!=='eitaa'||profiles.fromRecord(record)!==profiles.WEB||record.userId!==state.userId||
  typeof record.userId!=='string'||!/^[1-9]\d{0,18}$/.test(record.userId)||!id(BigInt(record.userId))||!profiles.validImei(record.imei)||
  typeof record.token!=='string'||!record.token||Buffer.byteLength(record.token)>4096||/[\0\r\n]/.test(record.token))throw new GroupStatusError('verified_web_session_required','validate');
 return {userId:record.userId,imei:record.imei,token:record.token};
}
async function readGroupStatus(session,selected,options={}){
 const target=selection(selected);
 if(!options||typeof options!=='object'||types.isProxy(options)||![Object.prototype,null].includes(Object.getPrototypeOf(options))||
  Reflect.ownKeys(options).some(key=>!['workerSource','fetchImpl','timeout'].includes(key)||!Object.hasOwn(Object.getOwnPropertyDescriptor(options,key),'value')))
  throw new GroupStatusError('invalid_options','validate');
 const {workerSource,fetchImpl,timeout=10000}=options;
 if(typeof fetchImpl!=='function'||!Number.isInteger(timeout)||timeout<1||timeout>15000)throw new GroupStatusError('invalid_options','validate');
 let account;try{account=snapshot(session);}catch{throw new GroupStatusError('verified_web_session_required','validate');}
 if(running.has(session))throw new GroupStatusError('account_busy','validate');
 let codec;try{if(ENDPOINTS[0]!==SERVER)throw Error();codec=createCodec(groupStatusSchema(workerSource));}catch{throw new GroupStatusError('invalid_source','validate');}
 const transport=new Transport({protocolProfile:profiles.WEB,server:SERVER,fetchImpl}),deadline=performance.now()+timeout;
 let stage='metadata';running.add(session);
 const guard=()=>{
  let now;try{now=snapshot(session);}catch{throw new GroupStatusError('account_binding_changed',stage);}
  if(Object.keys(account).some(key=>account[key]!==now[key]))throw new GroupStatusError('account_binding_changed',stage);
 };
 async function request(method,input){
  guard();const remaining=Math.ceil(deadline-performance.now());if(remaining<1)throw new GroupStatusError('timeout',stage);
  let packed,body,raw;
  try{
   packed=codec.method(method,input);body=wire.envelope(packed,{token:account.token,imei:account.imei});
   raw=await transport.post(body,{timeout:remaining});guard();
   let result=codec.response(raw,method);if(result?._==='rpc_result')result=result.result;
   if(['error','eitta_error'].includes(result?._))throw new GroupStatusError('service_rejected',stage,{serviceCode:result.text});
   if(['eitaa_updates_expire_token','eitaa_token_updating'].includes(result?._))throw new GroupStatusError('session_refresh_required',stage);
   return result;
  }finally{packed?.fill(0);body?.fill(0);raw?.fill(0);}
 }
 try{
  const result=await request(target.method,target.input),full=result?.full_chat;
  if(result?._!=='messages.chatFull'||full?._!==target.fullKind||full.id!==target.id)throw new GroupStatusError('group_binding_changed',stage);
  if(full.call===undefined)return {referencePresent:false,groupReadSucceeded:false,groupState:'absent'};
  const reference=full.call;
  if(reference?._!=='inputGroupCall'||!id(reference.id)||!long(reference.access_hash)||reference.access_hash===0n)throw new GroupStatusError('invalid_call_reference',stage);
  stage='group';const group=await request('phone.getGroupCall',{call:reference,limit:0});
  const call=group?.call;
  if(group?._!=='phone.groupCall'||!['groupCall','groupCallDiscarded'].includes(call?._)||call.id!==reference.id||call.access_hash!==reference.access_hash)
   throw new GroupStatusError('call_binding_changed',stage);
  return {referencePresent:true,groupReadSucceeded:true,groupState:call._==='groupCallDiscarded'?'discarded':'available'};
 }catch(error){
  guard();if(error instanceof GroupStatusError)throw error;
  if(error instanceof ApiError&&SAFE_TRANSPORT_ERRORS.has(error.reason))throw new GroupStatusError(error.reason,stage,{statusCode:error.statusCode});
  throw new GroupStatusError('invalid_response',stage);
 }finally{running.delete(session);transport.close();account.token='';account.imei='';}
}
module.exports={readGroupStatus};
