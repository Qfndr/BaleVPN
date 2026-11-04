// Private typed projections of Android call models. Never expose these to HTTP
// state/logs: accepted-call keys and TURN credentials are sensitive service data.
'use strict';
const net=require('node:net'),codec=require('./call-codec.cjs');
class UpdateError extends Error{constructor(reason='invalid_call_response',schemaDiagnostic){super('Rubika call '+reason);this.reason=reason;if(schemaDiagnostic)this.schemaDiagnostic=Object.freeze(schemaDiagnostic);}}
const fail=reason=>{throw new UpdateError(reason);};
function fieldFail(field,value){
 const kind=value===undefined?'missing':value===null?'null':Array.isArray(value)?'array':['string','number','boolean','object'].includes(typeof value)?typeof value:'other';
 const detail={field,kind};
 if(kind==='string')detail.length=Math.min(Buffer.byteLength(value),16385);
 if(kind==='array')detail.count=Math.min(value.length,65536);
 if(kind==='number')detail.integer=Number.isInteger(value);
 throw new UpdateError('invalid_call_response',detail);
}
const plain=v=>v&&typeof v==='object'&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v));
const id=v=>typeof v==='string'&&/^[A-Za-z0-9_-]{8,128}$/.test(v);
const uint=v=>Number.isInteger(v)&&v>=0&&v<=0x7fffffff;
const text=(v,max)=>typeof v==='string'&&v.length>0&&Buffer.byteLength(v)<=max&&!/[\x00-\x1f\x7f]/.test(v);
const STATES=['Requested','Waiting','Accepted','Discarded'];
const FIELDS=['call_id','call_type','state','key','protocol_layer','library_versions','other_participants','connections',
 'duration','receive_time','timestamp','discard_reason','p2p_allowed','report_rating'];
const DIAGNOSTIC_FIELDS=new Set(['response','call','connection','call_update',
 ...FIELDS.map(name=>'call.'+name),
 ...['call_id','action','timestamp','object_guid','type','updated_parameters'].map(name=>'call_update.'+name),
 ...['type','port','ip','ipv6','turn_username','turn_password','peer_tag','id','constructor'].map(name=>'connection.'+name)]);
function schemaDiagnostic(value){
 try{
  if(!plain(value)||!DIAGNOSTIC_FIELDS.has(value.field)||!['missing','null','array','object','string','number','boolean','other'].includes(value.kind))return undefined;
  const out={field:value.field,kind:value.kind};
  if(value.kind==='string'&&Number.isInteger(value.length)&&value.length>=0&&value.length<=16385)out.length=value.length;
  if(value.kind==='array'&&Number.isInteger(value.count)&&value.count>=0&&value.count<=65536)out.count=value.count;
  if(value.kind==='number'&&typeof value.integer==='boolean')out.integer=value.integer;
  return Object.freeze(out);
 }catch{return undefined;}
}
function versions(v){return Array.isArray(v)&&v.length<=16&&v.every(s=>typeof s==='string'&&/^\d{1,3}(?:\.\d{1,3}){1,3}$/.test(s))&&new Set(v).size===v.length;}
function connection(v){
 if(!plain(v))fieldFail('connection',v);
 if(!['Tg','WebRTC'].includes(v.type))fieldFail('connection.type',v.type);
 if(!Number.isInteger(v.port)||v.port<1||v.port>65535)fieldFail('connection.port',v.port);
 const result={type:v.type,port:v.port};
 for(const [name,family]of [['ip',4],['ipv6',6]])if(Object.hasOwn(v,name)&&v[name]!==null&&v[name]!==''){
  if(typeof v[name]!=='string'||v[name].length>64||net.isIP(v[name])!==family||v[name].includes('%'))fieldFail('connection.'+name,v[name]);result[name]=v[name];
 }
 if(!result.ip&&!result.ipv6)fieldFail('connection.ip',v.ip);
 for(const name of ['turn_username','turn_password','peer_tag'])if(v[name]!==null&&v[name]!==undefined){if(!text(v[name],1024))fieldFail('connection.'+name,v[name]);result[name]=v[name];}
 // ID is a Java long in the APK. Preserve exact decimal representation rather
 // than silently rounding an unsafe JSON number. It is not a socket address.
 if(Object.hasOwn(v,'id')){
  const value=v.id;if(!(Number.isSafeInteger(value)||typeof value==='string'&&/^-?\d{1,20}$/.test(value)))fieldFail('connection.id',value);
  const n=BigInt(value);if(n<-(2n**63n)||n>=2n**63n)fieldFail('connection.id',value);result.id=String(n);
 }
 if(Object.hasOwn(v,'constructor')){if(!Number.isInteger(v.constructor)||v.constructor<-(2**31)||v.constructor>0x7fffffff)fieldFail('connection.constructor',v.constructor);result.constructor=v.constructor;}
 return result;
}
function phoneCall(value,{partial=false}={}){
 if(!plain(value))fieldFail('call',value);const result={};
 for(const name of FIELDS){
  if(!Object.hasOwn(value,name)||value[name]===null)continue;const v=value[name];let valid=true,out=v;
  if(name==='call_id')valid=id(v);
  else if(name==='call_type')valid=['Voice','Video','CallOut'].includes(v);
  else if(name==='state')valid=STATES.includes(v);
  else if(name==='key')valid=text(v,8192);
  else if(name==='protocol_layer')valid=Number.isInteger(v)&&v>=1&&v<=1000;
  else if(name==='library_versions'){valid=versions(v);if(valid)out=[...v];}
  else if(name==='other_participants'){
   valid=Array.isArray(v)&&v.length<=2;
   if(valid)out=v.map(p=>{if(!plain(p)||!id(p.object_guid)||p.type!=='User')fieldFail('call.other_participants',v);return {object_guid:p.object_guid,type:'User'};});
   if(valid&&new Set(out.map(p=>p.object_guid)).size!==out.length)valid=false;
  }else if(name==='connections'){valid=Array.isArray(v)&&v.length<=16;if(valid)out=v.map(connection);}
  else if(['p2p_allowed','report_rating'].includes(name))valid=typeof v==='boolean';
  else if(name==='discard_reason')valid=['Missed','Disconnect','Hangup','Busy'].includes(v);
  else valid=uint(v);
  if(!valid)fieldFail('call.'+name,v);result[name]=out;
 }
 if(!partial){if(!id(result.call_id))fieldFail('call.call_id',result.call_id);if(!['Voice','Video','CallOut'].includes(result.call_type))fieldFail('call.call_type',result.call_type);if(!STATES.includes(result.state))fieldFail('call.state',result.state);}return result;
}
function callUpdate(value,{callId}={}){
 if(!plain(value))fieldFail('call_update',value);
 if(!id(value.call_id))fieldFail('call_update.call_id',value.call_id);
 if(!['New','Edit','Delete'].includes(value.action))fieldFail('call_update.action',value.action);
 if(!uint(value.timestamp))fieldFail('call_update.timestamp',value.timestamp);
 if(callId!==undefined&&value.call_id!==callId)fail('call_identity_mismatch');
 const result={call_id:value.call_id,action:value.action,timestamp:value.timestamp};
 for(const name of ['object_guid','type'])if(Object.hasOwn(value,name)&&value[name]!==null){if(name==='object_guid'?!id(value[name]):value[name]!=='User')fieldFail('call_update.'+name,value[name]);result[name]=value[name];}
 if(value.action==='New'&&!result.object_guid)fieldFail('call_update.object_guid',value.object_guid);
 if(value.action==='New'&&result.type!=='User')fieldFail('call_update.type',value.type);
 if(value.action!=='Delete'||value.call!==undefined&&value.call!==null){
  result.call=phoneCall(value.call,{partial:value.action!=='New'});
  if(result.call.call_id!==undefined&&result.call.call_id!==result.call_id)fail('call_identity_mismatch');
 }
 if(value.updated_parameters!==undefined&&value.updated_parameters!==null){
  if(!Array.isArray(value.updated_parameters)||value.updated_parameters.length>32||value.updated_parameters.some(s=>typeof s!=='string'||! /^[A-Za-z_]{1,64}$/.test(s))||new Set(value.updated_parameters).size!==value.updated_parameters.length)fieldFail('call_update.updated_parameters',value.updated_parameters);
  result.updated_parameters=[...value.updated_parameters];
 }
 return result;
}
function updates(value,selfId){
 if(!id(selfId)||!plain(value)||!plain(value.update_data))fail();const data=value.update_data;
 // Local fail-closed account policy; presence in every live server response is
 // unverified. A missing identity is not silently replaced with our own ID.
 if(data.user_guid!==selfId)fail('update_account_mismatch');
 const calls=data.call_updates??[],signals=data.call_signal_data??[];
 if(!Array.isArray(calls)||calls.length>64||!Array.isArray(signals)||signals.length>codec.MAX_BATCH)fail();
 const result={user_guid:selfId,call_updates:calls.map(v=>callUpdate(v)),call_signal_data:[]};let total=0;
 try{
  for(const item of signals){
   if(!plain(item)||!id(item.call_id))fail();let bytes;
   try{bytes=codec.decodeSignal(item.data);}catch{fail();}
   result.call_signal_data.push({call_id:item.call_id,data:bytes});total+=bytes.length;if(total>codec.MAX_SIGNAL)fail();
  }
  return result;
 }catch(error){for(const item of result.call_signal_data)item.data.fill(0);throw error;}
}
function response(method,value,{selfId,callId}={}){
 if(!plain(value))fieldFail('response',value);
 if(method==='getUpdate')return updates(value,selfId);
 if(method!=='requestCall'&&!id(callId))fail('call_identity_mismatch');
 if(method==='getSignalingData'){try{return {call_id:callId,data_list:codec.decodeSignalBatch(value)};}catch{fail();}}
 if(['sendSignalingData','callStarted'].includes(method)){if(Object.keys(value).length)fail();return {};}
 if(!['requestCall','receivedCall','acceptCall','discardCall'].includes(method))fail();
 if(method==='requestCall'&&value.call_type!=='WebRtc')fail('unsupported_call_protocol');
 const result={call_update:callUpdate(value.call_update,{callId})};
 if(method==='requestCall')result.call_type='WebRtc';return result;
}
module.exports={UpdateError,response,callUpdate,phoneCall,updates,schemaDiagnostic};
