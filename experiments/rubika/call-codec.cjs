// Private experimental RPC boundary, derived from Android 4.1.1 call models.
// This does not implement its native media protocol or assert Web API support.
const METHODS=Object.freeze(['requestCall','receivedCall','acceptCall','discardCall','sendSignalingData','getSignalingData','callStarted']);
const VERSIONS=Object.freeze(['2.4.4','2.7.7','5.0.0','6.0.0','7.0.0','8.0.0','9.0.0']);
// Local memory bounds, not advertised provider limits.
const MAX_SIGNAL=48*1024,MAX_BATCH=256;
class CallCodecError extends Error{constructor(){super('Invalid Rubika call payload');}}
function fail(){throw new CallCodecError();}
function id(value){return typeof value==='string'&&/^[A-Za-z0-9_-]{8,128}$/.test(value);}
function exact(value,fields){return value&&typeof value==='object'&&!Array.isArray(value)&&
 Object.keys(value).length===fields.length&&fields.every(k=>Object.hasOwn(value,k));}
function profile(v){return Number.isInteger(v.min_layer)&&v.min_layer>=1&&Number.isInteger(v.max_layer)&&
 v.max_layer>=v.min_layer&&v.max_layer<=1000&&Array.isArray(v.library_versions)&&v.library_versions.length>=1&&
 v.library_versions.length<=VERSIONS.length&&new Set(v.library_versions).size===v.library_versions.length&&v.library_versions.every(s=>VERSIONS.includes(s));}
function decodeSignal(value){
 if(typeof value!=='string'||value.length>MAX_SIGNAL*2||/[^A-Za-z0-9+/=\r\n\t ]/.test(value))fail();
 const compact=value.replace(/[\r\n\t ]/g,'');
 if(!compact||compact.length>Math.ceil(MAX_SIGNAL/3)*4||compact.length%4||! /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(compact))fail();
 const bytes=Buffer.from(compact,'base64');
 if(bytes.length>MAX_SIGNAL||bytes.toString('base64')!==compact){bytes.fill(0);fail();}return bytes;
}
function encodeSignal(bytes){if(!Buffer.isBuffer(bytes)||!bytes.length||bytes.length>MAX_SIGNAL)fail();return bytes.toString('base64');}
function validateInput(method,v){
 const layers=['min_layer','max_layer','library_versions'];let valid=false;
 if(method==='requestCall')valid=exact(v,['call_type','user_guid',...layers])&&v.call_type==='Voice'&&id(v.user_guid)&&profile(v);
 else if(method==='acceptCall')valid=exact(v,['call_id',...layers])&&id(v.call_id)&&profile(v);
 else if(['receivedCall','getSignalingData','callStarted'].includes(method))valid=exact(v,['call_id'])&&id(v.call_id);
 else if(method==='discardCall')valid=exact(v,['call_id','duration','reason'])&&id(v.call_id)&&Number.isInteger(v.duration)&&v.duration>=0&&v.duration<=2147483647&&['Missed','Disconnect','Hangup','Busy'].includes(v.reason);
 else if(method==='sendSignalingData'){
  valid=exact(v,['call_id','data'])&&id(v.call_id);
  if(valid){const bytes=decodeSignal(v.data);const canonical=bytes.toString('base64')===v.data;bytes.fill(0);valid=canonical;}
 }
 if(!valid)fail();return v;
}
function decodeSignalBatch(value){
 if(!exact(value,['data_list'])||!Array.isArray(value.data_list)||value.data_list.length>MAX_BATCH)fail();
 const result=[];let total=0;
 try{for(const item of value.data_list){const bytes=decodeSignal(item);result.push(bytes);total+=bytes.length;if(total>MAX_SIGNAL)fail();}return result;}
 catch(error){for(const bytes of result)bytes.fill(0);throw error;}
}
module.exports={METHODS,VERSIONS,MAX_SIGNAL,MAX_BATCH,CallCodecError,validateInput,encodeSignal,decodeSignal,decodeSignalBatch};
