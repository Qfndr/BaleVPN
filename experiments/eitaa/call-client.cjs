// Private authenticated call RPCs. No automatic dial, polling, retry or token
// refresh. The future call controller owns account epochs and call binding.
'use strict';
const crypto=require('node:crypto'),wire=require('./wire.cjs'),codec=require('./call-wire.cjs');
const {Transport,ApiError}=require('./http-client.cjs');
const {serviceError}=require('./account-client.cjs');
const FIELDS={
 'messages.getDhConfig':[],'phone.getCallConfig':[],'updates.getState':[],
 'phone.requestCall':['user_id','g_a_hash'],
 'phone.acceptCall':['peer','g_b'],'phone.confirmCall':['peer','g_a','key_fingerprint'],
 'phone.receivedCall':['peer'],'phone.discardCall':['peer','duration','reason'],
 'phone.sendSignalingData':['peer','data'],'updates.getDifference':['pts','date','qts'],
 'contacts.getContacts':[],'contacts.resolveUsername':['username']
};
const plain=v=>v&&typeof v==='object'&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v));
const long=v=>typeof v==='bigint'&&v>=-(2n**63n)&&v<2n**63n;
const positive=v=>long(v)&&v>0n;
const int=v=>Number.isInteger(v)&&v>=0&&v<=0x7fffffff;
const bytes=(v,min,max=min)=>v instanceof Uint8Array&&v.length>=min&&v.length<=max;
const text=v=>typeof v==='string'&&v.length>0&&Buffer.byteLength(v)<=4096&&!/[\0\r\n]/.test(v);
const REASONS=new Set(['phoneCallDiscardReasonMissed','phoneCallDiscardReasonDisconnect','phoneCallDiscardReasonHangup','phoneCallDiscardReasonBusy']);
function protocol(){return {_:'phoneCallProtocol',udp_reflector:true,min_layer:92,max_layer:92,library_versions:['4.0.0']};}
function shape(v,name,idField){return plain(v)&&Object.keys(v).every(k=>['_',idField,'access_hash'].includes(k))&&v._===name&&positive(v[idField])&&long(v.access_hash)&&v.access_hash!==0n;}
function input(name,value){
 const fields=Object.hasOwn(FIELDS,name)&&FIELDS[name];if(!fields||!plain(value)||Object.keys(value).some(k=>!fields.includes(k)))throw new ApiError('invalid_request');
 if(fields.includes('peer')&&!shape(value.peer,'inputPhoneCall','id'))throw new ApiError('invalid_call_peer');
 if(name==='phone.requestCall'){
  if(!shape(value.user_id,'inputUser','user_id')||!bytes(value.g_a_hash,32))throw new ApiError('invalid_request');
  return {...value,random_id:crypto.randomBytes(4).readInt32LE(),protocol:protocol()};
 }
 if(name==='messages.getDhConfig')return {version:0,random_length:256};
 if(name==='contacts.getContacts')return {hash:0n};
 if(name==='contacts.resolveUsername'&&(typeof value.username!=='string'||!/^[A-Za-z][A-Za-z0-9_]{2,31}$/.test(value.username)))throw new ApiError('invalid_request');
 if(name==='phone.acceptCall'){if(!bytes(value.g_b,256))throw new ApiError('invalid_request');return {...value,protocol:protocol()};}
 if(name==='phone.confirmCall'){if(!bytes(value.g_a,256)||!long(value.key_fingerprint))throw new ApiError('invalid_request');return {...value,protocol:protocol()};}
 if(name==='phone.discardCall'){
  if(!int(value.duration)||value.duration>7*24*3600||!REASONS.has(value.reason))throw new ApiError('invalid_request');
  return {...value,reason:{_:value.reason},connection_id:0n};
 }
 if(name==='phone.sendSignalingData'&&!bytes(value.data,21,48*1024+20))throw new ApiError('invalid_request');
 if(name==='updates.getDifference'){
  if(!int(value.pts)||!int(value.date)||!(int(value.qts)||value.qts===-1))throw new ApiError('invalid_request');
  return {...value,pts_total_limit:256};
 }
 return value;
}
class CallClient{
 #transport;#imei;#token;
 constructor({imei,token,provider='eitaa',...options}={}){
  if(provider!=='eitaa'||typeof imei!=='string'||!/^[a-z0-9]{15}__web$/.test(imei)||!text(token))throw new ApiError('invalid_credentials');
  this.#transport=new Transport(options);this.#imei=imei;this.#token=token;
 }
 async request(name,value={},options={}){
  this.#transport.assertOpen();const packed=codec.method(name,input(name,value));
  const body=wire.envelope(packed,{imei:this.#imei,token:this.#token});
  let result=codec.response(await this.#transport.post(body,options),name);this.#transport.assertOpen();
  if(result?._==='rpc_result')result=result.result;
  if(['error','eitta_error'].includes(result?._))throw serviceError(result);
  if(['eitaa_updates_expire_token','eitaa_token_updating'].includes(result?._))throw new ApiError('session_refresh_required');
  if(result?._==='pong')throw new ApiError('unexpected_acknowledgement');
  return result;
 }
 close(){this.#transport.close();this.#token='';this.#imei='';}
}
module.exports={CallClient,protocol};
