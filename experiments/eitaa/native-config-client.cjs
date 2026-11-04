// Explicit fixed-HTTPS Android configuration read. No DC connection, metadata
// refresh, native TCP, login, persistence, or public diagnostic endpoint.
'use strict';
const crypto=require('node:crypto'),net=require('node:net');
const codec=require('./native-config-wire.cjs'),profiles=require('./client-profile.cjs');
const {Transport,ApiError}=require('./http-client.cjs'),{validProfile,serviceError}=require('./account-client.cjs');
const {apkEnvelope}=require('./android-envelope.cjs');
function checked(record){
 let mode;try{mode=profiles.fromRecord(record);}catch{throw new ApiError('invalid_credentials');}
 if(record?.provider!=='eitaa'||mode!==profiles.ANDROID||!profiles.validImei(record.imei,mode)||!validProfile(record.profile)||typeof record.token!=='string'||!record.token||Buffer.byteLength(record.token)>4096||/[\x00-\x1f\x7f]/.test(record.token)||typeof record.userId!=='string'||!/^[1-9]\d{0,9}$/.test(record.userId)||BigInt(record.userId)>2147483647n)throw new ApiError('invalid_credentials');
 return {provider:'eitaa',userId:record.userId,token:record.token,imei:record.imei,profile:{deviceModel:record.profile.deviceModel,systemVersion:record.profile.systemVersion,protocolProfile:mode}};
}
function appInfo(record,language){
 const r=checked(record);if(!['fa','en'].includes(language))throw new ApiError('invalid_request');
 // APK getAppInfo falls back to these literals when package version/signature
 // is unavailable. Use actual retained desktop identity, never a handset or
 // the official application's signing certificate.
 const model=r.profile.deviceModel==='BaleVPN Provider Lab (desktop)'?'Desktop '+crypto.createHash('sha256').update(r.imei).digest('hex').slice(0,12):r.profile.deviceModel;
 return {_:'eitaaAppInfo',build_version:2637,device_model:model,system_version:r.profile.systemVersion,app_version:'App version unknown',lang_code:language,sign:'unknown'};
}
function validateConfig(value){
 // The service uses zero for an unspecified current DC and also returns DNS
 // names in ip_address. These are inert data, not permission to resolve/follow.
 const address=v=>typeof v==='string'&&v.length<=253&&(net.isIP(v)||v.split('.').length>=2&&v.split('.').every(label=>/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label)));
 if(value?._!=='androidConfig'||!Number.isInteger(value.date)||value.date<0||!Number.isInteger(value.expires)||value.expires<0||!Number.isInteger(value.this_dc)||value.this_dc<0||value.this_dc>65535||!Array.isArray(value.dc_options)||!value.dc_options.length||value.dc_options.length>64)throw new ApiError('invalid_config_response');
 for(const dc of value.dc_options)if(dc?._!=='dcOption'||!Number.isInteger(dc.id)||dc.id<1||dc.id>65535||!address(dc.ip_address)||!Number.isInteger(dc.port)||dc.port<1||dc.port>65535||dc.secret!==undefined&&(!(dc.secret instanceof Uint8Array)||dc.secret.length>256))throw new ApiError('invalid_config_response');
 return value;
}
const fingerprint=record=>crypto.createHash('sha256').update(JSON.stringify(checked(record))).digest('hex');
class NativeConfigClient{
 #source;#record;#identity;#transport;#language;
 constructor({record,language='fa',fetchImpl=globalThis.fetch}={}){this.#record=checked(record);this.#identity=fingerprint(this.#record);this.#source=record;if(!['fa','en'].includes(language)||typeof fetchImpl!=='function')throw new ApiError('invalid_request');this.#language=language;this.#transport=new Transport({protocolProfile:profiles.ANDROID,fetchImpl});}
 async getConfig(options={}){
  if(!options||typeof options!=='object'||Array.isArray(options)||![Object.prototype,null].includes(Object.getPrototypeOf(options))||Object.keys(options).some(k=>k!=='timeout'))throw new ApiError('invalid_request');
  this.#transport.assertOpen();this.#guard();const packed=codec.method('help.getConfig',{app_info:appInfo(this.#record,this.#language),user_id:Number(this.#record.userId)}),body=apkEnvelope(packed,{record:this.#record,language:this.#language});let frame;
  try{frame=await this.#transport.post(body,options);this.#guard();let result=codec.response(frame,'help.getConfig');if(result?._==='rpc_result')result=result.result;if(['error','eitta_error'].includes(result?._))throw serviceError(result);if(['eitaa_updates_expire_token','eitaa_token_updating'].includes(result?._))throw new ApiError('session_refresh_required');return validateConfig(result);}
  finally{packed.fill(0);body.fill(0);frame?.fill(0);}
 }
 #guard(){try{if(fingerprint(this.#source)!==this.#identity)throw Error();}catch{throw new ApiError('account_binding_changed');}}
 close(){this.#transport.close();this.#record.token='';this.#source=null;}
}
module.exports={NativeConfigClient,appInfo,validateConfig};
