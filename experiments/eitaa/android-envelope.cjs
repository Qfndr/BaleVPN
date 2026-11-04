// Exact pinned APK/socket TL wrappers; builders perform no network or storage.
'use strict';
const wire=require('./wire.cjs'),profiles=require('./client-profile.cjs');
const {ApiError}=require('./http-client.cjs');
const CONSTRUCTOR=2059302894,LAYER=138,BUILD=2637;
function credentials(record,{allowEmptyToken=false}={}){
 let valid=false,mode;try{mode=profiles.fromRecord(record);valid=profiles.validImei(record?.imei,mode);}catch{}
 if(record?.provider!=='eitaa'||typeof record.token!=='string'||!allowEmptyToken&&!record.token||Buffer.byteLength(record.token)>4096||/[\0\r\n]/.test(record.token)||!valid)throw new ApiError('invalid_credentials');return {token:record.token,imei:record.imei,...mode===profiles.ANDROID?{profile:{protocolProfile:mode}}:{}};
}
function payload(packed){if(!(packed instanceof Uint8Array)||!packed.length||packed.length%4||packed.length>wire.MAX-8192)throw new ApiError('invalid_request');}
function apkEnvelope(packed,{record,language='fa',wifi=false,mobileData=false,paused=false,background=false}={}){
 const {token,imei}=credentials(record,{allowEmptyToken:true});payload(packed);if(!['fa','en','ar'].includes(language)||[wifi,mobileData,paused,background].some(v=>typeof v!=='boolean'))throw new ApiError('invalid_request');
 const flags=(wifi?2:0)|(mobileData?4:0)|(paused?8:0)|(background?16:0)|(language==='en'?128:language==='ar'?64:32);
 return new wire.Writer().int(CONSTRUCTOR).string(token).string(imei,64).int(flags).bytes(packed).int(LAYER).int(BUILD).string(language).finish();
}
function socketEnvelope(packed,{record}={}){
 const {token,imei}=credentials(record);payload(packed);
 // Native Datacenter::createRequestsData sets object+112=2048,+128=136 and
 // uses writeByteArray for raw TL at +120. No APK build/language fields follow.
 return new wire.Writer().int(CONSTRUCTOR).string(token).string(imei,64).int(2048).bytes(packed).int(136).finish();
}
module.exports={apkEnvelope,socketEnvelope,credentials,CONSTRUCTOR,LAYER,BUILD};
