// Private typed HTTPS response retention only. This module opens no socket and
// grants no permission to transmit these credentials over an unverified route.
'use strict';
const crypto=require('node:crypto'),profiles=require('./client-profile.cjs');
const KEYS=['format','sourceConstructor','protocolProfile','userId','imei','httpTokenSha256','token','date','expire','messageId'];
const text=v=>typeof v==='string'&&v.length>0&&Buffer.byteLength(v)<=4096&&!/[\x00-\x1f\x7f]/.test(v);
const digest=v=>crypto.createHash('sha256').update(v).digest('hex');
function bound(record){try{return record?.provider==='eitaa'&&profiles.fromRecord(record)===profiles.ANDROID&&profiles.validImei(record.imei,profiles.ANDROID)&&typeof record.userId==='string'&&/^[1-9]\d{0,18}$/.test(record.userId)&&BigInt(record.userId)<2n**63n&&text(record.token);}catch{return false;}}
function valid(value,record){
 return bound(record)&&!!value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).length===KEYS.length&&Object.keys(value).every(k=>KEYS.includes(k))&&
  value.format==='eitaa-native-socket-credential-v1'&&value.sourceConstructor===-1519642063&&value.protocolProfile===profiles.ANDROID&&value.userId===record.userId&&value.imei===record.imei&&value.httpTokenSha256===digest(record.token)&&text(value.token)&&
  Number.isInteger(value.date)&&value.date>=0&&value.date<=0x7fffffff&&Number.isInteger(value.expire)&&value.expire>=0&&value.expire<=0x7fffffff&&typeof value.messageId==='string'&&/^-?(0|[1-9]\d{0,18})$/.test(value.messageId)&&BigInt(value.messageId)>=-(2n**63n)&&BigInt(value.messageId)<2n**63n;
}
function fromResponse(response,record){
 if(response?._!=='eitaa_updates_token'||!text(response.socket_token)||typeof response.msg_id!=='bigint')return null;
 const value={format:'eitaa-native-socket-credential-v1',sourceConstructor:-1519642063,protocolProfile:profiles.ANDROID,userId:record?.userId,imei:record?.imei,httpTokenSha256:typeof record?.token==='string'?digest(record.token):'',token:response.socket_token,date:response.date,expire:response.expire,messageId:String(response.msg_id)};
 return valid(value,record)?value:null;
}
module.exports={valid,fromResponse};
