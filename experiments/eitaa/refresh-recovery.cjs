'use strict';
const crypto=require('node:crypto');
const {MAX}=require('./wire.cjs');
const profiles=require('./client-profile.cjs');
const FORMAT='eitaa-refresh-recovery-v1';
const operationFields=['provider','format','method','createdAt','accountBinding','sourceTokenSha256','requestId'];
const fields=[...operationFields,'phase','frame'];
const digest=value=>crypto.createHash('sha256').update(value).digest('hex');

function accountBinding(record){
 if(record?.provider!=='eitaa'||typeof record.userId!=='string'||!/^[1-9]\d{0,18}$/.test(record.userId)||BigInt(record.userId)>=2n**63n){
  throw Error('invalid_refresh_recovery');
 }
 const mode=profiles.fromRecord(record);
 if(!profiles.validImei(record.imei,mode))throw Error('invalid_refresh_recovery');
 return digest(JSON.stringify([record.provider,record.userId,record.imei,mode,record.profile?.deviceModel,record.profile?.systemVersion]));
}

function valid(value,record){
 if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).length!==fields.length||Object.keys(value).some(key=>!fields.includes(key)))return false;
 if(value.provider!=='eitaa'||value.format!==FORMAT||value.method!=='eitaaRefreshToken'||!Number.isSafeInteger(value.createdAt)||value.createdAt<0)return false;
 if(typeof value.accountBinding!=='string'||typeof value.sourceTokenSha256!=='string'||!/^[a-f0-9]{64}$/.test(value.accountBinding)||!/^[a-f0-9]{64}$/.test(value.sourceTokenSha256))return false;
 if(value.phase==='requested'){
  if(value.frame!==null)return false;
 }else if(value.phase==='response'){
 if(typeof value.frame!=='string'||!value.frame||value.frame.length>4*Math.ceil(MAX/3)||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value.frame))return false;
 const bytes=Buffer.from(value.frame,'base64');
 try{
  if(!bytes.length||bytes.length>MAX||bytes.toString('base64')!==value.frame)return false;
 }finally{bytes.fill(0);}
 }else return false;
 if(typeof value.requestId!=='string'||!/^[a-f0-9]{32}$/.test(value.requestId))return false;
 try{return !record||value.accountBinding===accountBinding(record);}catch{return false;}
}

function createIntent(record){
 if(typeof record?.token!=='string'||!record.token)throw Error('invalid_refresh_recovery');
 const value={provider:'eitaa',format:FORMAT,method:'eitaaRefreshToken',createdAt:Date.now(),
  accountBinding:accountBinding(record),sourceTokenSha256:digest(record.token),requestId:crypto.randomBytes(16).toString('hex'),phase:'requested',frame:null};
 if(!valid(value,record))throw Error('invalid_refresh_recovery');
 return value;
}
function create(frame,record,intent=createIntent(record)){
 if(!(frame instanceof Uint8Array)||!frame.length||frame.length>MAX||!valid(intent,record)||intent.phase!=='requested'||intent.sourceTokenSha256!==digest(record.token))throw Error('invalid_refresh_recovery');
 return {...intent,phase:'response',frame:Buffer.from(frame).toString('base64')};
}
function same(a,b){return valid(a)&&valid(b)&&fields.every(key=>a[key]===b[key]);}
function canAdvance(a,b){return valid(a)&&valid(b)&&a.phase==='requested'&&b.phase==='response'&&operationFields.every(key=>a[key]===b[key]);}
module.exports={FORMAT,createIntent,create,valid,same,canAdvance,tokenHash:digest};
