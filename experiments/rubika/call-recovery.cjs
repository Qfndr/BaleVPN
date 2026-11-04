// Private one-shot call intent / bounded response candidate. An empty response
// records an uncertain operation before I/O, not an established call or success.
// No filesystem or network.
'use strict';
const {types}=require('node:util');
const MAX_CALL_RECOVERY_BYTES=64*1024,CALL_RECOVERY_TTL_MS=24*60*60*1000;
class CallRecoveryError extends Error{constructor(reason){super('Rubika call recovery '+reason);this.reason=reason;}}
// Copy data before JSON serialization: never execute accessors/toJSON, accept
// cycles or arbitrary prototypes, or retain an unbounded private server tree.
function validateCallRecovery(input){
 let nodes=0,bytes=0;const active=new Set();
 function count(text){bytes+=Buffer.byteLength(text);if(bytes>MAX_CALL_RECOVERY_BYTES)throw new CallRecoveryError('record_too_large');}
 function copy(value,depth){
  if(++nodes>4096||depth>16)throw new CallRecoveryError('invalid_call_recovery');
  if(value===null||typeof value==='boolean')return value;
  if(typeof value==='string'){count(value);return value;}
  if(typeof value==='number'&&Number.isFinite(value))return value;
  if(typeof value!=='object'||types.isProxy(value)||active.has(value)||Object.getOwnPropertySymbols(value).length)throw new CallRecoveryError('invalid_call_recovery');
  const array=Array.isArray(value),proto=Object.getPrototypeOf(value);
  if(array?proto!==Array.prototype:proto!==Object.prototype&&proto!==null)throw new CallRecoveryError('invalid_call_recovery');
  active.add(value);const out=array?[]:Object.create(null),descriptors=Object.getOwnPropertyDescriptors(value),keys=Object.keys(descriptors);
  if(array&&(keys.length!==value.length+1||keys.some(key=>key!=='length'&&!/^(0|[1-9]\d*)$/.test(key))))throw new CallRecoveryError('invalid_call_recovery');
  for(const key of keys){
   if(array&&key==='length')continue;
   const item=descriptors[key];if(!item.enumerable||!Object.hasOwn(item,'value')||key==='__proto__'||key==='prototype')throw new CallRecoveryError('invalid_call_recovery');
   count(key);out[key]=copy(item.value,depth+1);
  }
  active.delete(value);return out;
 }
 const data=copy(input,0),keys=['provider','operation','selfId','peerId','accountBinding','capturedAt','response'];
 if(!data||Array.isArray(data)||Object.keys(data).length!==keys.length||keys.some(key=>!Object.hasOwn(data,key))||
  data.provider!=='rubika'||data.operation!=='requestCall'||!data.response||Array.isArray(data.response)||typeof data.response!=='object'||
  typeof data.selfId!=='string'||!/^[A-Za-z0-9_-]{8,128}$/.test(data.selfId)||
  typeof data.peerId!=='string'||!/^[A-Za-z0-9_-]{8,128}$/.test(data.peerId)||data.selfId===data.peerId||
  typeof data.accountBinding!=='string'||!/^[a-f0-9]{64}$/.test(data.accountBinding)||
  !Number.isSafeInteger(data.capturedAt)||data.capturedAt<=0||data.capturedAt>Date.now()+60000)throw new CallRecoveryError('invalid_call_recovery');
 // Capture only the requestCall fields needed to reparse this call. Even
 // encrypted diagnostics must not retain unrelated chats or message updates.
 if(Object.keys(data.response).some(key=>!['call_type','call_update'].includes(key)))throw new CallRecoveryError('invalid_call_recovery');
 if(Date.now()-data.capturedAt>CALL_RECOVERY_TTL_MS)throw new CallRecoveryError('call_recovery_expired');
 const plain=Buffer.from(JSON.stringify(data));if(plain.length>MAX_CALL_RECOVERY_BYTES){plain.fill(0);throw new CallRecoveryError('record_too_large');}
 plain.fill(0);return data;
}
module.exports={validateCallRecovery,CallRecoveryError,MAX_CALL_RECOVERY_BYTES,CALL_RECOVERY_TTL_MS};
