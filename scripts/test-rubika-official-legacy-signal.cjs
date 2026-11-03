// Optional offline compatibility oracle: the pinned official Eitaa legacy raw
// cipher only. This is NOT an execution or interoperability test of Rubika APK.
'use strict';
const fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {LegacySignalCipher,MAX_PAYLOAD}=require('../experiments/rubika/legacy-signal-cipher.cjs');
const source=fs.readFileSync(process.env.BALEVPN_EITAA_CALL_UI||'','utf8');
assert.equal(crypto.createHash('sha256').update(source).digest('hex'),'877c5cf4317887f7144a682b18a6c01fe443206d1e12e0fb81a13df740049c40');
const start=source.indexOf('class $0{'),end=source.indexOf('class U0{',start);assert.ok(start>=0&&end>start&&end-start<6000);
const context=vm.createContext({pw:crypto.webcrypto.subtle,Uint8Array,ArrayBuffer,DataView,BQ:128*1024*1024,
 FQ:async bytes=>new Uint8Array(await crypto.webcrypto.subtle.digest('SHA-256',bytes)),fT:(...values)=>new Uint8Array(Buffer.concat(values.map(v=>Buffer.from(v))))});
vm.runInContext(source.slice(start,end)+';globalThis.OfficialCipher=$0;',context,{timeout:1000});
(async()=>{
 let comparisons=0;
 for(const isOutgoing of [true,false]){
  const key=crypto.randomBytes(256),original=new context.OfficialCipher(isOutgoing,key),peer=new context.OfficialCipher(!isOutgoing,key),
   local=new LegacySignalCipher({key,isOutgoing,libraryVersion:'6.0.0',protocolLayer:92}),receiver=new LegacySignalCipher({key,isOutgoing:!isOutgoing,libraryVersion:'6.0.0',protocolLayer:92});
  try{for(const payload of [Buffer.from([1]),Buffer.from('{"fixture":"فارسی"}'),Buffer.alloc(MAX_PAYLOAD,0x5a)]){
   const packet=local.encryptRaw(payload),expected=await original.encryptRawPacket(new Uint8Array(payload));
   assert.deepEqual(packet,Buffer.from(expected.bytes));assert.deepEqual(receiver.decryptRaw(Buffer.from(expected.bytes)),payload);
   assert.deepEqual(Buffer.from(await peer.decryptRawPacket(packet)),payload);comparisons++;
  }}finally{local.close();receiver.close();key.fill(0);}
 }
 const key=crypto.randomBytes(256),original=new context.OfficialCipher(true,key),receiver=new LegacySignalCipher({key,isOutgoing:false,libraryVersion:'6.0.0',protocolLayer:92});
 try{
  original.counter=0x80000000;const flagged=await original.encryptRawPacket(new Uint8Array([1]));assert.deepEqual(receiver.decryptRaw(Buffer.from(flagged.bytes)),Buffer.from([1]));
  original.counter=0;const duplicate=await original.encryptRawPacket(new Uint8Array([2]));assert.throws(()=>receiver.decryptRaw(Buffer.from(duplicate.bytes)),{reason:'signal_replayed'});
  original.counter=0x7fffffff;const zero=await original.encryptRawPacket(new Uint8Array([3]));assert.throws(()=>receiver.decryptRaw(Buffer.from(zero.bytes)),{reason:'invalid_signal_counter'});
 }finally{receiver.close();key.fill(0);}
 console.log('PASS '+comparisons+' byte-identical legacy packets, both directions and native-style masked-counter checks; offline Eitaa cipher oracle only, no UI/network/account/native APK execution');
})().catch(()=>{console.error('Offline legacy cipher comparison failed');process.exitCode=1;});
