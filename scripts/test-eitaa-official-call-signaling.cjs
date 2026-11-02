// Runs only the SHA-pinned private packet cipher class. Never starts the UI,
// imports, worker, account storage, media engine, telemetry or network.
'use strict';
const fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {SignalingCipher,MAX_PAYLOAD}=require('../experiments/eitaa/call-signaling.cjs');
const source=fs.readFileSync(process.env.BALEVPN_EITAA_CALL_UI||'','utf8');assert.equal(crypto.createHash('sha256').update(source).digest('hex'),'877c5cf4317887f7144a682b18a6c01fe443206d1e12e0fb81a13df740049c40');
const start=source.indexOf('class $0{'),end=source.indexOf('class U0{',start);assert.ok(start>=0&&end>start&&end-start<6000);assert.ok(source.includes('const BQ=128*1024*1024;'));
const context=vm.createContext({pw:crypto.webcrypto.subtle,Uint8Array,ArrayBuffer,DataView,BQ:128*1024*1024,FQ:async value=>new Uint8Array(await crypto.webcrypto.subtle.digest('SHA-256',value)),fT:(...values)=>new Uint8Array(Buffer.concat(values.map(v=>Buffer.from(v))))});
vm.runInContext(source.slice(start,end)+';globalThis.OfficialCipher=$0;',context,{timeout:1000});
(async()=>{
 let comparisons=0;
 for(const length of [248,255,256])for(const isOutgoing of [true,false]){
  const key=crypto.randomBytes(length),original=new context.OfficialCipher(isOutgoing,key),originalReceiver=new context.OfficialCipher(!isOutgoing,key),local=new SignalingCipher({key,isOutgoing}),receiver=new SignalingCipher({key,isOutgoing:!isOutgoing});
  try{for(const payload of [Buffer.from([1]),Buffer.from('{"@type":"Candidates","candidates":[],"fixture":"فارسی"}'),Buffer.alloc(254,0xa5),Buffer.alloc(MAX_PAYLOAD,0x5a)]){
   const officialPacket=await original.encryptRawPacket(new Uint8Array(payload)),packet=local.encryptRaw(payload);assert.ok(packet.equals(Buffer.from(officialPacket.bytes)),'Official and local packet bytes differ');
   assert.ok(receiver.decryptRaw(officialPacket.bytes).equals(payload),'Local decryption differs');assert.ok(Buffer.from(await originalReceiver.decryptRawPacket(packet)).equals(payload),'Official decryption differs');comparisons++;
  }}finally{local.close();receiver.close();key.fill(0);}
 }
 const key=crypto.randomBytes(256),original=new context.OfficialCipher(true,key),receiver=new SignalingCipher({key,isOutgoing:false});
 try{original.counter=0xfffffffe;const last=await original.encryptRawPacket(new Uint8Array([1]));assert.deepEqual(receiver.decryptRaw(last.bytes),Buffer.from([1]));const wrapped=await original.encryptRawPacket(new Uint8Array([2]));assert.throws(()=>receiver.decryptRaw(wrapped.bytes),{reason:'invalid_signal_counter'});}finally{receiver.close();key.fill(0);}
 console.log('PASS official Eitaa call cipher parity: '+comparisons+' byte-identical packets and bidirectional decryptions across caller/callee roles, 248/255/256-byte keys, Unicode, TL-size boundary and maximum payload; counter wrap refused; no UI startup/network/account/call');
})().catch(e=>{console.error(e);process.exitCode=1;});
