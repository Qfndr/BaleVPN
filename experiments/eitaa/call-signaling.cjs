// Private Eitaa layer-92 call signaling compatibility. This is the observed
// keyed-hash/AES-CTR construction, not a new AEAD or tunnel authentication.
'use strict';
const crypto=require('node:crypto');
const MAX_PAYLOAD=48*1024,WINDOW=4096,MAX_COUNTER=0xffffffff;
class SignalError extends Error{constructor(reason){super('Eitaa call signal '+reason);this.reason=reason;}}
function bytes(v,min,max=min){if(!(v instanceof Uint8Array)||v.length<min||v.length>max)throw new SignalError('invalid_signal_size');return Buffer.from(v);}
function digest(...values){const h=crypto.createHash('sha256');for(const value of values)h.update(value);return h.digest();}
function parameters(auth,key,x){
 const a=digest(key,auth.subarray(x,x+36)),b=digest(auth.subarray(x+40,x+76),key);
 try{return {key:Buffer.concat([a.subarray(0,8),b.subarray(8,24),a.subarray(24,32)]),iv:Buffer.concat([b.subarray(0,4),a.subarray(8,16),b.subarray(24,28)])};}finally{a.fill(0);b.fill(0);}
}
function crypt(value,p,encrypt){try{const c=encrypt?crypto.createCipheriv('aes-256-ctr',p.key,p.iv):crypto.createDecipheriv('aes-256-ctr',p.key,p.iv);return Buffer.concat([c.update(value),c.final()]);}catch{throw new SignalError('signal_crypto_failed');}}
const plain=v=>v&&typeof v==='object'&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v));
function validateSignal(value){
 let nodes=0;const active=new Set();
 function walk(v,depth=0){
  if(++nodes>4096||depth>12)throw new SignalError('invalid_signal_payload');
  if(v===null||typeof v==='boolean')return;
  if(typeof v==='number'){if(!Number.isSafeInteger(v))throw new SignalError('invalid_signal_payload');return;}
  if(typeof v==='string'){if(Buffer.byteLength(v)>4096||/[\x00-\x1f\x7f]/.test(v)||Buffer.from(v).toString('utf8')!==v)throw new SignalError('invalid_signal_payload');return;}
  if((!plain(v)&&!Array.isArray(v))||active.has(v)||Object.getOwnPropertySymbols(v).length)throw new SignalError('invalid_signal_payload');active.add(v);
  if(Array.isArray(v)){if(v.length>128||Object.getPrototypeOf(v)!==Array.prototype||Object.getOwnPropertyNames(v).length!==v.length+1)throw new SignalError('invalid_signal_payload');for(let i=0;i<v.length;i++){const p=Object.getOwnPropertyDescriptor(v,String(i));if(!p||!Object.hasOwn(p,'value'))throw new SignalError('invalid_signal_payload');walk(p.value,depth+1);}}
  else {const keys=Object.getOwnPropertyNames(v);if(keys.length>128)throw new SignalError('invalid_signal_payload');for(const key of keys){if(key.length>128||['__proto__','prototype','constructor','toJSON'].includes(key))throw new SignalError('invalid_signal_payload');const p=Object.getOwnPropertyDescriptor(v,key);if(!p||!p.enumerable||!Object.hasOwn(p,'value'))throw new SignalError('invalid_signal_payload');if(p.value!==undefined)walk(p.value,depth+1);}}
  active.delete(v);
 }
 walk(value);if(!plain(value))throw new SignalError('invalid_signal_payload');
 if(value['@type']==='Candidates'){
  if(!Array.isArray(value.candidates)||value.candidates.length>64||value.candidates.some(c=>!plain(c)||typeof c.sdpString!=='string'||c.sdpString.length>2048||!c.sdpString.startsWith('candidate:')))throw new SignalError('invalid_signal_payload');
 }else if(value['@type']==='InitialSetup'){
  if(!Array.isArray(value.fingerprints)||!value.fingerprints.length||value.fingerprints.length>4||value.fingerprints.some(f=>!plain(f)||f.hash!=='sha-256'||typeof f.fingerprint!=='string'||! /^(?:[0-9a-f]{2}:){31}[0-9a-f]{2}$/i.test(f.fingerprint)||!['active','passive','actpass'].includes(f.setup))||
   typeof value.ufrag!=='string'||! /^[A-Za-z0-9+/_-]{4,256}$/.test(value.ufrag)||typeof value.pwd!=='string'||! /^[A-Za-z0-9+/_-]{22,256}$/.test(value.pwd))throw new SignalError('invalid_signal_payload');
  const media=m=>plain(m)&&typeof m.ssrc==='string'&&/^\d{1,10}$/.test(m.ssrc)&&Number(m.ssrc)>0&&Number(m.ssrc)<=0xffffffff&&Array.isArray(m.rtpExtensions)&&m.rtpExtensions.length<=32&&Array.isArray(m.payloadTypes)&&m.payloadTypes.length>0&&m.payloadTypes.length<=64;
  if(!media(value.audio)||value.video!==undefined&&!media(value.video)||value.screencast!==undefined&&!media(value.screencast))throw new SignalError('invalid_signal_payload');
 }else throw new SignalError('unsupported_signal_type');
 return value;
}
class SignalingCipher{
 #key;#outgoing;#counter=0;#high=0;#seen=new Uint32Array(WINDOW);#closed=false;
 constructor({key,isOutgoing}={}){
  // The official DH helper returns minimal bytes. Permit rare leading-zero
  // trimming, but never allow a tiny key with empty/weak authentication slices.
  if(typeof isOutgoing!=='boolean')throw new SignalError('invalid_signal_role');this.#key=bytes(key,248,256);if(this.#key.every(b=>b===0))throw new SignalError('invalid_signal_key');this.#outgoing=isOutgoing;
 }
 #open(){if(this.#closed)throw new SignalError('closed');}
 encryptRaw(value){
  this.#open();const payload=bytes(value,1,MAX_PAYLOAD);if(this.#counter===MAX_COUNTER)throw new SignalError('signal_counter_exhausted');
  const frame=Buffer.alloc(4+payload.length),x=this.#outgoing?128:136;frame.writeUInt32BE(++this.#counter);payload.copy(frame,4);payload.fill(0);let h,p;
  try{h=digest(this.#key.subarray(x+88,x+120),frame);const header=h.subarray(8,24);p=parameters(this.#key,header,x);return Buffer.concat([header,crypt(frame,p,true)]);}
  finally{frame.fill(0);h?.fill(0);p?.key.fill(0);p?.iv.fill(0);}
 }
 decryptRaw(value){
  this.#open();const packet=bytes(value,21,MAX_PAYLOAD+20),x=this.#outgoing?136:128,header=packet.subarray(0,16);let frame,h,p;
  try{
   p=parameters(this.#key,header,x);frame=crypt(packet.subarray(16),p,false);h=digest(this.#key.subarray(x+88,x+120),frame);
   if(!crypto.timingSafeEqual(h.subarray(8,24),header))throw new SignalError('invalid_signal_authentication');
   const seq=frame.readUInt32BE();if(!seq)throw new SignalError('invalid_signal_counter');if(seq<=this.#high-WINDOW)throw new SignalError('signal_too_old');
   const index=seq%WINDOW;if(this.#seen[index]===seq)throw new SignalError('signal_replayed');
   this.#seen[index]=seq;this.#high=Math.max(seq,this.#high);return Buffer.from(frame.subarray(4));
  }finally{frame?.fill(0);h?.fill(0);p?.key.fill(0);p?.iv.fill(0);}
 }
 encryptJson(value){this.#open();validateSignal(value);const raw=Buffer.from(JSON.stringify(value),'utf8');try{return this.encryptRaw(raw);}finally{raw.fill(0);}}
 decryptJson(packet){const raw=this.decryptRaw(packet);try{let value;try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));}catch{throw new SignalError('invalid_signal_json');}return validateSignal(value);}finally{raw.fill(0);}}
 close(){this.#closed=true;this.#key?.fill(0);this.#key=null;this.#seen.fill(0);this.#high=0;this.#counter=0;}
}
module.exports={SignalingCipher,SignalError,validateSignal,MAX_PAYLOAD,WINDOW};
