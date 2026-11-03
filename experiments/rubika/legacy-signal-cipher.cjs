// Experimental explicit tgcalls 6.0.0/layer-92 raw signaling profile.
// Independent protocol implementation; no native library is loaded or executed.
// The messenger supplies this key: it is NOT provider-blind peer authentication.
'use strict';
const crypto=require('node:crypto');
const MAX_PAYLOAD=48*1024-20,WINDOW=64,MAX_COUNTER=0x3fffffff;
class SignalError extends Error{constructor(reason){super('Rubika legacy signal '+reason);this.reason=reason;}}
const fail=reason=>{throw new SignalError(reason);};
function serviceKey(value){
 if(typeof value!=='string'||value.length>256)fail('invalid_service_call_key');
 const bytes=Buffer.from(value,'utf8');
 if(bytes.length!==256||bytes.toString('utf8')!==value||bytes.every(v=>v===0)){bytes.fill(0);fail('invalid_service_call_key');}return bytes;
}
function hash(...values){const h=crypto.createHash('sha256');for(const v of values)h.update(v);return h.digest();}
function parameters(secret,tag,direction){
 const first=hash(tag,secret.subarray(direction,direction+36)),second=hash(secret.subarray(direction+40,direction+76),tag);
 try{return {key:Buffer.concat([first.subarray(0,8),second.subarray(8,24),first.subarray(24)]),iv:Buffer.concat([second.subarray(0,4),first.subarray(8,16),second.subarray(24,28)])};}
 finally{first.fill(0);second.fill(0);}
}
function crypt(input,p){
 try{const c=crypto.createCipheriv('aes-256-ctr',p.key,p.iv);return Buffer.concat([c.update(input),c.final()]);}
 catch{fail('signal_crypto_failed');}finally{p.key.fill(0);p.iv.fill(0);}
}
class LegacySignalCipher{
 #secret;#outgoing;#counter=0;#highest=0;#seen=new Uint32Array(WINDOW);#closed=false;
 constructor({key,isOutgoing,libraryVersion,protocolLayer}={}){
  if(libraryVersion!=='6.0.0'||protocolLayer!==92)fail('unsupported_signal_profile');
  if(typeof isOutgoing!=='boolean')fail('invalid_signal_role');
  if(!Buffer.isBuffer(key)||key.length!==256||key.every(v=>v===0))fail('invalid_signal_key');
  this.#secret=Buffer.from(key);this.#outgoing=isOutgoing;
 }
 #open(){if(this.#closed)fail('closed');}
 encryptRaw(value){
  this.#open();if(!Buffer.isBuffer(value)||!value.length||value.length>MAX_PAYLOAD)fail('invalid_signal_size');
  if(this.#counter>=MAX_COUNTER)fail('signal_counter_exhausted');
  const frame=Buffer.alloc(4+value.length),direction=this.#outgoing?128:136;let digest;
  frame.writeUInt32BE(++this.#counter);value.copy(frame,4);
  try{digest=hash(this.#secret.subarray(direction+88,direction+120),frame);const tag=digest.subarray(8,24);
   return Buffer.concat([tag,crypt(frame,parameters(this.#secret,tag,direction))]);
  }finally{frame.fill(0);digest?.fill(0);}
 }
 decryptRaw(packet){
  this.#open();if(!Buffer.isBuffer(packet)||packet.length<21||packet.length>MAX_PAYLOAD+20)fail('invalid_signal_size');
  const direction=this.#outgoing?136:128,tag=packet.subarray(0,16);let frame,digest;
  try{
   frame=crypt(packet.subarray(16),parameters(this.#secret,tag,direction));
   digest=hash(this.#secret.subarray(direction+88,direction+120),frame);
   if(!crypto.timingSafeEqual(tag,digest.subarray(8,24)))fail('invalid_signal_authentication');
   // Native raw receive strips the two sequence flag bits before replay checks.
   const sequence=frame.readUInt32BE()&MAX_COUNTER;
   if(!sequence)fail('invalid_signal_counter');if(sequence<=this.#highest-WINDOW)fail('signal_too_old');
   const index=sequence%WINDOW;if(this.#seen[index]===sequence)fail('signal_replayed');
   this.#seen[index]=sequence;this.#highest=Math.max(this.#highest,sequence);return Buffer.from(frame.subarray(4));
  }finally{frame?.fill(0);digest?.fill(0);}
 }
 close(){this.#closed=true;this.#secret?.fill(0);this.#secret=null;this.#seen.fill(0);this.#counter=0;this.#highest=0;}
}
module.exports={LegacySignalCipher,SignalError,serviceKey,MAX_PAYLOAD,WINDOW,MAX_COUNTER};
