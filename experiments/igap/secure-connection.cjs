// Isolated iGap connection-security handshake. No OTP/login or account storage.
// Uses Node crypto and verified wss TLS; never disables certificate validation.
const crypto=require('node:crypto');
const {wire:w,MAX_FRAME}=require('./signaling.cjs');
const ROOT_KEY=`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo+inlAfd8Qior8IMKaJ+
BREJcEc9J9RhHgh6g/LvHKsnMaiEbAL70jQBQTLpCRu5Cnpj20+isOi++Wtf/pIP
FdJbD/1H+5jS+ja0RA6unp93DnBuYZ2JjV60vF3Ynj6F4Vr1ts5Xg5dJlEaOcOO2
YzOU97ZGP0ozrXIT5S+Y0BC4M9ieQmlGREzt3UZlTBbyUYPS4mMFh88YcT3QTiTA
k897qlJLxkYxVyAgwAD/0ihmWEkBQe9IxwVT/x5/QbixGSl4Zvd+5d+9sTZcSZQS
iJInT4E6DcmgAVYu5jFMWJDTEuurOQZ1W4nbmGyoY1bZXaFoiMPfzy72VIddkoHg
mwIDAQAB
-----END PUBLIC KEY-----`;
function packet(bytes,action){const b=Buffer.from(bytes);if(b.length<2||b.length>MAX_FRAME||b.readUInt16LE()!==action)throw new Error('Unexpected connection-security packet');return w.parse(b.subarray(2));}
function decodeGreeting(bytes){const f=packet(bytes,30001),key=w.str(f,2,8192),length=w.number(f,3),chunk=w.number(f,6);if(length!==32||chunk<1||chunk>245)throw new Error('Unsupported connection-security parameters');return {key,length,chunk,heartbeat:w.number(f,4)};}
function keyExchange(greeting,key,rootKey=ROOT_KEY){
 if(key.length!==32)throw new Error('Invalid session key length');
 const encrypt=(pem,bytes)=>crypto.publicEncrypt({key:pem,padding:crypto.constants.RSA_PKCS1_PADDING},bytes);
 const inner=encrypt(greeting.key,key),chunks=[];
 for(let i=0;i<inner.length;i+=greeting.chunk)chunks.push(encrypt(rootKey,inner.subarray(i,i+greeting.chunk)));
 return w.frame(2,Buffer.concat([w.field(1,Buffer.alloc(0)),w.field(2,Buffer.concat(chunks)),w.field(3,2,0)]));
}
function decodeAccepted(bytes){const f=packet(bytes,30002);if(w.number(f,2,1n)!==1||w.number(f,5,1n)!==0)throw new Error('Connection-security rejected');const method=w.str(f,3,64),ivSize=w.number(f,4);if(!['AES-256-CBC','AES-256-GCM'].includes(method)||(method.endsWith('CBC')?ivSize!==16:![12,16].includes(ivSize)))throw new Error('Unsupported session cipher');return {method,ivSize};}
function encryptPacket(plain,key,params){if(plain.length>MAX_FRAME)throw new Error('Packet too large');const iv=crypto.randomBytes(params.ivSize),cipher=crypto.createCipheriv(params.method.toLowerCase(),key,iv);const encrypted=Buffer.concat([cipher.update(plain),cipher.final()]);return Buffer.concat([iv,encrypted,...params.method.endsWith('GCM')?[cipher.getAuthTag()]:[]]);}
function decryptPacket(bytes,key,params){const b=Buffer.from(bytes),tagSize=params.method.endsWith('GCM')?16:0;if(b.length<params.ivSize+tagSize+1||b.length>MAX_FRAME+64)throw new Error('Invalid encrypted packet');const d=crypto.createDecipheriv(params.method.toLowerCase(),key,b.subarray(0,params.ivSize));if(tagSize)d.setAuthTag(b.subarray(-tagSize));return Buffer.concat([d.update(b.subarray(params.ivSize,tagSize?-tagSize:b.length)),d.final()]);}
async function probe(){
 if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw new Error('TLS verification is required');
 if(typeof WebSocket!=='function')throw new Error('Node.js 22+ required');
 const key=crypto.randomBytes(32);let sent=0,phase='greeting';
 return new Promise(resolve=>{
  const socket=new WebSocket('wss://secure.igap.net/hybrid/?apiVersion=3&version=1');socket.binaryType='arraybuffer';let finished=false;
  const finish=result=>{if(finished)return;finished=true;clearTimeout(timer);key.fill(0);socket.close();resolve({...result,phase,applicationMessagesSent:sent,authenticated:false,otpSubmitted:false,liveCallTested:false,providerVerified:false});};
  const timer=setTimeout(()=>finish({ok:false,reason:'timeout'}),10000);
  socket.addEventListener('message',event=>{try{if(!(event.data instanceof ArrayBuffer))throw new Error();if(phase==='greeting'){const g=decodeGreeting(event.data);const request=keyExchange(g,key);phase='securing';socket.send(request);sent++;}else if(phase==='securing'){const cipher=decodeAccepted(event.data);phase='secured';finish({ok:true,cipher:cipher.method,ivSize:cipher.ivSize});}}catch{finish({ok:false,reason:'invalid_or_unsupported_handshake'});}});
  socket.addEventListener('error',()=>finish({ok:false,reason:'connection_error'}));socket.addEventListener('close',()=>finish({ok:false,reason:'closed'}));
 });
}
module.exports={decodeGreeting,keyExchange,decodeAccepted,encryptPacket,decryptPacket,probe};
