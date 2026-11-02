// Experimental account-scoped encrypted RPC channel. No disk, OTP UI or auto-redial.
const crypto=require('node:crypto');
const {wire:w,MAX_FRAME}=require('./signaling.cjs');
const security=require('./secure-connection.cjs');
const ENDPOINT='wss://secure.igap.net/hybrid/?apiVersion=3&version=1';
const ALLOWED=new Set([3,100,101,102,145,502,506,913,914,915,916,917,918]);
class RpcError extends Error{constructor(reason,major,minor,waitSeconds){super('iGap RPC '+reason);this.name='IgapRpcError';this.reason=reason;if(major!==undefined)this.major=major;if(minor!==undefined)this.minor=minor;if(waitSeconds)this.waitSeconds=waitSeconds;}}
class Connection{
 #socket;#key;#params;#phase='greeting';#pending=new Map();#deadline;#heartbeat;#resolve;#reject;#rootKey;#push;
 static async open({WebSocketImpl=globalThis.WebSocket,rootKey,onPush=()=>{},handshakeTimeout=10000}={}){
  if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw new RpcError('tls_verification_disabled');
  if(typeof WebSocketImpl!=='function')throw new RpcError('transport_unavailable');
  const c=new Connection();c.#key=crypto.randomBytes(32);c.#rootKey=rootKey;c.#push=onPush;
  return new Promise((resolve,reject)=>{c.#resolve=()=>resolve(c);c.#reject=reject;
   c.#deadline=setTimeout(()=>c.#fail('handshake_timeout'),handshakeTimeout);
   try{c.#socket=new WebSocketImpl(ENDPOINT);c.#socket.binaryType='arraybuffer';
    c.#socket.addEventListener('message',e=>c.#message(e.data));c.#socket.addEventListener('error',()=>c.#fail('connection_error'));c.#socket.addEventListener('close',()=>c.#fail('connection_closed'));
   }catch{c.#fail('transport_error');}
  });
 }
 #message(data){try{
  if(!(data instanceof ArrayBuffer))throw new RpcError('invalid_packet');
  if(this.#phase==='greeting'){
   const greeting=security.decodeGreeting(data);this.#phase='securing';this.#socket.send(security.keyExchange(greeting,this.#key,this.#rootKey));
   this.heartbeatSeconds=Math.max(10,Math.min(120,greeting.heartbeat));return;
  }
  if(this.#phase==='securing'){
   this.#params=security.decodeAccepted(data);this.#phase='ready';clearTimeout(this.#deadline);
   this.#heartbeat=setInterval(()=>{this.request(502).catch(()=>this.#fail('heartbeat_failed'));},this.heartbeatSeconds*500);
   this.#resolve();this.#resolve=null;this.#reject=null;return;
  }
  if(this.#phase!=='ready')return;
  const packet=security.decryptPacket(data,this.#key,this.#params);if(packet.length<2||packet.length>MAX_FRAME)throw new RpcError('invalid_packet');
  const action=packet.readUInt16LE(),fields=w.parse(packet.subarray(2)),meta=w.parse(w.one(fields,1,2,Buffer.alloc(0))),id=w.str(meta,1,128),pending=this.#pending.get(id);
  if(pending){
   if(action!==0&&action!==pending.action+30000)throw new RpcError('unexpected_response');
   const error=action===0?new RpcError('rejected',w.number(fields,2),w.number(fields,3),Math.min(w.number(fields,4),86400)):null;
   this.#pending.delete(id);clearTimeout(pending.timer);
   if(error)pending.reject(error);else pending.resolve({action,fields});
  }else if(!id&&[30914,30915,30916,30917,30918].includes(action)){
   try{this.#push(Buffer.from(packet));}catch{/* Consumer callbacks do not change channel integrity. */}
  }
 }catch{this.#fail('invalid_packet');}}
 request(action,fields=Buffer.alloc(0),{token='',timeout=8000}={}){
  if(this.#phase!=='ready')return Promise.reject(new RpcError('not_connected'));
  if(!ALLOWED.has(action)||!Buffer.isBuffer(fields)||fields.length>MAX_FRAME-4352||!Number.isFinite(timeout)||timeout<1||timeout>30000)return Promise.reject(new RpcError('invalid_request'));
  if(this.#pending.size>=32)return Promise.reject(new RpcError('too_many_requests'));
  let packet;const id=crypto.randomUUID();try{if(w.parse(fields).has(1))throw new Error();packet=w.frame(action,Buffer.concat([w.field(1,Buffer.concat([w.string(1,id,128),w.string(2,token,4096)])),fields]));}catch{return Promise.reject(new RpcError('invalid_request'));}
  return new Promise((resolve,reject)=>{
   const timer=setTimeout(()=>{this.#pending.delete(id);reject(new RpcError('timeout'));},timeout);this.#pending.set(id,{action,resolve,reject,timer});
   try{this.#socket.send(security.encryptPacket(packet,this.#key,this.#params));}catch{this.#fail('send_failed');}
  });
 }
 #fail(reason){if(this.#phase==='closed')return;this.#phase='closed';clearTimeout(this.#deadline);clearInterval(this.#heartbeat);this.#key?.fill(0);this.#params=null;
  this.#reject?.(new RpcError(reason));this.#resolve=null;this.#reject=null;
  for(const pending of this.#pending.values()){clearTimeout(pending.timer);pending.reject(new RpcError(reason));}this.#pending.clear();
  try{this.#socket?.close();}catch{}
 }
 close(){this.#fail('closed');}
 get status(){return {phase:this.#phase,pending:this.#pending.size,cipher:this.#params?.method||null,authenticated:false,providerVerified:false};}
}
async function probe(){const c=await Connection.open();try{
 const response=await c.request(506);const config=w.one(response.fields,20,2,Buffer.alloc(0));
 return {ok:true,encryptedRoundTrip:true,action:response.action,cipher:c.status.cipher,maxGroupParticipants:w.number(w.parse(config),1),authenticated:false,otpSubmitted:false,liveCallTested:false,providerVerified:false};
}finally{c.close();}}
module.exports={Connection,RpcError,probe,ENDPOINT};
