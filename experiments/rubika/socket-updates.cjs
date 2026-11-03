// Account-bound official Web notification channel. No reconnect or auto-dial.
'use strict';
const wire=require('./wire.cjs'),updates=require('./call-updates.cjs');
class StreamError extends Error{constructor(reason){super('Rubika updates '+reason);this.reason=reason;}}
function socketEndpoint(value){let url;try{url=new URL(value);}catch{throw new StreamError('invalid_update_server');}
 if(typeof value!=='string'||value.length>512||url.protocol!=='wss:'||url.username||url.password||url.search||url.hash||url.pathname!=='/'||url.port&&!['80','443'].includes(url.port)||!(url.hostname==='iranlms.ir'||url.hostname.endsWith('.iranlms.ir')))throw new StreamError('invalid_update_server');return url.href;
}
class SocketUpdates{
 #socket;#auth;#self;#phase='connecting';#reason=null;#calls=[];#signals=[];#bytes=0;#resolve;#reject;#timer;#heartbeat;#last=Date.now();#unbind;
 static async open(credentials,{url,WebSocketImpl=globalThis.WebSocket,signal}={}){
  if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw new StreamError('tls_verification_disabled');
  if(credentials?.provider!=='rubika'||! /^[A-Za-z0-9_-]{8,128}$/.test(credentials.userId||'')||! /^[a-z0-9]{32}$/.test(credentials.auth||''))throw new StreamError('invalid_credentials');
  if(signal?.aborted)throw new StreamError('closed');const endpoint=socketEndpoint(url),channel=new SocketUpdates();channel.#auth=credentials.auth;channel.#self=credentials.userId;
  const ready=new Promise((resolve,reject)=>{channel.#resolve=resolve;channel.#reject=reject;});
  if(signal){const abort=()=>channel.close();signal.addEventListener('abort',abort,{once:true});channel.#unbind=()=>signal.removeEventListener('abort',abort);}
  channel.#timer=setTimeout(()=>channel.#fail('update_stream_timeout'),10000);channel.#timer.unref?.();
  try{
   const socket=channel.#socket=new WebSocketImpl(endpoint);
   socket.addEventListener('open',()=>{if(channel.#phase!=='connecting')return;try{socket.send(JSON.stringify({api_version:'5',auth:channel.#auth,data:'',method:'handShake'}));}catch{channel.#fail('update_stream_failed');}});
   socket.addEventListener('message',event=>channel.#message(event.data));
   socket.addEventListener('error',()=>channel.#fail('update_stream_failed'));
   socket.addEventListener('close',()=>channel.#fail('update_stream_closed'));
  }catch{channel.#fail('update_stream_failed');}
  await ready;return channel;
 }
 #message(data){
  if(['failed','closed'].includes(this.#phase))return;
  try{
   if(typeof data!=='string'||Buffer.byteLength(data)>512*1024)throw new StreamError('invalid_update_stream');
   const envelope=JSON.parse(data);if(!envelope||typeof envelope!=='object'||Array.isArray(envelope))throw new StreamError('invalid_update_stream');
   if(envelope.status&&envelope.status!=='OK')throw new StreamError('update_stream_rejected');
   if(envelope.type==='messenger'){
    if(typeof envelope.data_enc!=='string')throw new StreamError('invalid_update_stream');
    const decoded=wire.decrypt(envelope.data_enc,this.#auth),payload=decoded?.update_data??decoded;
    if(!payload||typeof payload!=='object'||Array.isArray(payload)||payload.user_guid!==undefined&&payload.user_guid!==this.#self)throw new StreamError('update_account_mismatch');
    // The dedicated socket is pinned to the account that authenticated it.
    // If a packet includes an account ID it must match; other chat data drops.
    const projected=updates.updates({update_data:{user_guid:this.#self,call_updates:payload.call_updates,call_signal_data:payload.call_signal_data}},this.#self);
    if(this.#calls.length+projected.call_updates.length>64||this.#signals.length+projected.call_signal_data.length>256||this.#bytes+projected.call_signal_data.reduce((n,v)=>n+v.data.length,0)>48*1024){for(const v of projected.call_signal_data)v.data.fill(0);throw new StreamError('update_queue_full');}
    this.#calls.push(...projected.call_updates);this.#signals.push(...projected.call_signal_data);this.#bytes+=projected.call_signal_data.reduce((n,v)=>n+v.data.length,0);
   }
   this.#last=Date.now();if(this.#phase==='connecting'){this.#phase='connected';clearTimeout(this.#timer);this.#resolve();this.#resolve=this.#reject=null;this.#heartbeat=setInterval(()=>{if(Date.now()-this.#last>45000){this.#fail('update_stream_timeout');return;}try{this.#socket.send('{}');}catch{this.#fail('update_stream_failed');}},20000);this.#heartbeat.unref?.();}
  }catch(e){this.#fail(e instanceof StreamError?e.reason:'invalid_update_stream');}
 }
 read(){if(this.#phase!=='connected')throw new StreamError(this.#reason||'update_stream_closed');const signals=this.#signals.splice(0);this.#bytes=0;
  const data={user_guid:this.#self,call_updates:this.#calls.splice(0),call_signal_data:signals.map(v=>({call_id:v.call_id,data:v.data.toString('base64')}))};for(const v of signals)v.data.fill(0);return {update_data:data};
 }
 #fail(reason){if(['failed','closed'].includes(this.#phase))return;this.#reason=reason;this.#phase='failed';this.#dispose();}
 #dispose(){clearTimeout(this.#timer);clearInterval(this.#heartbeat);this.#unbind?.();this.#unbind=null;this.#reject?.(new StreamError(this.#reason||'closed'));this.#resolve=this.#reject=null;for(const v of this.#signals)v.data.fill(0);this.#signals=[];this.#calls=[];this.#bytes=0;this.#auth='';this.#self='';try{this.#socket?.close();}catch{}}
 close(){if(this.#phase==='closed')return;this.#phase='closed';this.#dispose();}
 get state(){return {phase:this.#phase,reason:this.#reason,queuedCalls:this.#calls.length,queuedSignals:this.#signals.length};}
}
module.exports={SocketUpdates,StreamError,socketEndpoint};
