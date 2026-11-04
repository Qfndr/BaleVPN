// Account-bound Web/native notification profiles. No reconnect or auto-dial.
'use strict';
const crypto=require('node:crypto'),wire=require('./wire.cjs'),updates=require('./call-updates.cjs');
const profiles=require('./client-profile.cjs');
// Default Gson used by the pinned native service omits nulls and escapes HTML
// characters, including when serializing the JSON string inside `data`.
const gson=value=>JSON.stringify(value).replace(/[<>&='\u2028\u2029]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'));
const ackId=value=>typeof value==='string'&&value.length>0&&Buffer.byteLength(value)<=256&&!/[\x00-\x1f\x7f]/.test(value)&&Buffer.from(value).toString('utf8')===value;
class StreamError extends Error{constructor(reason){super('Rubika updates '+reason);this.reason=reason;}}
function socketEndpoint(value){let url;try{url=new URL(value);}catch{throw new StreamError('invalid_update_server');}
 if(typeof value!=='string'||value.length>512||url.protocol!=='wss:'||url.username||url.password||url.search||url.hash||url.pathname!=='/'||url.port&&!['80','443'].includes(url.port)||!(url.hostname==='iranlms.ir'||url.hostname.endsWith('.iranlms.ir')))throw new StreamError('invalid_update_server');return url.href;
}
class SocketUpdates{
 #socket;#auth;#self;#profile='web';#language='fa';#acks=new Map();#phase='connecting';#reason=null;#calls=[];#signals=[];#bytes=0;#resolve;#reject;#timer;#heartbeat;#last=Date.now();#unbind;
 static async open(credentials,{url,WebSocketImpl=globalThis.WebSocket,signal,language='fa'}={}){
  if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw new StreamError('tls_verification_disabled');
  if(credentials?.provider!=='rubika'||! /^[A-Za-z0-9_-]{8,128}$/.test(credentials.userId||'')||! /^[a-z0-9]{32}$/.test(credentials.auth||''))throw new StreamError('invalid_credentials');
  let profile;try{profile=profiles.fromRecord(credentials);}catch{throw new StreamError('invalid_credentials');}
  if(!['fa','en'].includes(language))throw new StreamError('invalid_credentials');if(signal?.aborted)throw new StreamError('closed');const endpoint=socketEndpoint(url),channel=new SocketUpdates();channel.#auth=credentials.auth;channel.#self=credentials.userId;channel.#profile=profile;channel.#language=language;
  const ready=new Promise((resolve,reject)=>{channel.#resolve=resolve;channel.#reject=reject;});
  if(signal){const abort=()=>channel.close();signal.addEventListener('abort',abort,{once:true});channel.#unbind=()=>signal.removeEventListener('abort',abort);}
  channel.#timer=setTimeout(()=>channel.#fail('update_stream_timeout'),10000);channel.#timer.unref?.();
  try{
   const socket=channel.#socket=new WebSocketImpl(endpoint);
   socket.addEventListener('open',()=>{if(channel.#phase!=='connecting')return;try{if(profile===profiles.ANDROID){channel.#nativeSend('handShake',{version:'2'});channel.#ready();}else socket.send(JSON.stringify({api_version:'5',auth:channel.#auth,data:'',method:'handShake'}));}catch{channel.#fail('update_stream_failed');}});
   socket.addEventListener('message',event=>channel.#message(event.data));
   socket.addEventListener('error',()=>channel.#fail('update_stream_failed'));
   socket.addEventListener('close',()=>channel.#fail('update_stream_closed'));
  }catch{channel.#fail('update_stream_failed');}
  await ready;return channel;
 }
 #nativeSend(method,data){this.#socket.send(gson({api_version:'4',auth:this.#auth,client:profiles.client(profiles.ANDROID,this.#language),data:gson(data),is_background:false,method}));}
 #ready(){if(this.#phase!=='connecting')return;this.#phase='connected';clearTimeout(this.#timer);this.#resolve();this.#resolve=this.#reject=null;this.#heartbeat=setInterval(()=>{if(Date.now()-this.#last>45000){this.#fail('update_stream_timeout');return;}if(this.#profile===profiles.WEB)try{this.#socket.send('{}');}catch{this.#fail('update_stream_failed');}},20000);this.#heartbeat.unref?.();}
 #message(data){
  if(['failed','closed'].includes(this.#phase))return;
  try{
   if(typeof data!=='string'||Buffer.byteLength(data)>512*1024)throw new StreamError('invalid_update_stream');
   const envelope=JSON.parse(data);if(!envelope||typeof envelope!=='object'||Array.isArray(envelope))throw new StreamError('invalid_update_stream');
   if(envelope.status&&envelope.status!=='OK')throw new StreamError('update_stream_rejected');
   if(envelope.type==='messenger'){
    if(typeof envelope.data_enc!=='string')throw new StreamError('invalid_update_stream');
    const decoded=wire.decrypt(envelope.data_enc,this.#auth,this.#profile),payload=this.#profile===profiles.ANDROID?decoded:decoded?.update_data??decoded;
    if(!payload||typeof payload!=='object'||Array.isArray(payload)||payload.user_guid!==undefined&&payload.user_guid!==this.#self||decoded?.user_guid!==undefined&&decoded.user_guid!==this.#self)throw new StreamError('update_account_mismatch');
    // Native newNotif validates MessengerUpdateObject.user_guid against the
    // logged-in account before handing it to handleMessengerNotification.
    if(this.#profile===profiles.ANDROID&&payload.user_guid!==this.#self)throw new StreamError('update_account_mismatch');
    // The dedicated socket is pinned to the account that authenticated it.
    // If a packet includes an account ID it must match; other chat data drops.
    const projected=updates.updates({update_data:{user_guid:this.#self,call_updates:payload.call_updates,call_signal_data:payload.call_signal_data}},this.#self);
    const nativeAck=this.#profile===profiles.ANDROID&&(projected.call_updates.length||projected.call_signal_data.length)&&envelope.ack_id!==undefined;
    if(nativeAck&&!ackId(envelope.ack_id)){for(const v of projected.call_signal_data)v.data.fill(0);throw new StreamError('invalid_update_stream');}
    const digest=nativeAck?crypto.createHash('sha256').update(JSON.stringify(projected)).digest('hex'):null;
    if(nativeAck&&this.#acks.get(envelope.ack_id)===digest){for(const v of projected.call_signal_data)v.data.fill(0);this.#nativeSend('ack',{ack_id:envelope.ack_id});this.#last=Date.now();return;}
    if(this.#calls.length+projected.call_updates.length>64||this.#signals.length+projected.call_signal_data.length>256||this.#bytes+projected.call_signal_data.reduce((n,v)=>n+v.data.length,0)>48*1024){for(const v of projected.call_signal_data)v.data.fill(0);throw new StreamError('update_queue_full');}
    this.#calls.push(...projected.call_updates);this.#signals.push(...projected.call_signal_data);this.#bytes+=projected.call_signal_data.reduce((n,v)=>n+v.data.length,0);
    if(nativeAck){this.#nativeSend('ack',{ack_id:envelope.ack_id});this.#acks.delete(envelope.ack_id);this.#acks.set(envelope.ack_id,digest);if(this.#acks.size>128)this.#acks.delete(this.#acks.keys().next().value);}
   }
   this.#last=Date.now();this.#ready();
  }catch(e){this.#fail(e instanceof StreamError?e.reason:'invalid_update_stream');}
 }
 read(){if(this.#phase!=='connected')throw new StreamError(this.#reason||'update_stream_closed');const signals=this.#signals.splice(0);this.#bytes=0;
  const data={user_guid:this.#self,call_updates:this.#calls.splice(0),call_signal_data:signals.map(v=>({call_id:v.call_id,data:v.data.toString('base64')}))};for(const v of signals)v.data.fill(0);return {update_data:data};
 }
 #fail(reason){if(['failed','closed'].includes(this.#phase))return;this.#reason=reason;this.#phase='failed';this.#dispose();}
 #dispose(){clearTimeout(this.#timer);clearInterval(this.#heartbeat);this.#unbind?.();this.#unbind=null;this.#reject?.(new StreamError(this.#reason||'closed'));this.#resolve=this.#reject=null;for(const v of this.#signals)v.data.fill(0);this.#signals=[];this.#calls=[];this.#acks.clear();this.#bytes=0;this.#auth='';this.#self='';try{this.#socket?.close();}catch{}}
 close(){if(this.#phase==='closed')return;this.#phase='closed';this.#dispose();}
 get state(){return {phase:this.#phase,reason:this.#reason,queuedCalls:this.#calls.length,queuedSignals:this.#signals.length};}
}
module.exports={SocketUpdates,StreamError,socketEndpoint};
