'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {SocketUpdates,socketEndpoint}=require('../experiments/rubika/socket-updates.cjs'),wire=require('../experiments/rubika/wire.cjs');
const credentials={provider:'rubika',userId:'fixture_account_01',auth:'abcdefghijklmnopqrstuvwxyz012345'};
class Socket extends EventTarget{static all=[];sent=[];closed=false;constructor(url){super();this.url=url;Socket.all.push(this);queueMicrotask(()=>this.dispatchEvent(new Event('open')));}send(value){this.sent.push(JSON.parse(value));}message(value){this.dispatchEvent(new MessageEvent('message',{data:typeof value==='string'?value:JSON.stringify(value)}));}close(){this.closed=true;this.dispatchEvent(new Event('close'));}}
async function fixture(){const start=SocketUpdates.open(credentials,{url:'wss://jsocket5.iranlms.ir:80',WebSocketImpl:Socket});const socket=Socket.all.at(-1);await Promise.resolve();socket.message({});return {channel:await start,socket};}
test('socket URLs pin TLS provider domains and allow only observed standard/TLS-on-80 ports',()=>{
 assert.equal(socketEndpoint('wss://jsocket5.iranlms.ir:80'),'wss://jsocket5.iranlms.ir:80/');for(const url of ['ws://jsocket5.iranlms.ir','wss://iranlms.ir.attacker.invalid','wss://user:secret@jsocket5.iranlms.ir','wss://jsocket5.iranlms.ir:1234','wss://jsocket5.iranlms.ir/?auth=secret','wss://127.0.0.1'])assert.throws(()=>socketEndpoint(url));
});
test('official v5 handshake binds the account and an idle queue performs no HTTP polling or dialing',async()=>{
 const f=await fixture();try{assert.deepEqual(f.socket.sent,[{api_version:'5',auth:credentials.auth,data:'',method:'handShake'}]);assert.deepEqual(f.channel.read(),{update_data:{user_guid:credentials.userId,call_updates:[],call_signal_data:[]}});assert.ok(!JSON.stringify(f.channel.state).includes(credentials.auth));}finally{f.channel.close();}assert.equal(f.socket.closed,true);
});
test('encrypted socket notifications retain only bounded call fields and wipe drained signal buffers',async()=>{
 const f=await fixture();try{f.socket.message({type:'messenger',data_enc:wire.encrypt({user_guid:credentials.userId,call_signal_data:[{call_id:'fixture_call_01',data:'YQ=='}],message_updates:[{text:'private-chat'}]},credentials.auth)});const reply=f.channel.read();assert.deepEqual(reply.update_data.call_signal_data,[{call_id:'fixture_call_01',data:'YQ=='}]);assert.ok(!JSON.stringify(reply).includes('private-chat'));assert.equal(f.channel.state.queuedSignals,0);}finally{f.channel.close();}
});
test('Android notification decryption retains canonical wrapped framing and rejects an unknown stored profile before opening a socket',async()=>{
 const record={...credentials,profile:{protocolProfile:'android-4.1.1-compat'}},opening=SocketUpdates.open(record,{url:'wss://jsocket5.iranlms.ir:80',WebSocketImpl:Socket}),socket=Socket.all.at(-1);await Promise.resolve();socket.message({});const channel=await opening;
 try{socket.message({type:'messenger',data_enc:wire.encrypt({user_guid:record.userId,call_signal_data:[{call_id:'fixture_call_01',data:'YQ=='}]},record.auth,'android-4.1.1-compat')});assert.deepEqual(channel.read().update_data.call_signal_data,[{call_id:'fixture_call_01',data:'YQ=='}]);}finally{channel.close();}
 const count=Socket.all.length;await assert.rejects(SocketUpdates.open({...record,profile:{protocolProfile:'unknown'}},{url:'wss://jsocket5.iranlms.ir:80',WebSocketImpl:Socket}),/invalid_credentials/);assert.equal(Socket.all.length,count);
});

async function nativeFixture(language='fa'){
 const record={...credentials,profile:{protocolProfile:'android-4.1.1-compat'}},opening=SocketUpdates.open(record,{url:'wss://jsocket5.iranlms.ir:80',WebSocketImpl:Socket,language}),socket=Socket.all.at(-1),channel=await opening;return {record,socket,channel};
}
const nativePacket=(record,ack_id,body)=>({type:'messenger',ack_id,data_enc:wire.encrypt({user_guid:record.userId,...body},record.auth,'android-4.1.1-compat')});
test('native notification handshake uses exact raw Gson v4 fields and version-2 JSON data, with no fabricated application acknowledgement',async()=>{
 const f=await nativeFixture('en');try{
  assert.deepEqual(f.socket.sent,[{api_version:'4',auth:credentials.auth,client:{app_name:'Main',app_version:'4.1.1',platform:'Android',package:'app.rbmain.a',lang_code:'en'},data:'{"version":"2"}',is_background:false,method:'handShake'}]);
  assert.equal(f.channel.state.phase,'connected');assert.equal(Object.hasOwn(f.socket.sent[0].client,'packageName'),false);assert.ok(!JSON.stringify(f.channel.state).includes(credentials.auth));
 }finally{f.channel.close();}
});
test('native ACK follows only validated account-bound call projection and deduplicates call data while re-acknowledging delivery',async()=>{
 const f=await nativeFixture();try{
  f.socket.message(nativePacket(f.record,'ack_1',{user_guid:credentials.userId,call_signal_data:[{call_id:'fixture_call_01',data:'YQ=='}],message_updates:[{text:'private-chat'}]}));
  assert.equal(f.socket.sent.length,2);assert.equal(f.socket.sent[1].method,'ack');assert.equal(f.socket.sent[1].api_version,'4');assert.deepEqual(JSON.parse(f.socket.sent[1].data),{ack_id:'ack_1'});assert.equal(f.socket.sent[1].auth,credentials.auth);
  f.socket.message(nativePacket(f.record,'ack_1',{user_guid:credentials.userId,call_signal_data:[{call_id:'fixture_call_01',data:'YQ=='}]}));assert.equal(f.socket.sent.length,3);assert.equal(f.channel.read().update_data.call_signal_data.length,1);assert.equal(f.channel.read().update_data.call_signal_data.length,0);
  f.socket.message(nativePacket(f.record,'ack_1',{user_guid:credentials.userId,call_signal_data:[{call_id:'fixture_call_01',data:'Yg=='}]}));assert.equal(f.channel.read().update_data.call_signal_data[0].data,'Yg==','a reused ID with changed valid call data must not silently lose the update');
  const before=f.socket.sent.length;f.socket.message(nativePacket(f.record,'chat_ack',{user_guid:credentials.userId,message_updates:[{text:'unrelated'}]}));assert.equal(f.socket.sent.length,before);assert.ok(!JSON.stringify(f.channel.read()).includes('unrelated'));
 }finally{f.channel.close();}
});
test('native invalid account, malformed call data and invalid ACK IDs never receive an ACK',async()=>{
 for(const [id,body] of [['ok',{user_guid:'fixture_other_02',call_signal_data:[{call_id:'fixture_call_01',data:'YQ=='}]}],['x'.repeat(257),{call_signal_data:[{call_id:'fixture_call_01',data:'YQ=='}]}],['bad\nack',{call_signal_data:[{call_id:'fixture_call_01',data:'YQ=='}]}]]){
  const f=await nativeFixture();f.socket.message(nativePacket(f.record,id,body));assert.equal(f.channel.state.phase,'failed');assert.equal(f.socket.sent.length,1);assert.equal(f.socket.closed,true);f.channel.close();
 }
 const f=await nativeFixture();f.socket.message({type:'messenger',ack_id:'bad_cipher',data_enc:'bad'});assert.equal(f.socket.sent.length,1);assert.equal(f.channel.state.phase,'failed');f.channel.close();
 for(const body of [{call_signal_data:[{call_id:'fixture_call_01',data:'YQ=='}]},{update_data:{user_guid:credentials.userId,call_signal_data:[{call_id:'fixture_call_01',data:'YQ=='}]}}]){const f=await nativeFixture();f.socket.message({type:'messenger',ack_id:'missing_identity',data_enc:wire.encrypt(body,f.record.auth,'android-4.1.1-compat')});assert.equal(f.channel.state.reason,'update_account_mismatch');assert.equal(f.socket.sent.length,1);f.channel.close();}
});
test('native ACK history has bounded eviction and Gson string escaping preserves the exact private ACK identifier',async()=>{
 const f=await nativeFixture();try{
  const body={call_signal_data:[{call_id:'fixture_call_01',data:'YQ=='}]};
  for(let i=0;i<130;i++){f.socket.message(nativePacket(f.record,'id_'+i,body));assert.equal(f.channel.read().update_data.call_signal_data.length,1);}
  f.socket.message(nativePacket(f.record,'id_129',body));assert.equal(f.channel.read().update_data.call_signal_data.length,0);
  f.socket.message(nativePacket(f.record,'id_0',body));assert.equal(f.channel.read().update_data.call_signal_data.length,1);
  const special="ack<&='>";f.socket.message(nativePacket(f.record,special,body));const sent=f.socket.sent.at(-1);assert.equal(JSON.parse(sent.data).ack_id,special);assert.ok(sent.data.includes('\\u003c'));assert.ok(!JSON.stringify(f.channel.state).includes(special));
 }finally{f.channel.close();}
});
test('HTTP notification setup forwards its selected language without changing Web or native account records',async()=>{
 const {HttpClient}=require('../experiments/rubika/http-client.cjs');for(const mode of ['web','android-4.1.1-compat']){
  const record={...credentials,profile:{protocolProfile:mode}},snapshot=JSON.stringify(record);let options;
  const client=new HttpClient({language:'en',protocolProfile:mode,fetchImpl:()=>{throw Error('No HTTP request allowed');},updatesFactory:async(_binding,value)=>{options=value;return {close(){},read(){return {};}};}});
  try{await client.startUpdates(record);assert.equal(options.language,'en');assert.equal(JSON.stringify(record),snapshot);}finally{client.close();}
 }
});
test('mismatched account IDs and corrupt or oversized packets close the account event stream',async()=>{
 for(const packet of [{type:'messenger',data_enc:wire.encrypt({user_guid:'fixture_other_02'},credentials.auth)},{type:'messenger',data_enc:'corrupt'},'x'.repeat(512*1024+1)]){const f=await fixture();f.socket.message(packet);assert.equal(f.channel.state.phase,'failed');assert.throws(()=>f.channel.read());assert.equal(f.socket.closed,true);f.channel.close();}
});
test('aggregate event buffers are bounded and cannot grow while the call consumer is idle',async()=>{
 const f=await fixture();const packet={type:'messenger',data_enc:wire.encrypt({call_signal_data:[{call_id:'fixture_call_01',data:Buffer.alloc(30000).toString('base64')}]},credentials.auth)};f.socket.message(packet);f.socket.message(packet);assert.equal(f.channel.state.reason,'update_queue_full');assert.equal(f.channel.state.queuedSignals,0);f.channel.close();
});
test('abort during authentication closes promptly and a late packet cannot resurrect the stream',async()=>{
 const abort=new AbortController(),opening=SocketUpdates.open(credentials,{url:'wss://jsocket5.iranlms.ir:80',WebSocketImpl:Socket,signal:abort.signal}),socket=Socket.all.at(-1);abort.abort();await assert.rejects(opening,/closed/);socket.message({});assert.equal(socket.closed,true);
});
