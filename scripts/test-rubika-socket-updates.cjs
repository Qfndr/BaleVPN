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
test('mismatched account IDs and corrupt or oversized packets close the account event stream',async()=>{
 for(const packet of [{type:'messenger',data_enc:wire.encrypt({user_guid:'fixture_other_02'},credentials.auth)},{type:'messenger',data_enc:'corrupt'},'x'.repeat(512*1024+1)]){const f=await fixture();f.socket.message(packet);assert.equal(f.channel.state.phase,'failed');assert.throws(()=>f.channel.read());assert.equal(f.socket.closed,true);f.channel.close();}
});
test('aggregate event buffers are bounded and cannot grow while the call consumer is idle',async()=>{
 const f=await fixture();const packet={type:'messenger',data_enc:wire.encrypt({call_signal_data:[{call_id:'fixture_call_01',data:Buffer.alloc(30000).toString('base64')}]},credentials.auth)};f.socket.message(packet);f.socket.message(packet);assert.equal(f.channel.state.reason,'update_queue_full');assert.equal(f.channel.state.queuedSignals,0);f.channel.close();
});
test('abort during authentication closes promptly and a late packet cannot resurrect the stream',async()=>{
 const abort=new AbortController(),opening=SocketUpdates.open(credentials,{url:'wss://jsocket5.iranlms.ir:80',WebSocketImpl:Socket,signal:abort.signal}),socket=Socket.all.at(-1);abort.abort();await assert.rejects(opening,/closed/);socket.message({});assert.equal(socket.closed,true);
});
