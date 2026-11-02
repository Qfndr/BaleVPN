const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {wire:w}=require('../experiments/igap/signaling.cjs');
const security=require('../experiments/igap/secure-connection.cjs');
const {Connection}=require('../experiments/igap/rpc-connection.cjs');
const inner=crypto.generateKeyPairSync('rsa',{modulusLength:1024}),outer=crypto.generateKeyPairSync('rsa',{modulusLength:2048}),params={method:'AES-256-CBC',ivSize:16};
function unpad(key,data){const b=crypto.privateDecrypt({key,padding:crypto.constants.RSA_NO_PADDING},data);return b.subarray(b.indexOf(0,2)+1);}
class FakeSocket{
 static instances=[];handlers={};requests=[];closed=false;
 constructor(){FakeSocket.instances.push(this);queueMicrotask(()=>this.emit(w.frame(30001,Buffer.concat([w.string(2,inner.publicKey.export({type:'spki',format:'pem'}),8192),w.field(3,32,0),w.field(4,60,0),w.field(6,64,0)]))));}
 addEventListener(type,fn){(this.handlers[type]??=[]).push(fn);}
 emit(bytes){const b=Uint8Array.from(bytes);for(const fn of this.handlers.message||[])fn({data:b.buffer});}
 send(bytes){if(!this.key){const payload=w.one(w.parse(Buffer.from(bytes).subarray(2)),2,2);this.key=unpad(inner.privateKey,Buffer.concat([unpad(outer.privateKey,payload.subarray(0,256)),unpad(outer.privateKey,payload.subarray(256))]));queueMicrotask(()=>this.emit(w.frame(30002,Buffer.concat([w.field(2,1,0),w.string(3,params.method,64),w.field(4,16,0)]))));}else{const p=security.decryptPacket(bytes,this.key,params),f=w.parse(p.subarray(2));this.requests.push({action:p.readUInt16LE(),id:w.str(w.parse(w.one(f,1,2)),1,128),fields:f});}}
 respond(request,action,fields=Buffer.alloc(0)){this.emit(security.encryptPacket(w.frame(action,Buffer.concat([w.field(1,w.string(1,request.id,128)),fields])),this.key,params));}
 close(){this.closed=true;this.key?.fill(0);}
}
async function open(){const c=await Connection.open({WebSocketImpl:FakeSocket,rootKey:outer.publicKey.export({type:'spki',format:'pem'})});return [c,FakeSocket.instances.at(-1)];}
test('encrypted concurrent responses correlate by request ID and separate account channels',async()=>{
 const [a,sa]=await open(),[b,sb]=await open();try{
  const p1=a.request(506),p2=a.request(914,w.field(2,9,0),{token:'account-A'}),p3=b.request(506);
  assert.equal(sa.requests.length,2);assert.equal(sb.requests.length,1);assert.notDeepEqual(sa.key,sb.key);
  sa.respond(sa.requests[1],30914,w.string(2,'room-token',100));sa.respond(sa.requests[0],30506);sb.respond(sb.requests[0],30506);
  const results=await Promise.all([p1,p2,p3]);assert.deepEqual(results.map(r=>r.action),[30506,30914,30506]);assert.equal(a.status.pending,0);
  const encoded=JSON.stringify(a.status);for(const secret of ['account-A','room-token'])assert.ok(!encoded.includes(secret));
 }finally{a.close();b.close();}
});
test('timeout expires one request without retransmission or breaking the channel',async()=>{
 const [c,s]=await open();try{await assert.rejects(c.request(100,Buffer.alloc(0),{timeout:10}),e=>e.reason==='timeout');assert.equal(s.requests.length,1);s.respond(s.requests[0],30100);assert.equal(c.status.phase,'ready');assert.equal(c.status.pending,0);}finally{c.close();}
});
test('malformed error response rejects every waiter and closes rather than hanging a removed request',async()=>{
 const [c,s]=await open();const a=c.request(506),b=c.request(914,w.field(2,9,0));const results=Promise.allSettled([a,b]);s.respond(s.requests[0],0,w.string(2,'invalid-major-type',64));
 const settled=await results;assert.ok(settled.every(x=>x.status==='rejected'));assert.equal(c.status.phase,'closed');assert.equal(c.status.pending,0);assert.ok(s.key.every(x=>x===0));
});
test('provider errors expose numeric codes, never server text, and explicit close drains pending requests',async()=>{
 const [c,s]=await open();const p=c.request(506);s.respond(s.requests[0],0,Buffer.concat([w.field(2,403,0),w.field(3,2,0),w.field(4,30,0),w.string(5,'secret-provider-payload',100)]));await assert.rejects(p,e=>e.major===403&&e.minor===2&&e.waitSeconds===30&&!e.message.includes('secret'));
 const pending=c.request(506);c.close();await assert.rejects(pending,e=>e.reason==='closed');await assert.rejects(c.request(506),e=>e.reason==='not_connected');
});
test('inherited TLS verification bypass is refused before constructing a transport',async()=>{
 const previous=process.env.NODE_TLS_REJECT_UNAUTHORIZED,before=FakeSocket.instances.length;process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';
 try{await assert.rejects(Connection.open({WebSocketImpl:FakeSocket}),e=>e.reason==='tls_verification_disabled');assert.equal(FakeSocket.instances.length,before);}
 finally{if(previous===undefined)delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;else process.env.NODE_TLS_REJECT_UNAUTHORIZED=previous;}
});
test('login sends the current connection key only inside its encrypted RPC and rejects a supplied replacement',async()=>{
 const [c,s]=await open();try{const login=c.login(w.string(2,'fixture-session-token',100));const request=s.requests.at(-1);assert.equal(request.action,102);assert.deepEqual(w.one(request.fields,12,2),s.key);assert.equal(w.str(request.fields,2,100),'fixture-session-token');s.respond(request,30102,w.field(14,41,0));await login;const before=s.requests.length;await assert.rejects(c.login(w.field(12,Buffer.alloc(32))),e=>e.reason==='invalid_request');assert.equal(s.requests.length,before);}finally{c.close();}
});
test('invalid and overflowing requests never reach the transport',async()=>{
 const [c,s]=await open();try{
  await assert.rejects(c.request(999));await assert.rejects(c.request(506,w.field(1,Buffer.alloc(0))));await assert.rejects(c.request(506,Buffer.alloc(60000)));
  const pending=Array.from({length:32},()=>c.request(506));const settled=Promise.allSettled(pending);await assert.rejects(c.request(506),e=>e.reason==='too_many_requests');assert.equal(s.requests.length,32);c.close();await settled;
 }finally{c.close();}
});
