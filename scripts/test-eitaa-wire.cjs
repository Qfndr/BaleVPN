'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const w=require('../experiments/eitaa/wire.cjs');
const {HttpClient,ENDPOINTS}=require('../experiments/eitaa/http-client.cjs');
const imei='0123456789abcde__web';
function pong(id){return new w.Writer().int(w.IDS.pong).long(1n).long(id).finish();}
function unwrap(body){const r=new w.Reader(body);assert.equal(r.int(),w.IDS.eitaaObject);const token=r.string(),device=r.string(),payload=r.bytes(),layer=r.int(),flags=r.int();r.end();const p=new w.Reader(payload);assert.equal(p.int(),w.IDS.ping);const id=p.long();p.end();return {token,device,layer,flags,id};}
test('TL byte/string lengths cross the 253/254 boundary and preserve strict Unicode and signed longs',()=>{
 for(const n of [0,1,2,3,252,253,254,255,256,4096,65528]){const b=Buffer.alloc(n,0xa5),encoded=new w.Writer().bytes(b).finish(),r=new w.Reader(encoded);assert.deepEqual(r.bytes(),b);r.end();assert.equal(encoded.length%4,0);}
 const r=new w.Reader(new w.Writer().string('آزمایش ✓').long(-(2n**63n)).long(2n**63n-1n).finish());assert.equal(r.string(),'آزمایش ✓');assert.equal(r.long(),-(2n**63n));assert.equal(r.long(),2n**63n-1n);r.end();
 for(const value of [2n**63n,-(2n**63n)-1n,1,'1'])assert.throws(()=>new w.Writer().long(value));
 for(const value of [NaN,2**31,-(2**31)-1,1.5])assert.throws(()=>new w.Writer().int(value));
 assert.throws(()=>new w.Writer().string('\ud800'));assert.throws(()=>new w.Writer().string('a\nb'));assert.throws(()=>new w.Writer().bytes(Buffer.alloc(w.MAX)));
});
test('truncated, noncanonical, padded, invalid UTF-8 and oversized TL frames fail closed',()=>{
 for(const b of [Buffer.alloc(0),Buffer.alloc(3),Buffer.alloc(w.MAX+4)])assert.throws(()=>new w.Reader(b));
 assert.throws(()=>new w.Reader(Buffer.from([255,0,0,0])).bytes());
 assert.throws(()=>new w.Reader(Buffer.from([254,1,0,0])).bytes());
 assert.throws(()=>new w.Reader(Buffer.from([4,1,2,3])).bytes());
 assert.throws(()=>new w.Reader(Buffer.from([1,65,1,0])).bytes());
 assert.throws(()=>new w.Reader(Buffer.from([1,255,0,0])).string());
 const r=new w.Reader(new w.Writer().string('abc').int(2).finish());assert.equal(r.string(),'abc');assert.throws(()=>r.end());
 assert.throws(()=>new w.Reader(new w.Writer().bytes(Buffer.alloc(12)).finish()).bytes(8));
});
test('Eitaa service envelope has explicit layer/flags and independent opaque web device identities',()=>{
 const b=w.envelope(w.ping(0x1234567890abcdefn),{imei});assert.deepEqual(unwrap(b),{token:'',device:imei,layer:135,flags:128,id:0x1234567890abcdefn});
 const ids=new Set(Array.from({length:100},()=>w.deviceId()));assert.equal(ids.size,100);for(const id of ids)assert.match(id,/^[a-z0-9]{15}__web$/);
 for(const opts of [{imei,layer:136},{imei,flags:0},{imei:'../x'},{imei,token:'secret\n'}])assert.throws(()=>w.envelope(w.ping(1n),opts));
 assert.throws(()=>w.envelope(Buffer.alloc(3),{imei}));
});
test('only correlated pong and bounded RPC wrapping are parsed; pong never becomes a login/code response',()=>{
 assert.deepEqual(w.response(pong(-4n)),{type:'pong',messageId:1n,pingId:-4n});
 const packed=Buffer.concat([new w.Writer().int(w.IDS.rpcResult).long(3n).finish(),pong(4n)]);assert.equal(w.response(packed).result.pingId,4n);
 assert.throws(()=>w.response(Buffer.concat([new w.Writer().int(w.IDS.rpcResult).long(1n).finish(),packed])));
 assert.throws(()=>w.response(Buffer.alloc(4)));assert.throws(()=>w.response(Buffer.concat([pong(1n),Buffer.alloc(4)])));
 const e=w.response(new w.Writer().int(w.IDS.eitaaError).int(401).string('secret token raw text').finish());assert.deepEqual(e,{type:'service_error',code:401});assert.ok(!JSON.stringify(e).includes('secret'));
});
test('anonymous HTTPS probe sends exactly one fixed-provider request without phone, auth or telemetry',async()=>{
 let count=0;const client=new HttpClient({fetchImpl:async(url,o)=>{count++;assert.equal(url,ENDPOINTS[0]);assert.equal(o.method,'POST');assert.equal(o.redirect,'error');assert.equal(o.cache,'no-store');assert.equal(o.headers.origin,'https://web.eitaa.com');assert.equal(Object.keys(o.headers).length,3);const a=unwrap(o.body);assert.equal(a.token,'');assert.equal(a.layer,135);assert.equal(a.flags,128);return new Response(pong(a.id));}});
 const result=await client.ping();assert.equal(result.pong,true);assert.ok(result.elapsedMs>=0);assert.equal(count,1);assert.deepEqual(Object.keys(result).sort(),['elapsedMs','pong']);client.close();await assert.rejects(client.ping(),{reason:'closed'});assert.equal(count,1);
});
test('arbitrary URLs, redirects, service errors, correlation failures and raw HTTP errors never produce success',async()=>{
 for(const server of ['http://hasan.eitaa.ir/eitaa/','https://hasan.eitaa.ir.evil.test/eitaa/','https://hasan.eitaa.ir/eitaa/?token=secret','https://127.0.0.1/eitaa/','https://mohsen.eitaa.com/eitaa/'])assert.throws(()=>new HttpClient({server}),{reason:'invalid_server'});
 for(const [response,reason]of [[new Response('secret',{status:403}),'http_error'],[new Response('secret',{status:429}),'rate_limited'],[new Response('secret',{status:302}),'http_error'],[new Response(pong(0n)),'ping_mismatch'],[new Response(new w.Writer().int(w.IDS.error).int(400).string('secret').finish()),'service_rejected']]){
  let count=0;const client=new HttpClient({fetchImpl:async()=>{count++;return response;}});await assert.rejects(client.ping(),e=>e.reason===reason&&!e.message.includes('secret'));assert.equal(count,1);client.close();
 }
});
test('body caps apply to both declared size and streamed bytes; malformed bodies cannot authenticate',async()=>{
 for(const response of [new Response('x',{headers:{'content-length':String(w.MAX+1)}}),new Response(Buffer.alloc(w.MAX+4))]){
  const client=new HttpClient({fetchImpl:async()=>response});await assert.rejects(client.ping(),{reason:'response_too_large'});client.close();
 }
 const client=new HttpClient({fetchImpl:async()=>new Response('HTML error page')});await assert.rejects(client.ping());client.close();
});
test('pending requests serialize, close invalidates late replies, and timeout aborts without retries',async()=>{
 let resolve;const client=new HttpClient({fetchImpl:(_url,o)=>new Promise(r=>{resolve=()=>r(new Response(pong(unwrap(o.body).id)));})});const pending=client.ping();await assert.rejects(client.ping(),{reason:'account_busy'});client.close();resolve();await assert.rejects(pending,{reason:'closed'});
 let count=0;const slow=new HttpClient({fetchImpl:(_url,o)=>{count++;return new Promise((_resolve,reject)=>o.signal.addEventListener('abort',()=>reject(Error('secret transport data')),{once:true}));}});await assert.rejects(slow.ping({timeout:5}),{reason:'timeout'});assert.equal(count,1);slow.close();
});
test('default public probe is offline and rejects unknown command arguments',()=>{
 const {spawnSync}=require('node:child_process');let r=spawnSync(process.execPath,['scripts/probe-eitaa-public.cjs'],{encoding:'utf8'});assert.equal(r.status,0);assert.deepEqual(JSON.parse(r.stdout),{provider:'eitaa',connected:false,method:'ping',otpSubmitted:false});
 r=spawnSync(process.execPath,['scripts/probe-eitaa-public.cjs','--phone=secret'],{encoding:'utf8'});assert.equal(r.status,2);assert.ok(!r.stderr.includes('secret'));
});
test('declaration extraction reads literals without evaluation and rejects conflicts or different source versions',()=>{
 const {definition,extract}=require('./extract-eitaa-schema.cjs'),schema=require('../experiments/eitaa/service-schema.json');
 assert.equal(schema.methods.length,16);assert.equal(schema.constructors.length,15);assert.equal(schema.layer,135);
 assert.equal(schema.methods.find(m=>m.method==='eitaaObject').id,w.IDS.eitaaObject);
 assert.equal(schema.constructors.find(m=>m.predicate==='pong').id,w.IDS.pong);
 const literal='{id:1,method:"ping",params:[],type:"Pong"}';assert.equal(definition('throw Error("never execute");'+literal,'method','ping').id,1);
 assert.equal(definition(literal+literal,'method','ping').id,1);
 assert.throws(()=>definition(literal+literal.replace('id:1','id:2'),'method','ping'));
 assert.throws(()=>definition('{id:(global.pwned=true),method:"ping",params:[],type:"Pong"}','method','ping'));assert.equal(global.pwned,undefined);
 assert.throws(()=>extract(literal));
});
