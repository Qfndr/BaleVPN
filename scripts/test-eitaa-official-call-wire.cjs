// Offline protocol parity. Executes only the pinned pure serializer class;
// never starts a worker, connects, reads a session or sends a provider request.
'use strict';
const fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {callSchema,definition,SHA}=require('./extract-eitaa-schema.cjs');
const source=fs.readFileSync(process.env.BALEVPN_EITAA_WORKER||'','utf8');
assert.equal(crypto.createHash('sha256').update(source).digest('hex'),SHA);
const schema=callSchema(source);assert.deepEqual(schema,require('../experiments/eitaa/call-schema.json'));
const codec=require('../experiments/eitaa/call-wire.cjs'),f=require('./eitaa-call-fixtures.cjs');
const groupEvidence=require('../experiments/eitaa/group-call-route-evidence-2026-11-04.json').offlineReadOnlyFixture;
const readGroup=definition(source,'method',groupEvidence.method);
const groupInput=definition(source,'predicate','inputGroupCall');
assert.equal(readGroup.id,68699611);assert.equal(groupInput.id,-659913713);
const start=source.indexOf('class Bt{'),end=source.indexOf('class Gt{',start);assert.ok(start>=0&&end>start&&end-start<12000);
const context=vm.createContext({At:{API:{methods:[...schema.methods,readGroup],constructors:schema.constructors}},Uint8Array,ArrayBuffer,Int32Array,Float64Array,encodeURIComponent,unescape,He:v=>v!==null&&typeof v==='object',Mr:481674261,_r:schema.constructors.find(c=>c.predicate==='boolTrue').id,yr:schema.constructors.find(c=>c.predicate==='boolFalse').id});
vm.runInContext(source.slice(start,end)+';globalThis.OfficialWriter=Bt;',context,{timeout:1000});
function value(v){if(typeof v==='bigint'){const n=BigInt.asUintN(64,v);return [Number(n>>32n),Number(n&0xffffffffn)];}if(v instanceof Uint8Array)return v;if(Array.isArray(v))return v.map(value);if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).map(([k,v])=>[k,value(v)]));return v;}
for(const [name,input]of Object.entries(f.inputs)){const official=new context.OfficialWriter();official.storeMethod(name,value(input));assert.deepEqual(Buffer.from(official.getBytes()),codec.method(name,input));}
const groupFixture={call:{_:'inputGroupCall',id:0x0123456789abcde0n,access_hash:-42n},limit:0};
const groupCodec=require('../experiments/eitaa/tl-codec.cjs').createCodec({methods:[readGroup],constructors:[groupInput],responseAliases:{}});
const officialGroup=new context.OfficialWriter();officialGroup.storeMethod(readGroup.method,value(groupFixture));
const groupBytes=groupCodec.method(readGroup.method,groupFixture);
assert.deepEqual(Buffer.from(officialGroup.getBytes()),groupBytes);
assert.equal(groupBytes.toString('hex'),groupEvidence.requestHex);
assert.equal(crypto.createHash('sha256').update(groupBytes).digest('hex'),groupEvidence.requestSha256);
assert.throws(()=>codec.method(readGroup.method,groupFixture));
const difference={_:'updates.difference',new_messages:[{_:'message',id:7,peer_id:{_:'peerUser',user_id:101n},date:f.state.date,message:'fixture سلام'}],new_encrypted_messages:[],other_updates:[{_:'updatePhoneCall',phone_call:f.requested},{_:'updatePhoneCallSignalingData',phone_call_id:f.peer.id,data:Buffer.alloc(64,7)}],chats:[],users:[],state:f.state};
const responses=[f.wrap(f.waiting),f.wrap(f.accepted),f.wrap(f.active),f.updates([{_:'updatePhoneCall',phone_call:f.discarded}]),difference,f.state,{_:'dataJSON',data:'{}'},{_:'messages.dhConfig',g:3,p:Buffer.alloc(256,3),version:1,random:Buffer.alloc(256,1)},{_:'geoPoint',long:51.25,lat:35.75,access_hash:-3n}];
const user={_:'user',id:202n,access_hash:-22n,username:'FixtureTarget'};
responses.push({_:'contacts.contacts',contacts:[{_:'contact',user_id:202n,mutual:true}],users:[user]},{_:'contacts.resolvedPeer',peer:{_:'peerUser',user_id:202n},chats:[],users:[user]});
for(const response of responses){const official=new context.OfficialWriter();official.storeObject(value(response),'Object');const binary=Buffer.from(official.getBytes());assert.deepEqual(binary,codec.object(response));assert.deepEqual(codec.decode(binary),response);}
console.log('PASS pinned official Eitaa call wire: 12 call requests, 1 test-only group read, 11 responses; no network or real account data');
