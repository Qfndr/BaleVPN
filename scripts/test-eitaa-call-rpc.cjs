'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const codec=require('../experiments/eitaa/call-wire.cjs'),wire=require('../experiments/eitaa/wire.cjs');
const {CallClient,protocol}=require('../experiments/eitaa/call-client.cjs');
const f=require('./eitaa-call-fixtures.cjs');
const imei='0123456789abcde__web';
function unpack(body){const r=new wire.Reader(body);assert.equal(r.int(),wire.IDS.eitaaObject);const value={token:r.string(),imei:r.string(),packed:r.bytes(),layer:r.int(),flags:r.int()};r.end();return value;}
test('call schema includes complete update dependencies, exact long call IDs and bounded double primitives',()=>{
 const schema=require('../experiments/eitaa/call-schema.json');assert.equal(schema.methods.length,12);assert.equal(schema.constructors.length,499);
 for(const value of [f.waiting,f.requested,f.accepted,f.active,f.discarded,f.state,f.wrap(f.active),f.updates([{_:'updatePhoneCall',phone_call:f.active},{_:'updatePhoneCallSignalingData',phone_call_id:f.peer.id,data:Buffer.alloc(50)}])])assert.deepEqual(codec.decode(codec.object(value)),value);
 const geo={_:'geoPoint',long:51.25,lat:35.75,access_hash:-3n};assert.deepEqual(codec.decode(codec.object(geo)),geo);
 for(const value of [NaN,Infinity,-Infinity])assert.throws(()=>new wire.Writer().double(value),{reason:'invalid_double'});
 const invalid=Buffer.alloc(8);invalid.writeDoubleLE(Infinity);assert.throws(()=>new wire.Reader(invalid).double(),{reason:'invalid_double'});
});
test('all call requests encode and mismatched responses, nested RPCs, unknown flags and trailing bytes fail closed',()=>{
 for(const [name,input]of Object.entries(f.inputs))assert.ok(codec.method(name,input).length>0);
 assert.throws(()=>codec.method('auth.signIn',{}),{reason:'invalid_method'});
 assert.throws(()=>codec.response(codec.object(f.state),'phone.requestCall'),{reason:'unexpected_constructor'});
 const active=codec.object(f.active),bad=Buffer.from(active);bad.writeInt32LE(1<<30,4);assert.throws(()=>codec.decode(bad),{reason:'unknown_flags'});
 for(let size=4;size<active.length;size+=4)assert.throws(()=>codec.decode(active.subarray(0,size)));
 assert.throws(()=>codec.decode(Buffer.concat([active,Buffer.alloc(4)])),{reason:'trailing_data'});
 const h=new wire.Writer().int(wire.IDS.rpcResult).long(1n).finish();assert.throws(()=>codec.response(Buffer.concat([h,h,codec.object(f.wrap(f.waiting))]),'phone.requestCall'),{reason:'nesting_limit'});
 assert.throws(()=>codec.object(f.updates(Array(257).fill({_:'updatePhoneCall',phone_call:f.active}))),{reason:'invalid_vector'});
});
test('call differences retain call events alongside unrelated messages and final/intermediate cursors',()=>{
 const message={_:'message',id:45,peer_id:{_:'peerUser',user_id:101n},date:f.state.date,message:'fixture سلام'};
 for(const type of ['updates.difference','updates.differenceSlice']){
  const value={_:type,new_messages:[message],new_encrypted_messages:[],other_updates:[{_:'updatePhoneCall',phone_call:f.requested},{_:'updatePhoneCallSignalingData',phone_call_id:f.peer.id,data:Buffer.alloc(50)}],chats:[],users:[],[type==='updates.difference'?'state':'intermediate_state']:f.state};
  assert.deepEqual(codec.response(codec.object(value),'updates.getDifference'),value);
 }
 for(const value of [{_:'updates.differenceEmpty',date:f.state.date,seq:2},{_:'updates.differenceTooLong',pts:100}])assert.deepEqual(codec.response(codec.object(value),'updates.getDifference'),value);
});
test('legacy duplicate predicates decode by ID while encoding follows the first official API declaration',()=>{
 const schema=require('../experiments/eitaa/call-schema.json'),{createCodec}=require('../experiments/eitaa/tl-codec.cjs');
 const definitions=schema.constructors.filter(c=>c.predicate==='document');assert.equal(definitions.length,3);
 const canonical={_:'document',id:4n,access_hash:-5n,file_reference:Buffer.alloc(0),date:f.state.date,mime_type:'application/octet-stream',size:123,dc_id:1,attributes:[]};
 assert.equal(codec.object(canonical).readInt32LE(),definitions[0].id);assert.deepEqual(codec.decode(codec.object(canonical)),canonical);
 const legacy={_:'document',id:4n,access_hash:-5n,date:f.state.date,mime_type:'application/octet-stream',size:123,thumb:{_:'photoSizeEmpty',type:'s'},dc_id:1,version:1,attributes:[]};
 const legacyCodec=createCodec({...schema,constructors:schema.constructors.filter(c=>c.predicate!=='document'||c.id===definitions[1].id)});
 assert.deepEqual(codec.decode(legacyCodec.object(legacy)),legacy);
 assert.throws(()=>codec.object(legacy),{reason:'invalid_field'});
 assert.throws(()=>createCodec({...schema,constructors:[...schema.constructors,schema.constructors[0]]}),{reason:'conflicting_schema'});
});
test('authenticated call RPCs use independent saved account identities and fixed relay-only protocol',async()=>{
 const seen=[];const fetchImpl=async(_url,o)=>{seen.push(unpack(o.body));return new Response(codec.object(f.wrap(f.waiting)));};
 const a=new CallClient({imei,token:'fixture-token-a',fetchImpl}),b=new CallClient({imei:'fedcba987654321__web',token:'fixture-token-b',fetchImpl});
 await Promise.all([a.request('phone.requestCall',{user_id:f.user,g_a_hash:f.requested.g_a_hash}),b.request('phone.requestCall',{user_id:f.user,g_a_hash:f.requested.g_a_hash})]);
 assert.deepEqual(seen.map(v=>[v.imei,v.token]),[[imei,'fixture-token-a'],['fedcba987654321__web','fixture-token-b']]);
 for(const v of seen){const r=new wire.Reader(v.packed);assert.equal(r.int(),1124046573);assert.equal(r.int(),0);assert.equal(r.int(),-233744186);assert.equal(r.long(),f.user.user_id);assert.equal(r.long(),f.user.access_hash);r.int();assert.deepEqual(r.bytes(),f.requested.g_a_hash);assert.equal(r.int(),-58224696);assert.equal(r.int(),2);assert.equal(r.int(),92);assert.equal(r.int(),92);assert.equal(r.int(),481674261);assert.equal(r.int(),1);assert.equal(r.string(),'4.0.0');r.end();}
 assert.equal(protocol().udp_p2p,undefined);a.close();b.close();
});
test('call API adds only reviewed defaults; signaling and updates use authenticated envelopes',async()=>{
 const cases=[
 ['messages.getDhConfig',{},f.inputs['messages.getDhConfig'],{_:'messages.dhConfig',g:3,p:Buffer.alloc(256,3),version:1,random:Buffer.alloc(256,1)}],
 ['phone.getCallConfig',{}, {},{_:'dataJSON',data:'{}'}],
 ['phone.acceptCall',{peer:f.peer,g_b:f.accepted.g_b},f.inputs['phone.acceptCall'],f.wrap(f.accepted)],
 ['phone.confirmCall',{peer:f.peer,g_a:f.active.g_a_or_b,key_fingerprint:f.active.key_fingerprint},f.inputs['phone.confirmCall'],f.wrap(f.active)],
 ['phone.receivedCall',{peer:f.peer},f.inputs['phone.receivedCall'],{_:'boolTrue'}],
 ['phone.sendSignalingData',{peer:f.peer,data:Buffer.alloc(50,7)},f.inputs['phone.sendSignalingData'],{_:'boolTrue'}],
 ['phone.discardCall',{peer:f.peer,duration:5,reason:'phoneCallDiscardReasonHangup'},f.inputs['phone.discardCall'],f.updates([{_:'updatePhoneCall',phone_call:f.discarded}])],
 ['updates.getState',{}, {},f.state],
 ['contacts.getContacts',{},f.inputs['contacts.getContacts'],{_:'contacts.contacts',contacts:[{_:'contact',user_id:202n,mutual:true}],users:[{_:'user',id:202n,access_hash:-22n}]}],
 ['contacts.resolveUsername',{username:'FixtureTarget'},f.inputs['contacts.resolveUsername'],{_:'contacts.resolvedPeer',peer:{_:'peerUser',user_id:202n},chats:[],users:[{_:'user',id:202n,access_hash:-22n,username:'FixtureTarget'}]}],
 ['updates.getDifference',{pts:10,date:f.state.date,qts:-1},f.inputs['updates.getDifference'],{_:'updates.differenceEmpty',date:f.state.date,seq:2}]
 ];
 for(const [name,input,expected,reply]of cases){let n=0;const c=new CallClient({imei,token:'fixture-token',fetchImpl:async(_url,o)=>{n++;const v=unpack(o.body);assert.deepEqual(v.packed,codec.method(name,expected));assert.equal(v.token,'fixture-token');assert.equal(v.layer,135);assert.equal(v.flags,128);return new Response(codec.object(reply));}});const result=await c.request(name,input);assert.deepEqual(result,reply._==='boolTrue'?true:reply);assert.equal(n,1);c.close();}
});
test('unrelated API, malformed peers, weak payload sizes, protocol overrides and invalid cursors never reach network',async()=>{
 for(const options of [{imei,token:''},{imei,token:'secret\n'},{imei:'bad',token:'x'},{imei,token:'x',provider:'rubika'}])assert.throws(()=>new CallClient(options),{reason:'invalid_credentials'});
 let n=0;const c=new CallClient({imei,token:'fixture-token',fetchImpl:async()=>{n++;throw Error('unexpected request');}});
 const requests=[['auth.signIn',{}],['constructor',{}],['phone.requestCall',{user_id:f.user,g_a_hash:Buffer.alloc(31)}],['phone.requestCall',{user_id:{...f.user,access_hash:0n},g_a_hash:Buffer.alloc(32)}],['phone.requestCall',{user_id:f.user,g_a_hash:Buffer.alloc(32),protocol:{udp_p2p:true}}],['phone.acceptCall',{peer:f.peer,g_b:Buffer.alloc(255)}],['phone.confirmCall',{peer:f.peer,g_a:Buffer.alloc(256),key_fingerprint:1}],['phone.receivedCall',{peer:{...f.peer,id:-1n}}],['phone.receivedCall',{peer:{...f.peer,extra:true}}],['phone.sendSignalingData',{peer:f.peer,data:Buffer.alloc(20)}],['phone.sendSignalingData',{peer:f.peer,data:Buffer.alloc(48*1024+21)}],['phone.discardCall',{peer:f.peer,duration:-1,reason:'phoneCallDiscardReasonHangup'}],['phone.discardCall',{peer:f.peer,duration:0,reason:'__proto__'}],['updates.getDifference',{pts:1,date:1,qts:-2}],['messages.getDhConfig',{random_length:1}]];
 requests.push(['contacts.importContacts',{contacts:[]}],['contacts.getContacts',{hash:0n}],['contacts.resolveUsername',{username:'@private'}],['contacts.resolveUsername',{username:'http://private.invalid'}]);
 for(const [name,input]of requests)await assert.rejects(c.request(name,input));assert.equal(n,0);c.close();
});
test('call failures expose bounded metadata without raw secrets and never refresh, redial or retry',async()=>{
 for(const [reply,reason]of [[{_:'error',code:400,text:'private-number-token-call'},'service_rejected'],[{_:'eitta_error',code:420,text:'FLOOD_WAIT_123'},'rate_limited'],[{_:'eitaa_updates_expire_token'},'session_refresh_required'],[{_:'pong',msg_id:1n,ping_id:2n},'unexpected_acknowledgement']]){
  let n=0;const c=new CallClient({imei,token:'fixture-token',fetchImpl:async()=>{n++;return new Response(codec.object(reply));}});
  await assert.rejects(c.request('phone.receivedCall',{peer:f.peer}),e=>{assert.equal(e.reason,reason);assert.ok(!e.message.includes('private-number'));assert.ok(!JSON.stringify(e).includes('private-number'));return true;});assert.equal(n,1);c.close();
 }
});
test('single-request boundary and close cancel a late call reply before it can be adopted',async()=>{
 let finish;const c=new CallClient({imei,token:'fixture-token',fetchImpl:()=>new Promise(resolve=>{finish=()=>resolve(new Response(codec.object(f.wrap(f.waiting))));})});
 const pending=c.request('phone.requestCall',{user_id:f.user,g_a_hash:Buffer.alloc(32)});await assert.rejects(c.request('updates.getState'),{reason:'account_busy'});c.close();finish();await assert.rejects(pending,{reason:'closed'});await assert.rejects(c.request('updates.getState'),{reason:'closed'});
});
