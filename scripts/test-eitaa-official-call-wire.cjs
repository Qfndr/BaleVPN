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
const groupLookupMethods=['messages.getFullChat','channels.getFullChannel'].map(name=>definition(source,'method',name));
assert.deepEqual(groupLookupMethods.map(method=>method.id),[-1364194508,141781513]);
const groupConstructors=new Map(schema.constructors.map(item=>[item.id,item]));
for(const name of ['messages.chatFull','chatFull','channelFull','inputChannel','inputGroupCall',
 'chatParticipantsForbidden','peerNotifySettings','photoEmpty']){
 const item=definition(source,'predicate',name),existing=groupConstructors.get(item.id);
 if(existing)assert.deepEqual(existing,item);else groupConstructors.set(item.id,item);
}
const groupMethods=[readGroup,...groupLookupMethods];
const groupSchema={methods:groupMethods,constructors:[...groupConstructors.values()],responseAliases:{}};
const start=source.indexOf('class Bt{'),end=source.indexOf('class Gt{',start);assert.ok(start>=0&&end>start&&end-start<12000);
const context=vm.createContext({At:{API:{methods:[...schema.methods,...groupMethods],constructors:groupSchema.constructors}},Uint8Array,ArrayBuffer,Int32Array,Float64Array,encodeURIComponent,unescape,He:v=>v!==null&&typeof v==='object',Mr:481674261,_r:schema.constructors.find(c=>c.predicate==='boolTrue').id,yr:schema.constructors.find(c=>c.predicate==='boolFalse').id});
vm.runInContext(source.slice(start,end)+';globalThis.OfficialWriter=Bt;',context,{timeout:1000});
function value(v){if(typeof v==='bigint'){const n=BigInt.asUintN(64,v);return [Number(n>>32n),Number(n&0xffffffffn)];}if(v instanceof Uint8Array)return v;if(Array.isArray(v))return v.map(value);if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).map(([k,v])=>[k,value(v)]));return v;}
for(const [name,input]of Object.entries(f.inputs)){const official=new context.OfficialWriter();official.storeMethod(name,value(input));assert.deepEqual(Buffer.from(official.getBytes()),codec.method(name,input));}
const groupFixture={call:{_:'inputGroupCall',id:0x0123456789abcde0n,access_hash:-42n},limit:0};
const groupCodec=require('../experiments/eitaa/tl-codec.cjs').createCodec(groupSchema);
const officialGroup=new context.OfficialWriter();officialGroup.storeMethod(readGroup.method,value(groupFixture));
const groupBytes=groupCodec.method(readGroup.method,groupFixture);
assert.deepEqual(Buffer.from(officialGroup.getBytes()),groupBytes);
assert.equal(groupBytes.toString('hex'),groupEvidence.requestHex);
assert.equal(crypto.createHash('sha256').update(groupBytes).digest('hex'),groupEvidence.requestSha256);
assert.throws(()=>codec.method(readGroup.method,groupFixture));

// Test-only model. No production method allowlist or network transport is used.
function existingGroupFixture(selected,method,params,fullKind,exchange){
 const metadata=groupCodec.response(exchange(method,groupCodec.method(method,params)),method);
 if(metadata.full_chat?._!==fullKind||metadata.full_chat.id!==selected)throw new Error('Fixture group identity mismatch');
 const call=metadata.full_chat.call;
 if(call===undefined)return {referencePresent:false,groupReadPrepared:false};
 if(call._!=='inputGroupCall'||typeof call.id!=='bigint'||call.id<=0n||typeof call.access_hash!=='bigint')throw new Error('Invalid fixture call reference');
 exchange(readGroup.method,groupCodec.method(readGroup.method,{call,limit:0}));
 return {referencePresent:true,groupReadPrepared:true};
}
const selectedGroup=71003n,privateText='fixture-private-group-about';
const lookupCases=[
 {method:'messages.getFullChat',params:{chat_id:selectedGroup},full:{_:'chatFull',id:selectedGroup,about:privateText,
  participants:{_:'chatParticipantsForbidden',chat_id:selectedGroup},notify_settings:{_:'peerNotifySettings'}}},
 {method:'channels.getFullChannel',params:{channel:{_:'inputChannel',channel_id:selectedGroup,access_hash:-71004n}},
  full:{_:'channelFull',id:selectedGroup,about:privateText,read_inbox_max_id:0,read_outbox_max_id:0,unread_count:0,
   chat_photo:{_:'photoEmpty',id:0n},notify_settings:{_:'peerNotifySettings'},bot_info:[],pts:1}}
];
for(const {method,params,full}of lookupCases){
 const officialRequest=new context.OfficialWriter();officialRequest.storeMethod(method,value(params));
 const expectedRequest=Buffer.from(officialRequest.getBytes());
 assert.throws(()=>codec.method(method,params));
 for(const referencePresent of [true,false]){
  const response={_:'messages.chatFull',full_chat:{...full,...referencePresent?{call:groupFixture.call}:{}},chats:[],
   users:[{_:'user',id:71005n,first_name:'fixture-private-participant'}]};
  const officialReply=new context.OfficialWriter();officialReply.storeObject(value(response),'Object');
  const metadataBytes=Buffer.from(officialReply.getBytes());assert.deepEqual(metadataBytes,groupCodec.object(response));
  const seen=[];
  const summary=existingGroupFixture(selectedGroup,method,params,full._,(operation,request)=>{
   seen.push(operation);
   if(operation===method){assert.deepEqual(request,expectedRequest);return metadataBytes;}
   assert.equal(operation,readGroup.method);assert.deepEqual(request,groupBytes);
  });
  assert.deepEqual(summary,{referencePresent,groupReadPrepared:referencePresent});
  assert.deepEqual(seen,referencePresent?[method,readGroup.method]:[method]);
  for(const privateValue of [privateText,'fixture-private-participant',selectedGroup.toString(),groupFixture.call.id.toString(),'-42'])
   assert.ok(!JSON.stringify(summary).includes(privateValue));
  let invalidReads=0;
  assert.throws(()=>existingGroupFixture(selectedGroup+1n,method,params,full._,()=>{invalidReads++;return metadataBytes;}),/identity mismatch/);
  assert.equal(invalidReads,1);
  assert.throws(()=>existingGroupFixture(selectedGroup,method,params,full._,()=>metadataBytes.subarray(0,-4)),{reason:'truncated_frame'});
 }
}
const difference={_:'updates.difference',new_messages:[{_:'message',id:7,peer_id:{_:'peerUser',user_id:101n},date:f.state.date,message:'fixture سلام'}],new_encrypted_messages:[],other_updates:[{_:'updatePhoneCall',phone_call:f.requested},{_:'updatePhoneCallSignalingData',phone_call_id:f.peer.id,data:Buffer.alloc(64,7)}],chats:[],users:[],state:f.state};
const responses=[f.wrap(f.waiting),f.wrap(f.accepted),f.wrap(f.active),f.updates([{_:'updatePhoneCall',phone_call:f.discarded}]),difference,f.state,{_:'dataJSON',data:'{}'},{_:'messages.dhConfig',g:3,p:Buffer.alloc(256,3),version:1,random:Buffer.alloc(256,1)},{_:'geoPoint',long:51.25,lat:35.75,access_hash:-3n}];
const user={_:'user',id:202n,access_hash:-22n,username:'FixtureTarget'};
responses.push({_:'contacts.contacts',contacts:[{_:'contact',user_id:202n,mutual:true}],users:[user]},{_:'contacts.resolvedPeer',peer:{_:'peerUser',user_id:202n},chats:[],users:[user]});
for(const response of responses){const official=new context.OfficialWriter();official.storeObject(value(response),'Object');const binary=Buffer.from(official.getBytes());assert.deepEqual(binary,codec.object(response));assert.deepEqual(codec.decode(binary),response);}
console.log('PASS pinned official Eitaa call wire: 12 call requests, 11 responses, test-only group read and 2 bounded lookup paths; no network or real account data');
