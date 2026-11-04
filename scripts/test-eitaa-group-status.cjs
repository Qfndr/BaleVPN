// Offline-only runner tests using synthetic records and an injected fetch.
'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const {readGroupStatus}=require('./eitaa-group-status.cjs'),{groupStatusSchema}=require('./extract-eitaa-schema.cjs');
const wire=require('../experiments/eitaa/wire.cjs'),{createCodec}=require('../experiments/eitaa/tl-codec.cjs');
const workerSource=fs.readFileSync(process.env.BALEVPN_EITAA_WORKER||'','utf8');
const codec=createCodec(groupStatusSchema(workerSource)),groupId=71003n,callId=0x0123456789abcde0n,accessHash=-42n;
const reference={_:'inputGroupCall',id:callId,access_hash:accessHash};
const selection={kind:'chat',id:groupId,consent:true};
function session(){return {
 state:{provider:'eitaa',signedIn:true,selfConfirmed:true,busy:false,protocolProfile:'web',userId:'71001'},
 record:{provider:'eitaa',userId:'71001',imei:'0123456789abcde__web',token:'fixture-private-web-token',profile:{protocolProfile:'web'}},
 exportSession(){return {...this.record};}
};}
function metadata(kind='chat',call=reference,id=groupId){
 const common={id,about:'fixture-private-group-about',notify_settings:{_:'peerNotifySettings'},...call?{call}:{}};
 const full_chat=kind==='chat'?{_:'chatFull',...common,participants:{_:'chatParticipantsForbidden',chat_id:id}}:
  {_:'channelFull',...common,read_inbox_max_id:0,read_outbox_max_id:0,unread_count:0,chat_photo:{_:'photoEmpty',id:0n},bot_info:[],pts:1};
 return {_:'messages.chatFull',full_chat,chats:[],users:[{_:'user',id:71002n,first_name:'fixture-private-participant'}]};
}
function group(state='available',id=callId){
 const call=state==='discarded'?{_:'groupCallDiscarded',id,access_hash:accessHash,duration:12}:
  {_:'groupCall',id,access_hash:accessHash,participants_count:1,title:'fixture-private-call-title',unmuted_video_limit:0,version:1};
 return {_:'phone.groupCall',call,participants:[],participants_next_offset:'',chats:[],users:[]};
}
function mock(record,target,replies){
 const seen=[];
 const first=target.kind==='chat'?['messages.getFullChat',{chat_id:target.id}]:
  ['channels.getFullChannel',{channel:{_:'inputChannel',channel_id:target.id,access_hash:target.accessHash}}];
 return {seen,fetchImpl:async(url,options)=>{
  assert.equal(url,'https://hasan.eitaa.ir/eitaa/');assert.equal(options.method,'POST');assert.equal(options.redirect,'error');
  assert.equal(options.headers.origin,'https://web.eitaa.com');
  const reader=new wire.Reader(options.body);
  assert.equal(reader.int(),wire.IDS.eitaaObject);assert.equal(reader.string(),record.token);assert.equal(reader.string(),record.imei);
  const packed=reader.bytes();assert.equal(reader.int(),135);assert.equal(reader.int(),128);reader.end();
  const [method,input]=seen.length?['phone.getGroupCall',{call:reference,limit:0}]:first;
  assert.deepEqual(packed,codec.method(method,input));const reply=replies[seen.length];seen.push(method);
  if(typeof reply==='function')return reply(options);
  return reply instanceof Response?reply:new Response(codec.object(reply));
 }};
}
test('selected normal and channel groups use exact same Web endpoint and private matching references',async()=>{
 for(const target of [selection,{kind:'channel',id:groupId,accessHash:-71004n,consent:true}]){
  const account=session(),retained=JSON.stringify(account.record),f=mock(account.record,target,[metadata(target.kind),group()]);
  const result=await readGroupStatus(account,target,{workerSource,fetchImpl:f.fetchImpl});
  assert.deepEqual(result,{referencePresent:true,groupReadSucceeded:true,groupState:'available'});
  assert.deepEqual(f.seen,[target.kind==='chat'?'messages.getFullChat':'channels.getFullChannel','phone.getGroupCall']);
  assert.equal(JSON.stringify(account.record),retained);
 }
});
test('absent reference stops after metadata and discarded reference produces only safe state',async()=>{
 const account=session();
 const absent=mock(account.record,selection,[metadata('chat',null)]);
 assert.deepEqual(await readGroupStatus(account,selection,{workerSource,fetchImpl:absent.fetchImpl}),
  {referencePresent:false,groupReadSucceeded:false,groupState:'absent'});
 assert.equal(absent.seen.length,1);
 const discarded=mock(account.record,selection,[metadata(),group('discarded')]);
 assert.deepEqual(await readGroupStatus(account,selection,{workerSource,fetchImpl:discarded.fetchImpl}),
  {referencePresent:true,groupReadSucceeded:true,groupState:'discarded'});
});
test('bad metadata, wrong group or mismatched call never passes identity checks',async()=>{
 for(const [replies,reason,count]of [
  [[metadata('chat',reference,groupId+1n)],'group_binding_changed',1],
  [[metadata('channel')],'group_binding_changed',1],
  [[metadata('chat',{...reference,access_hash:0n})],'invalid_call_reference',1],
  [[new Response(Buffer.from([1,2,3]))],'invalid_response',1],
  [[new Response(Buffer.alloc(wire.MAX+1))],'response_too_large',1],
  [[metadata(),group('available',callId+1n)],'call_binding_changed',2]
 ]){
  const account=session(),f=mock(account.record,selection,replies);
  await assert.rejects(readGroupStatus(account,selection,{workerSource,fetchImpl:f.fetchImpl}),{reason});assert.equal(f.seen.length,count);
 }
});
test('wrong selection, source or session profile cannot make a request',async()=>{
 let requests=0;const fetchImpl=async()=>{requests++;throw Error('unexpected');};
 for(const selected of [null,{...selection,consent:false},{...selection,accessHash:-1n},{...selection,id:0n},
  {kind:'channel',id:groupId,consent:true,accessHash:0n}]){
  await assert.rejects(readGroupStatus(session(),selected,{workerSource,fetchImpl}),{reason:'invalid_selection'});
 }
 await assert.rejects(readGroupStatus(session(),selection,{workerSource,fetchImpl,server:'https://other.invalid/'}),{reason:'invalid_options'});
 let accessed=false;const accessor={workerSource,get fetchImpl(){accessed=true;return fetchImpl;}};
 await assert.rejects(readGroupStatus(session(),selection,accessor),{reason:'invalid_options'});assert.equal(accessed,false);
 await assert.rejects(readGroupStatus(session(),selection,{workerSource:workerSource+'\n',fetchImpl}),{reason:'invalid_source'});
 const android=session();android.state.protocolProfile='android-7.1.8-compat';
 await assert.rejects(readGroupStatus(android,selection,{workerSource,fetchImpl}),{reason:'verified_web_session_required'});
 assert.equal(requests,0);
});
test('account changes and simultaneous operations cannot admit the second read',async()=>{
 const account=session();let release;
 const f=mock(account.record,selection,[()=>new Promise(resolve=>{release=resolve;})]);
 const pending=readGroupStatus(account,selection,{workerSource,fetchImpl:f.fetchImpl});
 while(!release)await new Promise(resolve=>setImmediate(resolve));
 await assert.rejects(readGroupStatus(account,selection,{workerSource,fetchImpl:f.fetchImpl}),{reason:'account_busy'});
 account.record.token='fixture-private-new-token';release(new Response(codec.object(metadata())));
 await assert.rejects(pending,{reason:'account_binding_changed'});assert.equal(f.seen.length,1);
});
test('group service rejection returns only allowlisted status and never retries',async()=>{
 for(const [text,serviceCode]of [['INVALID_CONSTRUCTOR','INVALID_CONSTRUCTOR'],['fixture-private-service-text',undefined]]){
  const account=session(),f=mock(account.record,selection,[metadata(),{_:'error',code:400,text}]);
  await assert.rejects(readGroupStatus(account,selection,{workerSource,fetchImpl:f.fetchImpl}),error=>{
   assert.equal(error.reason,'service_rejected');assert.equal(error.stage,'group');assert.equal(error.serviceCode,serviceCode);
   assert.ok(!JSON.stringify(error).includes('fixture-private'));return true;
  });assert.equal(f.seen.length,2);
 }
});
