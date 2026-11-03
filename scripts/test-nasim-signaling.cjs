const {test}=require('node:test'),assert=require('node:assert/strict');
const {SSEParser}=require('../experiments/nasim/sse-parser.cjs');
const codec=require('../experiments/nasim/call-codec.cjs');
const {SignalingConnection,serverBase}=require('../experiments/nasim/signaling-connection.cjs');
const wire=require('../experiments/nasim/wire.cjs');
const token='fixture-session-token-no-real-account';
const session={provider:'nasim',userId:'41',clientId:'client-41',deviceId:'web.fixture-nasim-device.12345',token};
const fingerprint=Array(32).fill('AA').join(':');
const sdp='v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=fingerprint:sha-256 '+fingerprint+'\r\n';
function config(){return {type:'msgGroupCall',senderClientID:'client-42',time:1000,data:{type:'config',callUUID:'fixture-call-1',callData:{
 method:'audio',participants:[{userID:41,nickname:'fixture-private-name'},{userID:42}],invitedParticipantUserID:41,
 stunServer:{url:'stun.fixture.gap.im:3478'},turnServer:{url:'turn.fixture.gap.im:3478?transport=udp',username:'fixture-turn-user',password:'fixture-turn-secret'}}}};}
function frame(id,messages,ending='\r\n'){
 const encrypted=wire.encryptBytes(Buffer.from(JSON.stringify({messages})),token).toString('base64');
 return Buffer.from('id: '+id+ending+'event: message'+ending+'data: '+encrypted+ending+ending);
}
function reply(value){return new Response(wire.encrypt({status:'success',data:value},token),{status:200});}
async function waitFor(predicate){const deadline=Date.now()+2000;while(!predicate()){if(Date.now()>deadline)throw new Error('Fixture state timed out');await new Promise(resolve=>setTimeout(resolve,5));}}
function fixture({base='https://stream.gaplication.com',onEvent,apiResponse}={}){
 const seen=[],events=[];let stream,cancelled=false;
 const fetchImpl=async(url,options)=>{
  seen.push({url,options});assert.equal(options.redirect,'error');
  if(url==='https://api.gaplication.com/groupList?page=reset')return Response.json({data:{groups:[]}});
  if(url==='https://core.gaplication.com/message/get/config'){
   assert.equal(options.method,'POST');assert.equal(options.body,undefined);assert.equal(options.headers.token,token);
   return reply({SSEServerAddress:base});
  }
  if(url===base+'/message/get'){
   assert.equal(options.method,'GET');assert.equal(options.headers.clientid,'client-41');assert.equal(options.headers.duid,session.deviceId);
   return new Response(new ReadableStream({start(controller){stream=controller;},cancel(){cancelled=true;}}),
    {headers:{'content-type':'text/event-stream'}});
  }
  if(url==='https://api.gaplication.com/'){
   assert.equal(options.headers['x-token'],token);assert.equal(options.headers['x-clientid'],'client-41');
   const body=JSON.parse(wire.decryptBytes(options.body,token).toString());assert.equal(body.type,'msgGroupCall');
   assert.equal(options.headers['x-topic'],'u/42/41');
   if(apiResponse)return apiResponse({url,options,body});
   return new Response(wire.encryptBytes(Buffer.from(JSON.stringify({status:'success'})),token));
  }
  throw new Error('Unexpected external destination in offline test');
 };
 return {seen,events,open:()=>SignalingConnection.open(session,{fetchImpl,onEvent:onEvent||((event)=>events.push(event))}),
  push:bytes=>stream.enqueue(bytes),end:()=>stream.close(),cancelled:()=>cancelled};
}

test('SSE parser preserves every byte boundary, CRLF/LF frames and split UTF-8 comments before authenticated JSON delivery',()=>{
 const bytes=Buffer.concat([Buffer.from(': آزمایش\r\n\r\n'),frame(1,[config()]),frame(2,[], '\n')]);
 for(const size of [1,2,7,bytes.length]){
  const parser=new SSEParser(token),events=[];
  for(let at=0;at<bytes.length;at+=size)events.push(...parser.push(bytes.subarray(at,at+size)));
  parser.finish();assert.equal(events.length,2);assert.deepEqual(events[0].data.messages,[config()]);parser.close();
 }
});

test('SSE parser rejects altered ciphertext, invalid metadata, huge lines, unfinished frames and duplicate event IDs within a frame',()=>{
 const encrypted=frame(1,[config()]);
 for(const bytes of [Buffer.from('id: 1\nevent: message\ndata: not-base64!\n\n'),
  Buffer.from('id: 1\nid: 2\nevent: establish\n\n'),Buffer.from('id: bad\nevent: establish\n\n'),
  Buffer.from('id: 1\nevent: message\ndata: '+wire.encryptBytes(Buffer.from('{}'),'wrong-token-fixture-42').toString('base64')+'\n\n')]){
  const parser=new SSEParser(token);assert.throws(()=>parser.push(bytes));parser.close();
 }
 const partial=new SSEParser(token);assert.deepEqual(partial.push(encrypted.subarray(0,encrypted.length-1)),[]);assert.throws(()=>partial.finish());
 const huge=new SSEParser(token);assert.throws(()=>huge.push(Buffer.alloc(400*1024,65)));
 const closed=new SSEParser(token);closed.close();assert.throws(()=>closed.push(encrypted));
});

test('call codec admits only bounded two-party audio shapes and keeps sensitive relay/SDP fields out of unrelated metadata',()=>{
 const incoming=codec.incoming(config(),'41');assert.deepEqual(incoming.participantIds,['41','42']);assert.equal(incoming.peerId,'42');
 assert.equal(incoming.iceServers[1].credential,'fixture-turn-secret');assert.ok(!JSON.stringify(incoming).includes('fixture-private-name'));
 const outbound=codec.outgoing({type:'offer',callUUID:'fixture-call-1',callData:{type:'offer',sdp}},'41','42');
 assert.equal(outbound.topic,'u/42/41');assert.equal(outbound.body.data.callData.sdp,sdp);
 for(const change of [value=>value.data.callData.participants.push({userID:43}),value=>value.data.callData.method='video',
  value=>value.senderClientID='',value=>value.data.callData.turnServer.url='host\r\nsecret',value=>value.data.callData.participants[0].userID=Number.MAX_SAFE_INTEGER+1]){
  const bad=config();change(bad);assert.throws(()=>codec.incoming(bad,'41'));
 }
 assert.throws(()=>codec.outgoing({type:'callRequest',callData:{method:'audio'}},'41','41'));
 assert.throws(()=>codec.outgoing({type:'offer',callUUID:'fixture-call-1',callData:{type:'offer',sdp:'v=0\nm=audio 9 RTP/AVP 0\n'}},'41','42'));
});

test('stream destinations must use HTTPS on verified provider domains without token-bearing URLs or arbitrary ports',()=>{
 assert.equal(serverBase('https://stream.gaplication.com/'),'https://stream.gaplication.com');
 assert.equal(serverBase('https://stream.gap.im/sse'),'https://stream.gap.im/sse');
 for(const url of ['http://stream.gap.im','https://127.0.0.1','https://gap.im.attacker.invalid',
  'https://evil-gap.im','https://user:password@stream.gap.im','https://stream.gap.im:8443','https://stream.gap.im/?token=secret',
  'https://stream.gap.im/#secret','https://stream.gap.im/private'])assert.throws(()=>serverBase(url));
});

test('encrypted stream forwards only validated call events, ignores replay/chat content and exposes no token, relay password or SDP in status',async()=>{
 const f=fixture(),connection=await f.open();
 try{
  f.push(frame(1,[{type:'msgText',data:'fixture-private-chat-text'},config()]));await waitFor(()=>f.events.length===1);
  f.push(frame(1,[config()]));f.push(frame(2,[{type:'msgGroupCall',data:{type:'config',callUUID:'bad'}}]));
  await waitFor(()=>connection.state.lastEventId==='2');
  assert.equal(connection.state.callEvents,1);assert.equal(connection.state.ignoredMessages,1);assert.equal(connection.state.replayedFrames,1);
  assert.equal(connection.state.invalidCallMessages,1);assert.equal(connection.state.phase,'connected');
  const state=JSON.stringify(connection.state);for(const secret of [token,'fixture-private-chat-text','fixture-turn-secret',sdp])assert.ok(!state.includes(secret));
 }finally{connection.close();}await waitFor(()=>f.cancelled());
});

test('call requests use v2.5 encrypted JSON on the fixed topic and do not retry or return unrelated account metadata',async()=>{
 const f=fixture(),connection=await f.open();
 try{
  assert.deepEqual(await connection.send({type:'callRequest',callData:{method:'audio'}},{peerId:'42'}),{acknowledged:true,reply:null});
  assert.equal(f.seen.length,4);assert.equal(f.seen[3].options.headers['api-version'],'v2.5');
  assert.ok(f.seen[3].options.body.every(value=>value===0));
  await assert.rejects(connection.send({type:'msgText',callData:{}},{peerId:'42'}),/invalid_call_signal/);assert.equal(f.seen.length,4);
 }finally{connection.close();}
});

test('cleanSession resets old call state and continues receiving fresh events without loading chat history or reconnecting',async()=>{
 const f=fixture(),connection=await f.open();
 try{
  f.push(Buffer.from('id: 0\nevent: cleanSession\n\n'));
  await waitFor(()=>f.events.length===1);assert.equal(f.events[0].type,'streamReset');
  assert.equal(connection.state.phase,'connected');assert.equal(connection.state.historyGaps,1);assert.equal(connection.state.awaitingFreshEvent,true);
  f.push(frame(1,[config()]));await waitFor(()=>f.events.length===2);
  assert.deepEqual(f.events.map(event=>event.type),['streamReset','config']);
  assert.equal(connection.state.callEvents,1);assert.equal(connection.state.awaitingFreshEvent,false);assert.equal(f.seen.length,3);
 }finally{connection.close();}
});

test('callback failures and truncated EOF end the stream visibly without automatically reading chat history or reconnecting',async()=>{
 for(const mode of ['callback','truncated']){
  const f=fixture({onEvent:mode==='callback'?()=>{throw new Error('private callback detail');}:undefined}),connection=await f.open();
  if(mode==='callback')f.push(frame(1,[config()]));
  else{const bytes=frame(1,[config()]);f.push(bytes.subarray(0,bytes.length-1));f.end();}
  await waitFor(()=>connection.state.phase==='failed');
  assert.equal(f.seen.length,3);assert.ok(!JSON.stringify(connection.state).includes('private callback detail'));
  await assert.rejects(connection.send({type:'callRequest',callData:{method:'audio'}},{peerId:'42'}),/not_connected/);connection.close();
 }
});

test('an untrusted stream server is rejected before receiving account headers',async()=>{
 const f=fixture({base:'https://attacker.invalid'});await assert.rejects(f.open(),/invalid_stream_server/);assert.equal(f.seen.length,2);
});

test('abort during cursor fetch cannot open a late stream or create a new device',async()=>{
 const abort=new AbortController();let finish;const pending=new Promise(resolve=>{finish=resolve;}),urls=[];
 const opening=SignalingConnection.open(session,{signal:abort.signal,fetchImpl:async(url)=>{urls.push(url);return pending;}});
 abort.abort();finish(reply({SSEServerAddress:'https://stream.gap.im'}));await assert.rejects(opening,/closed/);
 assert.deepEqual(urls,['https://api.gaplication.com/groupList?page=reset']);
});

test('call HTTP authorization failure invalidates the event connection and cannot turn a failed request into a call acknowledgment',async()=>{
 const f=fixture({apiResponse:()=>new Response('private gateway error',{status:401})}),connection=await f.open();
 await assert.rejects(connection.send({type:'callRequest',callData:{method:'audio'}},{peerId:'42'}),/not_authorized/);
 assert.equal(connection.state.phase,'failed');assert.equal(connection.state.reason,'not_authorized');assert.equal(f.seen.length,4);connection.close();
});
