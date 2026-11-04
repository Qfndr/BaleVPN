const {test}=require('node:test'),assert=require('node:assert/strict');
const {CallSession}=require('../experiments/rubika/call-session.cjs'),updates=require('../experiments/rubika/call-updates.cjs');
const self='fixture_self_01',peer='fixture_peer_01',other='fixture_other_01',call='fixture_call_01';
const protocol={min_layer:65,max_layer:92,library_versions:['9.0.0']}; // Offline profile, not live-negotiated defaults.
const update=(timestamp,overrides={})=>({action:'New',call_id:call,timestamp,type:'User',object_guid:peer,
 call:{call_id:call,call_type:'Voice',state:'Requested',other_participants:[{object_guid:self,type:'User'}]},...overrides});
const edit=(timestamp,fields,overrides={})=>({action:'Edit',call_id:call,timestamp,call:fields,updated_parameters:Object.keys(fields),...overrides});
function fixture({hook,allowedPeers=[peer],options={}}={}){
 let clock=1700000000000;const accountState={provider:'rubika',userId:self,signedIn:true,selfConfirmed:true},record={provider:'rubika',userId:self,auth:'fixture-account-auth',privateKey:'fixture-private-key',publicKey:'fixture-public-key'};
 const account={get state(){return {...accountState};},exportSession(){return {...record};}},calls=[],events=[],signals=[],clients=[];
 const clientFactory=()=>{
  const client={closed:false,get state(){return {ready:!this.closed};},async start(){calls.push({method:'start'});if(hook){const v=await hook('start',{},client);if(v!==undefined)return v;}return {ready:true,mediaReady:false};},
   async request(method,input){calls.push({method,input});if(hook){const v=await hook(method,input,client);if(v!==undefined)return v;}
    const timestamp=Math.floor(clock/1000);
    if(method==='getUpdate')return {user_guid:self,call_updates:events.splice(0),call_signal_data:signals.splice(0)};
    if(method==='requestCall')return {call_type:'WebRtc',call_update:update(timestamp,{call:{call_id:call,call_type:'Voice',state:'Waiting'}})};
    if(method==='receivedCall')return {call_update:edit(timestamp+1,{state:'Waiting'})};
    if(method==='acceptCall')return {call_update:edit(timestamp+2,{state:'Accepted',key:'fixture-private-media-key'})};
    if(method==='discardCall')return {call_update:{action:'Delete',call_id:call,timestamp:timestamp+3}};
    if(method==='getSignalingData')return {call_id:call,data_list:[Buffer.from('opaque-poll-fixture')]};
    if(method==='sendSignalingData')return {};
    throw Error('fixture-private unexpected method');
   },close(){this.closed=true;}};clients.push(client);return client;
 };
 const session=new CallSession(account,{allowedPeers,protocol,createClient:clientFactory,now:()=>clock,...options});
 return {session,calls,events,signals,clients,record,accountState,now:()=>clock,seconds:()=>Math.floor(clock/1000),advance:ms=>{clock+=ms;}};
}
async function incoming(f){await f.session.start();f.events.push(update(f.seconds()));await f.session.pollOnce();}
async function outgoingAccepted(f){await f.session.start();await f.session.dial(peer);f.events.push(edit(f.seconds()+1,{state:'Accepted'}));await f.session.pollOnce();}
test('explicit profile and peer allow-list are required, with no network during construction or invalid actions',async()=>{
 for(const options of [{protocol:undefined},{protocol:{...protocol,call_id:call}},{allowedPeers:[peer,peer]},{protocol:{...protocol,library_versions:['4.0.0']}}])assert.throws(()=>fixture({options}),/invalid_call_options/);
 const f=fixture();assert.equal(f.calls.length,0);await assert.rejects(f.session.dial(other),/call_peer_not_allowed/);assert.equal(f.calls.length,0);
 await f.session.start();await assert.rejects(f.session.accept(),/call_not_ringing/);assert.equal(f.session.state.phase,'listening');f.session.close();
});
test('incoming voice call rings only for an allowed peer and receipt never accepts automatically',async()=>{
 const f=fixture();await incoming(f);assert.equal(f.session.state.phase,'ringing');assert.equal(f.session.state.direction,'incoming');
 assert.deepEqual(f.calls.map(x=>x.method),['start','getUpdate']);await f.session.acknowledge();assert.equal(f.session.state.phase,'ringing');
 assert.equal(f.calls.at(-1).method,'receivedCall');await f.session.accept();assert.equal(f.session.state.phase,'accepted');assert.equal(f.session.state.mediaReady,false);
 for(const secret of ['fixture-private-media-key',f.record.auth,f.record.privateKey])assert.ok(!JSON.stringify(f.session.state).includes(secret));
 assert.equal(f.calls.some(x=>x.method==='callStarted'),false);f.session.close();
});
test('unapproved peers, stale/future calls, video and unrelated edits are ignored without any callback or RPC',async()=>{
 const f=fixture();await f.session.start();f.events.push(update(f.seconds(),{object_guid:other}),update(f.seconds()-121),update(f.seconds()+31),
  update(f.seconds(),{call:{call_id:call,call_type:'Video',state:'Requested'}}),edit(f.seconds(),{state:'Accepted'}));
 await f.session.pollOnce();assert.equal(f.session.state.phase,'listening');assert.equal(f.session.state.ignoredEvents,5);
 assert.deepEqual(f.calls.map(x=>x.method),['start','getUpdate']);f.session.close();
});
test('outgoing call validates peer and service reply and never becomes an internet connection from Accepted alone',async()=>{
 const f=fixture();await outgoingAccepted(f);assert.equal(f.session.state.phase,'accepted');assert.equal(f.session.state.direction,'outgoing');
 assert.equal(f.session.state.mediaReady,false);assert.equal(f.session.state.peerAuthenticated,false);assert.equal(f.session.state.providerVerified,false);
 assert.deepEqual(f.calls[1].input,{call_type:'Voice',user_guid:peer,...protocol});await assert.rejects(f.session.dial(peer),/call_not_listening/);f.session.close();
});
test('per-field timestamps preserve new values through out-of-order edits, and a stale state cannot regress acceptance',async()=>{
 const f=fixture({options:{protocol:{...protocol,library_versions:['6.0.0']}},hook:method=>{
  if(method==='requestCall')return {call_type:'WebRtc',call_update:update(f.seconds(),
   {call:{call_id:call,call_type:'Voice',state:'Waiting',duration:3}})};
 }});await outgoingAccepted(f);
 f.events.push(edit(f.seconds()+10,{protocol_layer:92,duration:5}),
  edit(f.seconds()+5,{protocol_layer:91,state:'Waiting'}),
  edit(f.seconds()+2,{key:'k'.repeat(256),library_versions:['6.0.0'],connections:[
   {type:'WebRTC',ip:'192.0.2.1',port:3478,turn_username:'fixture-user',turn_password:'fixture-password'}
  ]}));
 await f.session.pollOnce();assert.equal(f.session.state.serviceState,'Accepted');assert.equal(f.session.state.phase,'accepted');
 assert.equal(f.session.state.serviceDuration,3);assert.equal(f.session.state.legacyMediaAvailable,true);assert.equal(f.session.state.ignoredEvents,1);
 await f.session.hangup();assert.equal(f.session.state.phase,'listening');f.session.close();
});
test('state progression and a terminal discard still work when several service updates share one Unix second',async()=>{
 const f=fixture();await f.session.start();await f.session.dial(peer);
 f.events.push(edit(f.seconds(),{state:'Accepted'}));await f.session.pollOnce();assert.equal(f.session.state.phase,'accepted');
 f.events.push(edit(f.seconds(),{state:'Waiting'}));await f.session.pollOnce();assert.equal(f.session.state.phase,'accepted');
 f.events.push(edit(f.seconds(),{state:'Discarded'}));await f.session.pollOnce();assert.equal(f.session.state.phase,'listening');assert.equal(f.session.state.reason,'remote_call_ended');f.session.close();
});
test('only named updated_parameters are applied; an ambiguous Edit halts the session without retries',async()=>{
 const f=fixture();await f.session.start();await f.session.dial(peer);
 f.events.push(edit(f.seconds()+1,{state:'Discarded',duration:4},{updated_parameters:['duration']}));await f.session.pollOnce();assert.equal(f.session.state.phase,'waiting');
 f.events.push({action:'Edit',call_id:call,timestamp:f.seconds()+2,call:{state:'Accepted'}});
 await assert.rejects(f.session.pollOnce(),/missing_update_parameters/);assert.equal(f.session.state.phase,'failed');assert.equal(f.clients[0].closed,true);f.session.close();
});
test('fields the official client ignores cannot advance the deletion watermark and leave a finished call stuck',async()=>{
 const f=fixture();await f.session.start();await f.session.dial(peer);
 f.events.push(edit(f.seconds()+10,{duration:4},{updated_parameters:['duration','future_metadata_field']}),
  {action:'Delete',call_id:call,timestamp:f.seconds()+1});
 await f.session.pollOnce();assert.equal(f.session.state.phase,'listening');assert.equal(f.session.state.callId,null);f.session.close();
});
test('a mixed Edit older than the embedded snapshot cannot suppress a terminal Delete',async()=>{
 const f=fixture({hook:method=>{
  if(method==='requestCall')return {call_type:'WebRtc',call_update:update(f.seconds(),
   {call:{call_id:call,call_type:'Voice',state:'Waiting',timestamp:f.seconds()+10}})};
 }});
 await f.session.start();await f.session.dial(peer);
 f.events.push(edit(f.seconds()+5,{protocol_layer:92,duration:4}),
  {action:'Delete',call_id:call,timestamp:f.seconds()+3});
 await f.session.pollOnce();assert.equal(f.session.state.phase,'listening');assert.equal(f.session.state.callId,null);f.session.close();
});
test('remote deletion wipes pending opaque signals and a retired call cannot ring or deliver into another call',async()=>{
 const f=fixture();await incoming(f);const source=Buffer.from('private-early-signal');f.signals.push({call_id:call,data:source});await f.session.pollOnce();
 assert.equal(source.every(x=>x===0),true);assert.equal(f.session.state.queuedSignals,1);
 f.events.push({action:'Delete',call_id:call,timestamp:f.seconds()+5});await f.session.pollOnce();assert.equal(f.session.state.queuedSignals,0);assert.equal(f.session.state.phase,'listening');
 f.events.push(update(f.seconds()+6));f.signals.push({call_id:call,data:Buffer.from('late')});await f.session.pollOnce();assert.equal(f.session.state.phase,'listening');
 assert.equal(f.session.state.callId,null);f.session.close();
});
test('acceptance on another device ends an incoming call unless local accept was explicitly requested',async()=>{
 const f=fixture();await incoming(f);f.events.push(edit(f.seconds()+1,{state:'Accepted'}));await f.session.pollOnce();
 assert.equal(f.session.state.phase,'listening');assert.equal(f.session.state.reason,'call_answered_elsewhere');f.session.close();
});
test('opaque signal buffers are private, ordered, transferred only after acceptance and wrong call IDs are ignored',async()=>{
 const f=fixture();await incoming(f);const raw=Buffer.from('first');f.signals.push({call_id:call,data:raw},{call_id:'fixture_other_call',data:Buffer.from('other')});await f.session.pollOnce();
 assert.throws(()=>f.session.takeOpaqueSignals(),/call_not_accepted/);await f.session.accept();await f.session.pollSignals();
 const signals=f.session.takeOpaqueSignals();assert.deepEqual(signals,[Buffer.from('first'),Buffer.from('opaque-poll-fixture')]);assert.equal(f.session.state.queuedSignals,0);
 await f.session.sendOpaqueSignal(Buffer.from('encrypted-fixture'));assert.equal(f.calls.at(-1).input.call_id,call);assert.equal(f.calls.at(-1).input.data,Buffer.from('encrypted-fixture').toString('base64'));
 assert.equal(raw.every(x=>x===0),true);f.session.close();for(const bytes of signals)bytes.fill(0);
});
test('signal queue overflow terminates the call and zeroes all service-owned buffers',async()=>{
 const f=fixture();await incoming(f);const raw=Array.from({length:33},()=>Buffer.from('private'));
 f.signals.push(...raw.map(data=>({call_id:call,data})));await assert.rejects(f.session.pollOnce(),/too_many_call_signals/);
 assert.equal(f.session.state.phase,'failed');assert.equal(f.session.state.queuedSignals,0);assert.ok(raw.every(bytes=>bytes.every(v=>v===0)));f.session.close();
});
test('hangup reports bounded duration once, clears the call and never redials automatically',async()=>{
 const f=fixture();await outgoingAccepted(f);f.advance(6500);await assert.rejects(f.session.hangup('private-invalid-reason'),/invalid_call_options/);
 assert.equal(f.session.state.phase,'accepted');await f.session.hangup();assert.deepEqual(f.calls.at(-1).input,{call_id:call,duration:6,reason:'Hangup'});
 assert.equal(f.session.state.callId,null);assert.equal(f.session.state.reason,'local_call_ended');assert.equal(f.calls.filter(x=>x.method==='requestCall').length,1);f.session.close();
});
test('pending call timeout retires the owned transport without an implicit retry or automatic answer',async()=>{
 const f=fixture();await incoming(f);f.advance(60001);assert.equal(f.session.state.phase,'failed');assert.equal(f.session.state.reason,'call_timeout');
 assert.equal(f.clients[0].closed,true);assert.deepEqual(f.calls.map(x=>x.method),['start','getUpdate']);f.session.close();
});
test('changed credentials, sign-out and a dead call transport retire readiness without touching the auth account',async()=>{
 for(const change of [f=>{f.record.auth='changed-account-auth';},f=>{f.accountState.signedIn=false;},f=>{f.clients[0].closed=true;}]){
  const f=fixture();await incoming(f);change(f);assert.equal(f.session.state.ready,false);assert.equal(f.session.state.phase,'failed');
  assert.equal(f.session.state.queuedSignals,0);f.session.close();
 }
});
test('close during a pending reply cancels it, wipes late buffers and cannot revive the session',async()=>{
 let release;const f=fixture({hook:method=>method==='getUpdate'?new Promise(r=>{release=r;}):undefined});await f.session.start();
 const pending=f.session.pollOnce();await assert.rejects(f.session.pollOnce(),/call_busy/);f.session.close();const raw=Buffer.from('private-late');
 release({user_guid:self,call_updates:[],call_signal_data:[{call_id:call,data:raw}]});await assert.rejects(pending,/call_cancelled/);
 assert.equal(raw.every(x=>x===0),true);assert.equal(f.session.state.phase,'closed');await assert.rejects(f.session.start(),/closed/);
});
test('cross-peer participants or a mismatched service call ID fail before further call operations',async()=>{
 for(const type of ['participant','identity']){
  const f=fixture({hook:method=>method==='requestCall'?{call_type:'WebRtc',call_update:update(f.seconds(),type==='participant'?{
   call:{call_id:call,call_type:'Voice',state:'Waiting',other_participants:[{object_guid:other,type:'User'}]}}:{call:{call_id:'fixture_other_call',call_type:'Voice',state:'Waiting'}})}:undefined});
  await f.session.start();await assert.rejects(f.session.dial(peer),/call_participant_mismatch|call_identity_mismatch/);assert.equal(f.session.state.ready,false);f.session.close();
 }
});
test('an unrelated active call update cannot replace the current destination or state',async()=>{
 const f=fixture();await outgoingAccepted(f);f.events.push(update(f.seconds()+2,{call_id:'fixture_other_call',object_guid:other,call:{call_id:'fixture_other_call',call_type:'Voice',state:'Requested'}}));
 await f.session.pollOnce();assert.equal(f.session.state.callId,call);assert.equal(f.session.state.peerId,peer);assert.equal(f.session.state.phase,'accepted');f.session.close();
});
test('the typed update reader preserves Video for filtering while outgoing voice requests remain voice-only',()=>{
 const value=update(1700000000,{call:{call_id:call,call_type:'Video',state:'Requested'}});
 assert.equal(updates.callUpdate(value).call.call_type,'Video');
 assert.throws(()=>require('../experiments/rubika/call-codec.cjs').validateInput('requestCall',{...protocol,call_type:'Video',user_guid:peer}));
});
test('real account-bound client, HTTP signing and service encryption carry the full offline call lifecycle',async()=>{
 const wire=require('../experiments/rubika/wire.cjs'),{CallClient}=require('../experiments/rubika/call-client.cjs'),{HttpClient}=require('../experiments/rubika/http-client.cjs');
 const identity=await wire.createIdentity(),methods=[];
 const f=fixture({options:{createClient:account=>new CallClient(account,{createClient:options=>new HttpClient({...options,updatesFactory:null,fetchImpl:async(url,options)=>{
  const envelope=JSON.parse(options.body);
  if(envelope.method==='getDCs'){methods.push('getDCs');return new Response(JSON.stringify({status:'OK',data:{default_api_urls:['https://messengerg2c1.iranlms.ir/']}}));}
  assert.equal(require('node:crypto').verify('RSA-SHA256',Buffer.from(envelope.data_enc),identity.publicKey,Buffer.from(envelope.sign,'base64')),true);
  const payload=wire.decrypt(envelope.data_enc,f.record.auth);methods.push(payload.method);let data;
  if(payload.method==='requestCall')data={call_type:'WebRtc',call_update:update(f.seconds(),{call:{call_id:call,call_type:'Voice',state:'Waiting'}})};
  else if(payload.method==='getUpdate')data={update_data:{user_guid:self,call_updates:[edit(f.seconds()+1,{state:'Accepted'})]}};
  else if(payload.method==='sendSignalingData'){assert.equal(payload.input.call_id,call);data={};}
  else if(payload.method==='discardCall')data={call_update:{action:'Delete',call_id:call,timestamp:f.seconds()+2}};
  else throw Error('Unexpected offline RPC');
  return new Response(JSON.stringify({data_enc:wire.encrypt({status:'OK',data},f.record.auth)}));
 }})})}});
 Object.assign(f.record,identity,{auth:'abcdefghijklmnopqrstuvwxyz012345'});
 try{
  await f.session.start();await f.session.dial(peer);await f.session.pollOnce();assert.equal(f.session.state.phase,'accepted');
  await f.session.sendOpaqueSignal(Buffer.from('encrypted-fixture'));await f.session.hangup();assert.equal(f.session.state.phase,'listening');
  assert.deepEqual(methods,['getDCs','requestCall','getUpdate','sendSignalingData','discardCall']);assert.equal(f.session.state.mediaReady,false);
 }finally{f.session.close();}
});
