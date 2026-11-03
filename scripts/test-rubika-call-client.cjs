const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {CallClient}=require('../experiments/rubika/call-client.cjs'),{ApiError}=require('../experiments/rubika/http-client.cjs');
const codec=require('../experiments/rubika/call-codec.cjs'),updates=require('../experiments/rubika/call-updates.cjs'),wire=require('../experiments/rubika/wire.cjs');
const selfId='fixture_self_01',peerId='fixture_peer_02',callId='fixture_call_01';
const profile={min_layer:65,max_layer:92,library_versions:['9.0.0']}; // Fixture values, not observed negotiation defaults.
const requestInput={call_type:'Voice',user_guid:peerId,...profile};
function callUpdate(overrides={}){return {call_id:callId,action:'New',timestamp:10,type:'User',object_guid:peerId,
 call:{call_id:callId,call_type:'Voice',state:'Waiting',key:'fixture-private-call-key',other_participants:[{object_guid:selfId,type:'User'}],
  protocol_layer:92,library_versions:['9.0.0'],p2p_allowed:true,connections:[{type:'WebRTC',ip:'192.0.2.1',ipv6:'2001:db8::1',port:3478,
   id:'9223372036854775807',turn_username:'fixture-private-turn-user',turn_password:'fixture-private-turn-password'}]},...overrides};}
async function fixture(hook){
 const identity=await wire.createIdentity(),record={provider:'rubika',userId:selfId,auth:'abcdefghijklmnopqrstuvwxyz012345',...identity};
 const authState={provider:'rubika',userId:selfId,signedIn:true,selfConfirmed:true},calls=[],transports=[];
 const account={get state(){return {...authState};},exportSession(){return {...record};}};
 const client=new CallClient(account,{createClient:options=>{
  const transport={closed:false,async discover(){calls.push({method:'getDCs',options});if(hook)return hook('getDCs',{},transport);},
   async request(method,input,options){calls.push({method,input,options});if(hook){const reply=await hook(method,input,transport);if(reply!==undefined)return reply;}
    if(method==='requestCall')return {call_type:'WebRtc',call_update:callUpdate()};
    if(method==='getUpdate')return {update_data:{user_guid:selfId,call_updates:[callUpdate()],call_signal_data:[{call_id:callId,data:'YQ=='}],message_updates:[{text:'fixture-private-chat'}]}};
    if(method==='getSignalingData')return {data_list:['YQ==']};
    if(['sendSignalingData','callStarted'].includes(method))return {};
    return {call_update:callUpdate({action:'Edit',call:{call_id:callId,state:'Accepted'}})};
   },close(){this.closed=true;}};transports.push(transport);return transport;
 }});
 return {client,record,authState,calls,account,transports};
}
test('typed call client snapshots independent account credentials and explicitly discovers without logging in or registering',async()=>{
 const f=await fixture();assert.equal(f.calls.length,0);await assert.rejects(f.client.request('requestCall',requestInput),/call_not_started/);
 assert.deepEqual(await f.client.start(),{ready:true,mediaReady:false});
 const reply=await f.client.request('requestCall',requestInput);assert.equal(reply.call_update.call.key,'fixture-private-call-key');
 assert.equal(reply.call_type,'WebRtc');assert.deepEqual(f.calls.map(x=>x.method),['getDCs','requestCall']);
 assert.equal(f.calls[1].options.credentials.auth,f.record.auth);assert.equal(f.calls[1].options.credentials.privateKey,f.record.privateKey);
 for(const secret of [f.record.auth,f.record.privateKey,'fixture-private-call-key','fixture-private-turn-password'])assert.ok(!JSON.stringify(f.client.state).includes(secret));
 assert.equal(f.client.state.mediaReady,false);await assert.rejects(f.client.start(),/call_already_started/);f.client.close();
});
test('update projection is bound to self, contains call-only data, preserves opaque signals and drops unrelated chats',async()=>{
 const f=await fixture();await f.client.start();const reply=await f.client.request('getUpdate',{});
 assert.equal(reply.user_guid,selfId);assert.deepEqual(reply.call_signal_data[0],{call_id:callId,data:Buffer.from('a')});
 assert.equal(reply.message_updates,undefined);assert.ok(!JSON.stringify(reply).includes('fixture-private-chat'));f.client.close();
});
test('two simultaneous signed-in accounts retain separate transports, self IDs and private keys',async()=>{
 const a=await fixture(),b=await fixture();b.record.userId='fixture_other_self';b.authState.userId=b.record.userId;
 b.record.auth='012345abcdefghijklmnopqrstuvwxyz';await Promise.all([a.client.start(),b.client.start()]);
 await Promise.all([a.client.request('requestCall',requestInput),b.client.request('requestCall',requestInput)]);
 assert.notEqual(a.calls[1].options.credentials.auth,b.calls[1].options.credentials.auth);
 assert.notEqual(a.calls[1].options.credentials.privateKey,b.calls[1].options.credentials.privateKey);a.client.close();b.client.close();
});
test('missing or mismatched self identity in a provider update fails before its signals can be returned',async()=>{
 for(const user_guid of [undefined,'fixture_other_self']){
  const f=await fixture(method=>method==='getUpdate'?{update_data:{user_guid,call_signal_data:[{call_id:callId,data:'YQ=='}]}}:undefined);
  await f.client.start();await assert.rejects(f.client.request('getUpdate'),/update_account_mismatch/);
  assert.equal(f.client.state.ready,false);assert.equal(f.transports[0].closed,true);f.client.close();
 }
});
test('account sign-out, identity changes and key rotation retire only the call transport before any new RPC',async()=>{
 for(const change of [f=>{f.authState.signedIn=false;},f=>{f.record.auth='012345abcdefghijklmnopqrstuvwxyz';},
  f=>{f.record.userId='fixture_other_self';},f=>{f.record.privateKey+='\n';}]){
  const f=await fixture();await f.client.start();change(f);await assert.rejects(f.client.request('getUpdate'),/not_authenticated|account_binding_changed|invalid_account_binding/);
  assert.equal(f.calls.length,1);assert.equal(f.transports[0].closed,true);assert.equal(f.client.state.ready,false);f.client.close();
 }
});
test('late request response after a changed account is rejected and never restores readiness',async()=>{
 let release;const f=await fixture(method=>method==='requestCall'?new Promise(r=>{release=r;}):undefined);await f.client.start();
 const pending=f.client.request('requestCall',requestInput);f.record.auth='012345abcdefghijklmnopqrstuvwxyz';
 release({call_type:'WebRtc',call_update:callUpdate()});await assert.rejects(pending,/account_binding_changed/);
 assert.equal(f.client.state.ready,false);assert.equal(f.transports[0].closed,true);f.client.close();
});
test('reading readiness after account logout retires transport immediately, without polling or network writes',async()=>{
 const f=await fixture();await f.client.start();f.authState.signedIn=false;
 assert.equal(f.client.state.ready,false);assert.equal(f.client.state.error.reason,'not_authenticated');assert.equal(f.transports[0].closed,true);
 assert.equal(f.calls.length,1);f.client.close();
});
test('close during discovery and request cancels transport; late completion cannot revive a closed client',async()=>{
 for(const step of ['getDCs','requestCall']){
  let release;const f=await fixture(method=>method===step?new Promise(r=>{release=r;}):undefined);
  let pending;if(step==='getDCs')pending=f.client.start();else{await f.client.start();pending=f.client.request(step,requestInput);}
  f.client.close();assert.equal(f.transports[0].closed,true);release({call_type:'WebRtc',call_update:callUpdate()});
  await assert.rejects(pending,/closed/);assert.equal(f.client.state.ready,false);await assert.rejects(f.client.start(),/closed/);
 }
});
test('concurrent operations are refused and inputs cannot mutate while a request is pending',async()=>{
 let release;const f=await fixture(method=>method==='requestCall'?new Promise(r=>{release=r;}):undefined);await f.client.start();
 const input={...requestInput,library_versions:['9.0.0']},pending=f.client.request('requestCall',input);
 input.user_guid='fixture_changed_peer';input.library_versions[0]='4.0.0';
 await assert.rejects(f.client.request('getUpdate'),/account_busy/);
 assert.equal(f.calls[1].input.user_guid,peerId);assert.deepEqual(f.calls[1].input.library_versions,['9.0.0']);
 release({call_type:'WebRtc',call_update:callUpdate()});await pending;f.client.close();
});
test('response call IDs cannot disagree with the request or the nested PhoneCall',async()=>{
 for(const reply of [{call_update:callUpdate({call_id:'fixture_other_call'})},
  {call_update:callUpdate({call:{call_id:'fixture_other_call',call_type:'Voice',state:'Accepted'}})}]){
  const f=await fixture(method=>method==='acceptCall'?reply:undefined);await f.client.start();
  await assert.rejects(f.client.request('acceptCall',{call_id:callId,...profile}),/call_identity_mismatch/);assert.equal(f.client.state.ready,false);f.client.close();
 }
});
test('partial edits and deletion keep explicit metadata without inventing absent full-call fields',()=>{
 const edit=updates.callUpdate({action:'Edit',call_id:callId,timestamp:12,call:{state:'Accepted'},updated_parameters:['state']});
 assert.deepEqual(edit.call,{state:'Accepted'});assert.equal(edit.object_guid,undefined);
 assert.deepEqual(updates.callUpdate({action:'Delete',call_id:callId,timestamp:13}),{action:'Delete',call_id:callId,timestamp:13});
 const reply=updates.callUpdate(callUpdate());reply.call.connections[0].turn_password='changed';assert.equal(callUpdate().call.connections[0].turn_password,'fixture-private-turn-password');
});
test('unsafe numeric connection IDs, malformed endpoints, unsupported call types and oversized lists fail closed',()=>{
 const base=callUpdate();
 for(const change of [v=>{v.call.call_type='Video';},v=>{v.call.connections[0].ip='https://attacker.invalid';},
  v=>{v.call.connections[0].id=9223372036854776000;},v=>{v.call.connections[0].id='9223372036854775808';},
  v=>{v.call.connections[0].port=0;},v=>{v.call.connections[0].turn_password='private\nsecret';},
  v=>{v.call.other_participants[0].type='Bot';},v=>{v.call.key='x'.repeat(8193);},
  v=>{v.updated_parameters=['state','state'];},v=>{v.call.library_versions=Array(17).fill('9.0.0');}]){
  const v=structuredClone(base);change(v);assert.throws(()=>updates.callUpdate(v),/invalid_call_response/);
 }
 const legacy=structuredClone(base);legacy.call.connections[0].type='Tg';assert.equal(updates.callUpdate(legacy).call.connections[0].type,'Tg');
 assert.throws(()=>updates.response('requestCall',{call_type:'CallOut',call_update:base}),/unsupported_call_protocol/);
});
test('mixed or oversized signal update batches are rejected as a whole',()=>{
 for(const call_signal_data of [[{call_id:callId,data:'YQ=='},{call_id:callId,data:'broken'}],
  Array(codec.MAX_BATCH+1).fill({call_id:callId,data:'YQ=='}),
  [{call_id:callId,data:Buffer.alloc(codec.MAX_SIGNAL).toString('base64')},{call_id:callId,data:'YQ=='}]]){
  assert.throws(()=>updates.updates({update_data:{user_guid:selfId,call_signal_data}},selfId),/invalid_call_response/);
 }
});
test('private signal response projections require the exact requested call namespace',()=>{
 for(const callId of [undefined,'bad','fixture\ncall'])assert.throws(()=>updates.response('getSignalingData',{data_list:['YQ==']},{callId}),/call_identity_mismatch/);
 assert.equal(updates.response('getSignalingData',{data_list:['YQ==']},{callId}).call_id,callId);
});
test('untrusted network errors are redacted and never retry, while invalid local methods leave the ready client alone',async()=>{
 const f=await fixture(method=>{if(method==='requestCall')throw Error('fixture-private-server-dump');});await f.client.start();
 await assert.rejects(f.client.request('logout'),/invalid_request/);assert.equal(f.client.state.ready,true);
 await assert.rejects(f.client.request('requestCall',requestInput),e=>e.reason==='call_operation_failed'&&!e.message.includes('private'));
 assert.deepEqual(f.calls.map(c=>c.method),['getDCs','requestCall']);assert.ok(!JSON.stringify(f.client.state).includes('private'));f.client.close();
});
test('start verifies strong RSA ownership once and rejects a mismatched or weak account identity without discovery',async()=>{
 for(const change of [async f=>{f.record.publicKey=(await wire.createIdentity()).publicKey;},async f=>{
  const pair=crypto.generateKeyPairSync('rsa',{modulusLength:1024,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});Object.assign(f.record,pair);
 }]){
  const f=await fixture();await change(f);await assert.rejects(f.client.start(),/invalid_account_binding/);assert.equal(f.calls.length,0);f.client.close();
 }
});
test('real HTTP transport signs getUpdate and returns only authenticated call data from an encrypted offline service',async()=>{
 const f=await fixture();let sent=0;
 const client=new CallClient(f.account,{createClient:options=>new (require('../experiments/rubika/http-client.cjs').HttpClient)({...options,fetchImpl:async(url,o)=>{
  sent++;const body=JSON.parse(o.body);
  if(body.method==='getDCs')return new Response(JSON.stringify({status:'OK',data:{default_api_urls:['https://messengerg2c1.iranlms.ir/']}}));
  assert.equal(crypto.verify('RSA-SHA256',Buffer.from(body.data_enc),f.record.publicKey,Buffer.from(body.sign,'base64')),true);
  const payload=wire.decrypt(body.data_enc,f.record.auth);assert.equal(payload.method,'getUpdate');assert.deepEqual(payload.input,{});
  return new Response(JSON.stringify({data_enc:wire.encrypt({status:'OK',data:{update_data:{user_guid:selfId,call_updates:[callUpdate()]}}},f.record.auth)}));
 }})});
 await client.start();const reply=await client.request('getUpdate');assert.equal(reply.call_updates[0].call_id,callId);assert.equal(sent,2);client.close();f.client.close();
});
