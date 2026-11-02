'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {CallSession}=require('../experiments/eitaa/call-session.cjs'),{pair,service,account,signal}=require('./eitaa-call-session-fixture.cjs');
const f=require('./eitaa-call-fixtures.cjs');
test('two account controllers complete actual DH/fingerprint checks and bidirectional authenticated signaling without claiming media',async t=>{
 const p=await pair(t);await p.negotiate();assert.equal(p.a.state.phase,'secure');assert.equal(p.b.state.phase,'secure');
 assert.equal(p.a.state.keyNegotiated,true);assert.equal(p.b.state.keyNegotiated,true);assert.equal(p.a.state.mediaConnected,false);assert.equal(p.a.state.proxyReady,false);
 await p.a.sendSignal(signal);await p.b.pollOnce();assert.deepEqual(p.bSignals,[signal]);await p.b.sendSignal(signal);await p.a.pollOnce();assert.deepEqual(p.aSignals,[signal]);
 const state=JSON.stringify([p.a.state,p.b.state]);for(const secret of ['token','__web','access_hash','fixture-turn','key_fingerprint','g_a','candidate:'])assert.ok(!state.includes(secret));
 await p.a.hangUp();await p.b.pollOnce();assert.equal(p.a.state.phase,'listening');assert.equal(p.b.state.phase,'listening');assert.equal(p.a.state.keyNegotiated,false);assert.equal(p.b.state.keyNegotiated,false);
 assert.equal(p.api.calls.filter(v=>v.method==='phone.requestCall').length,1);assert.equal(p.api.calls.filter(v=>v.method==='phone.acceptCall').length,1);
});
test('signals arriving before the confirmed key remain bounded and decrypt only after verified commitment/fingerprint',async t=>{
 const p=await pair(t,{onASecure:context=>context.send(signal)});await p.a.dial({userId:'202',accessHash:2n});await p.b.pollOnce();await p.b.accept();await p.a.pollOnce();
 const events=p.api.queues.get(202);assert.equal(events.length,2);events.reverse();await p.b.pollOnce();assert.equal(p.b.state.phase,'secure');assert.deepEqual(p.bSignals,[signal]);
});
test('a mismatched incoming commitment cannot establish a key or invoke the private media callback',async t=>{
 const p=await pair(t);await p.a.dial({userId:'202',accessHash:2n});p.api.queues.get(202)[0].phone_call.g_a_hash=Buffer.alloc(32,7);await p.b.pollOnce();await p.b.accept();await p.a.pollOnce();
 await assert.rejects(p.b.pollOnce(),{reason:'commitment_mismatch'});assert.equal(p.b.state.phase,'failed');assert.equal(p.b.state.keyNegotiated,false);assert.equal(p.bSecure.length,0);
});
test('wrong confirmed fingerprints, invalid DH groups and changed participants fail closed before secure media',async t=>{
 const p=await pair(t);await p.a.dial({userId:'202',accessHash:2n});await p.b.pollOnce();await p.b.accept();
 p.api.override=({method})=>method==='phone.confirmCall'?f.wrap({...f.active,admin_id:101n,participant_id:202n,key_fingerprint:123n}):undefined;
 await assert.rejects(p.a.pollOnce(),{reason:'fingerprint_mismatch'});assert.equal(p.aSecure.length,0);assert.equal(p.a.state.phase,'failed');
 const q=await pair(t);q.api.override=({method})=>method==='messages.getDhConfig'?{_:'messages.dhConfig',g:2,p:Buffer.alloc(256),random:Buffer.alloc(256),version:1}:undefined;
 await assert.rejects(q.a.dial({userId:'202',accessHash:2n}),{reason:'invalid_group'});assert.equal(q.api.calls.some(v=>v.method==='phone.requestCall'),false);
 const r=await pair(t);await r.a.dial({userId:'202',accessHash:2n});await r.b.pollOnce();await r.b.accept();r.api.queues.get(101)[0].phone_call.participant_id=303n;
 await assert.rejects(r.a.pollOnce(),{reason:'call_participant_mismatch'});assert.equal(r.api.calls.some(v=>v.method==='phone.confirmCall'),false);
});
test('unallowed and wrong-ID calls/signals never receive an acknowledgement or replace the active call',async t=>{
 const p=await pair(t);const requested={_:'phoneCallRequested',...f.base,admin_id:303n,participant_id:202n,g_a_hash:Buffer.alloc(32)};
 await p.b.ingest({_:'updatePhoneCall',phone_call:requested});assert.equal(p.b.state.phase,'listening');assert.equal(p.api.calls.some(v=>v.method==='phone.receivedCall'),false);
 await p.negotiate();const before=p.b.state.callId;await p.b.ingest({_:'updatePhoneCallSignalingData',phone_call_id:123n,data:Buffer.alloc(21)});await p.b.ingest({_:'updatePhoneCall',phone_call:{_:'phoneCallDiscarded',id:123n}});assert.equal(p.b.state.callId,before);assert.equal(p.b.state.phase,'secure');assert.equal(p.bSignals.length,0);
});
test('changed retained token or stopped authentication invalidates pending work and clears call keys',async t=>{
 const p=await pair(t);await p.negotiate();p.aAccount.record.token='fixture-new-token';await assert.rejects(p.a.sendSignal(signal),{reason:'account_binding_changed'});assert.equal(p.a.state.phase,'failed');assert.equal(p.a.state.keyNegotiated,false);
 p.bAccount.stop();await assert.rejects(p.b.pollOnce(),{reason:'not_authenticated'});assert.equal(p.b.state.keyNegotiated,false);
});
test('stop during a pending dial closes its client and late replies cannot resurrect the call',async t=>{
 const p=await pair(t);let release,entered;const gate=new Promise(r=>{entered=r;});p.api.override=async({method})=>{if(method==='phone.requestCall'){entered();return new Promise(r=>{release=()=>r(f.wrap(f.waiting));});}};
 const dialing=p.a.dial({userId:'202',accessHash:2n});await gate;p.a.stop();release();await assert.rejects(dialing,{reason:'call_cancelled'});assert.equal(p.a.state.phase,'stopped');assert.equal(p.a.state.keyNegotiated,false);assert.equal(p.api.clients[0].closed,true);
});
test('retired calls, stale private send closures and duplicate key transitions cannot cross into a new call',async t=>{
 const p=await pair(t);await p.negotiate();const send=p.aSecure[0].send,active=p.api.clone({_:'updatePhoneCall',phone_call:{_:'phoneCallAccepted',...p.api.call.base,g_b:p.api.call.gb}});
 await p.a.ingest(active);assert.equal(p.aSecure.length,1);await p.a.hangUp();assert.throws(()=>send(signal),{reason:'call_cancelled'});await p.a.ingest(active);assert.equal(p.a.state.phase,'listening');assert.equal(p.a.state.keyNegotiated,false);
});
test('replayed or corrupted encrypted signaling cannot be delivered twice or remain ready after authentication failure',async t=>{
 const p=await pair(t);await p.negotiate();await p.a.sendSignal(signal);const event=p.api.clone(p.api.queues.get(202)[0]);await p.b.ingest(event);assert.equal(p.bSignals.length,1);
 await assert.rejects(p.b.ingest(event),{reason:'signal_replayed'});assert.equal(p.b.state.phase,'failed');assert.equal(p.b.state.keyNegotiated,false);
 const q=await pair(t);await q.negotiate();await q.a.sendSignal(signal);const bad=q.api.clone(q.api.queues.get(202)[0]);bad.data[0]^=1;await assert.rejects(q.b.ingest(bad),{reason:'invalid_signal_authentication'});assert.equal(q.bSignals.length,0);
});
test('update cursor regression and too-long history cannot acknowledge events or silently skip them',async t=>{
 const p=await pair(t);await p.a.dial({userId:'202',accessHash:2n});const request=p.api.clone(p.api.queues.get(202)[0]);p.api.override=({self,method})=>self===202&&method==='updates.getDifference'?{_:'updates.difference',other_updates:[request],state:{...f.state,pts:0,seq:0}}:undefined;
 await assert.rejects(p.b.pollOnce(),{reason:'update_cursor_regressed'});assert.equal(p.api.calls.some(v=>v.method==='phone.receivedCall'),false);
 const q=await pair(t);q.api.override=({method})=>method==='updates.getDifference'?{_:'updates.differenceTooLong',pts:999}:undefined;await assert.rejects(q.a.pollOnce(),{reason:'update_resync_required'});assert.equal(q.a.state.phase,'failed');
});
test('early signaling overflow, invalid event frames and unauthorized local actions are bounded',async t=>{
 const p=await pair(t);await p.a.dial({userId:'202',accessHash:2n});await p.b.pollOnce();
 for(let i=0;i<16;i++)await p.b.ingest({_:'updatePhoneCallSignalingData',phone_call_id:f.peer.id,data:Buffer.alloc(21,i)});
 await assert.rejects(p.b.ingest({_:'updatePhoneCallSignalingData',phone_call_id:f.peer.id,data:Buffer.alloc(21)}),{reason:'too_many_early_signals'});assert.equal(p.b.state.phase,'failed');
 const q=await pair(t);await assert.rejects(q.a.ingest({_:'unknown',data:'private-secret'}),{reason:'invalid_call_event'});assert.equal(q.a.state.phase,'listening');await assert.rejects(q.a.dial({userId:'303',accessHash:2n}),{reason:'call_peer_not_allowed'});assert.equal(q.a.state.phase,'listening');await assert.rejects(q.a.accept(),{reason:'call_not_ringing'});
});
test('acknowledgement false, unconfirmed hangup and callback failures never report media/proxy readiness',async t=>{
 const p=await pair(t);await p.a.dial({userId:'202',accessHash:2n});p.api.override=({method})=>method==='phone.receivedCall'?false:undefined;await assert.rejects(p.b.pollOnce(),{reason:'call_receipt_not_confirmed'});
 const q=await pair(t);await q.negotiate();q.api.override=({method})=>method==='phone.discardCall'?f.updates([]):undefined;await assert.rejects(q.a.hangUp(),{reason:'call_end_not_confirmed'});assert.equal(q.a.state.proxyReady,false);
 const r=await pair(t,{onASecure:()=>{throw Error('private-key-secret');}});await r.a.dial({userId:'202',accessHash:2n});await r.b.pollOnce();await r.b.accept();await assert.rejects(r.a.pollOnce(),{reason:'call_operation_failed'});assert.ok(!JSON.stringify(r.a.state).includes('private-key-secret'));
});
test('only confirmed Eitaa accounts and explicit allowed-peer sets can start call processing',async t=>{
 const api=service(),a=account(101);a.stop();const session=new CallSession(a,{createClient:o=>api.createClient(o),allowedPeers:['202']});t.after(()=>session.close());await assert.rejects(session.start(),{reason:'not_authenticated'});assert.equal(api.calls.length,0);
 for(const allowedPeers of [['202','202'],['0'],['x'],Array(33).fill('202')])assert.throws(()=>new CallSession(account(101),{allowedPeers}),{reason:'invalid_call_options'});
 const s=new CallSession(account(101),{createClient:o=>api.createClient(o),allowedPeers:['101']});t.after(()=>s.close());await assert.rejects(s.start(),{reason:'invalid_call_options'});assert.equal(api.calls.length,0);
});
test('private callback sends serialize, retain call binding after callback return, and snapshot mutable input',async t=>{
 const p=await pair(t,{onASecure:context=>Promise.all([context.send(signal),context.send(signal)])});await p.negotiate();assert.equal(p.bSignals.length,2);
 const original=JSON.parse(JSON.stringify(signal));const sending=p.aSecure[0].send(original);original.candidates[0].sdpString='candidate:mutated';await sending;await p.b.pollOnce();assert.deepEqual(p.bSignals[2],signal);
 await p.a.hangUp();await p.b.pollOnce();await p.negotiate();const active=p.a.state.callId;assert.throws(()=>p.aSecure[0].send(signal),{reason:'call_cancelled'});assert.equal(p.a.state.callId,active);assert.equal(p.a.state.phase,'secure');
});
test('same-ID access hash changes and duplicate active confirmations with a changed fingerprint are rejected',async t=>{
 const p=await pair(t);await p.negotiate();const call={_:'phoneCall',...p.api.call.base,g_a_or_b:p.api.call.gb,key_fingerprint:p.api.call.fingerprint,connections:[f.connection],start_date:f.state.date};
 await assert.rejects(p.a.ingest({_:'updatePhoneCall',phone_call:{...call,access_hash:123n}}),{reason:'call_identity_mismatch'});assert.equal(p.a.state.phase,'failed');
 await assert.rejects(p.b.ingest({_:'updatePhoneCall',phone_call:{...call,key_fingerprint:call.key_fingerprint+1n}}),{reason:'fingerprint_mismatch'});assert.equal(p.b.state.phase,'failed');
});
test('optional polling sends at most one pending poll, stops after close and never automatically dials or accepts',async t=>{
 t.mock.timers.enable({apis:['Date','setInterval']});const api=service(),s=new CallSession(account(101),{allowedPeers:['202'],createClient:o=>api.createClient(o)});t.after(()=>s.close());
 await s.start({pollInterval:1000});let release;api.override=({method})=>method==='updates.getDifference'?new Promise(r=>{release=()=>r({_:'updates.differenceEmpty',date:f.state.date,seq:10});}):undefined;
 t.mock.timers.tick(1000);assert.equal(api.calls.filter(v=>v.method==='updates.getDifference').length,1);t.mock.timers.tick(5000);assert.equal(api.calls.filter(v=>v.method==='updates.getDifference').length,1);s.close();release();await new Promise(setImmediate);t.mock.timers.tick(10000);assert.equal(api.calls.length,2);assert.equal(s.state.phase,'stopped');
});
test('handshake deadline clears keys and closes the account client without redial or another call request',async t=>{
 t.mock.timers.enable({apis:['Date','setInterval']});const p=await pair(t);await p.a.dial({userId:'202',accessHash:2n});t.mock.timers.tick(61000);assert.equal(p.a.state.phase,'failed');assert.equal(p.a.state.reason,'call_timeout');assert.equal(p.api.clients[0].closed,true);assert.equal(p.api.calls.filter(v=>v.method==='phone.requestCall').length,1);
});
test('queued event count is bounded even when a service response is stalled',async t=>{
 const p=await pair(t);let release,entered;const gate=new Promise(r=>{entered=r;});p.api.override=({method})=>{if(method==='updates.getDifference'){entered();return new Promise(r=>{release=()=>r({_:'updates.differenceEmpty',date:f.state.date,seq:10});});}};
 const polling=p.a.pollOnce();await gate;const errors=[];for(let i=0;i<33;i++)errors.push(p.a.ingest({_:'updatePhoneCall',phone_call:{_:'phoneCallDiscarded',id:BigInt(i+1)}}).catch(e=>e));release();await assert.rejects(polling,{reason:'call_cancelled'});const results=await Promise.all(errors);assert.equal(results.filter(e=>e.reason==='too_many_call_events').length,1);assert.equal(p.a.state.queued,0);assert.equal(p.a.state.phase,'failed');
});
test('either retained account can be caller and the other can explicitly accept without changing signaling roles',async t=>{
 const p=await pair(t);await p.b.dial({userId:'101',accessHash:-11n});await p.a.pollOnce();assert.equal(p.a.state.phase,'ringing');await p.a.accept();await p.b.pollOnce();await p.a.pollOnce();assert.equal(p.a.state.direction,'incoming');assert.equal(p.b.state.direction,'outgoing');await p.b.sendSignal(signal);await p.a.pollOnce();assert.deepEqual(p.aSignals,[signal]);
});
test('real AuthSession restore and real CallClient envelopes reuse the confirmed account token/device without another login',async t=>{
 const crypto=require('node:crypto'),wire=require('../experiments/eitaa/wire.cjs'),authWire=require('../experiments/eitaa/auth-wire.cjs'),callWire=require('../experiments/eitaa/call-wire.cjs');
 const {AuthSession}=require('../experiments/eitaa/auth-session.cjs'),{AccountClient}=require('../experiments/eitaa/account-client.cjs'),{CallClient}=require('../experiments/eitaa/call-client.cjs');
 const seen=[],record={provider:'eitaa',format:1,userId:'101',token:'fixture-retained-token',imei:'0123456789abcde__web',loginPhone:'+989120000001',profile:{deviceModel:'BaleVPN Provider Lab (desktop)',systemVersion:'fixture platform'},deviceMetadataSent:false,name:'fixture'};
 function envelope(bytes){const r=new wire.Reader(bytes);assert.equal(r.int(),wire.IDS.eitaaObject);assert.equal(r.string(),record.token);assert.equal(r.string(),record.imei);const packed=r.bytes();assert.equal(r.int(),135);assert.equal(r.int(),128);r.end();seen.push(packed.readInt32LE());return packed;}
 const auth=new AuthSession({createClient:o=>new AccountClient({...o,fetchImpl:async(_url,o)=>{
  assert.deepEqual(envelope(o.body),authWire.method('users.getUsers',{id:[{_:'inputUserSelf'}]}));const user={_:'user',self:true,id:101n,first_name:'fixture',phone:'989120000001'};
  return new Response(Buffer.concat([new wire.Writer().int(481674261).int(1).finish(),authWire.object(user)]));
 }})});t.after(()=>auth.close());await auth.restore(record);
 const schema=require('../experiments/eitaa/call-schema.json'),methodIds=new Map(schema.methods.map(v=>[v.id,v.method]));
 const session=new CallSession(auth,{allowedPeers:['202'],createClient:o=>new CallClient({...o,fetchImpl:async(_url,o)=>{
  const name=methodIds.get(envelope(o.body).readInt32LE());let reply;
  if(name==='updates.getState')reply=f.state;
  else if(name==='messages.getDhConfig')reply={_:'messages.dhConfig',g:2,p:crypto.getDiffieHellman('modp14').getPrime(),random:crypto.randomBytes(256),version:1};
  else {assert.equal(name,'phone.requestCall');reply=f.wrap(f.waiting);}return new Response(callWire.object(reply));
 }})});t.after(()=>session.close());await session.start();await session.dial({userId:'202',accessHash:22n});assert.equal(session.state.phase,'waiting');assert.equal(seen.length,4);assert.equal(seen[0],authWire.method('users.getUsers',{id:[{_:'inputUserSelf'}]}).readInt32LE());
 auth.stop();await assert.rejects(session.pollOnce(),{reason:'not_authenticated'});assert.equal(seen.length,4);
});
test('a stalled private media callback times out and explicit stop releases it without waiting for completion',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});let entered;let gate=new Promise(r=>{entered=r;});
 const p=await pair(t,{onASecure:()=>{entered();return new Promise(()=>{});}});await p.a.dial({userId:'202',accessHash:2n});await p.b.pollOnce();await p.b.accept();const polling=p.a.pollOnce();await gate;t.mock.timers.tick(20001);await assert.rejects(polling,{reason:'media_callback_timeout'});assert.equal(p.a.state.phase,'failed');assert.equal(p.a.state.keyNegotiated,false);
 gate=new Promise(r=>{entered=r;});const q=await pair(t,{onASecure:()=>{entered();return new Promise(()=>{});}});await q.a.dial({userId:'202',accessHash:2n});await q.b.pollOnce();await q.b.accept();const waiting=q.a.pollOnce();await gate;q.a.stop();await assert.rejects(waiting,{reason:'call_cancelled'});await q.a.start();assert.equal(q.a.state.phase,'listening');assert.equal(q.a.state.keyNegotiated,false);
 let r;r=await pair(t,{onASecure:()=>{r.a.stop();return new Promise(()=>{});}});await r.a.dial({userId:'202',accessHash:2n});await r.b.pollOnce();await r.b.accept();await assert.rejects(r.a.pollOnce(),{reason:'call_cancelled'});await r.a.start();assert.equal(r.a.state.phase,'listening');
});
