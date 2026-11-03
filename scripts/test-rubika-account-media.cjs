'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {AccountMedia}=require('../experiments/rubika/account-media.cjs'),{pair}=require('./rubika-account-media-fixture.cjs');
const profile={libraryVersion:'6.0.0',protocolLayer:92};
function sdp(type){return {type,sdp:['v=0','o=- 1 2 IN IP4 127.0.0.1','s=-','t=0 0','a=group:BUNDLE 0','a=fingerprint:sha-256 '+Array(32).fill('A5').join(':'),`a=setup:${type==='offer'?'actpass':'active'}`,
 'm=audio 9 UDP/TLS/RTP/SAVPF 111','c=IN IP4 0.0.0.0','a=ice-ufrag:fixture-ufrag','a=ice-pwd:fixture-private-ice-password','a=mid:0','a=sendrecv','a=rtcp-mux','a=rtpmap:111 opus/48000/2','a=ssrc:1234 cname:fixture','a=candidate:1 1 udp 1 192.0.2.1 40000 typ relay',''].join('\r\n')};}
function helper(cert){const state={phase:'prepared',relayPair:false,mediaConnected:false,peerAuthenticated:false,proxyReady:false};let closed=0,role;
 return {state,get closed(){return closed;},connected(){Object.assign(state,{phase:'connected',relayPair:true,mediaConnected:true,peerAuthenticated:true,proxyReady:role==='client',socksAddress:role==='client'?'127.0.0.1:1089':null});},
 bridge:{publicCertificate:cert,get state(){return {...state};},async configure(call,options){assert.equal(call.provider,'rubika');role=options.role;state.phase='configured';},
 async offer(){state.phase='connecting';return sdp('offer');},async answer(){state.phase='connecting';return sdp('answer');},async setAnswer(){},async addCandidate(){},close(){closed++;state.phase='closed';}}};}
async function fixture(t,options={}){
 const p=await pair(options),left=helper('aa'.repeat(80)),right=helper('bb'.repeat(80));
 const a=new AccountMedia(p.a,{...profile,executable:'fixture-rubika-helper',role:'client',socksPort:0,open:async()=>left.bridge});
 const b=new AccountMedia(p.b,{...profile,executable:'fixture-rubika-helper',role:'server',open:async()=>right.bridge});
 t.after(()=>{a.close();b.close();p.close();});
 const [ac,bc]=await Promise.all([a.prepare(),b.prepare()]);a.trustCertificate(bc.publicCertificate);b.trustCertificate(ac.publicCertificate);await p.negotiate();
 return {p,a,b,left,right,async attach(){await b.attachAccepted();await a.attachAccepted();await b.pollOnce();await a.pollOnce();},
  async ready(){left.connected();right.connected();await a.pollOnce();await b.pollOnce();}};
}
test('accepted-only media handoff has one nonserializable consumer and an owned defensive key/context copy',async t=>{
 const p=await pair();t.after(()=>p.close());assert.throws(()=>p.a.issueLegacyMedia(),/call_not_accepted/);await p.negotiate();
 const lease=p.a.issueLegacyMedia();assert.equal(JSON.stringify(lease),'{}');const context=lease.consumeContext();assert.equal(context.key.toString(),p.key);
 context.key.fill(0);context.connections[0].turn_password='changed';assert.equal(p.a.state.phase,'accepted');
 assert.throws(()=>lease.consumeContext(),/media_lease_consumed/);assert.throws(()=>p.a.issueLegacyMedia(),/media_lease_already_issued/);
 assert.ok(!JSON.stringify(p.a.state).includes(p.key));assert.equal(p.a.state.mediaStarted,false);
});
test('key, relay or negotiated-profile changes revoke a handoff; duration changes preserve it',async t=>{
 for(const field of ['key','connections','protocol_layer','library_versions','duration']){
  const p=await pair();t.after(()=>p.close());await p.negotiate();const lease=p.a.issueLegacyMedia();
  const value=p.update(0,'Accepted');value.updated_parameters=[field];
  value.call[field]=field==='key'?'b'.repeat(256):field==='connections'?[{type:'WebRTC',ip:'192.0.2.2',port:3478,turn_username:'fixture',turn_password:'other'}]:field==='protocol_layer'?93:field==='library_versions'?['9.0.0']:4;
  p.events[0].push(value);await p.a.pollOnce();if(field==='duration')assert.doesNotThrow(()=>lease.assertCurrent());else assert.throws(()=>lease.assertCurrent(),/media_lease_expired/);
 }
});
test('an unconfirmed service key or incompatible negotiation cannot be handed to a media worker',async t=>{
 for(const field of ['key','protocol_layer','library_versions','connections']){
  const p=await pair();t.after(()=>p.close());await p.negotiate();const u=p.update(0,'Accepted');u.updated_parameters=[field];
  u.call[field]=field==='key'?'short':field==='protocol_layer'?93:field==='library_versions'?['9.0.0']:[{type:'Tg',ip:'192.0.2.1',port:3478}];
  p.events[0].push(u);await p.a.pollOnce();assert.throws(()=>p.a.issueLegacyMedia(),/invalid_media_parameters|unsupported_media_profile/);
 }
});
test('same-second acceptance can supply newly negotiated relays and version fields before any media handoff',async t=>{
 let waitingAt;const p=await pair({hook:async(slot,method)=>{
  if(slot===0&&method==='requestCall'){const u=p.update(0,'Waiting','New');waitingAt=u.timestamp;u.call.connections=[];u.call.library_versions=[];return {call_type:'WebRtc',call_update:u};}
 }});t.after(()=>p.close());await p.a.start();await p.a.dial(p.ids[1]);const accepted=p.update(0,'Accepted');accepted.timestamp=waitingAt;p.events[0].push(accepted);await p.a.pollOnce();
 const lease=p.a.issueLegacyMedia(),context=lease.consumeContext();assert.equal(context.connections.length,1);assert.equal(context.libraryVersion,'6.0.0');context.key.fill(0);
});
test('an ambiguous same-timestamp security change after handoff terminates media instead of retaining a stale key',async t=>{
 const f=await fixture(t);await f.attach();await f.ready();
 // Establish a known per-field timestamp, then conflict at that same timestamp.
 const accepted=f.p.update(0,'Accepted');f.p.events[0].push(accepted);await f.a.pollOnce();
 const conflict=structuredClone(accepted);conflict.call.key='c'.repeat(256);conflict.updated_parameters=['key'];f.p.events[0].push(conflict);
 await assert.rejects(f.a.pollOnce(),/ambiguous_media_update/);assert.equal(f.a.state.ready,false);assert.equal(f.left.closed,1);
});
test('full typed call controllers carry encrypted setup/candidates into owned media, with no early callStarted',async t=>{
 const f=await fixture(t);await f.attach();assert.equal(f.a.state.ready,false);assert.deepEqual(f.p.started,[0,0]);
 assert.ok(f.p.calls.filter(x=>x.method==='sendSignalingData').length>=4);assert.ok(!JSON.stringify(f.p.calls).includes('fixture-private-ice-password'));
 await f.ready();assert.equal(f.a.state.proxyReady,true);assert.equal(f.b.state.serverReady,true);assert.equal(f.b.state.proxyReady,false);assert.deepEqual(f.p.started,[1,1]);
 await f.a.pollOnce();await f.b.pollOnce();assert.deepEqual(f.p.started,[1,1]);
 for(const secret of [f.p.key,f.p.records[0].auth,f.p.records[0].privateKey,'fixture-private-ice-password'])assert.ok(!JSON.stringify(f.a.state).includes(secret));
 for(const flag of ['providerPathVerified','billingVerified','internationalOutageVerified'])assert.equal(f.a.state[flag],false);
});
test('false native authentication cannot report callStarted or expose a SOCKS endpoint',async t=>{
 const f=await fixture(t);await f.attach();f.left.connected();f.left.state.peerAuthenticated=false;await f.a.pollOnce();assert.equal(f.a.state.ready,false);assert.equal(f.a.state.socksAddress,null);assert.equal(f.p.started[0],0);
});
test('normal hangup and remote deletion close both workers and preserve authenticated account sessions',async t=>{
 const f=await fixture(t);await f.attach();await f.ready();assert.deepEqual(await f.a.hangup(),{ended:true});assert.equal(f.left.closed,1);assert.equal(f.p.a.state.phase,'listening');
 assert.deepEqual(await f.b.pollOnce(),{ended:true});assert.equal(f.right.closed,1);assert.equal(f.p.b.state.phase,'listening');assert.ok(f.p.accountStates.every(a=>a.signedIn));
 assert.equal(f.a.state.proxyReady,false);assert.equal(f.b.state.ready,false);
});
test('service-key changes, account logout and media failure revoke proxy readiness and close only owned resources',async t=>{
 for(const mutation of [f=>{f.p.accountStates[0].signedIn=false;},f=>{f.p.records[0].auth='changed-auth';},f=>{f.left.state.phase='failed';f.left.state.reason='transport_disconnected';}]){
  const f=await fixture(t);await f.attach();await f.ready();mutation(f);assert.equal(f.a.state.ready,false);assert.equal(f.left.closed,1);assert.equal(f.a.state.socksAddress,null);assert.equal(f.p.accountStates[1].signedIn,true);
 }
});
test('a lost callStarted response aborts without retrying the service or publishing false readiness',async t=>{
 const f=await fixture(t,{hook:async(slot,method)=>{if(slot===0&&method==='callStarted')throw Object.assign(new(require('../experiments/rubika/http-client.cjs').ApiError)('network_error'),{privateDetail:'private response dump'});}});
 await f.attach();f.left.connected();await assert.rejects(f.a.pollOnce(),e=>e.reason==='network_error'&&!e.message.includes('private'));
 assert.equal(f.a.state.ready,false);assert.equal(f.a.state.phase,'failed');assert.equal(f.p.calls.filter(x=>x.slot===0&&x.method==='callStarted').length,1);
 await assert.rejects(f.a.pollOnce());assert.equal(f.p.calls.filter(x=>x.slot===0&&x.method==='callStarted').length,1);
});
test('routine wrong-state actions or an invalid hangup option cannot tear down prepared or connected media',async t=>{
 const f=await fixture(t);await assert.rejects(f.a.prepare(),/media_not_prepared/);await assert.rejects(f.a.pollOnce(),/media_not_attached/);assert.equal(f.left.closed,0);
 await f.attach();await f.ready();await assert.rejects(f.a.hangup('invalid'),/invalid_call_options/);assert.equal(f.a.state.ready,true);assert.equal(f.left.closed,0);
});
test('a changed negotiated key ends the owned media before any further encrypted packet is sent',async t=>{
 const f=await fixture(t);await f.attach();await f.ready();const before=f.p.calls.filter(x=>x.method==='sendSignalingData').length;
 const change=f.p.update(0,'Accepted');change.updated_parameters=['key'];change.call.key='b'.repeat(256);f.p.events[0].push(change);
 await assert.rejects(f.a.pollOnce(),/media_lease_expired/);assert.equal(f.a.state.ready,false);assert.equal(f.left.closed,1);
 assert.equal(f.p.calls.filter(x=>x.method==='sendSignalingData').length,before);
});
test('bad ciphertext fails before media delivery and clears queued signaling and readiness',async t=>{
 const f=await fixture(t);await f.attach();f.p.signals[0].push({call_id:f.p.callId,data:Buffer.alloc(32,0xa5).toString('base64')});
 await assert.rejects(f.a.pollOnce(),/invalid_signal_authentication/);assert.equal(f.a.state.ready,false);assert.equal(f.p.a.state.queuedSignals,0);assert.equal(f.left.closed,1);
});
test('authenticated service redelivery is ignored without resetting replay protection or tearing down a working proxy',async t=>{
 const f=await fixture(t);await f.attach();await f.ready();const sent=f.p.calls.find(x=>x.slot===1&&x.method==='sendSignalingData');
 f.p.signals[0].push({call_id:f.p.callId,data:sent.input.data});await f.a.pollOnce();assert.equal(f.a.state.ready,true);assert.equal(f.a.state.discardedSignals,1);assert.equal(f.left.closed,0);
 assert.deepEqual(f.p.started,[1,1]);
});
test('close while a signal send is awaiting service response cannot revive media or retain a usable handoff',async t=>{
 let release;const f=await fixture(t,{hook:async(slot,method)=>{if(slot===0&&method==='sendSignalingData')return new Promise(r=>{release=r;});}});
 await f.b.attachAccepted();const pending=f.a.attachAccepted();
 for(let i=0;i<100&&!release;i++)await new Promise(r=>setTimeout(r,1));assert.equal(typeof release,'function');f.a.close();release({});await assert.rejects(pending);
 assert.equal(f.a.state.phase,'closed');assert.equal(f.a.state.ready,false);assert.equal(f.left.closed,1);assert.equal(f.p.a.state.phase,'closed');
});
