const {test} = require('node:test');
const assert = require('node:assert/strict');
const {CallSession} = require('../experiments/igap/call-session.cjs');
const {wire: w} = require('../experiments/igap/signaling.cjs');
const {RpcError} = require('../experiments/igap/rpc-connection.cjs');

const token = 'fixtureHeader.fixturePayload.fixtureSignature';
const numeric = (field, value) => w.field(field, BigInt(value), 0);
const offer = (sender, room, extra = Buffer.alloc(0)) => w.frame(30915,
  Buffer.concat([numeric(2, sender), numeric(3, room), extra]));
const boundToken=(claims={})=>'header.'+Buffer.from(JSON.stringify({sub:'41',video:{room:'99',roomJoin:true},exp:Math.floor(Date.now()/1000)+300,...claims})).toString('base64url')+'.signature';
const joinPush=(token,user='41')=>w.frame(30914,Buffer.concat([w.string(2,token,16384),numeric(3,user)]));

test('caller accepts only an authenticated outgoing push bound to the exact LiveKit room/account and does not join twice',async()=>{
 const {session,calls}=fixture();await session.dial('42');const token=boundToken();await session.handlePush(joinPush(token));assert.equal(session.state.phase,'joined');assert.equal(session.state.credentialReady,true);assert.ok(Object.values(session.state.joinPushDiagnostic).every(v=>v===true));await session.join();assert.deepEqual(calls.map(c=>c.action),[913,915]);await session.handlePush(joinPush(boundToken({exp:Math.floor(Date.now()/1000)+600})));assert.equal(session.takeTransportSession().token,token);assert.equal(session.state.joinPushDiagnostic.contextMatches,false);assert.ok(!JSON.stringify(session.state).includes(token));
});

test('media grant diagnostics attach only to accepted credentials and cannot alter authorization',async()=>{
 const token=boundToken({video:{room:'99',roomJoin:true,canPublish:false,canSubscribe:true,canPublishData:false,canPublishSources:['microphone']}}),expected={publish:false,subscribe:true,publishData:false,microphoneAllowed:true};for(const incoming of [false,true]){const f=fixture();if(incoming){await f.session.handlePush(offer('42','99'));f.rpc.handler=async()=>({action:30914,fields:w.parse(joinPush(token).subarray(2))});await f.session.join();}else{await f.session.dial('42');await f.session.handlePush(joinPush(token));}assert.equal(f.session.state.credentialReady,true);assert.deepEqual(f.session.state.mediaGrants,expected);const copy=f.session.state.mediaGrants;copy.publish=true;assert.equal(f.session.state.mediaGrants.publish,false);f.session.reset('ended');assert.deepEqual(f.session.state.mediaGrants,expected);f.session.reset();assert.equal(f.session.state.mediaGrants,null);}
 const f=fixture();await f.session.dial('42');await f.session.handlePush(joinPush(boundToken({sub:'42'})));assert.equal(f.session.state.mediaGrants,null);
});

test('caller token pushes reject cross-room, cross-account, expired, malformed and missing grants without exposing claims',async()=>{
 const cases=[boundToken({video:{room:'100',roomJoin:true}}),boundToken({sub:'42'}),boundToken({exp:1}),boundToken({nbf:Math.floor(Date.now()/1000)+600}),boundToken({video:{room:'99'}}),boundToken({video:{roomJoin:true}}),'header.payload.signature'];
 for(const token of cases){const {session}=fixture();await session.dial('42');await session.handlePush(joinPush(token));assert.equal(session.state.phase,'outgoing');assert.equal(session.state.credentialReady,false);assert.ok(Object.values(session.state.joinPushDiagnostic).every(v=>typeof v==='boolean'));assert.ok(!JSON.stringify(session.state.joinPushDiagnostic).includes(token));session.reset();assert.equal(session.state.joinPushDiagnostic,null);}
 const {session}=fixture();await session.handlePush(offer('42','99'));await session.handlePush(joinPush(boundToken()));assert.equal(session.state.phase,'incoming');assert.equal(session.state.credentialReady,false);session.reset();await session.handlePush(joinPush(boundToken()));assert.equal(session.state.credentialReady,false);
});

test('late or wrong-user token pushes cannot revive an ended call or a replaced authenticated connection',async()=>{
 for(const change of [f=>f.session.reset('ended'),f=>{f.account.connection={request:async()=>{throw Error('must not call');}};},f=>{f.account.state.signedIn=false;}]){const f=fixture();await f.session.dial('42');change(f);await f.session.handlePush(joinPush(boundToken()));assert.equal(f.session.state.credentialReady,false);assert.ok(['idle','ended'].includes(f.session.state.phase));}
 const f=fixture();await f.session.dial('42');await f.session.handlePush(joinPush(boundToken(),'42'));assert.equal(f.session.state.phase,'outgoing');assert.equal(f.session.state.credentialReady,false);
});

test('peer leave during a pending join retains safe terminal actor/stage and rejects the stale credential reply',async()=>{
 for(const [actor,id]of [['peer','42']]){const {session,rpc}=fixture();await session.handlePush(offer('42','99'));const reply=deferred();rpc.handler=()=>reply.promise;const joining=session.join();assert.equal(session.state.phase,'joining');await session.handlePush(w.frame(30918,numeric(2,id)));assert.equal(session.state.phase,'ended');assert.deepEqual(session.state.terminalDiagnostic,{cause:'service_leave',endingActor:actor,phaseBeforeEnd:'joining'});
  reply.resolve({action:30914,fields:w.parse(Buffer.concat([w.string(2,token,100),numeric(3,'41')]))});await assert.rejects(joining,/call_cancelled/);assert.equal(session.state.credentialReady,false);assert.equal(session.state.busy,false);assert.equal(session.state.terminalDiagnostic.endingActor,actor);const diagnostic=JSON.stringify(session.state.terminalDiagnostic);for(const secret of [token,'41','42','99'])assert.ok(!diagnostic.includes(secret));
  const exported=session.state.terminalDiagnostic;exported.endingActor='altered';assert.equal(session.state.terminalDiagnostic.endingActor,actor);session.reset('ended');assert.equal(session.state.terminalDiagnostic.endingActor,actor);await session.handlePush(offer('42','100'));assert.equal(session.state.terminalDiagnostic,null);session.reset();assert.equal(session.state.terminalDiagnostic,null);
 }
});

test('receiver self-leave during correlated join is resolved only by exact current-room credentials; later self-leave still ends it',async()=>{
 const {session,rpc,calls}=fixture();await session.handlePush(offer('42','99'));const reply=deferred();rpc.handler=()=>reply.promise;const joining=session.join();for(let n=0;n<3;n++)await session.handlePush(w.frame(30918,numeric(2,'41')));assert.equal(session.state.phase,'joining');assert.equal(session.state.credentialReady,false);assert.equal(session.state.terminalDiagnostic.selfLeaveDeferred,true);const token=boundToken();reply.resolve({action:30914,fields:w.parse(joinPush(token).subarray(2))});await joining;assert.equal(session.state.phase,'joined');assert.equal(session.state.terminalDiagnostic.joinConfirmed,true);assert.equal(session.takeTransportSession().token,token);assert.deepEqual(calls.map(v=>v.action),[914]);await session.handlePush(w.frame(30918,numeric(2,'41')));assert.equal(session.state.phase,'ended');assert.equal(session.state.terminalDiagnostic.selfLeaveDeferred,undefined);
});

test('deferred receiver self-leave ends on invalid credentials, request timeout, peer leave, or local reset without retry',async()=>{
 for(const outcome of ['invalid','timeout','peer','reset','replaced','revoked']){const {session,rpc,account,calls}=fixture();await session.handlePush(offer('42','99'));const reply=deferred();rpc.handler=()=>reply.promise;const joining=session.join();await session.handlePush(w.frame(30918,numeric(2,'41')));if(outcome==='peer')await session.handlePush(w.frame(30918,numeric(2,'42')));if(outcome==='reset')session.reset();if(outcome==='revoked')account.state.signedIn=false;if(outcome==='replaced')account.connection={request:async()=>{throw Error('must not call');}};if(outcome==='timeout')reply.reject(new RpcError('timeout'));else reply.resolve({action:30914,fields:w.parse(joinPush(outcome==='invalid'?boundToken({video:{room:'100',roomJoin:true}}):boundToken()).subarray(2))});await assert.rejects(joining);assert.equal(session.state.credentialReady,false);assert.ok(['idle','ended'].includes(session.state.phase));assert.equal(calls.length,1);}
});

test('unrelated and stale correlated leave pushes during a pending join do not end the call',async()=>{
 const {session,rpc}=fixture();await session.dial('42');const reply=deferred();rpc.handler=()=>reply.promise;const joining=session.join();await session.handlePush(w.frame(30918,numeric(2,'43')));await session.handlePush(w.frame(30918,Buffer.concat([w.field(1,w.string(1,'stale-correlation',64)),numeric(2,'41')])));assert.equal(session.state.phase,'joining');assert.equal(session.state.terminalDiagnostic,null);reply.resolve({action:30914,fields:w.parse(Buffer.concat([w.string(2,token,100),numeric(3,'41')]))});await joining;assert.equal(session.state.phase,'joined');assert.equal(session.state.credentialReady,true);assert.equal(session.state.terminalDiagnostic,null);session.reset();
});
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}
function fixture(self = '41', peer = '42', room = '99') {
  const calls = [];
  const account = {state: {signedIn: true, userId: self}, connection: null};
  const rpc = {handler: null, async request(action, bytes) {
    const fields = w.parse(bytes);
    assert.equal(fields.has(1), false, 'RPC owns the real correlation ID');
    calls.push({action, fields});
    if (rpc.handler) return rpc.handler(action, fields);
    let payload;
    if (action === 913) {
      assert.equal(w.number(fields, 2), 0);
      assert.equal(w.number(fields, 3), 0);
      payload = numeric(2, room);
    } else if (action === 915) {
      assert.equal(w.one(fields, 2, 0).toString(), peer);
      assert.equal(w.one(fields, 3, 0).toString(), room);
      payload = offer(self, room).subarray(2);
    } else if (action === 914) {
      assert.equal(w.one(fields, 2, 0).toString(), room);
      payload = Buffer.concat([w.string(2, token, 100), numeric(3, self)]);
    } else if (action === 916 || action === 918) {
      payload = numeric(2, self);
    } else throw new Error('Unexpected request');
    return {action: action + 30000, fields: w.parse(payload)};
  }};
  account.connection = rpc;
  const session = new CallSession(account);
  session.setAllowedPeers([peer]);
  return {account, rpc, session, calls};
}

test('outgoing create/offer/join/leave uses one account and never exposes credentials in state', async () => {
  const {session, calls} = fixture();
  await session.dial('42');
  assert.deepEqual(calls.map(c => c.action), [913, 915]);
  assert.equal(session.state.phase, 'outgoing');
  await session.handlePush(w.frame(30916, numeric(2, '42')));
  assert.equal(session.state.ringing, true);
  await session.join();
  assert.equal(session.state.phase, 'joined');
  assert.ok(!JSON.stringify(session.state).includes(token));
  const privateSession = session.takeTransportSession();
  assert.deepEqual(privateSession, {provider: 'igap', url: 'wss://call.igap.net/', token,
    peerId: '42', roomId: '99', selfId: '41'});
  assert.throws(() => session.takeTransportSession(), /call_transport_not_ready/);
  await session.leave({terminate: true});
  assert.equal(w.number(calls.at(-1).fields, 2), 1);
  assert.equal(session.state.phase, 'ended');
  assert.equal(session.state.tunnelReady, false);
});

test('incoming calls require an allowed peer, explicit ringing and explicit acceptance', async () => {
  const {session, calls} = fixture();
  await session.handlePush(offer('43', '99'));
  assert.equal(session.state.phase, 'idle');
  assert.equal(calls.length, 0);
  await session.handlePush(offer('42', '99'));
  assert.equal(session.state.phase, 'incoming');
  assert.equal(calls.length, 0, 'receiving a call does not automatically answer');
  await session.ring();
  await session.join();
  assert.deepEqual(calls.map(c => c.action), [916, 914]);
  assert.equal(session.state.credentialReady, true);
  await session.leave();
  assert.equal(w.number(calls.at(-1).fields, 2), 0);
});

test('two simultaneous accounts retain independent peers, room IDs and credential ownership', async () => {
  const a = fixture('9007199254740993', '9007199254740994', '18446744073709551615');
  const b = fixture('9007199254740994', '9007199254740993', '9007199254740995');
  await Promise.all([a.session.dial('9007199254740994'), b.session.dial('9007199254740993')]);
  await Promise.all([a.session.join(), b.session.join()]);
  assert.equal(a.session.takeTransportSession().selfId, '9007199254740993');
  assert.equal(b.session.takeTransportSession().roomId, '9007199254740995');
  assert.equal(a.session.state.roomId, '18446744073709551615');
});

test('unsolicited credentials, stale correlated pushes and third-party events cannot hijack an active call', async () => {
  const {session} = fixture();
  await session.dial('42');
  const credential = w.frame(30914, Buffer.concat([w.string(2, token, 100), numeric(3, '41')]));
  await session.handlePush(credential);
  assert.equal(session.state.credentialReady, false);
  await session.handlePush(offer('42', '100'));
  await session.handlePush(w.frame(30918, numeric(2, '43')));
  await session.handlePush(w.frame(30914, numeric(3, '43')));
  assert.equal(session.state.roomId, '99');
  assert.equal(session.state.phase, 'outgoing');
  assert.equal(session.state.peerJoined, false);
  await session.handlePush(w.frame(30914, Buffer.concat([w.field(1, w.string(1, 'stale', 16)), numeric(3, '42')])));
  assert.equal(session.state.peerJoined, false);
  await session.handlePush(w.frame(30914, numeric(3, '42')));
  assert.equal(session.state.peerJoined, true);
  await session.handlePush(w.frame(30918, numeric(2, '42')));
  assert.equal(session.state.phase, 'ended');
});

test('a join response for a different account never yields transport credentials', async () => {
  const {session, rpc} = fixture();
  await session.dial('42');
  rpc.handler = async () => ({action: 30914, fields: w.parse(Buffer.concat([w.string(2, token, 100), numeric(3, '43')]))});
  await assert.rejects(session.join(), /invalid_call_response/);
  assert.equal(session.state.phase, 'uncertain');
  assert.equal(session.state.credentialReady, false);
  assert.throws(() => session.takeTransportSession(), /call_transport_not_ready/);
});

test('disconnect or replacement of authenticated connection invalidates room credentials', async () => {
  for (const change of [a => { a.state.signedIn = false; }, a => { a.connection = {...a.connection}; }]) {
    const {session, account} = fixture();
    await session.dial('42'); await session.join();
    change(account);
    assert.equal(session.state.phase, 'ended');
    assert.equal(session.state.credentialReady, false);
    assert.throws(() => session.takeTransportSession());
  }
});

test('a late room response after reset cannot send the next request or reactivate the call', async () => {
  const {session, rpc, calls} = fixture(), pending = deferred();
  rpc.handler = () => pending.promise;
  const dialing = session.dial('42');
  assert.equal(calls.length, 1);
  session.reset();
  pending.resolve({action: 30913, fields: w.parse(numeric(2, '99'))});
  await assert.rejects(dialing, /call_cancelled/);
  assert.equal(session.state.phase, 'idle');
  assert.equal(calls.length, 1);
});

test('timeout remains uncertain with no automatic retry; known room can be explicitly left', async () => {
  const {session, rpc, calls} = fixture();
  await session.dial('42');
  rpc.handler = async () => { throw new RpcError('timeout'); };
  await assert.rejects(session.join(), /timeout/);
  assert.equal(calls.length, 3);
  assert.equal(session.state.phase, 'uncertain');
  await assert.rejects(session.dial('42'), /call_busy/);
  rpc.handler = null;
  await session.leave();
  assert.equal(calls.length, 4);
  assert.equal(session.state.phase, 'ended');
});

test('late join credentials after disconnect are discarded and overlapping operations do not issue RPCs', async () => {
  const {session, rpc, account, calls} = fixture(), pending = deferred();
  await session.dial('42');
  rpc.handler = () => pending.promise;
  const joining = session.join();
  await assert.rejects(session.leave(), /call_busy/);
  assert.equal(calls.length, 3);
  account.state.signedIn = false;
  pending.resolve({action: 30914, fields: w.parse(Buffer.concat([w.string(2, token, 100), numeric(3, '41')]))});
  await assert.rejects(joining, /call_connection_changed/);
  assert.equal(session.state.phase, 'ended');
  assert.equal(session.state.credentialReady, false);
  assert.equal(calls.length, 3);
});

test('busy calls, malformed IDs, groups, video and self calls are rejected without network requests', async () => {
  const {session, calls} = fixture();
  assert.throws(() => session.setAllowedPeers(['42', '42']));
  assert.throws(() => session.setAllowedPeers(['18446744073709551616']));
  await assert.rejects(session.dial('43'), /call_peer_not_allowed/);
  for (const extra of [numeric(4, '43'), numeric(5, 1), numeric(8, 1)]) {
    await session.handlePush(offer('42', '99', extra));
    assert.equal(session.state.phase, 'idle');
  }
  session.setAllowedPeers(['41']);
  await assert.rejects(session.dial('41'), /call_self_not_allowed/);
  assert.equal(calls.length, 0);
});
