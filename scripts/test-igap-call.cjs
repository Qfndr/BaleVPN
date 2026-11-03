const {test} = require('node:test');
const assert = require('node:assert/strict');
const {CallSession} = require('../experiments/igap/call-session.cjs');
const {wire: w} = require('../experiments/igap/signaling.cjs');
const {RpcError} = require('../experiments/igap/rpc-connection.cjs');

const token = 'fixtureHeader.fixturePayload.fixtureSignature';
const numeric = (field, value) => w.field(field, BigInt(value), 0);
const offer = (sender, room, extra = Buffer.alloc(0)) => w.frame(30915,
  Buffer.concat([numeric(2, sender), numeric(3, room), extra]));

test('service leave during a pending join retains safe terminal actor/stage and rejects the stale credential reply',async()=>{
 for(const [actor,id]of [['self','41'],['peer','42']]){const {session,rpc}=fixture();await session.handlePush(offer('42','99'));const reply=deferred();rpc.handler=()=>reply.promise;const joining=session.join();assert.equal(session.state.phase,'joining');await session.handlePush(w.frame(30918,numeric(2,id)));assert.equal(session.state.phase,'ended');assert.deepEqual(session.state.terminalDiagnostic,{cause:'service_leave',endingActor:actor,phaseBeforeEnd:'joining'});
  reply.resolve({action:30914,fields:w.parse(Buffer.concat([w.string(2,token,100),numeric(3,'41')]))});await assert.rejects(joining,/call_cancelled/);assert.equal(session.state.credentialReady,false);assert.equal(session.state.busy,false);assert.equal(session.state.terminalDiagnostic.endingActor,actor);const diagnostic=JSON.stringify(session.state.terminalDiagnostic);for(const secret of [token,'41','42','99'])assert.ok(!diagnostic.includes(secret));
  const exported=session.state.terminalDiagnostic;exported.endingActor='altered';assert.equal(session.state.terminalDiagnostic.endingActor,actor);session.reset('ended');assert.equal(session.state.terminalDiagnostic.endingActor,actor);await session.handlePush(offer('42','100'));assert.equal(session.state.terminalDiagnostic,null);session.reset();assert.equal(session.state.terminalDiagnostic,null);
 }
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
