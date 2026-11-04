const {test}=require('node:test'),assert=require('node:assert/strict');
const {fixture,sdp,waitFor}=require('./nasim-call-fixture.cjs');
const flags=state=>Object.fromEntries(['configured','offerSeen','answerSeen','negotiated'].map(key=>[key,state[key]]));

test('terminal ICE diagnostics preserve connectivity-check counts through cleanup',async()=>{
 const f=fixture();try{
  const {a,b}=await f.prepare();await a.dial('42');await waitFor(()=>b.state.phase==='incoming');
  const ice={localRelayCandidates:1,remoteRelayCandidates:1,pairWaiting:0,pairInProgress:0,pairFailed:1,pairSucceeded:0,
   pairUnspecified:0,nominatedPairs:0,requestsSent:null,requestsReceived:null,responsesSent:null,responsesReceived:null};
  f.natives[1].latest={phase:'failed',reason:'ice_failed',ice};await waitFor(()=>b.state.phase==='uncertain');
  assert.deepEqual(b.state.terminalSnapshot.media.ice,ice);
  const view=b.state.terminalSnapshot;view.media.ice.pairFailed=999;
  assert.equal(b.state.terminalSnapshot.media.ice.pairFailed,1);assert.equal(b.state.terminalSnapshot.media.ice.requestsSent,null);
  await b.end();assert.equal(b.state.terminalSnapshot.media.ice.pairFailed,1);
  b.reset();assert.equal(b.state.terminalSnapshot,null);
 }finally{f.close();}
});

test('terminal diagnostics retain verified peer signal across late frames and cleanup, then reset',async()=>{
 for(const signal of ['bye','reject','busy']){
  const f=fixture();try{const {a,b}=await f.prepare();await a.dial('42');await waitFor(()=>b.state.phase==='incoming');
   f.deliver('42',f.raw('41',signal,'fixture-call-1',null));await waitFor(()=>b.state.phase==='ended');
   const expected={signal,phaseBeforeEnd:'incoming',actor:'peer'};
   assert.deepEqual(b.state.terminal,expected);
   f.deliver('42',f.config('42'));f.deliver('42',f.raw('41','bye','fixture-call-1',null));
   assert.deepEqual(b.state.terminal,expected);await b.end();assert.deepEqual(b.state.terminal,expected);
   const snapshot=b.state.terminal;snapshot.actor='changed';assert.equal(b.state.terminal.actor,'peer');
   await b.prepare({role:'server'});assert.equal(b.state.terminal,null);
   b.reset();assert.equal(b.state.terminal,null);
  }finally{f.close();}
 }
});

test('ignored own accept echo is distinct from missing config or a wrong bound device',async()=>{
 const f=fixture({autoConfig:false});try{const {a}=await f.prepare();await a.dial('42');
  f.deliver('41',f.raw('41','accept','fixture-call-1',{}));
  await waitFor(()=>a.state.signaling.acceptOwnEcho===1);
  assert.equal(a.state.remoteAccepted,false);assert.equal(a.state.signaling.acceptNoCall,0);
  f.deliver('41',f.config('41'));f.deliver('41',f.raw('42','accept','fixture-call-1',{}));
  await waitFor(()=>a.state.remoteAccepted);
  const mismatch=f.raw('42','accept','fixture-call-1',{});mismatch.senderClientID='unselected-device';f.deliver('41',mismatch);
  await waitFor(()=>a.state.signaling.acceptWrongDevice===1);assert.equal(a.state.terminal,null);
  a.reset();assert.equal(a.state.signaling.acceptOwnEcho,0);assert.equal(a.state.signaling.acceptWrongDevice,0);
 }finally{f.close();}
});

test('native terminal failure has no claimed actor and local end records the local actor',async()=>{
 const f=fixture();try{const {a,b}=await f.prepare();await a.dial('42');await waitFor(()=>b.state.phase==='incoming');
  f.natives[1].latest={phase:'failed',reason:'ice_failed'};
  await waitFor(()=>b.state.phase==='uncertain');
  assert.deepEqual(b.state.terminal,{signal:'media_failure',phaseBeforeEnd:'incoming',actor:null});
  await a.end();assert.deepEqual(a.state.terminal,{signal:'local_end',phaseBeforeEnd:'outgoing',actor:'self'});
  b.reset();assert.equal(b.state.terminal,null);
 }finally{f.close();}
});

test('safe signaling diagnostics distinguish pending answer installation and clear on reset',async()=>{
 const f=fixture();let release;
 try{
  const {a,b}=await f.prepare();
  const blank={configured:false,offerSeen:false,answerSeen:false,negotiated:false};
  assert.deepEqual(flags(a.state.signaling),blank);assert.deepEqual(flags(b.state.signaling),blank);
  await a.dial('42');await waitFor(()=>b.state.phase==='incoming');
  assert.deepEqual(flags(b.state.signaling),blank);
  const native=f.natives[1],install=native.setAnswer.bind(native);
  const pending=new Promise(resolve=>{release=resolve;});
  native.setAnswer=async description=>{await pending;return install(description);};
  await b.accept();await waitFor(()=>b.state.signaling.answerSeen);
  assert.deepEqual(flags(b.state.signaling),{configured:true,offerSeen:true,answerSeen:true,negotiated:false});
  release();await waitFor(()=>a.state.phase==='connected'&&b.state.phase==='connected');
  assert.deepEqual(flags(a.state.signaling),{configured:true,offerSeen:true,answerSeen:false,negotiated:true});
  assert.deepEqual(flags(b.state.signaling),{configured:true,offerSeen:true,answerSeen:true,negotiated:true});
  for(const state of [a.state.signaling,b.state.signaling])assert.ok(Object.values(state).every(value=>typeof value==='boolean'||Number.isInteger(value)));
  a.reset();b.reset();assert.deepEqual(flags(a.state.signaling),blank);assert.deepEqual(flags(b.state.signaling),blank);
 }finally{release?.();f.close();}
});

test('terminal snapshots preserve only bounded negotiation facts before media cleanup and cannot be mutated through state',async()=>{
 const f=fixture();try{const {a,b}=await f.prepare();await a.dial('42');await waitFor(()=>b.state.phase==='incoming');
  await b.accept();await waitFor(()=>a.state.phase==='connected'&&b.state.phase==='connected');
  const before=b.state.signaling;f.natives[1].latest={phase:'failed',reason:'ice_failed',relayPair:false,peerAuthenticated:false,private:'fixture-private-password'};
  await waitFor(()=>b.state.phase==='uncertain');
  const snapshot=b.state.terminalSnapshot;assert.equal(snapshot.signaling.configured,true);assert.equal(snapshot.signaling.negotiated,true);
  assert.equal(snapshot.signaling.receivedConfig,before.receivedConfig);assert.equal(snapshot.signaling.receivedAnswer,before.receivedAnswer);
  assert.deepEqual(snapshot.media,{phase:'failed',reason:'ice_failed',relayPair:false,mediaConnected:false,peerAuthenticated:false,proxyReady:false});
  assert.ok(Object.values(snapshot.signaling).every(v=>typeof v==='boolean'||Number.isSafeInteger(v)&&v>=0&&v<=1000000));
  assert.ok(!JSON.stringify(snapshot).includes('fixture-private-password'));snapshot.signaling.receivedAnswer=999;snapshot.media.reason='changed';
  assert.equal(b.state.terminalSnapshot.signaling.receivedAnswer,before.receivedAnswer);assert.equal(b.state.terminalSnapshot.media.reason,'ice_failed');
  await b.end();assert.equal(b.state.terminalSnapshot.media.reason,'ice_failed');b.reset();assert.equal(b.state.terminalSnapshot,null);
 }finally{f.close();}
});

test('bounded signaling counters separate an offer awaiting acceptance from wrong peer and device',async()=>{
 const f=fixture({autoConfig:false});try{
  const {a}=await f.prepare();await a.dial('42');
  f.deliver('41',f.config('41'));await waitFor(()=>a.state.callUUID!==null);
  f.deliver('41',f.raw('42','offer','fixture-call-1',sdp('offer')));
  await waitFor(()=>a.state.signaling.pendingOfferCount===1);
  assert.equal(a.state.signaling.offerSeen,false);assert.equal(a.state.remoteAccepted,false);
  assert.equal(a.state.signaling.receivedConfig,1);assert.equal(a.state.signaling.receivedOffer,1);
  f.deliver('41',f.raw('42','accept','fixture-call-1',{}));
  await waitFor(()=>a.state.signaling.negotiated);
  assert.equal(a.state.signaling.pendingOfferCount,0);assert.equal(a.state.signaling.receivedAccept,1);
  const wrongDevice=f.raw('42','offer','fixture-call-1',sdp('offer'));wrongDevice.senderClientID='another-device';
  f.deliver('41',wrongDevice);f.deliver('41',f.raw('99','offer','fixture-call-1',sdp('offer')));
  await waitFor(()=>a.state.signaling.wrongDevice===1&&a.state.signaling.wrongPeer===1);
  assert.equal(a.state.signaling.receivedOffer,3);
  const before=a.state.signaling;before.wrongDevice=900;assert.equal(a.state.signaling.wrongDevice,1);
  a.reset();for(const value of Object.values(a.state.signaling))assert.ok(value===false||value===0);
 }finally{f.close();}
});

test('two account controllers require explicit incoming acceptance, then bind the reverse SDP direction to native roles',async()=>{
 const f=fixture();try{const {a,b}=await f.prepare();assert.equal(f.sent.length,0);
  await a.dial('42');await waitFor(()=>b.state.phase==='incoming');
  assert.equal(b.state.localAccepted,false);assert.ok(f.natives.every(n=>n.ops.length===0));
  await b.accept();await waitFor(()=>a.state.phase==='connected'&&b.state.phase==='connected');
  assert.deepEqual(f.sent.map(x=>x.signal.type),['callRequest','accept','offer','answer']);
  assert.equal(f.natives[0].options.role,'client');assert.equal(f.natives[1].options.role,'server');
  assert.equal(f.natives[0].state.proxyReady,true);assert.equal(f.natives[1].state.proxyReady,false);
  assert.ok(f.natives[1].ops.some(x=>x.op==='offer'));assert.ok(f.natives[0].ops.some(x=>x.op==='answer'));
  const state=JSON.stringify([a.state,b.state]);for(const secret of ['fixture-private-password','fixture-private-user','ice-pwd','fingerprint','iceServers'])assert.ok(!state.includes(secret));
  assert.equal(a.state.billingVerified,false);assert.equal(a.state.liveCallVerified,false);
  await a.end();await waitFor(()=>b.state.phase==='ended');assert.ok(f.natives.every(n=>n.state.phase==='closed'));
 }finally{f.close();}
});
test('wrong peer, self dialing and unpaired or unauthenticated accounts cannot send calls',async()=>{
 const f=fixture();try{const {a}=await f.prepare();for(const peer of ['41','99'])await assert.rejects(a.dial(peer),/call_peer_not_allowed/);
  assert.equal(f.sent.length,0);f.accounts.get('41').state.signedIn=false;await assert.rejects(a.dial('42'),/not_authenticated/);
  assert.equal(f.sent.length,0);assert.equal(f.natives[0].state.phase,'closed');
 }finally{f.close();}
});

test('call-log history placeholders cannot terminate a ringing or connected call; explicit peer bye still can',async()=>{
 const f=fixture();try{const {a,b}=await f.prepare();await a.dial('42');await waitFor(()=>b.state.phase==='incoming');
  for(const status of ['notAnswered','not_answered','rejected','busied','finished']){const log=f.config('41');log.data.type='callLog';log.data.callData.status=status;f.deliver('41',log);}await waitFor(()=>a.state.ignoredEvents===5);assert.equal(a.state.phase,'outgoing');assert.notEqual(a.state.media,null);
  await b.accept();await waitFor(()=>a.state.phase==='connected');const log=f.config('41');log.data.type='callLog';log.data.callData.status='not_answered';f.deliver('41',log);await waitFor(()=>a.state.ignoredEvents===6);assert.equal(a.state.phase,'connected');await b.end();await waitFor(()=>a.state.phase==='ended');
 }finally{f.close();}
});
test('config for another local device, unapproved callers and duplicate config cannot replace private media credentials',async()=>{
 const f=fixture({autoConfig:false});try{const {a,b}=await f.prepare();await a.dial('42');
  const other=f.config('41');other.senderClientID='different-local-device';f.deliver('41',other);await waitFor(()=>a.state.ignoredEvents===1);assert.equal(a.state.callUUID,null);
  const foreign=f.config('42');foreign.data.callData.participants=[{userID:42},{userID:99}];f.deliver('42',foreign);await waitFor(()=>b.state.ignoredEvents===1);assert.equal(b.state.phase,'ready');
  f.deliver('41',f.config('41'));f.deliver('42',f.config('42'));await waitFor(()=>b.state.phase==='incoming');
  const duplicate=f.config('42');duplicate.data.callData.turnServer.password='other-private-password';f.deliver('42',duplicate);
  await b.accept();await waitFor(()=>b.state.phase==='connected');assert.equal(f.natives[1].call.iceServers[1].credential,'fixture-private-password');
 }finally{f.close();}
});
test('early accept/offer before config are bounded and applied only to the eventual matching call',async()=>{
 const f=fixture({autoConfig:false});try{const {a}=await f.prepare();await a.dial('42');
  f.deliver('41',f.raw('42','accept','wrong-call',{}));
  f.deliver('41',f.raw('42','offer','fixture-call-1',sdp('offer')));f.deliver('41',f.raw('42','accept','fixture-call-1',{}));
  f.deliver('41',f.config('41'));await waitFor(()=>f.sent.some(x=>x.signal.type==='answer'));
  assert.equal(a.state.remoteClientId,'client-42');assert.ok(f.natives[0].ops.some(x=>x.op==='answer'));assert.equal(a.state.localAccepted,true);
 }finally{f.close();}
});
test('wrong sender device, answer target and call UUID cannot enter an approved negotiation',async()=>{
 const f=fixture();try{const {a,b}=await f.prepare();await a.dial('42');await waitFor(()=>b.state.phase==='incoming');
  const bad=f.raw('41','answer','fixture-call-1',{...sdp('answer'),clientID:'wrong-target'});f.deliver('42',bad);
  const wrongDevice=f.raw('41','bye','fixture-call-1',null);wrongDevice.senderClientID='different-device';f.deliver('42',wrongDevice);
  f.deliver('42',f.raw('41','bye','other-call',null));await waitFor(()=>b.state.ignoredEvents>=3);
  assert.equal(b.state.phase,'incoming');assert.ok(f.natives[1].ops.length===0);await b.accept();await waitFor(()=>a.state.phase==='connected');
 }finally{f.close();}
});
test('stream history loss closes native media, invalidates queued signals and requires fresh event subscription',async()=>{
 const f=fixture();try{const {a,b}=await f.prepare();await a.dial('42');await waitFor(()=>b.state.phase==='incoming');
  b.handleEvent({provider:'nasim',type:'streamReset',lastEventId:'3'});assert.equal(b.state.phase,'uncertain');assert.equal(b.state.reason,'call_stream_reset');
  assert.deepEqual(b.state.terminal,{signal:'stream_reset',phaseBeforeEnd:'incoming',actor:null});
  assert.equal(f.natives[1].state.phase,'closed');assert.equal(f.accounts.get('42').disconnects,1);
  f.deliver('42',f.config('42'));await waitFor(()=>!b.state.busy);assert.notEqual(b.state.phase,'incoming');
 }finally{f.close();}
});
test('other own-account device acceptance stops this instance without admitting another peer',async()=>{
 const f=fixture();try{const {a,b}=await f.prepare();await a.dial('42');await waitFor(()=>b.state.phase==='incoming');
  const event=f.raw('42','accept','fixture-call-1',{});event.senderClientID='own-other-device';f.deliver('42',event);
  await waitFor(()=>b.state.phase==='ended');assert.equal(b.state.reason,'call_handled_on_other_device');assert.equal(f.natives[1].state.phase,'closed');
  assert.deepEqual(b.state.terminal,{signal:'other_device',phaseBeforeEnd:'incoming',actor:'self'});
 }finally{f.close();}
});
test('reset during late native preparation closes the late process and cannot resurrect account state',async()=>{
 let release,closed=false;const f=fixture({open:()=>new Promise(r=>{release=r;})});
 try{const a=f.controllers.get('41');const pending=a.prepare({role:'client'});const rejected=assert.rejects(pending,/call_cancelled/);
  a.reset();release({publicCertificate:'aa'.repeat(80),close(){closed=true;},state:{phase:'prepared'}});await rejected;
  assert.equal(closed,true);assert.equal(a.state.phase,'idle');assert.equal(a.state.media,null);
 }finally{f.close();}
});
test('lost dial acknowledgment is uncertain and never redials or leaves media alive',async()=>{
 const f=fixture({sendHook:({signal})=>{if(signal.type==='callRequest')throw Object.assign(Error('fixture secret must not surface'),{reason:'timeout'});}});
 try{const {a}=await f.prepare();await assert.rejects(a.dial('42'),/timeout/);assert.equal(a.state.phase,'uncertain');assert.equal(a.state.reason,'timeout');
  assert.equal(f.sent.length,1);assert.equal(f.natives[0].state.phase,'closed');assert.ok(!JSON.stringify(a.state).includes('secret'));
 }finally{f.close();}
});
test('initial or idle cleanSession keeps event reception and prepared pairing intact',async()=>{
 const f=fixture();try{const a=f.controllers.get('41');a.handleEvent({provider:'nasim',type:'streamReset'});assert.equal(f.accounts.get('41').disconnects,0);
  await f.prepare();a.handleEvent({provider:'nasim',type:'streamReset'});assert.equal(a.state.phase,'ready');assert.equal(f.natives[0].state.phase,'prepared');assert.equal(f.accounts.get('41').disconnects,0);
 }finally{f.close();}
});
test('a prepared but unpaired native identity cannot place a call',async()=>{
 const f=fixture();try{const a=f.controllers.get('41');a.setAllowedPeers(['42']);await a.prepare({role:'client'});
  await assert.rejects(a.dial('42'),/call_not_ready/);assert.equal(f.sent.length,0);assert.equal(a.state.phase,'prepared');
 }finally{f.close();}
});
test('native failure or replacement of an authenticated event connection closes the call',async()=>{
 const f=fixture();try{const {a,b}=await f.prepare();await a.dial('42');await waitFor(()=>b.state.phase==='incoming');
  let oldClosed=false;f.accounts.get('42').signalConnection.close=()=>{oldClosed=true;};
  const fresh={send:async()=>({acknowledged:true})};f.accounts.get('42').signalConnection=fresh;await assert.rejects(b.accept(),/call_connection_changed/);
  assert.equal(b.state.phase,'uncertain');assert.equal(f.natives[1].state.phase,'closed');
  assert.equal(oldClosed,true);assert.equal(f.accounts.get('42').signalConnection,fresh);assert.equal(f.accounts.get('42').disconnects,0);
 }finally{f.close();}
});
test('ending before config arrives aborts the ambiguous subscription instead of reusing it for another call',async()=>{
 const f=fixture({autoConfig:false});try{const {a}=await f.prepare();await a.dial('42');await a.end();
  assert.equal(f.accounts.get('41').disconnects,1);assert.equal(a.state.phase,'ended');assert.equal(f.natives[0].state.phase,'closed');assert.equal(f.sent.length,1);
 }finally{f.close();}
});
test('relay ICE is device-targeted, deduplicated and bounded until remote SDP has been installed',async()=>{
 const f=fixture();try{const {a,b}=await f.prepare();await a.dial('42');await waitFor(()=>b.state.phase==='incoming');
  const candidate={sdpCandidate:'candidate:1 1 udp 1 127.0.0.1 33333 typ relay',sdpMid:'0',sdpMLineIndex:0,clientID:'client-42'};
  for(let i=0;i<3;i++)f.deliver('42',f.raw('41','ice','fixture-call-1',candidate));
  f.deliver('42',f.raw('41','ice','fixture-call-1',{...candidate,clientID:'different-target'}));
  f.deliver('42',f.raw('41','ice','fixture-call-1',{...candidate,sdpCandidate:candidate.sdpCandidate.replace('typ relay','typ host')}));
  await waitFor(()=>b.state.ignoredEvents>=2);assert.equal(f.natives[1].ops.length,0);
  await b.accept();await waitFor(()=>a.state.phase==='connected'&&b.state.phase==='connected');
  assert.equal(f.natives[1].ops.filter(x=>x.op==='candidate').length,1);
 }finally{f.close();}
});
test('ending during pending native negotiation is immediate and late SDP is never sent',async()=>{
 const f=fixture();try{const {a,b}=await f.prepare();await a.dial('42');await waitFor(()=>b.state.phase==='incoming');
  let release;f.natives[1].offer=()=>new Promise(r=>{release=r;});const pending=b.accept();const rejected=assert.rejects(pending,/call_cancelled/);
  await waitFor(()=>!!release);await b.end();assert.equal(f.natives[1].state.phase,'closed');release(sdp('offer'));await rejected;
  assert.equal(b.state.phase,'ended');assert.equal(f.sent.filter(x=>x.signal.type==='offer').length,0);
 }finally{f.close();}
});
test('event queue overflow closes media and the account stream instead of growing without bound',async()=>{
 const f=fixture();try{const {a,b}=await f.prepare();await a.dial('42');await waitFor(()=>b.state.phase==='incoming');
  let release;f.natives[1].offer=()=>new Promise(r=>{release=r;});const pending=b.accept();const rejected=assert.rejects(pending,/call_cancelled/);
  await waitFor(()=>!!release);
  for(let n=0;n<50;n++)f.deliver('42',f.raw('41','ice','fixture-call-1',{sdpCandidate:'candidate:'+n+' 1 udp 1 127.0.0.1 33333 typ relay',sdpMid:'0',sdpMLineIndex:0,clientID:'client-42'}));
  assert.equal(b.state.phase,'failed');assert.equal(b.state.reason,'too_many_call_events');assert.equal(b.state.queuedEvents,0);
  assert.equal(f.natives[1].state.phase,'closed');assert.equal(f.accounts.get('42').disconnects,1);release(sdp('offer'));await rejected;
 }finally{f.close();}
});
