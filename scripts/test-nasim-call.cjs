const {test}=require('node:test'),assert=require('node:assert/strict');
const {fixture,sdp,waitFor}=require('./nasim-call-fixture.cjs');

test('two account controllers require explicit incoming acceptance, then bind the reverse SDP direction to native roles',async()=>{
 const f=fixture();try{const {a,b}=await f.prepare();assert.equal(f.sent.length,0);
  await a.dial('42');await waitFor(()=>b.state.phase==='incoming');
  assert.equal(b.state.localAccepted,false);assert.ok(f.natives.every(n=>n.ops.length===0));
  await b.accept();await waitFor(()=>a.state.phase==='connected'&&b.state.phase==='connected');
  assert.deepEqual(f.sent.map(x=>x.signal.type),['callRequest','accept','offer','answer']);
  assert.equal(f.natives[0].options.role,'client');assert.equal(f.natives[1].options.role,'server');
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
  assert.equal(f.natives[1].state.phase,'closed');assert.equal(f.accounts.get('42').disconnects,1);
  f.deliver('42',f.config('42'));await waitFor(()=>!b.state.busy);assert.notEqual(b.state.phase,'incoming');
 }finally{f.close();}
});
test('other own-account device acceptance stops this instance without admitting another peer',async()=>{
 const f=fixture();try{const {a,b}=await f.prepare();await a.dial('42');await waitFor(()=>b.state.phase==='incoming');
  const event=f.raw('42','accept','fixture-call-1',{});event.senderClientID='own-other-device';f.deliver('42',event);
  await waitFor(()=>b.state.phase==='ended');assert.equal(b.state.reason,'call_handled_on_other_device');assert.equal(f.natives[1].state.phase,'closed');
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
