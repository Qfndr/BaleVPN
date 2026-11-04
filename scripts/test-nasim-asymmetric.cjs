const {test}=require('node:test'),assert=require('node:assert/strict');
const {EventEmitter}=require('node:events'),{PassThrough,Writable}=require('node:stream'),path=require('node:path');
const {allows}=require('../experiments/nasim/asymmetric-route.cjs');
const {createBridge}=require('../experiments/providers/relay-media-bridge.cjs');
const {fixture:callFixture,waitFor}=require('./nasim-call-fixture.cjs');
const proof='client-relay/server-public';
const own='aa'.repeat(80),peer='bb'.repeat(80);
const description=(type,candidate)=>({type,sdp:'v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=fingerprint:sha-256 '+Array(32).fill('AA').join(':')+'\r\na=candidate:'+candidate+'\r\n'});
function childFixture(Bridge){
 const child=new EventEmitter(),commands=[];child.stdout=new PassThrough();child.stderr=new PassThrough();
 child.stdin=new Writable({write(bytes,_,done){commands.push(JSON.parse(bytes.toString()));done();}});child.kill=()=>child.emit('exit',1);
 const emit=value=>child.stdout.write(JSON.stringify(value)+'\n');
 return {emit,commands,child,open:()=>Bridge.open(path.resolve('fixture-native'),{spawnImpl:()=>{
  queueMicrotask(()=>emit({event:'prepared',protocol:2,provider:'nasim',publicCertificate:own}));return child;
 }})};
}
const call={provider:'nasim',callUUID:'fixture',selfId:'41',peerId:'42',iceServers:[{urls:'turn:fixture.test:3478',username:'fixture',credential:'fixture'}]};
async function configure(f,b){const pending=b.configure(call,{role:'client',trustedCertificates:[peer]});f.emit({event:'configured',provider:'nasim'});await pending;}
function close(f,b){b.close();f.emit({event:'stopped'});f.child.emit('exit',0);}

test('experimental policy accepts changing public server addresses and rejects private candidates',()=>{
 for(const address of ['127.0.0.1','192.0.0.192','10.0.0.1','198.18.0.1','example.test','::ffff:8.8.8.8','2001:db8::1','fe80::1%eth0'])
  assert.equal(allows('candidate:1 1 udp 1 '+address+' 37000 typ host','client'),false);
 for(const value of ['candidate:1 1 udp 1 8.8.8.8 37000 typ host','candidate:1 1 udp 1 9.9.9.9 38000 typ srflx'])assert.equal(allows(value,'client'),true);
 for(const bad of ['candidate:1 1 udp 1 8.8.8.8 443 typ host','candidate:1 1 tcp 1 8.8.8.8 37000 typ host','candidate:1 1 udp 1 8.8.8.8 37000 typ host raddr 10.0.0.1 rport 9'])assert.equal(allows(bad,'client'),false);
 assert.throws(()=>createBridge('eitaa',{nasimAsymmetric:true}));
 assert.throws(()=>createBridge('rubika',{nasimAsymmetric:true}));
 assert.throws(()=>createBridge('nasim',{nasimServerEndpoint:'8.8.8.8:37000'}));
});

test('explicit Nasim factory keeps asymmetric proof separate from relayPair',async()=>{
 const {NativeMediaBridge}=createBridge('nasim',{nasimAsymmetric:true});const f=childFixture(NativeMediaBridge),b=await f.open();
 try {await configure(f,b);assert.equal(f.commands[0].experimentalRoute,'nasim-client-relay-server-public');
  const pending=b.answer(description('offer','1 1 udp 1 8.8.8.8 37000 typ host'));
  f.emit({event:'description',description:description('answer','1 1 udp 1 1.1.1.1 48000 typ relay')});await pending;
  f.emit({event:'connected',provider:'nasim',mediaConnected:true,relayPair:false,routeProof:proof,peerAuthenticated:true,proxyReady:true,socksAddress:'127.0.0.1:1089',providerPathVerified:false,billingVerified:false});
  assert.equal(b.state.phase,'connected');assert.equal(b.state.relayPair,false);assert.equal(b.state.routeProof,proof);
  assert.equal(b.acceptsCandidate('candidate:1 1 udp 1 8.8.8.8 37000 typ host'),true);
  assert.equal(b.acceptsCandidate('candidate:1 1 udp 1 9.9.9.9 37001 typ host'),true);
  assert.equal(b.acceptsCandidate('candidate:1 1 udp 1 10.0.0.1 37001 typ host'),false);
 }finally{close(f,b);}
});

test('experimental server uses only the STUN entry from its current call',async()=>{
 const {NativeMediaBridge}=createBridge('nasim',{nasimAsymmetric:true});const f=childFixture(NativeMediaBridge),b=await f.open();
 try {
  const pending=b.configure({...call,iceServers:[...call.iceServers,{urls:'stun:fixture.test:3478'}]},{role:'server',trustedCertificates:[peer]});
  f.emit({event:'configured',provider:'nasim'});await pending;
  assert.deepEqual(f.commands[0].iceServers,[{urls:['stun:fixture.test:3478'],username:'',credential:''}]);
 }finally{close(f,b);}
});

test('default factory still rejects host SDP and asymmetric output',async()=>{
 const {NativeMediaBridge}=createBridge('nasim');const f=childFixture(NativeMediaBridge),b=await f.open();
 try {await configure(f,b);assert.equal(f.commands[0].experimentalRoute,undefined);
  await assert.rejects(b.answer(description('offer','1 1 udp 1 8.8.8.8 37000 typ host')));
  assert.equal(b.acceptsCandidate('candidate:1 1 udp 1 8.8.8.8 37000 typ host'),false);
  const pending=b.offer();f.emit({event:'description',description:description('offer','1 1 udp 1 127.0.0.1 48000 typ relay')});await pending;
  f.emit({event:'connected',provider:'nasim',mediaConnected:true,relayPair:false,routeProof:proof,peerAuthenticated:true,proxyReady:true,socksAddress:'127.0.0.1:1089',providerPathVerified:false,billingVerified:false});
  assert.equal(b.state.reason,'invalid_native_output');
 }finally{close(f,b);}
});

test('Nasim call readiness requires an explicitly opted-in bridge for asymmetric proof',async()=>{
 const f=callFixture();try{const {a,b}=await f.prepare();await a.dial('42');await waitFor(()=>b.state.phase==='incoming');await b.accept();
  await waitFor(()=>a.state.signaling.negotiated&&b.state.signaling.negotiated);
  for(const native of f.natives){native.latest={...native.latest,relayPair:false,routeProof:proof};}
  assert.equal(a.state.phase,'negotiating');assert.equal(b.state.phase,'negotiating');
  for(const native of f.natives)native.experimentalRoute=proof;
  assert.equal(a.state.phase,'connected');assert.equal(b.state.phase,'connected');
 }finally{f.close();}
});

const routeProofDiagnostic={reason:'remoteCandidateRejected',localKind:'relay',remoteKind:'prflx',currentGeneration:true};
test('typed route diagnostics are limited to asymmetric IPC and retained after failure',async()=>{
 const {NativeMediaBridge}=createBridge('nasim',{nasimAsymmetric:true});const f=childFixture(NativeMediaBridge),b=await f.open();
 await configure(f,b);f.emit({event:'routeProofDiagnostic',diagnostic:routeProofDiagnostic});
 assert.deepEqual(b.state.routeProofDiagnostic,routeProofDiagnostic);
 const copy=b.state.routeProofDiagnostic;copy.remoteKind='host';assert.equal(b.state.routeProofDiagnostic.remoteKind,'prflx');
 f.emit({event:'error',reason:'relay_route_failed'});
 assert.deepEqual(b.state.routeProofDiagnostic,routeProofDiagnostic);
 for(const bad of [{...routeProofDiagnostic,address:'fixture-private-address'},
  {...routeProofDiagnostic,reason:'fixture-private-reason'},{...routeProofDiagnostic,localKind:'fixture-private-kind'},
  {...routeProofDiagnostic,currentGeneration:1}]){
  const invalid=childFixture(NativeMediaBridge),bridge=await invalid.open();await configure(invalid,bridge);
  invalid.emit({event:'routeProofDiagnostic',diagnostic:bad});
  assert.equal(bridge.state.reason,'invalid_native_output');assert.equal(bridge.state.routeProofDiagnostic,undefined);
 }
 const strict=childFixture(createBridge('nasim').NativeMediaBridge),bridge=await strict.open();await configure(strict,bridge);
 strict.emit({event:'routeProofDiagnostic',diagnostic:routeProofDiagnostic});
 assert.equal(bridge.state.reason,'invalid_native_output');
});

test('terminal call snapshots retain validated proof reason and isolate returned copies',async()=>{
 const f=callFixture();try{
  const {a,b}=await f.prepare();await a.dial('42');await waitFor(()=>b.state.phase==='incoming');
  f.natives[0].latest={phase:'failed',reason:'relay_route_failed',routeProofDiagnostic};
  await waitFor(()=>a.state.phase==='uncertain');
  const snapshot=a.state.terminalSnapshot.media.routeProofDiagnostic;
  assert.deepEqual(snapshot,routeProofDiagnostic);snapshot.remoteKind='host';
  assert.equal(a.state.terminalSnapshot.media.routeProofDiagnostic.remoteKind,'prflx');
 }finally{f.close();}
});
