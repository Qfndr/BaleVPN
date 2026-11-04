const {test:nodeTest}=require('node:test'),assert=require('node:assert/strict');
const {EventEmitter}=require('node:events'),{PassThrough,Writable}=require('node:stream'),path=require('node:path');
function register(provider,NativeMediaBridge,executable){
const test=(name,...args)=>nodeTest(provider+': '+name,...args);
const own='aa'.repeat(80),peer='bb'.repeat(80),secret='fixture-private-relay-password';
const call={provider,callUUID:'fixture-call',selfId:provider==='rubika'?'fixture_self_01':'41',peerId:provider==='rubika'?'fixture_peer_02':'42',iceServers:[
 {urls:'stun:relay.example.test:3478'}, {urls:'turn:relay.example.test:3478',username:'fixture-private-user',credential:secret}]};
function sdp(type){return {type,sdp:'v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=fingerprint:sha-256 '+Array(32).fill('AA').join(':')+'\r\na=ice-pwd:fixture-private-ice-secret\r\na=candidate:1 1 udp 1 127.0.0.1 33333 typ relay\r\n'};}
function fixture({prepared=true}={}){
 let invocation;const commands=[],child=new EventEmitter();child.stdout=new PassThrough();child.stderr=new PassThrough();child.killed=false;
 child.stdin=new Writable({write(bytes,_,done){for(const line of bytes.toString().trim().split('\n'))if(line)commands.push(JSON.parse(line));done();}});
 child.kill=()=>{child.killed=true;queueMicrotask(()=>child.emit('exit',1));};
 const emit=v=>child.stdout.write(JSON.stringify(v)+'\n');
 const spawnImpl=(executable,args,options)=>{invocation={executable,args,options};if(prepared)queueMicrotask(()=>emit({event:'prepared',protocol:2,provider,publicCertificate:own}));return child;};
 return {child,emit,commands,invocation:()=>invocation,open:()=>NativeMediaBridge.open(path.resolve('fixture-native-helper'),{spawnImpl,prepareTimeout:100})};
}
async function configure(f,b){const p=b.configure(call,{role:'client',trustedCertificates:[peer],throughput:true});f.emit({event:'configured',provider});await p;}
const iceCounts=()=>({localRelayCandidates:1,remoteRelayCandidates:1,pairWaiting:0,pairInProgress:0,pairFailed:1,pairSucceeded:0,
 pairUnspecified:0,nominatedPairs:0,requestsSent:null,requestsReceived:null,responsesSent:null,responsesReceived:null});
test('ICE failure retains only validated bounded numeric diagnostics without mutable references',async()=>{
 const f=fixture(),b=await f.open();await configure(f,b);
 const counts=iceCounts();f.emit({event:'iceDiagnostics',ice:counts});
 assert.deepEqual(b.state.ice,counts);const view=b.state;view.ice.pairFailed=999;assert.equal(b.state.ice.pairFailed,1);assert.equal(b.state.ice.requestsSent,null);
 f.emit({event:'error',reason:'ice_failed'});assert.equal(b.state.reason,'ice_failed');assert.deepEqual(b.state.ice,counts);
 assert.ok(!JSON.stringify(b.state).includes(secret));
});
test('ICE diagnostics reject raw fields, incomplete records and unbounded counters',async()=>{
 for(const ice of [{...iceCounts(),address:'private-address'}, {...iceCounts(),pairFailed:-1}, {...iceCounts(),pairFailed:1000000001},
  {...iceCounts(),pairFailed:0.5}, {...iceCounts(),requestsSent:0}, {...iceCounts(),requestsSent:'7'}, {localRelayCandidates:1}]){
  const f=fixture(),b=await f.open();await configure(f,b);f.emit({event:'iceDiagnostics',ice});
  assert.equal(b.state.phase,'failed');assert.equal(b.state.reason,'invalid_native_output');assert.equal(b.state.ice,undefined);
 }
});
test('retained candidate evidence is nullable, distinct from terminal current counts and survives failure',async()=>{
 for(const retained of [null,0,1]){
  const f=fixture(),b=await f.open();await configure(f,b);
  const counts={...iceCounts(),localRelayCandidates:0,remoteRelayCandidates:0,
   gatheredLocalRelayCandidates:retained,remoteDescriptionRelayCandidates:retained};
  f.emit({event:'iceDiagnostics',ice:counts});f.emit({event:'error',reason:'ice_failed'});
  assert.deepEqual(b.state.ice,counts);assert.equal(b.state.phase,'failed');
 }
 for(const extra of [{gatheredLocalRelayCandidates:1},
  {gatheredLocalRelayCandidates:-1,remoteDescriptionRelayCandidates:1},
  {gatheredLocalRelayCandidates:1,remoteDescriptionRelayCandidates:'private-address'}]){
  const f=fixture(),b=await f.open();await configure(f,b);
  f.emit({event:'iceDiagnostics',ice:{...iceCounts(),...extra}});
  assert.equal(b.state.reason,'invalid_native_output');assert.equal(b.state.ice,undefined);
 }
});
const connected=(extra={})=>({event:'connected',provider,mediaConnected:true,relayPair:true,peerAuthenticated:false,proxyReady:false,socksAddress:'127.0.0.1:1089',providerPathVerified:false,billingVerified:false,...extra});
const metrics=(extra={})=>({event:'metrics',mediaConnected:true,relayPair:true,peerAuthenticated:true,proxyReady:true,receivedBytes:3000,sentBytes:1000,quic:{rttMs:12,lostPackets:0,sentPackets:30,congestionWindow:60000,sendWindowBytes:200000,profile:'balanced'},providerPathVerified:false,billingVerified:false,...extra});
function stopped(f,b){b.close();f.emit({event:'stopped'});f.child.emit('exit',0);}
test('private relay credentials and SDP use hidden pipes, never command args or public state',async()=>{
 const f=fixture(),b=await f.open();assert.equal(b.publicCertificate,own);await configure(f,b);
 assert.deepEqual(f.invocation().args,[]);assert.equal(f.invocation().options.shell,false);assert.equal(f.invocation().options.windowsHide,true);
 assert.equal(f.invocation().options.env.SSLKEYLOGFILE,undefined);assert.ok(!JSON.stringify(f.invocation()).includes(secret));
 assert.equal(f.commands[0].iceServers.length,1);assert.equal(f.commands[0].iceServers[0].credential,secret);
 const pending=b.offer();f.emit({event:'description',description:sdp('offer')});assert.deepEqual(await pending,sdp('offer'));
 f.emit(connected());assert.equal(b.state.proxyReady,false);f.emit(metrics());assert.equal(b.state.proxyReady,true);
 for(const privateText of [secret,'fixture-private-user','fixture-private-ice-secret','candidate:','fingerprint:'])assert.ok(!JSON.stringify(b.state).includes(privateText));
 const copy=b.state;copy.quic.rttMs=999;assert.equal(b.state.quic.rttMs,12);assert.equal(b.state.billingVerified,false);stopped(f,b);
});
test('answer, setAnswer and relay candidates have private correlated acknowledgments',async()=>{
 const f=fixture(),b=await f.open();await configure(f,b);
 const reply=b.answer(sdp('offer'));f.emit({event:'description',description:sdp('answer')});assert.deepEqual(await reply,sdp('answer'));
 const candidate=b.addCandidate({candidate:'candidate:1 1 udp 1 127.0.0.1 33333 typ relay',sdpMid:'0',sdpMLineIndex:0});
 await assert.rejects(b.setAnswer(sdp('answer')),/operation_busy/);f.emit({event:'candidateAdded'});await candidate;
 const answer=b.setAnswer(sdp('answer'));f.emit({event:'negotiated'});await answer;stopped(f,b);
});

test('typed ICE, DTLS and route failures retain only the fixed diagnostic reason',async()=>{
 for(const reason of ['ice_failed','dtls_failed','relay_route_failed']){const f=fixture(),b=await f.open();await configure(f,b);const pending=b.offer(),rejected=assert.rejects(pending,e=>e.reason===reason);f.emit({event:'error',reason});await rejected;assert.equal(b.state.phase,'failed');assert.equal(b.state.reason,reason);assert.ok(!JSON.stringify(b.state).includes(secret));}
});
test('other providers, self pairing, unsupported transports and invalid roles/ports never configure',async()=>{
 const f=fixture(),b=await f.open();
 for(const c of [{...call,provider:'bale'},{...call,provider:provider==='eitaa'?'nasim':'eitaa'},{...call,selfId:'42'},{...call,token:'private-token'},
  {...call,iceServers:[{urls:'turn:relay.example.test:3478?transport=tcp',username:'u',credential:'p'}]},
  {...call,iceServers:[{urls:'stun:relay.example.test:3478'}]},
  {...call,iceServers:[{urls:'turn:user:pass@foreign.invalid:3478',username:'u',credential:'p'}]}])await assert.rejects(b.configure(c,{role:'client',trustedCertificates:[peer]}));
 for(const change of [{role:'unknown'},{socksPort:80},{trustedCertificates:[own]},{trustedCertificates:[peer,peer]},{throughput:'true'}])
  await assert.rejects(b.configure(call,{role:'client',trustedCertificates:[peer],...change}));
 assert.equal(f.commands.length,0);stopped(f,b);
});
test('unsolicited or secret-bearing output and false proxy readiness fail closed',async()=>{
 for(const value of [connected({token:secret}),connected({socksAddress:'0.0.0.0:1089'}),connected({proxyReady:true}),
  metrics({billingVerified:true}),{event:'description',description:sdp('offer')},{event:'error',reason:secret}]){
  const f=fixture(),b=await f.open();await configure(f,b);const p=b.offer();f.emit({event:'description',description:sdp('offer')});await p;
  f.emit(value);assert.equal(b.state.phase,'failed');assert.equal(b.state.reason,'invalid_native_output');assert.equal(f.child.killed,true);assert.ok(!JSON.stringify(b.state).includes(secret));
 }
});
test('close rejects pending negotiation and discards late private replies and metrics',async()=>{
 const f=fixture(),b=await f.open();await configure(f,b);const p=b.offer();const rejected=assert.rejects(p,/closed/);b.close();await rejected;
 f.emit({event:'description',description:sdp('offer')});f.emit(metrics());assert.equal(b.state.phase,'closing');assert.ok(!JSON.stringify(b.state).includes('ice-pwd'));
 f.emit({event:'stopped'});f.child.emit('exit',0);assert.equal(b.state.phase,'closed');
});
test('fragmented replies, stderr, oversized output, early exits and timeouts remain bounded',async()=>{
 const f=fixture(),b=await f.open();const configuring=b.configure(call,{role:'client',trustedCertificates:[peer]});
 const line=JSON.stringify({event:'configured',provider})+'\n';for(const char of line)f.child.stdout.write(char);await configuring;
 f.child.stderr.write(secret);assert.equal(b.state.stderrPresent,true);assert.ok(!JSON.stringify(b.state).includes(secret));
 f.child.stdout.write(Buffer.alloc(192*1024+1,65));assert.equal(b.state.phase,'failed');assert.equal(f.child.killed,true);
 const early=fixture({prepared:false}),p=early.open();early.child.emit('exit',1);await assert.rejects(p,/process_exited/);
 await assert.rejects(fixture({prepared:false}).open(),/prepare_timeout/);
});
test('plaintext, multiple media sections and host ICE are rejected before native signaling',async()=>{
 const f=fixture(),b=await f.open();await configure(f,b);
 for(const description of [{...sdp('offer'),sdp:sdp('offer').sdp.replace('UDP/TLS/RTP/SAVPF','RTP/AVP')},
  {...sdp('offer'),sdp:sdp('offer').sdp+'m=video 9 UDP/TLS/RTP/SAVPF 96\r\n'},
  {...sdp('offer'),sdp:sdp('offer').sdp.replace('typ relay','typ host')}])await assert.rejects(b.answer(description),/invalid_description/);
 assert.equal(f.commands.length,1);stopped(f,b);
});


test('actual helper rejects arguments, key logging and oversized private commands without echoing them',{skip:!executable},()=>{
 const {spawnSync}=require('node:child_process');const env={...process.env};delete env.SSLKEYLOGFILE;delete env.NODE_TLS_REJECT_UNAUTHORIZED;
 const invoke=(args,input,extra={})=>spawnSync(executable,args,{input,encoding:'utf8',timeout:5000,maxBuffer:32768,windowsHide:true,shell:false,env:{...env,...extra}});
 const args=invoke(['fixture-private-argument'],'');assert.equal(args.status,2);assert.ok(args.stdout.includes('arguments_not_allowed'));assert.ok(!args.stdout.includes('fixture-private-argument'));
 const keylog=invoke([], '',{SSLKEYLOGFILE:path.resolve('fixture-must-not-be-created.keys')});assert.equal(keylog.status,2);assert.ok(keylog.stdout.includes('unsafe_environment'));
 const large=invoke([],'X'.repeat(192*1024+1)+'\n');assert.equal(large.status,1);assert.ok(large.stdout.includes('invalid_command'));assert.ok(large.stdout.length<32768);
 const other=invoke([],JSON.stringify({command:'configure',provider:'bale',token:secret})+'\n');assert.equal(other.status,1);assert.ok(other.stdout.includes('invalid_config'));assert.ok(!other.stdout.includes(secret));
});
async function waitClosed(bridge){for(let i=0;i<100;i++){if(['closed','failed'].includes(bridge.state.phase))return;await new Promise(r=>setTimeout(r,30));}throw Error('Helper did not stop');}
test('provider-specific IDs preserve exact 64-bit Eitaa values and keep the existing Nasim boundary',async()=>{
 const f=fixture(),b=await f.open(),large={...call,selfId:'9007199254740993',peerId:'9223372036854775807'};
 if(provider==='eitaa'||provider==='rubika'){const configuring=b.configure(large,{role:'client',trustedCertificates:[peer]});f.emit({event:'configured',provider});await configuring;assert.equal(b.state.context.selfId,large.selfId);}
 else {await assert.rejects(b.configure(large,{role:'client',trustedCertificates:[peer]}));assert.equal(f.commands.length,0);}
 stopped(f,b);
});
test('a helper announcing another provider cannot supply a pairing identity',async()=>{
 const f=fixture({prepared:false}),opening=f.open();f.emit({event:'prepared',protocol:2,provider:provider==='eitaa'?'nasim':'eitaa',publicCertificate:own});await assert.rejects(opening,/invalid_native_output/);assert.equal(f.child.killed,true);
});
test('actual native helper creates fresh identities and closes cleanly on stop',{skip:!executable},async()=>{
 const a=await NativeMediaBridge.open(executable),b=await NativeMediaBridge.open(executable);
 assert.notEqual(a.publicCertificate,b.publicCertificate);a.close();b.close();await Promise.all([waitClosed(a),waitClosed(b)]);
 assert.equal(a.state.phase,'closed');assert.equal(b.state.phase,'closed');
});
test('actual helper cancels a pending local relay gather without waiting for its deadline',{skip:!executable},async()=>{
 const a=await NativeMediaBridge.open(executable),b=await NativeMediaBridge.open(executable);const certificate=b.publicCertificate;
 const relay=require('node:dgram').createSocket('udp4');await new Promise((resolve,reject)=>{relay.once('error',reject);relay.bind(0,'127.0.0.1',resolve);});
 try{await a.configure({...call,iceServers:[{urls:'turn:127.0.0.1:'+relay.address().port,username:'fixture',credential:secret}]},{role:'client',trustedCertificates:[certificate]});
  const gathering=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('No local TURN attempt observed')),2000);relay.once('message',()=>{clearTimeout(timer);resolve();});});
  const pending=a.offer();const rejected=assert.rejects(pending,/closed/);await gathering;
  // The local socket deliberately never answers: the native gather is
  // verifiably waiting for network I/O when the stop command arrives.
  a.close();await rejected;await waitClosed(a);assert.equal(a.state.phase,'closed');
 }finally{relay.close();a.close();b.close();await Promise.all([waitClosed(a),waitClosed(b)]);}
});

}
module.exports={register};
