'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {CallMedia}=require('../experiments/eitaa/call-media.cjs'),{relayServers}=require('../experiments/eitaa/relay-config.cjs');
const {fromDescription}=require('../experiments/eitaa/media-description.cjs'),{pair}=require('./eitaa-call-session-fixture.cjs'),f=require('./eitaa-call-fixtures.cjs');
function sdp(type){return {type,sdp:['v=0','o=- 1 2 IN IP4 127.0.0.1','s=-','t=0 0','a=group:BUNDLE 0','a=fingerprint:sha-256 '+Array(32).fill('AA').join(':'),`a=setup:${type==='offer'?'actpass':'active'}`,'m=audio 9 UDP/TLS/RTP/SAVPF 111','c=IN IP4 0.0.0.0','a=ice-ufrag:fixture-ufrag','a=ice-pwd:fixture-private-ice-password','a=mid:0','a=sendrecv','a=rtcp-mux','a=rtpmap:111 opus/48000/2','a=ssrc:1234 cname:fixture','a=candidate:1 1 udp 1 192.0.2.1 40000 typ relay',''].join('\r\n')};}
function helper(cert){const state={phase:'prepared',provider:'eitaa',mediaConnected:false,relayPair:false,peerAuthenticated:false,proxyReady:false},calls=[];let closed=0;return {calls,state,get closed(){return closed;},bridge:{publicCertificate:cert,get state(){return {...state};},async configure(call,options){calls.push(['configure',call,options]);state.phase='configured';},async offer(){calls.push(['offer']);state.phase='connecting';return sdp('offer');},async answer(offer){calls.push(['answer',offer]);state.phase='connecting';return sdp('answer');},async setAnswer(answer){calls.push(['setAnswer',answer]);},async addCandidate(candidate){calls.push(['candidate',candidate]);},close(){closed++;state.phase='closed';}}};}
async function composed(t){
 const left=helper('aa'.repeat(80)),right=helper('bb'.repeat(80));const a=new CallMedia({executable:'fixture-eitaa-helper',role:'client',socksPort:0,open:async()=>left.bridge}),b=new CallMedia({executable:'fixture-eitaa-helper',role:'server',open:async()=>right.bridge});t.after(()=>{a.close();b.close();});const [ac,bc]=await Promise.all([a.prepare(),b.prepare()]);a.trustCertificate(bc.publicCertificate);b.trustCertificate(ac.publicCertificate);
 const p=await pair(t,{onASecure:c=>a.onSecure(c),onBSecure:c=>b.onSecure(c),onASignal:(v,c)=>a.onSignal(v,c),onBSignal:(v,c)=>b.onSignal(v,c),onAEnd:()=>a.close(),onBEnd:()=>b.close()});return {...p,aMedia:a,bMedia:b,left,right,async complete(){await p.negotiate();await p.a.pollOnce();}};
}
test('Eitaa relay projection preserves IPv4/IPv6 TURN credentials and excludes STUN or legacy reflectors',()=>{
 const servers=relayServers([{_:'phoneConnection',ip:'unused'},{...f.connection,turn:undefined,stun:true},{...f.connection,id:12n}]);assert.deepEqual(servers,[{urls:['turn:192.0.2.1:3478','turn:[2001:db8::1]:3478'],username:f.connection.username,credential:f.connection.password}]);assert.ok(!JSON.stringify(servers).includes('stun:'));
});
test('relay input rejects malformed addresses, duplicate targets/IDs, wrong families, ports, credentials and excessive lists',()=>{
 for(const change of [{ip:'relay.example.test'},{ip:'192.0.2.1/path'},{ipv6:'fe80::1%eth0'},{ip:'2001:db8::1'},{ip:'',ipv6:''},{port:0},{port:65536},{username:''},{password:'private\nsecret'},{id:1}])assert.throws(()=>relayServers([{...f.connection,...change}]),{reason:'invalid_relay'});
 for(const values of [[],[{...f.connection,turn:false,stun:true}],[f.connection,f.connection],[f.connection,{...f.connection,id:12n}],Array.from({length:5},(_,i)=>({...f.connection,id:BigInt(i),ip:'192.0.2.'+(i+1),ipv6:''}))])assert.throws(()=>relayServers(values),{reason:'invalid_relay'});
});
test('full call controllers drive offer/answer media, configure only Eitaa TURN and require independent identity pairing',async t=>{
 const p=await composed(t);await p.complete();assert.deepEqual(p.left.calls.map(v=>v[0]),['configure','offer','setAnswer']);assert.deepEqual(p.right.calls.map(v=>v[0]),['configure','answer']);assert.equal(p.left.calls[0][1].provider,'eitaa');assert.equal(p.left.calls[0][1].selfId,'101');assert.deepEqual(p.left.calls[0][2].trustedCertificates,['bb'.repeat(80)]);
 assert.equal(p.aMedia.state.phase,'connecting');assert.equal(p.aMedia.state.proxyReady,false);await p.a.hangUp();assert.equal(p.aMedia.state.phase,'closed');await p.b.pollOnce();assert.equal(p.bMedia.state.phase,'closed');
});
test('media readiness requires negotiated relay media plus mutually authenticated QUIC; private fields never reach state',async t=>{
 const p=await composed(t);await p.complete();Object.assign(p.left.state,{phase:'connected',mediaConnected:true,relayPair:true,proxyReady:true,peerAuthenticated:false,socksAddress:'127.0.0.1:1089'});assert.equal(p.aMedia.state.proxyReady,false);assert.equal(p.aMedia.state.peerAuthenticated,false);p.left.state.peerAuthenticated=true;assert.equal(p.aMedia.state.proxyReady,true);assert.equal(p.aMedia.state.phase,'connected');assert.equal(p.aMedia.state.billingVerified,false);
 for(const secret of ['fixture-turn','fixture-private','candidate:','fingerprint:','trustedCertificates','__web'])assert.ok(!JSON.stringify(p.aMedia.state).includes(secret));p.left.state.mediaConnected=false;assert.equal(p.aMedia.state.proxyReady,false);
 Object.assign(p.right.state,{phase:'connected',mediaConnected:true,relayPair:true,peerAuthenticated:true,proxyReady:false});assert.equal(p.bMedia.state.ready,true);assert.equal(p.bMedia.state.serverReady,true);assert.equal(p.bMedia.state.proxyReady,false);assert.equal(p.bMedia.state.phase,'connected');assert.equal(p.bMedia.state.socksAddress,null);
});
test('late relay candidates are validated and added once, while host/context changes terminate the media owner',async t=>{
 const p=await composed(t);await p.complete();const candidate={sdpString:'candidate:2 1 udp 2 192.0.2.2 40001 typ relay',sdpMid:'0',sdpMLineIndex:0};await p.a.sendSignal({'@type':'Candidates',candidates:[candidate]});await p.b.pollOnce();assert.equal(p.right.calls.filter(v=>v[0]==='candidate').length,1);await p.a.sendSignal({'@type':'Candidates',candidates:[candidate]});await p.b.pollOnce();assert.equal(p.right.calls.filter(v=>v[0]==='candidate').length,1);
 await p.a.sendSignal({'@type':'Candidates',candidates:[{...candidate,sdpString:candidate.sdpString.replace('typ relay','typ host')}]});await assert.rejects(p.b.pollOnce());assert.equal(p.bMedia.state.phase,'failed');assert.equal(p.bMedia.state.reason,'non_relay_candidate');assert.equal(p.right.closed,1);
});
test('media setup arriving after candidates negotiates once; repeated setup and mismatched call contexts are rejected',async t=>{
 const h=helper('aa'.repeat(80)),m=new CallMedia({executable:'fixture',role:'server',open:async()=>h.bridge});t.after(()=>m.close());await m.prepare();m.trustCertificate('bb'.repeat(80));const sent=[];await m.onSecure({callId:'1',selfId:'202',peerId:'101',direction:'incoming',connections:[f.connection],send:async v=>sent.push(v)});const projected=fromDescription(sdp('offer')),ctx={callId:'1',send:async v=>sent.push(v)};
 await m.onSignal(projected.candidateMessages[0],ctx);assert.equal(h.calls.length,1);await m.onSignal(projected.initialSetup,ctx);assert.equal(h.calls[1][0],'answer');assert.equal(sent.length,2);await assert.rejects(m.onSignal(projected.initialSetup,ctx),{reason:'duplicate_initial_setup'});assert.equal(m.state.phase,'failed');
});
test('unpaired, self-paired and invalid media options cannot create a configured carrier',async t=>{
 for(const options of [{role:'other'},{role:'client',socksPort:80},{role:'client',throughput:'yes'}])assert.throws(()=>new CallMedia({executable:'fixture',...options}),{reason:'invalid_media_options'});
 const h=helper('aa'.repeat(80)),m=new CallMedia({executable:'fixture',role:'client',open:async()=>h.bridge});t.after(()=>m.close());await m.prepare();assert.throws(()=>m.trustCertificate('aa'.repeat(80)),{reason:'invalid_pairing'});await assert.rejects(m.onSecure({}),{reason:'media_not_paired'});assert.equal(h.calls.length,0);
});
test('closing during native preparation prevents a late helper from reappearing and closes it',async()=>{
 let resolve;const h=helper('aa'.repeat(80)),m=new CallMedia({executable:'fixture',role:'client',open:()=>new Promise(r=>{resolve=r;})});const pending=m.prepare();m.close();resolve(h.bridge);await assert.rejects(pending,{reason:'media_cancelled'});assert.equal(h.closed,1);assert.equal(m.state.phase,'closed');assert.equal(m.state.proxyReady,false);
});
test('bounded candidate queues reject excess entries and wrong signaling call IDs without exposing contents',async t=>{
 const p=await composed(t);await p.complete();await assert.rejects(p.aMedia.onSignal({'@type':'Candidates',candidates:[]},{callId:'999',send:async()=>{}}),{reason:'invalid_media_context'});assert.equal(p.aMedia.state.phase,'failed');
 const q=await composed(t);await q.complete();const c=fromDescription(sdp('offer')).candidateMessages[0];for(let i=0;i<7;i++){await q.a.sendSignal(c);await q.b.pollOnce();}await q.a.sendSignal(c);await assert.rejects(q.b.pollOnce());assert.equal(q.bMedia.state.reason,'too_many_candidates');
});
test('native worker failure clears proxy readiness and invokes a bounded failure hook',async t=>{
 t.mock.timers.enable({apis:['setInterval']});let reason;const h=helper('aa'.repeat(80)),m=new CallMedia({executable:'fixture',role:'client',open:async()=>h.bridge,onFailure:r=>{reason=r;}});t.after(()=>m.close());await m.prepare();h.state.phase='failed';h.state.reason='transport_disconnected';t.mock.timers.tick(250);assert.equal(reason,'transport_disconnected');assert.equal(m.state.phase,'failed');assert.equal(m.state.proxyReady,false);assert.equal(h.closed,1);
});
