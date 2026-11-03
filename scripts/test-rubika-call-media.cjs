'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {CallMedia}=require('../experiments/rubika/call-media.cjs'),{relayServers}=require('../experiments/rubika/relay-config.cjs');
const {LegacySignalCipher}=require('../experiments/rubika/legacy-signal-cipher.cjs');
const {fromDescription,validateSignal}=require('../experiments/rubika/media-description.cjs');
const profile={libraryVersion:'6.0.0',protocolLayer:92},connection={type:'WebRTC',ip:'192.0.2.1',ipv6:'2001:db8::1',port:3478,turn_username:'fixture-private-user',turn_password:'fixture-private-password'};
function sdp(type){return {type,sdp:['v=0','o=- 1 2 IN IP4 127.0.0.1','s=-','t=0 0','a=group:BUNDLE 0','a=fingerprint:sha-256 '+Array(32).fill('A5').join(':'),`a=setup:${type==='offer'?'actpass':'active'}`,
 'm=audio 9 UDP/TLS/RTP/SAVPF 111','c=IN IP4 0.0.0.0','a=ice-ufrag:fixture-ufrag','a=ice-pwd:fixture-private-ice-password','a=mid:0','a=sendrecv','a=rtcp-mux','a=rtpmap:111 opus/48000/2','a=ssrc:1234 cname:fixture','a=candidate:1 1 udp 1 192.0.2.1 40000 typ relay',''].join('\r\n')};}
function helper(certificate){const state={phase:'prepared',mediaConnected:false,relayPair:false,peerAuthenticated:false,proxyReady:false},calls=[];let closed=0;
 return {state,calls,get closed(){return closed;},bridge:{publicCertificate:certificate,get state(){return {...state};},async configure(call,options){calls.push(['configure',call,options]);state.phase='configured';},
 async offer(){calls.push(['offer']);state.phase='connecting';return sdp('offer');},async answer(description){calls.push(['answer',description]);state.phase='connecting';return sdp('answer');},
 async setAnswer(description){calls.push(['setAnswer',description]);},async addCandidate(value){calls.push(['candidate',value]);},close(){closed++;state.phase='closed';}}};}
async function fixture(t){
 const left=helper('aa'.repeat(80)),right=helper('bb'.repeat(80));
 const a=new CallMedia({...profile,executable:'fixture-helper',role:'client',socksPort:0,open:async()=>left.bridge}),b=new CallMedia({...profile,executable:'fixture-helper',role:'server',open:async()=>right.bridge});
 const key=crypto.randomBytes(256),aCipher=new LegacySignalCipher({...profile,key,isOutgoing:true}),bCipher=new LegacySignalCipher({...profile,key,isOutgoing:false});key.fill(0);const queue=[];
 t.after(()=>{a.close();b.close();aCipher.close();bCipher.close();for(const item of queue)item.packet.fill(0);});
 const [ac,bc]=await Promise.all([a.prepare(),b.prepare()]);a.trustCertificate(bc.publicCertificate);b.trustCertificate(ac.publicCertificate);
 const send=(cipher,side)=>async value=>{validateSignal(value);const raw=Buffer.from(JSON.stringify(value));try{queue.push({side,packet:cipher.encryptRaw(raw)});}finally{raw.fill(0);}};
 const aContext={callId:'fixture_call_01',selfId:'fixture_self_01',peerId:'fixture_peer_02',direction:'outgoing',connections:[connection],send:send(aCipher,'right')};
 const bContext={...aContext,selfId:aContext.peerId,peerId:aContext.selfId,direction:'incoming',send:send(bCipher,'left')};
 const flush=async()=>{let count=0;while(queue.length){assert.ok(++count<32);const item=queue.shift();let raw;try{raw=(item.side==='left'?aCipher:bCipher).decryptRaw(item.packet);const signal=JSON.parse(raw.toString('utf8'));validateSignal(signal);await(item.side==='left'?a:b).onSignal(signal,item.side==='left'?aContext:bContext);}finally{raw?.fill(0);item.packet.fill(0);}}};
 return {a,b,left,right,aContext,bContext,flush,async connect(){await b.onSecure(bContext);await a.onSecure(aContext);await flush();}};
}
test('Rubika relay selection accepts only credentialed WebRTC IP relays and excludes legacy reflectors',()=>{
 assert.deepEqual(relayServers([{type:'Tg',ip:'not-forwarded'},connection]),[{urls:['turn:192.0.2.1:3478','turn:[2001:db8::1]:3478'],username:connection.turn_username,credential:connection.turn_password}]);
 for(const value of [[],[{type:'Tg'}],[connection,connection]])assert.throws(()=>relayServers(value),{reason:'invalid_relay'});
 for(const change of [{ip:'relay.invalid'},{ip:'2001:db8::1'},{ipv6:'fe80::1%eth0'},{ip:'',ipv6:''},{port:0},{port:65536},{turn_username:''},{turn_password:'private\nvalue'}])assert.throws(()=>relayServers([{...connection,...change}]),{reason:'invalid_relay'});
});
test('media cannot silently select a newer native profile or an unsafe local port',()=>{
 for(const change of [{libraryVersion:undefined},{libraryVersion:'9.0.0'},{protocolLayer:93},{socksPort:80}])assert.throws(()=>new CallMedia({...profile,executable:'fixture',role:'client',...change}));
});
test('encrypted legacy messages configure independent Rubika helpers with opaque account IDs and paired QUIC certificates',async t=>{
 const f=await fixture(t);await f.connect();assert.deepEqual(f.left.calls.map(x=>x[0]),['configure','offer','setAnswer']);assert.deepEqual(f.right.calls.map(x=>x[0]),['configure','answer']);
 assert.equal(f.left.calls[0][1].provider,'rubika');assert.equal(f.left.calls[0][1].selfId,'fixture_self_01');assert.deepEqual(f.left.calls[0][2].trustedCertificates,['bb'.repeat(80)]);
 assert.equal(f.a.state.proxyReady,false);assert.equal(f.a.state.providerPathVerified,false);assert.equal(f.b.state.serverReady,false);
});
test('only selected relay media plus pinned QUIC authentication can make a local proxy ready',async t=>{
 const f=await fixture(t);await f.connect();Object.assign(f.left.state,{phase:'connected',mediaConnected:true,relayPair:true,proxyReady:true,peerAuthenticated:false,socksAddress:'127.0.0.1:1089'});
 assert.equal(f.a.state.ready,false);f.left.state.peerAuthenticated=true;assert.equal(f.a.state.proxyReady,true);
 Object.assign(f.right.state,{phase:'connected',mediaConnected:true,relayPair:true,peerAuthenticated:true,proxyReady:false});assert.equal(f.b.state.serverReady,true);assert.equal(f.b.state.proxyReady,false);
 for(const key of ['providerPathVerified','billingVerified','internationalOutageVerified'])assert.equal(f.a.state[key],false);
 for(const secret of [connection.turn_password,connection.turn_username,'candidate:','fingerprint:','fixture-private-ice-password'])assert.ok(!JSON.stringify(f.a.state).includes(secret));
 f.left.state.relayPair=false;assert.equal(f.a.state.proxyReady,false);
});
test('direct ICE candidate or another call context terminates the owned helper',async t=>{
 const f=await fixture(t);await f.connect();const projected=fromDescription(sdp('offer')).candidateMessages[0];projected.candidates[0].sdpString=projected.candidates[0].sdpString.replace('typ relay','typ host');
 await assert.rejects(f.a.onSignal(projected,f.aContext));assert.equal(f.a.state.phase,'failed');assert.equal(f.left.closed,1);
 const g=await fixture(t);await g.connect();await assert.rejects(g.a.onSignal({'@type':'Candidates',candidates:[]},{...g.aContext,callId:'fixture_other_call'}));assert.equal(g.a.state.phase,'failed');
});
test('unpaired media and close during preparation cannot configure a carrier or revive a helper',async()=>{
 let release;const h=helper('aa'.repeat(80)),m=new CallMedia({...profile,executable:'fixture',role:'client',open:()=>new Promise(r=>{release=r;})});
 const pending=m.prepare();m.close();release(h.bridge);await assert.rejects(pending,{reason:'media_cancelled'});assert.equal(h.closed,1);assert.equal(m.state.proxyReady,false);
 const n=new CallMedia({...profile,executable:'fixture',role:'client',open:async()=>h.bridge});try{await n.prepare();assert.throws(()=>n.trustCertificate('aa'.repeat(80)));await assert.rejects(n.onSecure({}));assert.equal(h.calls.length,0);}finally{n.close();}
});
