'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {fromDescription,toDescription}=require('../experiments/eitaa/media-description.cjs');
const {SignalingCipher,validateSignal}=require('../experiments/eitaa/call-signaling.cjs');
const ice='fixture-private-ice-password',fingerprint=Array(32).fill('A5').join(':');
function description(type='offer',count=1){return {type,sdp:['v=0','o=- 1 2 IN IP4 127.0.0.1','s=-','t=0 0','a=group:BUNDLE 0',`a=fingerprint:sha-256 ${fingerprint}`,`a=setup:${type==='offer'?'actpass':'active'}`,'m=audio 9 UDP/TLS/RTP/SAVPF 111 9','c=IN IP4 0.0.0.0','a=ice-ufrag:fixture-ufrag',`a=ice-pwd:${ice}`,'a=mid:0','a=sendrecv','a=rtcp-mux','a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid','a=rtpmap:111 opus/48000/2','a=rtpmap:9 G722/8000','a=fmtp:111 minptime=10;useinbandfec=1','a=rtcp-fb:111 transport-cc','a=ssrc:12345678 cname:fixture','a=ssrc:12345678 msid:fixture audio',...Array.from({length:count},(_,i)=>`a=candidate:${i+1} 1 udp 123 203.0.113.${i+1} ${3478+i} typ relay raddr 0.0.0.0 rport 0 generation 0`),''].join('\r\n')};}
test('secure Opus descriptions project into Eitaa setup/candidates and reconstruct without losing ICE, DTLS, RTP or relay fields',()=>{
 for(const type of ['offer','answer']){const original=description(type),projected=fromDescription(original);assert.equal(projected.initialSetup.audio.payloadTypes.length,1);assert.equal(projected.initialSetup.audio.payloadTypes[0].name,'opus');assert.equal(projected.initialSetup.pwd,ice);assert.equal(projected.initialSetup.fingerprints[0].fingerprint,fingerprint);assert.equal(projected.candidateMessages.length,1);validateSignal(projected.initialSetup);
  const reconstructed=toDescription(projected.initialSetup,projected.candidateMessages,{type});assert.equal(reconstructed.type,type);assert.ok(reconstructed.sdp.includes('m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n'));assert.ok(!reconstructed.sdp.includes('G722'));assert.deepEqual(fromDescription(reconstructed),projected);
 }
});
test('actual encrypted Eitaa-shaped signaling carries the projected descriptions in both caller directions',()=>{
 const key=crypto.randomBytes(256),a=new SignalingCipher({key,isOutgoing:true}),b=new SignalingCipher({key,isOutgoing:false});key.fill(0);
 try{for(const type of ['offer','answer']){const p=fromDescription(description(type)),sender=type==='offer'?a:b,receiver=type==='offer'?b:a,initial=receiver.decryptJson(sender.encryptJson(p.initialSetup)),candidates=p.candidateMessages.map(m=>receiver.decryptJson(sender.encryptJson(m)));assert.deepEqual(fromDescription(toDescription(initial,candidates,{type})),p);}}finally{a.close();b.close();}
});
test('host/reflexive/TCP candidates, hostnames and wrong candidate context cannot enter the native description',()=>{
 const p=fromDescription(description());for(const change of ['host','srflx'])assert.throws(()=>fromDescription({...description(),sdp:description().sdp.replace('typ relay','typ '+change)}),{reason:'non_relay_candidate'});
 for(const replacement of [[' 1 udp ',' 1 tcp '],['203.0.113.1','relay.example.test'],[' 3478 typ',' 0 typ'],[' 1 udp ',' 2 udp ']])assert.throws(()=>fromDescription({...description(),sdp:description().sdp.replace(...replacement)}));
 for(const c of [{...p.candidateMessages[0].candidates[0],sdpMid:'1'},{...p.candidateMessages[0].candidates[0],sdpMLineIndex:1},{sdpString:p.candidateMessages[0].candidates[0].sdpString+' ufrag other'}])assert.throws(()=>toDescription(p.initialSetup,[{'@type':'Candidates',candidates:[c]}],{type:'offer'}),{reason:'candidate_context_mismatch'});
 assert.throws(()=>toDescription(p.initialSetup,[],{type:'offer'}),{reason:'no_relay_candidate'});
});
test('insecure, ambiguous and unsupported media descriptions fail without echoing private SDP',()=>{
 const original=description();const changes=[original.sdp.replace('UDP/TLS/RTP/SAVPF','RTP/AVP'),original.sdp+'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:private\r\n',original.sdp+'m=video 9 UDP/TLS/RTP/SAVPF 96\r\n',original.sdp.replace('a=setup:actpass','a=setup:active'),original.sdp.replace('sha-256','sha-1'),original.sdp+'a=ice-pwd:different-private-ice-password\r\n',original.sdp.replace('a=mid:0','a=mid:other'),original.sdp.replace('a=sendrecv','a=recvonly'),original.sdp+'a=ssrc:42 cname:other\r\n'];
 for(const sdp of changes)assert.throws(()=>fromDescription({type:'offer',sdp}),e=>!e.message.includes(ice));
 assert.throws(()=>fromDescription({type:'offer',sdp:'X'.repeat(65536)}));assert.throws(()=>fromDescription({type:'offer',sdp:original.sdp+'\0'}));
});
test('RTP parameters and DTLS/ICE fields reject line injection, prototype keys, codec downgrades and conflicting extensions',()=>{
 const p=fromDescription(description()),clone=()=>structuredClone(p.initialSetup);
 const bad=clone();bad.audio.payloadTypes[0].parameters=JSON.parse('{"__proto__":"x"}');assert.throws(()=>toDescription(bad,p.candidateMessages,{type:'offer'}));
 for(const modify of [i=>i.audio.payloadTypes[0].name='PCMU',i=>i.audio.payloadTypes[0].clockrate=8000,i=>i.audio.rtpExtensions.push({...i.audio.rtpExtensions[0]}),i=>i.audio.rtpExtensions[0].uri+='\r\na=bad',i=>i.audio.payloadTypes[0].parameters.minptime='10;evil=1',i=>i.fingerprints[0].setup='passive',i=>i.pwd='short']){const value=clone();modify(value);assert.throws(()=>toDescription(value,p.candidateMessages,{type:'offer'}));}
 assert.throws(()=>fromDescription({...description(),sdp:description().sdp.replace('minptime=10;useinbandfec=1','__proto__=unsafe')}));assert.equal({}.unsafe,undefined);
});
test('candidate batches fit the private signaling cap, deduplicate safely and preserve all relay choices',()=>{
 const p=fromDescription(description('offer',20));assert.deepEqual(p.candidateMessages.map(m=>m.candidates.length),[16,4]);for(const m of p.candidateMessages)validateSignal(m);
 const again=fromDescription(toDescription(p.initialSetup,[...p.candidateMessages,...p.candidateMessages],{type:'offer'}));assert.equal(again.candidateMessages.flatMap(m=>m.candidates).length,20);assert.deepEqual(again,p);
});
test('rtcp-mux omits the native RTCP component without accepting non-relay fallback or losing RTP',()=>{
 const original=description(),rtcp='a=candidate:rtcp 2 udp 123 203.0.113.2 3479 typ relay raddr 0.0.0.0 rport 0\r\n';const p=fromDescription({...original,sdp:original.sdp+rtcp});assert.equal(p.candidateMessages.flatMap(m=>m.candidates).length,1);
 const extra={'@type':'Candidates',candidates:[{sdpString:rtcp.trim().slice(2),sdpMid:'0',sdpMLineIndex:0}]};const converted=toDescription(p.initialSetup,[...p.candidateMessages,extra],{type:'offer'});assert.ok(!converted.sdp.includes('candidate:rtcp'));assert.deepEqual(fromDescription(converted),p);
 assert.throws(()=>fromDescription({...original,sdp:original.sdp+rtcp.replace('typ relay','typ host')}),{reason:'non_relay_candidate'});
});
test('conversion does not mutate private input and cannot silently adapt video/SCTP or missing audio identity',()=>{
 const p=fromDescription(description()),snapshot=structuredClone(p);toDescription(p.initialSetup,p.candidateMessages,{type:'offer'});assert.deepEqual(p,snapshot);
 const video={...structuredClone(p.initialSetup),video:structuredClone(p.initialSetup.audio)};assert.throws(()=>toDescription(video,p.candidateMessages,{type:'offer'}),{reason:'unsupported_media'});
 assert.throws(()=>fromDescription({...description(),sdp:description().sdp.replaceAll('a=ssrc:12345678','a=ssrc:0')}));assert.throws(()=>toDescription(p.initialSetup,p.candidateMessages,{type:'rollback'}),{reason:'invalid_description_type'});
});
test('legacy signed SSRC strings round-trip high-bit native RTP sources without changing their wire identity',()=>{
 for(const value of [0x7fffffff,0x80000000,0xffffffff]){const original={...description(),sdp:description().sdp.replaceAll('12345678',String(value))},p=fromDescription(original);assert.equal(p.initialSetup.audio.ssrc,String(value|0));const sdp=toDescription(p.initialSetup,p.candidateMessages,{type:'offer'}).sdp;assert.ok(sdp.includes('a=ssrc:'+value+' '));assert.deepEqual(fromDescription({type:'offer',sdp}),p);}
 const p=fromDescription(description());p.initialSetup.audio.ssrc='-2147483649';assert.throws(()=>toDescription(p.initialSetup,p.candidateMessages,{type:'offer'}));
});
