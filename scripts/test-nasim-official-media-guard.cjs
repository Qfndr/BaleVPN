'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {OfficialMediaGuard}=require('../experiments/nasim/official-media-guard.cjs');
const fixture=()=>new OfficialMediaGuard({approvedServers:['stun:8.8.8.8:3478','turn:turn.example.invalid:3478'],hostPins:{'turn.example.invalid':'1.1.1.1'}});
const candidate=(ip,port=40000,protocol='udp')=>`candidate:0 1 ${protocol} 123 ${ip} ${port} typ host`;
const ice=(ip,port,protocol)=>({type:'ice',callData:{sdpCandidate:candidate(ip,port,protocol)}});
test('only exact approved public relay servers and DNS pins may reach RTC configuration',()=>{
 const guard=fixture();assert.equal(guard.resolverRules,'MAP turn.example.invalid 1.1.1.1');
 guard.checkServers([{urls:'stun:8.8.8.8:3478'},{urls:'turn:turn.example.invalid:3478'}]);
 assert.throws(()=>guard.checkServers([{urls:'stun:8.8.8.8:3478'},{urls:'turn:turn.example.invalid:1'}]));
 for(const address of ['127.0.0.1','192.168.1.1','::1','169.254.1.1','224.1.2.3','::ffff:127.0.0.1']){
  assert.throws(()=>new OfficialMediaGuard({approvedServers:['turn:turn.example.invalid:3478'],hostPins:{'turn.example.invalid':address}}));
 }
});
test('public UDP is accepted and private candidate requires exact owner, address and port',async()=>{
 const guard=fixture();await guard.checkSignal(1,ice('8.8.8.8'));
 const pending=guard.checkSignal(1,ice('192.168.1.3'));setTimeout(()=>guard.capture(1,candidate('192.168.1.3')),20);
 await pending;
 await Promise.all([
  assert.rejects(guard.checkSignal(2,ice('192.168.1.3')),e=>e.reason==='candidate_denied'),
  assert.rejects(guard.checkSignal(1,ice('192.168.1.3',40001)),e=>e.reason==='candidate_denied'),
  assert.rejects(guard.checkSignal(1,ice('8.8.8.8',40000,'tcp')),e=>e.reason==='invalid_candidate'),
  assert.rejects(guard.checkSignal(1,ice('224.1.2.3')),e=>e.reason==='candidate_denied')
 ]);
});
test('SDP checks candidate and connection addresses before remote description',async()=>{
 const guard=fixture();guard.capture(2,candidate('127.0.0.1',40000));
 const sdp=ip=>['v=0','m=audio 40000 UDP/TLS/RTP/SAVPF 111','c=IN IP4 '+ip,'a='+candidate('127.0.0.1'), ''].join('\r\n');
 await guard.checkSignal(2,{type:'offer',callData:{sdp:sdp('127.0.0.1')}});
 await assert.rejects(guard.checkSignal(2,{type:'answer',callData:{sdp:sdp('192.168.1.2')}}),e=>e.reason==='candidate_denied');
 await assert.rejects(guard.checkSignal(2,{type:'answer',callData:{sdp:sdp('127.0.0.1')+'a=remote-candidates:1 8.8.8.8 40000\n'}}),e=>e.reason==='invalid_sdp');
});
