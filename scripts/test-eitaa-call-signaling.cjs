'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {SignalingCipher,validateSignal,MAX_PAYLOAD,WINDOW}=require('../experiments/eitaa/call-signaling.cjs');
const key=()=>crypto.randomBytes(256),pair=k=>[new SignalingCipher({key:k,isOutgoing:true}),new SignalingCipher({key:k,isOutgoing:false})];
const candidates={'@type':'Candidates',candidates:[{sdpString:'candidate:1 1 udp 123 203.0.113.10 3478 typ relay',sdpMLineIndex:0}]};
function setup(){return {'@type':'InitialSetup',fingerprints:[{hash:'sha-256',fingerprint:Array(32).fill('A5').join(':'),setup:'actpass'}],ufrag:'fixture-ufrag',pwd:'fixture-private-ice-password',audio:{ssrc:'12345678',rtpExtensions:[{id:1,uri:'urn:ietf:params:rtp-hdrext:ssrc-audio-level'}],payloadTypes:[{id:111,name:'opus',clockrate:48000,channels:2,parameters:{minptime:'10',useinbandfec:'1'},feedbackTypes:[{type:'transport-cc',subtype:''}]}]},video:undefined};}
test('both call directions exchange private typed setup/candidates without exposing raw credentials or instance key state',()=>{
 const [a,b]=pair(key());try{const payload=setup(),packet=a.encryptJson(payload);assert.ok(!packet.includes(Buffer.from(payload.pwd)));assert.deepEqual(b.decryptJson(packet),JSON.parse(JSON.stringify(payload)));assert.deepEqual(a.decryptJson(b.encryptJson(candidates)),candidates);assert.equal(JSON.stringify(a),'{}');}finally{a.close();b.close();}
});
test('wrong keys, role reflections and every altered header/body byte fail authentication without poisoning valid receive state',()=>{
 const k=key(),[a,b]=pair(k),wrong=new SignalingCipher({key:key(),isOutgoing:false});try{const packet=a.encryptJson(candidates);assert.throws(()=>wrong.decryptRaw(packet),{reason:'invalid_signal_authentication'});assert.throws(()=>a.decryptRaw(packet),{reason:'invalid_signal_authentication'});
  for(let i=0;i<packet.length;i++){const changed=Buffer.from(packet);changed[i]^=1;assert.throws(()=>b.decryptRaw(changed),{reason:'invalid_signal_authentication'});}
  assert.deepEqual(b.decryptJson(packet),candidates);
 }finally{a.close();b.close();wrong.close();k.fill(0);}
});
test('duplicates are refused while authenticated out-of-order packets within the replay window work',()=>{
 const [a,b]=pair(key());try{const packets=['one','two','three'].map(s=>a.encryptRaw(Buffer.from(s)));assert.equal(b.decryptRaw(packets[2]).toString(),'three');assert.equal(b.decryptRaw(packets[0]).toString(),'one');assert.equal(b.decryptRaw(packets[1]).toString(),'two');for(const p of packets)assert.throws(()=>b.decryptRaw(p),{reason:'signal_replayed'});}finally{a.close();b.close();}
});
test('bounded replay tracking drops stale sequences after a large forward gap and survives ring index reuse',()=>{
 const [a,b]=pair(key());try{let first,second,last;for(let i=0;i<WINDOW+1;i++){const p=a.encryptRaw(Buffer.from([i&255]));if(!i)first=p;if(i===1)second=p;last=p;}
  b.decryptRaw(last);assert.throws(()=>b.decryptRaw(first),{reason:'signal_too_old'});b.decryptRaw(second);assert.throws(()=>b.decryptRaw(second),{reason:'signal_replayed'});assert.throws(()=>b.decryptRaw(last),{reason:'signal_replayed'});
 }finally{a.close();b.close();}
});
test('key/packet bounds reject truncated, oversized and weak-short inputs; rare trimmed DH keys remain interoperable',()=>{
 for(const length of [0,1,247,257])assert.throws(()=>new SignalingCipher({key:Buffer.alloc(length,0xa5),isOutgoing:true}));assert.throws(()=>new SignalingCipher({key:Buffer.alloc(256),isOutgoing:true}),{reason:'invalid_signal_key'});assert.throws(()=>new SignalingCipher({key:key(),isOutgoing:1}),{reason:'invalid_signal_role'});
 for(const length of [248,255,256]){const [a,b]=pair(crypto.randomBytes(length));try{for(const value of [Buffer.alloc(0),Buffer.alloc(MAX_PAYLOAD+1)])assert.throws(()=>a.encryptRaw(value),{reason:'invalid_signal_size'});for(const p of [Buffer.alloc(20),Buffer.alloc(MAX_PAYLOAD+21)])assert.throws(()=>b.decryptRaw(p),{reason:'invalid_signal_size'});const payload=Buffer.alloc(MAX_PAYLOAD,0xa5);assert.ok(b.decryptRaw(a.encryptRaw(payload)).equals(payload));}finally{a.close();b.close();}}
});
test('JSON decoder refuses bad UTF-8, malformed JSON, unknown types and unsafe fields without plaintext in errors',()=>{
 const [a,b]=pair(key());try{for(const raw of [Buffer.from([255]),Buffer.from('fixture-private-malformed-json')])assert.throws(()=>b.decryptJson(a.encryptRaw(raw)),e=>e.reason==='invalid_signal_json'&&!e.message.includes('fixture-private'));
  const malicious=[{'@type':'Other',private:'fixture-private-secret'},JSON.parse('{"@type":"Candidates","candidates":[],"__proto__":{"polluted":true}}'),{'@type':'Candidates',candidates:[{sdpString:'candidate:1\r\na=bad'}]}];for(const value of malicious)assert.throws(()=>b.decryptJson(a.encryptRaw(Buffer.from(JSON.stringify(value)))),e=>!e.message.includes('fixture-private'));
  assert.equal({}.polluted,undefined);assert.deepEqual(b.decryptJson(a.encryptJson(candidates)),candidates);
 }finally{a.close();b.close();}
});
test('JSON encoder rejects cycles, getters, hidden serialization hooks, deep/wide data and invalid setup',()=>{
 let invoked=0;const hidden={'@type':'Candidates',candidates:[]};Object.defineProperty(hidden,'toJSON',{value:()=>{invoked++;return candidates;}});assert.throws(()=>validateSignal(hidden));
 const getter={'@type':'Candidates'};Object.defineProperty(getter,'candidates',{enumerable:true,get(){invoked++;return [];}});assert.throws(()=>validateSignal(getter));
 const array=[];Object.defineProperty(array,'toJSON',{value:()=>{invoked++;return [];}});assert.throws(()=>validateSignal({'@type':'Candidates',candidates:array}));assert.equal(invoked,0);
 const cycle={'@type':'Candidates',candidates:[]};cycle.cycle=cycle;assert.throws(()=>validateSignal(cycle));
 const deep={'@type':'Candidates',candidates:[]};let at=deep;for(let i=0;i<20;i++)at=at.child={};assert.throws(()=>validateSignal(deep));assert.throws(()=>validateSignal({'@type':'Candidates',candidates:Array.from({length:65},()=>candidates.candidates[0])}));
 for(const change of [{pwd:'short'},{ufrag:'bad\nufrag'},{fingerprints:[{hash:'sha-1',fingerprint:'A5',setup:'active'}]},{audio:{ssrc:'0',rtpExtensions:[],payloadTypes:[]}}])assert.throws(()=>validateSignal({...setup(),...change}));
 assert.doesNotThrow(()=>validateSignal(setup()));
});
test('close is terminal, constructor owns a defensive key copy and an authenticated malformed packet stays consumed',()=>{
 const k=key(),[a,b]=pair(k);k.fill(0);try{const packet=a.encryptRaw(Buffer.from('not-json'));assert.throws(()=>b.decryptJson(packet),{reason:'invalid_signal_json'});assert.throws(()=>b.decryptRaw(packet),{reason:'signal_replayed'});assert.deepEqual(b.decryptJson(a.encryptJson(candidates)),candidates);a.close();assert.throws(()=>a.encryptJson(candidates),{reason:'closed'});b.close();assert.throws(()=>b.decryptRaw(packet),{reason:'closed'});}finally{a.close();b.close();}
});
test('native DH output feeds the signaling layer without exporting a private exponent or disabling peer checks',async()=>{
 const {CallKeyExchange}=require('../experiments/eitaa/call-key.cjs'),p=crypto.getDiffieHellman('modp14').getPrime();const a=await CallKeyExchange.create({prime:p,generator:2}),b=await CallKeyExchange.create({prime:p,generator:2});let x,y,left,right;
 try{const ap=a.publicValue,bp=b.publicValue;x=a.derive(bp,{expectedCommitment:b.commitment});y=b.derive(ap,{expectedCommitment:a.commitment,expectedFingerprint:x.fingerprint});left=new SignalingCipher({key:x.key,isOutgoing:true});right=new SignalingCipher({key:y.key,isOutgoing:false});assert.deepEqual(right.decryptJson(left.encryptJson(setup())),JSON.parse(JSON.stringify(setup())));assert.deepEqual(left.decryptJson(right.encryptJson(candidates)),candidates);}finally{x?.key.fill(0);y?.key.fill(0);left?.close();right?.close();a.close();b.close();}
});
