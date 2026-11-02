const {test}=require('node:test'),assert=require('node:assert/strict');
const {encodeRequest,decodeResponse,capabilities,inspectGreeting,MAX_FRAME}=require('../experiments/igap/signaling.cjs');
const auth={id:'test',token:'fixture-only-not-a-real-token'};
test('official action and protobuf field numbers preserve uint64 peer IDs',()=>{
 const data=encodeRequest(901,auth,{peerId:18446744073709551615n,type:1,sdp:'v=0\r\n'});
 assert.equal(data.readUInt16LE(),901);assert.ok(data.includes(Buffer.from([0x10,255,255,255,255,255,255,255,255,255,1])));
 // Synthetic response: empty metadata, caller 42, voice type 0 (omitted), SDP.
 const response=Buffer.from([181,120,10,0,16,42,34,5,118,61,48,13,10]);
 assert.deepEqual(decodeResponse(response),{action:30901,id:'',timestamp:0,peerId:'42',type:0,sdp:'v=0\r\n'});
});
test('configuration preserves ICE username/credential field ordering; safe report redacts both',()=>{
 // 30900, server {url:turn:test, credential:secret, username:user}, voice enabled.
 const server=Buffer.from([10,9,...Buffer.from('turn:test'),18,6,...Buffer.from('secret'),26,4,...Buffer.from('user')]);
 const data=Buffer.from([180,120,18,server.length,...server,24,1]);const config=decodeResponse(data);
 assert.deepEqual(config.iceServers,[{urls:'turn:test',credential:'secret',username:'user'}]);
 assert.deepEqual(capabilities(config),{voice:true,video:false,stun:false,turn:true,providerVerified:false});
 assert.ok(!JSON.stringify(capabilities(config)).includes('secret'));
});
test('accept/candidate/ringing/leave encoding and defaults',()=>{
 for(const action of [900,902,905])assert.equal(encodeRequest(action,auth).readUInt16LE(),action);
 assert.equal(encodeRequest(903,auth,{sdp:'v=0\r\n'}).readUInt16LE(),903);
 assert.equal(encodeRequest(904,auth,{candidate:'candidate:fixture',mid:'audio',lineIndex:0}).readUInt16LE(),904);
 assert.deepEqual(decodeResponse(Buffer.from([184,120])),{action:30904,id:'',timestamp:0,candidate:'',mid:'',lineIndex:0});
});
test('bounded parser rejects truncation, oversized packets, invalid UTF8/types and duplicate scalars',()=>{
 for(const data of [Buffer.alloc(0),Buffer.alloc(MAX_FRAME+1),Buffer.from([181,120,34,10]),Buffer.from([181,120,34,1,255]),Buffer.from([181,120,16,1,16,2]),Buffer.from([181,120,16,...Array(10).fill(255)]),Buffer.from([181,120,0]),Buffer.from([181,120,19])])assert.throws(()=>decodeResponse(data),/Invalid iGap signaling frame/);
 for(const peerId of [0,-1,2**53,1n<<64n])assert.throws(()=>encodeRequest(901,auth,{peerId,sdp:'x'}));
 assert.throws(()=>encodeRequest(901,auth,{peerId:1,sdp:'x'.repeat(MAX_FRAME)}));assert.throws(()=>encodeRequest(903,{id:'x',token:''},{sdp:'x'}));
 assert.throws(()=>encodeRequest(904,auth,{candidate:'x',mid:'0',lineIndex:-1}));
});
test('valid unknown fields are skipped and malformed input errors never echo secrets',()=>{
 const data=Buffer.from([183,120,0x51,...Array(8).fill(0),0x5d,0,0,0,0,0x62,3,1,2,3]);assert.equal(decodeResponse(data).action,30903);
 try{decodeResponse(Buffer.concat([Buffer.from([181,120,34,255]),Buffer.from('secret-token')]));assert.fail();}catch(e){assert.equal(e.message,'Invalid iGap signaling frame');}
});
test('public greeting inspection returns metadata without the public key or server node name',()=>{
 const key=Buffer.from('-----BEGIN PUBLIC KEY-----fixture');const result=inspectGreeting(Buffer.from([49,117,18,key.length,...key,24,32,32,60,42,4,110,111,100,101]));
 assert.deepEqual(result,{action:30001,publicKeyPresent:true,symmetricKeyLength:32,heartbeatSeconds:60,providerVerified:false});
 assert.ok(!JSON.stringify(result).includes('fixture'));assert.ok(!JSON.stringify(result).includes('node'));assert.throws(()=>inspectGreeting(Buffer.from([50,117])));
});
test('bounded deterministic malformed-input sweep always returns or rejects without leaked data',()=>{
 let seed=0x51c0ffee;for(let sample=0;sample<2048;sample++){
  const bytes=Buffer.alloc(2+(sample%127));bytes.writeUInt16LE(30900+sample%6);
  for(let i=2;i<bytes.length;i++){seed=(Math.imul(seed,1664525)+1013904223)>>>0;bytes[i]=seed>>>24;}
  try{decodeResponse(bytes);}catch(e){assert.equal(e.message,'Invalid iGap signaling frame');}
 }
});
