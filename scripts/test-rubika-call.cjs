const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const codec=require('../experiments/rubika/call-codec.cjs'),wire=require('../experiments/rubika/wire.cjs');
const {HttpClient}=require('../experiments/rubika/http-client.cjs');
const call_id='fixture_call_01',user_guid='fixture_user_01',profile={min_layer:65,max_layer:92,library_versions:['9.0.0']}; // Synthetic profile; no live layer negotiation claimed.
const inputs={requestCall:{call_type:'Voice',user_guid,...profile},receivedCall:{call_id},acceptCall:{call_id,...profile},
 discardCall:{call_id,duration:5,reason:'Hangup'},sendSignalingData:{call_id,data:Buffer.from('encrypted fixture').toString('base64')},getSignalingData:{call_id},callStarted:{call_id}};
test('seven typed voice methods use exact observed names and reject SIP, video, guessed method names or extra fields',()=>{
 assert.equal(codec.METHODS.length,7);
 for(const [method,input]of Object.entries(inputs)){assert.equal(codec.validateInput(method,input),input);assert.throws(()=>codec.validateInput(method,{...input,receiver_phone_number:'fixture'}));}
 for(const v of [null,{}, {...inputs.requestCall,call_type:'Video'},{...inputs.requestCall,min_layer:0},
  {...inputs.requestCall,max_layer:64},{...inputs.requestCall,library_versions:['4.0.0']},
  {...inputs.requestCall,library_versions:['9.0.0','9.0.0']},{...inputs.requestCall,user_guid:'bad\nidentifier'}])assert.throws(()=>codec.validateInput('requestCall',v));
 assert.throws(()=>codec.validateInput('sendSignalData',inputs.sendSignalingData));
 assert.throws(()=>codec.validateInput('discardCall',{...inputs.discardCall,duration:-1}));
 assert.throws(()=>codec.validateInput('discardCall',{...inputs.discardCall,reason:'hangup'}));
});
test('Android DEFAULT base64 whitespace is decoded, output is canonical, malformed padding and oversized data fail closed',()=>{
 const bytes=crypto.randomBytes(codec.MAX_SIGNAL);assert.deepEqual(codec.decodeSignal(codec.encodeSignal(bytes)),bytes);
 assert.deepEqual(codec.decodeSignal(' Zm9v\r\nYmFy\t '),Buffer.from('foobar'));
 for(const value of ['',null,'Zg','Zh==','Zg===','Zg==\u00a0','-_==','====',Buffer.alloc(codec.MAX_SIGNAL+1).toString('base64')])assert.throws(()=>codec.decodeSignal(value));
 assert.throws(()=>codec.encodeSignal(Buffer.alloc(0)));
 assert.throws(()=>codec.validateInput('sendSignalingData',{call_id,data:' Zg=='}));
});
test('poll response accepts only bounded ordered string arrays and never mixes call envelope objects into bytes',()=>{
 assert.deepEqual(codec.decodeSignalBatch({data_list:['YQ==','Yg==']}),[Buffer.from('a'),Buffer.from('b')]);
 assert.deepEqual(codec.decodeSignalBatch({data_list:[]}),[]);
 for(const value of [{}, {data_list:[{call_id,data:'YQ=='}]}, {data_list:['YQ=='],call_id},
  {data_list:Array(codec.MAX_BATCH+1).fill('YQ==')},{data_list:[Buffer.alloc(codec.MAX_SIGNAL).toString('base64'),'YQ==']}])assert.throws(()=>codec.decodeSignalBatch(value));
});
test('call RPCs are authenticated, signed, encrypted and sent once with honest Web client metadata',async()=>{
 const identity=await wire.createIdentity(),auth='abcdefghijklmnopqrstuvwxyz012345',seen=[];
 const credentials={provider:'rubika',auth,privateKey:identity.privateKey};
 const client=new HttpClient({fetchImpl:async(url,options)=>{
  const body=JSON.parse(options.body),payload=wire.decrypt(body.data_enc,auth);seen.push(payload.method);
  assert.equal(crypto.verify('RSA-SHA256',Buffer.from(body.data_enc),identity.publicKey,Buffer.from(body.sign,'base64')),true);
  assert.equal(body.tmp_session,undefined);assert.equal(payload.client.platform,'Web');assert.equal(payload.client.package,'web.rubika.ir');
  assert.deepEqual(payload.input,inputs[payload.method]);
  return new Response(JSON.stringify({data_enc:wire.encrypt({status:'OK',data:payload.method==='getSignalingData'?{data_list:[]}:{}},auth)}));
 }});
 for(const [method,input]of Object.entries(inputs))await client.request(method,input,{credentials});
 assert.deepEqual(seen,codec.METHODS);client.close();
});
test('missing or cross-provider call credentials and malformed payloads never reach network',async()=>{
 let sent=0;const client=new HttpClient({fetchImpl:async()=>{sent++;throw Error('private fixture');}});
 for(const method of codec.METHODS){await assert.rejects(client.request(method,inputs[method]),/invalid_credentials/);
  await assert.rejects(client.request(method,inputs[method],{credentials:{provider:'eitaa'}}),/invalid_credentials/);}
 await assert.rejects(client.request('requestCall',{...inputs.requestCall,key:'private'}),/invalid_request/);assert.equal(sent,0);client.close();
});
test('server call refusal remains a fixed private-safe error, without retries or automatic call escalation',async()=>{
 const identity=await wire.createIdentity(),auth='abcdefghijklmnopqrstuvwxyz012345';let sent=0;
 const client=new HttpClient({fetchImpl:async()=>{sent++;return new Response(JSON.stringify({data_enc:wire.encrypt({status:'ERROR_ACTION',status_det:'ACCESS_DENIED',message:'private call key'},auth)}));}});
 await assert.rejects(client.request('requestCall',inputs.requestCall,{credentials:{provider:'rubika',auth,privateKey:identity.privateKey}}),e=>e.reason==='service_rejected'&&!e.message.includes('private'));
 assert.equal(sent,1);client.close();
});
