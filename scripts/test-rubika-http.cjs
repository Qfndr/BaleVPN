const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {HttpClient,endpoint,DISCOVERY}=require('../experiments/rubika/http-client.cjs'),wire=require('../experiments/rubika/wire.cjs');
const tmp='abcdefghijklmnopqrstuvwxyzabcdef',auth='abcdefghijklmnopqrstuvwxyz012345',guid='u0'+'a'.repeat(32);
const response=(data,key=tmp)=>new Response(JSON.stringify({data_enc:wire.encrypt({status:'OK',data},key)}));
test('anonymous DC discovery sends no session and cannot select non-provider or credential-bearing destinations',async()=>{
 const seen=[],client=new HttpClient({temporarySession:tmp,fetchImpl:async(url,o)=>{seen.push({url,o});return new Response(JSON.stringify({status:'OK',data:{default_api_urls:['https://messengerg2c1.iranlms.ir/']}}));}});
 assert.deepEqual(await client.discover(),{apiServerSelected:true});assert.equal(seen.length,1);assert.equal(seen[0].url,DISCOVERY);
 const body=JSON.parse(seen[0].o.body);assert.equal(body.method,'getDCs');assert.equal(body.api_version,'4');assert.equal(body.auth,undefined);assert.equal(body.tmp_session,undefined);assert.equal(body.sign,undefined);
 assert.equal(seen[0].o.redirect,'error');client.close();
 for(const value of ['http://messengerg2c1.iranlms.ir/','https://iranlms.ir.attacker.invalid/','https://user:password@messengerg2c1.iranlms.ir/',
  'https://messengerg2c1.iranlms.ir:444/','https://messengerg2c1.iranlms.ir/?auth=secret','https://messengerg2c1.iranlms.ir/path','https://127.0.0.1/'])assert.throws(()=>endpoint(value));
});
test('sendCode and signIn use separate temporary service framing without account auth or signature',async()=>{
 const identity=await wire.createIdentity(),seen=[];
 const client=new HttpClient({temporarySession:tmp,fetchImpl:async(url,o)=>{const body=JSON.parse(o.body),payload=wire.decrypt(body.data_enc,tmp);seen.push({url,body,payload});
  assert.equal(body.tmp_session,tmp);assert.equal(body.auth,undefined);assert.equal(body.sign,undefined);assert.equal(body.api_version,'6');assert.equal(o.headers['content-type'],'text/plain');
  if(payload.method==='sendCode')return response({status:'OK',phone_code_hash:'fixture-hash',code_digits_count:6,send_type:'SMS'});
  assert.equal(payload.input.public_key,wire.publicKeyField(identity.publicKey));
  const encrypted=crypto.publicEncrypt({key:identity.publicKey,padding:crypto.constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha1'},Buffer.from(auth)).toString('base64');
  return response({status:'OK',auth:encrypted,user:{user_guid:guid}});
 }});
 assert.equal((await client.request('sendCode',{phone_number:'989120000001',send_type:'SMS'})).status,'OK');
 const result=await client.request('signIn',{phone_number:'989120000001',phone_code_hash:'fixture-hash',phone_code:'123456',public_key:wire.publicKeyField(identity.publicKey)});
 assert.equal(wire.decryptAuth(result.auth,identity.privateKey),auth);assert.equal(seen.length,2);client.close();
});
test('authenticated v6 requests sign ciphertext and keep two accounts keys independent',async()=>{
 for(const token of [auth,'012345abcdefghijklmnopqrstuvwxyz']){
  const identity=await wire.createIdentity();let count=0;
  const client=new HttpClient({fetchImpl:async(url,o)=>{count++;const body=JSON.parse(o.body);assert.equal(body.auth,wire.transform(token));assert.equal(body.tmp_session,undefined);
   assert.equal(crypto.verify('RSA-SHA256',Buffer.from(body.data_enc),identity.publicKey,Buffer.from(body.sign,'base64')),true);
   assert.equal(o.body.includes(identity.privateKey),false);const payload=wire.decrypt(body.data_enc,token);assert.equal(payload.input.user_guid,guid);
   return response({user:{user_guid:guid}},token);
  }});
  const value=await client.request('getUserInfo',{user_guid:guid},{credentials:{provider:'rubika',auth:token,privateKey:identity.privateKey}});
  assert.equal(value.user.user_guid,guid);assert.equal(count,1);client.close();
 }
});
test('invalid method, input, cross-provider credentials and plaintext success cannot send or establish an account response',async()=>{
 let count=0;const client=new HttpClient({fetchImpl:async()=>{count++;return new Response(JSON.stringify({status:'OK',data:{auth:'fixture-must-not-be-trusted'}}));}});
 await assert.rejects(client.request('requestCall',{}),/invalid_request/);
 await assert.rejects(client.request('sendCode',{phone_number:'+989120000001',send_type:'SMS'}),/invalid_request/);
 await assert.rejects(client.request('sendCode',{phone_number:'989120000001',send_type:'SMS'},{credentials:{provider:'bale'}}),/invalid_credentials/);
 await assert.rejects(client.request('logout',{}, {credentials:{provider:'nasim',auth}}),/invalid_credentials/);assert.equal(count,0);
 await assert.rejects(client.request('sendCode',{phone_number:'989120000001',send_type:'SMS'}),/invalid_encrypted_response/);assert.equal(count,1);client.close();
});
test('only fixed error codes survive raw response errors; a response never triggers auto-registration or retries',async()=>{
 let count=0;const client=new HttpClient({fetchImpl:async()=>{count++;return new Response(JSON.stringify({status:'ERROR_ACTION',status_det:'INVALID_AUTH',message:'fixture-private-error'}));}});
 await assert.rejects(client.request('sendCode',{phone_number:'989120000001',send_type:'SMS'}),e=>e.reason==='not_authorized'&&e.serviceCode==='INVALID_AUTH'&&!e.message.includes('fixture-private-error'));
 assert.equal(count,1);client.close();
});
test('closing cancels outstanding I/O, prevents late discovery selection and rejects concurrent requests',async()=>{
 let release,signal;const client=new HttpClient({fetchImpl:async(url,o)=>{signal=o.signal;return new Promise(r=>{release=r;});}});
 const pending=client.discover();await assert.rejects(client.discover(),/account_busy/);client.close();assert.equal(signal.aborted,true);
 release(new Response(JSON.stringify({status:'OK',data:{default_api_urls:['https://messengerg2c1.iranlms.ir/']}})));await assert.rejects(pending,/closed/);
 await assert.rejects(client.request('sendCode',{phone_number:'989120000001',send_type:'SMS'}),/closed/);
});
test('oversized response bodies and HTTP rate limits terminate once without leaking response content',async()=>{
 let cancelled=false;const client=new HttpClient({fetchImpl:async()=>new Response(new ReadableStream({start(c){c.enqueue(new Uint8Array(512*1024+1));},cancel(){cancelled=true;}}))});
 await assert.rejects(client.discover(),/response_too_large/);assert.equal(cancelled,true);client.close();
 let count=0;const limited=new HttpClient({fetchImpl:async()=>{count++;return new Response('fixture-private-rate-limit',{status:429});}});
 await assert.rejects(limited.discover(),e=>e.reason==='rate_limited'&&e.statusCode===429);assert.equal(count,1);limited.close();
});
