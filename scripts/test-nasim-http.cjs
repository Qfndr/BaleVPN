const {test} = require('node:test'), assert = require('node:assert/strict');
const {HttpClient} = require('../experiments/nasim/http-client.cjs');
const wire = require('../experiments/nasim/wire.cjs');
const deviceId = 'web.fixture-account-device.123456';
const token = 'fixture-account-token-private';
function response(data,secret=deviceId,{status=200,headers={}}={}) {
  return new Response(wire.encrypt(data,secret),{status,headers});
}

test('current Nasim auth transport encrypts MessagePack and fixes endpoint, headers, redirect policy and device binding',async()=>{
  const calls=[],client=new HttpClient({deviceId,fetchImpl:async(url,options)=>{
    calls.push({url,options});assert.equal(url,'https://core.gaplication.com/otp/sendByMobile');
    assert.equal(options.method,'POST');assert.equal(options.redirect,'error');
    assert.equal(options.headers.project,'nasimrezvan');assert.equal(options.headers.duid,deviceId);
    assert.equal(options.headers.token,undefined);assert.equal(options.headers['api-version'],'v2.8');
    assert.deepEqual(JSON.parse(JSON.stringify(wire.decrypt(options.body,deviceId))),{countryCode:'+98',mobile:'0000000000',subsystem:'client'});
    return response({status:'success',data:{sentOTPDescription:'fixture-only'}});
  }});
  assert.equal((await client.request('/otp/sendByMobile',{countryCode:'+98',mobile:'0000000000',subsystem:'client'})).sentOTPDescription,'fixture-only');
  assert.equal(calls.length,1);assert.ok(calls[0].options.body.every(byte=>byte===0),'temporary request ciphertext is released after completion');
  client.close();
});

test('authenticated and verified-token requests use only their own account key and never return raw service error text',async()=>{
  const client=new HttpClient({deviceId,fetchImpl:async(url,options)=>{
    assert.equal(options.headers.token,token);assert.equal(options.headers.clientid,'fixture-client');
    assert.equal(options.headers['verified-token'],'fixture-verified-token');
    wire.decrypt(options.body,token);
    return response({status:'error',error:{type:'inCorrectOTP',message:token,private:deviceId}},token,{status:429,headers:{'retry-after':'20'}});
  }});
  await assert.rejects(client.request('/mxb/user/status',{}, {token,clientId:'fixture-client',verifiedToken:'fixture-verified-token'}),error=>{
    assert.equal(error.reason,'rejected');assert.equal(error.serviceType,'inCorrectOTP');assert.equal(error.waitSeconds,20);
    assert.ok(!JSON.stringify(error).includes(token));assert.ok(!error.message.includes(token));return true;
  });client.close();
});

test('malformed, plaintext, oversized and wrong-key responses cannot be accepted as successful login',async()=>{
  for(const answer of [new Response('plaintext error',{status:403}),response({status:'success',data:{}},'wrong-account-token-fixture'),
    new Response(new Uint8Array(256*1024+29)),new Response('x',{headers:{'content-length':'9999999'}})]){
    const client=new HttpClient({deviceId,fetchImpl:async()=>answer});await assert.rejects(client.request('/mxb/user/status'));
    client.close();
  }
});

test('unlisted destinations, header injection and invalid device identifiers cannot send any request',async()=>{
  let sent=0;const client=new HttpClient({deviceId,fetchImpl:async()=>{sent++;throw new Error();}});
  for(const [path,options]of [['https://foreign.invalid/',{}],['/unknown',{}],['/user/login',{token:'fixture-token\r\nInjected:x'}],
    ['/user/login',{verifiedToken:'short'}],['/user/login',{clientId:'bad\nvalue'}]])await assert.rejects(client.request(path,{},options));
  assert.equal(sent,0);assert.throws(()=>new HttpClient({deviceId:'../other-account'}));client.close();
});

test('timeout and close cancel a single pending operation without retry or a late successful reply',async()=>{
  let count=0;const fetchImpl=async(url,{signal})=>{count++;return new Promise((resolve,reject)=>signal.addEventListener('abort',()=>reject(new Error('private raw failure')),{once:true}));};
  const client=new HttpClient({deviceId,fetchImpl});await assert.rejects(client.request('/mxb/user/status',{}, {timeout:5}),/timeout/);
  assert.equal(count,1);
  const pending=client.request('/mxb/user/status');await assert.rejects(client.request('/mxb/user/status'),/account_busy/);
  client.close();await assert.rejects(pending,/closed/);assert.equal(count,2);
});

test('explicit legacy logout uses the official PUT route and accepts bounded JSON or AES-CBC acknowledgments',async()=>{
  const crypto=require('node:crypto'),logoutToken='fixture-logout-session-token-32-bytes-long';
  const iv=Buffer.from('0123456789abcdef'),cipher=crypto.createCipheriv('aes-256-cbc',Buffer.from(logoutToken).subarray(0,32),iv);
  const encrypted=iv.toString()+Buffer.concat([cipher.update(JSON.stringify({status:'success'})),cipher.final()]).toString('base64');
  for(const payload of [JSON.stringify({status:'success'}),encrypted]){
    const client=new HttpClient({deviceId,fetchImpl:async(url,options)=>{
      assert.equal(url,'https://core.gap.im/v1/user/logout.json');assert.equal(options.method,'PUT');assert.equal(options.body,'');
      assert.equal(options.headers['X-Token'],logoutToken);assert.equal(options.headers.project,'nasimrezvan');assert.equal(options.redirect,'error');
      return new Response(payload,{status:200});
    }});
    assert.deepEqual(await client.logout({token:logoutToken}),{loggedOut:true});client.close();
  }
  for(const payload of ['broken',JSON.stringify({status:'error',message:logoutToken}),encrypted.slice(1)]){
    const client=new HttpClient({deviceId,fetchImpl:async()=>new Response(payload)});
    await assert.rejects(client.logout({token:logoutToken}),error=>{assert.equal(error.reason,'invalid_logout_response');assert.ok(!JSON.stringify(error).includes(logoutToken));return true;});client.close();
  }
});
