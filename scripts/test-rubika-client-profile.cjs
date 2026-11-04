'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const wire=require('../experiments/rubika/wire.cjs'),profiles=require('../experiments/rubika/client-profile.cjs');
const {HttpClient}=require('../experiments/rubika/http-client.cjs'),{AuthSession}=require('../experiments/rubika/auth-session.cjs');
const {CallClient}=require('../experiments/rubika/call-client.cjs'),{CallPrivacy}=require('../experiments/rubika/call-privacy.cjs');
const reference=require('./fixtures/rubika-android-public-key.json');
const phone={country:'IR',nationalNumber:'9120000001',internationalNumber:'+989120000001'},tmp='abcdefghijklmnopqrstuvwxyzabcdef',auth='abcdefghijklmnopqrstuvwxyz012345',uid='fixture_self_01';
function transport(seen){return options=>new HttpClient({...options,temporarySession:tmp,updatesFactory:null,fetchImpl:async(_url,o)=>{
 const body=JSON.parse(o.body);if(body.method==='getDCs'){seen.push({method:'getDCs',client:body.client,headers:o.headers});return new Response(JSON.stringify({status:'OK',data:{default_api_urls:['https://messengerg2c1.iranlms.ir/']}}));}
 const session=body.tmp_session?tmp:auth,payload=wire.decrypt(body.data_enc,session,options.protocolProfile||'web');seen.push({...payload,body,headers:o.headers});let data={};
 if(payload.method==='sendCode')data={status:'OK',phone_code_hash:'fixture-hash',code_digits_count:6,send_type:'SMS'};
 if(payload.method==='signIn')data={status:'OK',user:{user_guid:uid},auth:crypto.publicEncrypt({key:Buffer.from(wire.transform(payload.input.public_key),'base64').toString(),padding:crypto.constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha1'},Buffer.from(auth)).toString('base64')};
 if(payload.method==='getUserInfo')data={user:{user_guid:uid}};
 if(payload.method==='getPrivacySetting')data={privacy_setting:{can_called_by:'Everybody'}};
 if(payload.method==='getSignalingData')data={data_list:[]};
 return new Response(JSON.stringify({data_enc:wire.encrypt({status:'OK',data},session,options.protocolProfile||'web')}));
 }});}
test('Android public key bytes match a fixed independent Base64.DEFAULT reference and preserve the Web format',()=>{
 assert.equal(wire.publicKeyField(reference.publicKey,profiles.ANDROID),reference.androidField);
 const pem=Buffer.from(wire.transform(reference.androidField),'base64').toString();assert.ok(pem.startsWith('-----BEGIN PUBLIC KEY-----\r\n'));assert.ok(pem.endsWith('\n-----END PUBLIC KEY-----'));
 assert.ok(pem.split('\n').slice(1,-2).every(line=>line.length===76));
 assert.equal(wire.publicKeyField(reference.publicKey),wire.transform(Buffer.from(reference.publicKey).toString('base64')));
 assert.throws(()=>wire.publicKeyField(reference.publicKey,'unknown'),/invalid_identity/);
});
test('Android ciphertext and signatures preserve DEFAULT line breaks as signed bytes without relaxing Web parsing',async()=>{
 const value={text:'آزمایش '+'.'.repeat(200)},unwrapped=wire.encrypt(value,auth),encoded=wire.encrypt(value,auth,profiles.ANDROID);
 assert.equal(encoded,unwrapped.match(/.{1,76}/g).join('\n')+'\n');assert.deepEqual(wire.decrypt(encoded,auth,profiles.ANDROID),value);assert.deepEqual(wire.decrypt(unwrapped,auth,profiles.ANDROID),value);assert.throws(()=>wire.decrypt(encoded,auth));
 for(const malformed of [encoded.replace(/\n/g,'\r\n'),encoded.replace('\n',' \n'),encoded.slice(0,-1)+'\n\n',encoded.slice(0,30)+'\n'+encoded.slice(30)])assert.throws(()=>wire.decrypt(malformed,auth,profiles.ANDROID));
 const id=await wire.createIdentity(),signature=wire.signature(encoded,id.privateKey,profiles.ANDROID);assert.ok(signature.endsWith('\n'));assert.equal(crypto.verify('RSA-SHA256',Buffer.from(encoded),id.publicKey,Buffer.from(signature,'base64')),true);assert.equal(crypto.verify('RSA-SHA256',Buffer.from(unwrapped),id.publicKey,Buffer.from(signature,'base64')),false);
});
test('explicit fresh Android login retains its protocol, key and truthful device metadata across registration and restoration',async()=>{
 const seen=[],saved=[],session=new AuthSession({createClient:transport(seen),saveSession:async r=>saved.push(structuredClone(r))});
 await session.start(phone,{protocolProfile:profiles.ANDROID});await session.verify('123456');assert.equal(session.state.signedIn,true);assert.equal(session.state.protocolProfile,profiles.ANDROID);
 const record=session.exportSession();assert.equal(record.profile.protocolProfile,profiles.ANDROID);assert.match(record.profile.deviceModel,/^Desktop [a-f0-9]{12}$/);assert.equal(saved[0].registration,'required');
 for(const request of seen){assert.equal(request.client.platform,'Android');assert.equal(request.client.package,'app.rbmain.a');assert.equal(request.client.app_version,'4.1.1');assert.equal(request.headers.origin,undefined);if(request.method!=='getDCs'){assert.equal(request.is_background,false);assert.equal(request.body.api_version,6);}}
 const registered=seen.find(r=>r.method==='registerDevice');assert.equal(registered.input.token_type,'Firebase');assert.equal(registered.input.app_version,'MA_4.1.1');assert.equal(registered.input.is_multi_account,false);assert.equal(registered.input.ads_id,undefined);
 for(const request of seen.filter(r=>r.body?.sign))assert.equal(crypto.verify('RSA-SHA256',Buffer.from(request.body.data_enc),record.publicKey,Buffer.from(request.body.sign,'base64')),true);
 const snapshot=JSON.stringify(record),count=seen.length;await assert.rejects(session.start(phone,{protocolProfile:profiles.WEB}),/already_signed_in/);assert.equal(JSON.stringify(session.exportSession()),snapshot);assert.equal(seen.length,count);
 session.close();seen.length=0;const restored=new AuthSession({createClient:transport(seen),createIdentity:()=>{throw Error('No replacement key');}});await restored.restore(record);assert.deepEqual(seen.map(r=>r.method),['getDCs','getUserInfo']);assert.deepEqual(restored.exportSession(),record);restored.close();
});
test('legacy Web records stay Web and unknown profile selections fail before network',async()=>{
 const seen=[],s=new AuthSession({createClient:transport(seen)});await assert.rejects(s.start(phone,{protocolProfile:'unknown'}),/invalid_client_profile/);assert.equal(seen.length,0);
 await s.start(phone);await s.verify('123456');const record=s.exportSession();delete record.profile.protocolProfile;s.close();seen.length=0;
 const restored=new AuthSession({createClient:transport(seen)});await restored.restore(record);assert.equal(restored.state.protocolProfile,'web');assert.equal(Object.hasOwn(restored.exportSession().profile,'protocolProfile'),false);assert.ok(seen.every(r=>r.client.platform==='Web'));restored.close();
});
test('Android profile is bound through call and privacy clients; Web transport cannot use Android credentials',async()=>{
 const seen=[],session=new AuthSession({createClient:transport(seen)});await session.start(phone,{protocolProfile:profiles.ANDROID});await session.verify('123456');seen.length=0;
 const client=new CallClient(session,{createClient:transport(seen)});await client.start();await client.request('getSignalingData',{call_id:'fixture_call_01'});assert.ok(seen.every(r=>r.client.platform==='Android'));assert.equal(seen.at(-1).is_background,false);client.close();seen.length=0;
 const privacy=new CallPrivacy(session,{createClient:transport(seen)});assert.equal((await privacy.allowEveryone()).verified,true);assert.ok(seen.every(r=>r.client.platform==='Android'));privacy.close();
 const web=new HttpClient({fetchImpl:()=>{throw Error('Must not send');}});await assert.rejects(web.request('getUserInfo',{user_guid:uid},{credentials:session.exportSession()}),/invalid_credentials/);web.close();session.close();
});
test('profile replacement retires call ownership and cancels late privacy discovery before protected requests',async()=>{
 const seen=[],session=new AuthSession({createClient:transport(seen)});await session.start(phone,{protocolProfile:profiles.ANDROID});await session.verify('123456');const record=session.exportSession();
 const account={state:{provider:'rubika',signedIn:true,selfConfirmed:true,userId:uid},exportSession:()=>structuredClone(record)};
 const call=new CallClient(account,{createClient:transport(seen)});await call.start();record.profile.protocolProfile='web';const count=seen.length;await assert.rejects(call.request('getSignalingData',{call_id:'fixture_call_01'}),/account_binding_changed/);assert.equal(seen.length,count);assert.equal(call.state.ready,false);call.close();
 record.profile.protocolProfile=profiles.ANDROID;let requests=0;
 const privacy=new CallPrivacy(account,{createClient:options=>{assert.equal(options.protocolProfile,profiles.ANDROID);return {async discover(){record.profile.protocolProfile='web';},async request(){requests++;throw Error('Must not send');},close(){}};}});
 await assert.rejects(privacy.read(),/account_binding_changed/);assert.equal(requests,0);privacy.close();session.close();
});

test('legacy branded registration names are projected only in serialized outbound payload without changing saved identity',async()=>{
 const identity=await wire.createIdentity(),deviceHash='0123456789abcdef0123456789abcdef';
 const labels=['BaleVPN','BaleVPNDesktop','BaleVPN Desktop','BaleVPN Desktop abcdef012345','BaleVPN Provider Lab','BaleVPN Provider Lab (desktop)','ProviderLab','Provider Lab','Provider Lab (desktop)'];
 for(const mode of [profiles.WEB,profiles.ANDROID])for(const label of labels){
  const record={provider:'rubika',userId:uid,auth,...identity,profile:{protocolProfile:mode,deviceHash,deviceModel:label,systemVersion:'fixture-system'}};
  const before=JSON.stringify(record);let sent=0;
  const client=new HttpClient({protocolProfile:mode,updatesFactory:null,fetchImpl:async(_url,options)=>{
   sent++;const body=JSON.parse(options.body),decoded=wire.decrypt(body.data_enc,auth,mode);
   assert.equal(decoded.method,'registerDevice');assert.equal(decoded.input.device_model,'Desktop 0123456789ab');
   assert.equal(decoded.input.device_hash,deviceHash);assert.equal(decoded.input.system_version,'fixture-system');
   assert.equal(decoded.client.platform,mode===profiles.ANDROID?'Android':'Web');
   assert.equal(decoded.client.package,mode===profiles.ANDROID?'app.rbmain.a':'web.rubika.ir');
   assert.ok(!JSON.stringify(decoded).includes('BaleVPN'));assert.ok(!JSON.stringify(decoded).includes('Provider Lab'));
   return new Response(JSON.stringify({data_enc:wire.encrypt({status:'OK',data:{}},auth,mode)}));
  }});
  try{
   const first=profiles.registration(mode,record.profile,'fa'),second=profiles.registration(mode,record.profile,'fa');
   assert.deepEqual(first,second,'outgoing label must be stable, not randomized per request');
   await client.request('registerDevice',first,{credentials:record});assert.equal(sent,1);assert.equal(JSON.stringify(record),before);
  }finally{client.close();}
 }
});

test('neutral and custom registration names remain unchanged while malformed legacy identity cannot be substituted',()=>{
 const hash='abcdef0123456789abcdef0123456789';
 for(const label of ['Desktop abcdef012345','Pixel 9','Personal desktop','My BaleVPN-compatible client','BaleVPN Desktop custom-name']){
  const device={deviceHash:hash,deviceModel:label,systemVersion:'fixture-system'},before=JSON.stringify(device);
  assert.equal(profiles.registration(profiles.ANDROID,device,'fa').device_model,label);assert.equal(JSON.stringify(device),before);
 }
 assert.throws(()=>profiles.registration(profiles.WEB,{deviceModel:'BaleVPN',deviceHash:'invalid',systemVersion:'fixture-system'},'fa'),/invalid_client_profile/);
});
