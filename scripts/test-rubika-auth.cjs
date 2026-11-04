const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {AuthSession}=require('../experiments/rubika/auth-session.cjs'),{ApiError}=require('../experiments/rubika/http-client.cjs'),wire=require('../experiments/rubika/wire.cjs');
const phone={country:'IR',nationalNumber:'9120000001',internationalNumber:'+989120000001'},auth='abcdefghijklmnopqrstuvwxyz012345',guid='u0'+'a'.repeat(32);
const codeReply={status:'OK',phone_code_hash:'fixture-private-code-hash',code_digits_count:6,send_type:'SMS'};
function fixture({hook,save,createIdentity}={}){
 const calls=[],saved=[],clients=[],events=[];let generated=0;
 const options={createIdentity:async()=>{generated++;return createIdentity?createIdentity():wire.createIdentity();},
  saveSession:async record=>{events.push('save');if(save)await save(record);saved.push(structuredClone(record));},
  createClient:()=>{const client={closed:false,async discover(){calls.push({method:'getDCs'});return {apiServerSelected:true};},
   async request(method,input,options){calls.push({method,input,options});events.push(method);
    if(hook){const result=await hook(method,input,options,client);if(result!==undefined)return result;}
    if(method==='sendCode')return codeReply;
    if(method==='signIn'){const pem=Buffer.from(wire.transform(input.public_key),'base64').toString();return {status:'OK',user:{user_guid:guid},
     auth:crypto.publicEncrypt({key:pem,padding:crypto.constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha1'},Buffer.from(auth)).toString('base64')};}
    if(method==='registerDevice'||method==='logout')return {};
    if(method==='getUserInfo')return {user:{user_guid:guid}};
    throw Error('Unexpected fixture method');
   },close(){this.closed=true;}};clients.push(client);return client;}};
 return {session:new AuthSession(options),options,calls,saved,events,clients,generated:()=>generated};
}
async function login(f){await f.session.start(phone);await f.session.verify('123456');}
test('login saves native auth before device registration, confirms self and exposes only safe metadata',async()=>{
 const f=fixture();await login(f);assert.equal(f.session.state.signedIn,true);assert.equal(f.session.state.selfConfirmed,true);
 assert.deepEqual(f.calls.map(c=>c.method),['getDCs','sendCode','signIn','registerDevice','getUserInfo']);
 assert.ok(f.events.indexOf('save')<f.events.indexOf('registerDevice'));assert.equal(f.saved[0].registration,'required');assert.equal(f.saved.at(-1).registration,'confirmed');
 const record=f.session.exportSession();assert.equal(record.auth,auth);assert.equal(record.profile.deviceHash.length,32);
 const register=f.calls.find(c=>c.method==='registerDevice');assert.equal(register.input.device_hash,record.profile.deviceHash);assert.equal(register.input.device_model,record.profile.deviceModel);assert.match(record.profile.deviceModel,/^Desktop [a-f0-9]{12}$/);
 for(const value of [auth,record.privateKey,phone.internationalNumber,'fixture-private-code-hash'])assert.ok(!JSON.stringify(f.session.state).includes(value));
 record.profile.deviceHash='changed';assert.notEqual(f.session.exportSession().profile.deviceHash,'changed');f.session.close();
});
test('password challenge does not pretend a code was sent and correct password obtains a fresh cooldown',async()=>{
 const f=fixture({hook:async(method,input)=>{if(method==='sendCode')return input.pass_key==='lab-1234-رمز'?codeReply:input.pass_key?{status:'InvalidPassKey'}:{status:'SendPassKey',hint_pass_key:'fixture hint',has_confirmed_recovery_email:true};}});
 await f.session.start(phone);assert.equal(f.session.state.stage,'password');assert.equal(f.session.state.delivery,null);
 await assert.rejects(f.session.password('wrong'),/invalid_password/);assert.equal(f.session.state.stage,'password');
 await f.session.password('lab-۱۲۳۴-رمز');assert.equal(f.session.state.stage,'code');assert.equal(f.session.state.retryAfter,60);
 await f.session.verify('123456');assert.equal(f.session.state.signedIn,true);assert.ok(!JSON.stringify(f.session.exportSession()).includes('lab-1234-رمز'));f.session.close();
});
test('service delivery channel, invalid digits and expired/used codes are explicit without another sign-in',async()=>{
 const f=fixture({hook:async(method)=>method==='sendCode'?{...codeReply,send_type:'Internal'}:method==='signIn'?{status:'CodeIsExpired'}:undefined});
 await f.session.start(phone);assert.equal(f.session.state.delivery,'Internal');await assert.rejects(f.session.verify('12345'),/invalid_code_format/);
 assert.equal(f.calls.filter(c=>c.method==='signIn').length,0);await assert.rejects(f.session.verify('123456'),/code_expired/);
 await assert.rejects(f.session.verify('123456'),/no_pending_code/);assert.equal(f.calls.filter(c=>c.method==='signIn').length,1);f.session.close();
});
test('a lost code request cannot be repeated immediately, and unsafe phone shapes never reach the network',async()=>{
 const f=fixture({hook:async(method)=>{if(method==='sendCode')throw new ApiError('timeout');}});
 await assert.rejects(f.session.start({...phone,nationalNumber:'09120000001'}),/invalid_phone/);assert.equal(f.calls.length,0);
 await assert.rejects(f.session.start(phone),/timeout/);await assert.rejects(f.session.start(phone),/cooldown/);assert.equal(f.calls.filter(c=>c.method==='sendCode').length,1);f.session.close();
});
test('stopping a pending code clears the login challenge but retains its cooldown',async()=>{
 const f=fixture();await f.session.start(phone);
 try{
  f.session.stop();
  assert.equal(f.session.state.stage,'idle');assert.equal(f.session.state.hasSession,false);
  assert.ok(f.session.state.retryAfter>0);
  await assert.rejects(f.session.verify('123456'),{reason:'no_pending_code'});
  await assert.rejects(f.session.start(phone,{protocolProfile:'android-4.1.1-compat'}),{reason:'cooldown'});
  assert.equal(f.calls.filter(call=>call.method==='sendCode').length,1);
 }finally{f.session.close();}
});
test('restoring an encrypted record reuses auth, RSA key and device hash without OTP or registration',async()=>{
 const f=fixture();await login(f);const record=f.session.exportSession();f.session.close();
 const restored=fixture({createIdentity:()=>{throw Error('New identity must not be created');}});await restored.session.restore(record);
 assert.deepEqual(restored.calls.map(c=>c.method),['getDCs','getUserInfo']);assert.equal(restored.generated(),0);assert.equal(restored.session.state.signedIn,true);
 assert.equal(restored.session.exportSession().privateKey,record.privateKey);assert.equal(restored.session.exportSession().profile.deviceHash,record.profile.deviceHash);restored.session.close();
});
test('stop between a protected response and confirmation cannot restore signed-in state',async()=>{
 const original=fixture();await login(original);const record=original.session.exportSession();original.session.close();
 let stopRan=false;
 const session=new AuthSession({createClient:()=>({async discover(){},async request(method){
  assert.equal(method,'getUserInfo');
  // The second microtask runs after the inner request guard, before its caller resumes.
  queueMicrotask(()=>queueMicrotask(()=>{session.stop();stopRan=true;}));
  return {user:{user_guid:guid}};
 },close(){}})});
 try{
  await assert.rejects(session.restore(record),{reason:'closed'});
  assert.equal(stopRan,true);
  assert.equal(session.state.stage,'stopped');
  assert.equal(session.state.signedIn,false);assert.equal(session.state.selfConfirmed,false);
  assert.deepEqual(session.exportSession(),record);
 }finally{session.close();}
});
test('uncertain registration retains auth and a later protected read does not automatically register again',async()=>{
 const f=fixture({hook:async(method)=>{if(method==='registerDevice')throw new ApiError('timeout');}});await f.session.start(phone);
 await assert.rejects(f.session.verify('123456'),/timeout/);assert.equal(f.session.state.hasSession,true);assert.equal(f.session.state.registration,'uncertain');assert.equal(f.saved.at(-1).auth,auth);
 const key=f.session.exportSession().privateKey;f.session.stop();await f.session.resume();assert.equal(f.session.state.signedIn,true);
 assert.equal(f.calls.filter(c=>c.method==='registerDevice').length,1);assert.equal(f.calls.filter(c=>c.method==='sendCode').length,1);assert.equal(f.session.exportSession().privateKey,key);f.session.close();
});
test('registration is retried only after an explicit service requirement and explicit user action',async()=>{
 let required=true;const f=fixture({hook:async(method)=>{if(method==='getUserInfo'&&required)throw new ApiError('registration_required');}});
 await f.session.start(phone);await assert.rejects(f.session.verify('123456'),/registration_required/);assert.equal(f.session.state.stage,'device_required');
 assert.equal(f.calls.filter(c=>c.method==='registerDevice').length,1);required=false;await f.session.register();
 assert.equal(f.calls.filter(c=>c.method==='registerDevice').length,2);assert.equal(f.calls.filter(c=>c.method==='signIn').length,1);f.session.close();
});

test('an explicit NOT_REGISTERED after a confirmed login clears stale confirmation but preserves the same session and device',async()=>{
 const f=fixture({hook:async method=>{if(method==='logout')throw new ApiError('registration_required',undefined,'NOT_REGISTERED');}});
 try{
  await login(f);const before=f.session.exportSession();assert.equal(f.session.state.signedIn,true);
  await assert.rejects(f.session.logout(),/registration_required/);
  const state=f.session.state,after=f.session.exportSession();assert.equal(state.signedIn,false);assert.equal(state.connected,false);assert.equal(state.selfConfirmed,false);
  assert.equal(state.stage,'device_required');assert.equal(state.registration,'required');assert.equal(state.hasSession,true);
  assert.deepEqual(after,{...before,registration:'required'});assert.equal(f.calls.filter(c=>c.method==='registerDevice').length,1);
  assert.deepEqual(f.calls.map(c=>c.method),['getDCs','sendCode','signIn','registerDevice','getUserInfo','logout']);
  assert.ok(!JSON.stringify(state).includes(before.auth));
 }finally{f.session.close();}
});

test('a method-specific access denial does not pretend the retained account session was globally revoked',async()=>{
 const f=fixture({hook:async method=>{if(method==='logout')throw new ApiError('access_denied',undefined,'INVALID_AUTH');}});
 try{await login(f);const before=f.session.exportSession();await assert.rejects(f.session.logout(),/access_denied/);
  assert.equal(f.session.state.signedIn,true);assert.equal(f.session.state.selfConfirmed,true);assert.deepEqual(f.session.exportSession(),before);
  assert.equal(f.calls.filter(c=>c.method==='registerDevice').length,1);
 }finally{f.session.close();}
});
test('failure to seal new auth halts device registration and keeps the auth available for recovery',async()=>{
 let fail=true;const f=fixture({save:async()=>{if(fail)throw Error('fixture disk error');}});await f.session.start(phone);
 await assert.rejects(f.session.verify('123456'),/session_save_failed/);assert.equal(f.session.state.hasSession,true);assert.equal(f.calls.some(c=>c.method==='registerDevice'),false);
 fail=false;await f.session.resume();assert.equal(f.session.state.signedIn,true);assert.equal(f.calls.filter(c=>c.method==='signIn').length,1);f.session.close();
});
test('mismatched self profile, cross-provider records and mismatched keys never establish a restored account',async()=>{
 const source=fixture();await login(source);const record=source.session.exportSession();source.session.close();
 const f=fixture({hook:async(method)=>method==='getUserInfo'?{user:{user_guid:'u0'+'b'.repeat(32)}}:undefined});
 await assert.rejects(f.session.restore({...record,provider:'bale'}),/invalid_saved_session/);assert.equal(f.calls.length,0);
 const other=await wire.createIdentity();await assert.rejects(f.session.restore({...record,publicKey:other.publicKey}),/invalid_saved_session/);assert.equal(f.calls.length,0);
 await assert.rejects(f.session.restore(record),/login_account_mismatch/);assert.equal(f.session.state.signedIn,false);f.session.close();
});
test('close during late identity preparation prevents saving or registering an accepted login',async()=>{
 let release;const f=fixture({createIdentity:()=>new Promise(r=>{release=r;})});await f.session.start(phone);
 const pending=f.session.verify('123456');const rejected=assert.rejects(pending,/closed/);f.session.close();release(await wire.createIdentity());await rejected;
 assert.equal(f.saved.length,0);assert.equal(f.session.state.hasSession,false);assert.equal(f.calls.some(c=>c.method==='signIn'),false);assert.equal(f.session.state.busy,false);
});
test('a late registration reply cannot mutate a restored session or clear its busy guard',async()=>{
 let oldReply,newReply;const f=fixture({hook:async(method)=>{
  if(method==='registerDevice')return new Promise(resolve=>{oldReply=resolve;});
  if(method==='getUserInfo')return new Promise(resolve=>{newReply=resolve;});
 }});
 await f.session.start(phone);const pending=f.session.verify('123456');const rejected=assert.rejects(pending,/closed/);
 const until=async predicate=>{const end=Date.now()+3000;while(!predicate()){if(Date.now()>end)throw Error('Auth fixture timed out');await new Promise(r=>setTimeout(r,5));}};
 await until(()=>!!oldReply);const record=f.session.exportSession();f.session.close();const restored=f.session.restore(record);await until(()=>!!newReply);
 oldReply({});await rejected;assert.equal(f.session.state.busy,true);assert.equal(f.session.state.stage,'restoring');
 newReply({user:{user_guid:guid}});await restored;assert.equal(f.session.state.signedIn,true);assert.equal(f.calls.filter(c=>c.method==='registerDevice').length,1);f.session.close();
});
test('sealed disk restore retains native keys and device identity without another code or registration',async()=>{
 const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),{SessionVault}=require('../experiments/providers/session-vault.cjs');
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'rubika-auth-vault-')),vault=new SessionVault(dir);let source,restored;
 try{await vault.unlock('fixture-rubika-vault-passphrase');source=fixture({save:record=>vault.save('rubika',1,record)});await login(source);
  const original=source.session.exportSession(),encrypted=await fs.readFile(path.join(dir,'rubika','1.json'),'utf8');assert.ok(!encrypted.includes(auth));assert.ok(!encrypted.includes('PRIVATE KEY'));source.session.close();vault.lock();
  await vault.unlock('fixture-rubika-vault-passphrase');const record=await vault.load('rubika',1);restored=fixture({createIdentity:()=>{throw Error('Restore must retain the key');}});
  await restored.session.restore(record);assert.equal(restored.session.exportSession().privateKey,original.privateKey);assert.equal(restored.session.exportSession().profile.deviceHash,original.profile.deviceHash);
  assert.deepEqual(restored.calls.map(c=>c.method),['getDCs','getUserInfo']);assert.equal(restored.generated(),0);
 }finally{source?.session.close();restored?.session.close();vault.lock();await fs.rm(dir,{recursive:true,force:true,maxRetries:5,retryDelay:100});}
});
test('the real auth and HTTP classes complete the encrypted RSA login/restore pipeline against an offline service fixture',async()=>{
 const {HttpClient,DISCOVERY}=require('../experiments/rubika/http-client.cjs');const methods=[];let publicKey;
 const fetchImpl=async(url,options)=>{
  const body=JSON.parse(options.body);assert.equal(options.redirect,'error');
  if(url===DISCOVERY)return new Response(JSON.stringify({status:'OK',data:{default_api_urls:['https://fixture.iranlms.ir/']}}));
  assert.equal(url,'https://fixture.iranlms.ir/');const authenticated=body.auth!==undefined,key=authenticated?auth:body.tmp_session;
  if(authenticated){assert.equal(body.auth,wire.transform(auth));assert.equal(crypto.verify('RSA-SHA256',Buffer.from(body.data_enc),publicKey,Buffer.from(body.sign,'base64')),true);}
  const payload=wire.decrypt(body.data_enc,key);methods.push(payload.method);let data;
  if(payload.method==='sendCode')data=codeReply;
  else if(payload.method==='signIn'){
   publicKey=Buffer.from(wire.transform(payload.input.public_key),'base64').toString();
   data={status:'OK',user:{user_guid:guid},auth:crypto.publicEncrypt({key:publicKey,padding:crypto.constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha1'},Buffer.from(auth)).toString('base64')};
  }else if(payload.method==='registerDevice')data={};else if(payload.method==='getUserInfo')data={user:{user_guid:guid}};else throw Error('Unexpected offline API method');
  return new Response(JSON.stringify({data_enc:wire.encrypt({status:'OK',data},key)}));
 };
 const options={createClient:options=>new HttpClient({...options,fetchImpl})},first=new AuthSession(options);let restored;
 try{await first.start(phone);await first.verify('123456');assert.equal(first.state.signedIn,true);const record=first.exportSession();first.close();restored=new AuthSession(options);await restored.restore(record);
  assert.equal(restored.state.selfConfirmed,true);assert.deepEqual(methods,['sendCode','signIn','registerDevice','getUserInfo','getUserInfo']);
 }finally{first.close();restored?.close();}
});
