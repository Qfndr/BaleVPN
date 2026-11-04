'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {AuthSession,requestIds}=require('../experiments/eitaa/auth-session.cjs'),{ApiError}=require('../experiments/eitaa/http-client.cjs');
const {passwordHash,AccountClient}=require('../experiments/eitaa/account-client.cjs');
const phone={country:'IR',nationalNumber:'9120000001',internationalNumber:'+989120000001'},token='fixture-private-eitaa-token';
const user={_:'user',id:123456789012345n,self:true,first_name:'کاربر',phone:'989120000001'};
const sent={_:'auth.sentCode',phone_code_hash:'fixture-service-code-hash',type:{_:'auth.sentCodeTypeSms',length:6},timeout:60};
function fixture({hook,save,createRequestId}={}){
 const calls=[],saved=[],clients=[],events=[];
 const session=new AuthSession({createRequestId,saveRefreshRecovery:async()=>{},clearRefreshRecovery:async()=>{},saveSession:async r=>{events.push('save');if(save)await save(r);saved.push(structuredClone(r));},createClient:options=>{
  const snapshot={...options};delete snapshot.onRefreshResponse;
  const client={options:structuredClone(snapshot),closed:false,token:options.token,setToken(value){this.token=value;},close(){this.closed=true;},async request(method,input){calls.push({method,input:structuredClone(input),token:this.token,imei:options.imei});events.push(method);if(hook){const result=await hook(method,input,this);if(result!==undefined)return result;}
   if(method==='auth.sendCode')return sent;if(method==='auth.signIn'||method==='auth.checkPassword2')return {_:'auth.authorization',token,user};if(method==='users.getUsers')return [user];
   if(method==='account.getPassword')return {_:'account.password2',current_salt:Buffer.alloc(24,0xa5),hint:'fixture hint'};
   if(method==='eitaaRefreshToken'){const response={_:'eitaa_updates_token',token:'fixture-refreshed-token',date:123,expire:456};await options.onRefreshResponse(require('../experiments/eitaa/auth-wire.cjs').object(response));return response;}if(method==='auth.logOut')return true;throw Error('Unexpected method');
  }};clients.push(client);return client;
 }});return {session,calls,saved,clients,events};
}
async function login(f){await f.session.start(phone);return f.session.verify('123456');}
function service(code){const e=new ApiError('service_rejected');e.serviceCode=code;return e;}
test('Eitaa login seals accepted credentials before protected self read and exposes safe public state',async()=>{
 const f=fixture();await login(f);assert.equal(f.session.state.signedIn,true);assert.equal(f.session.state.selfConfirmed,true);assert.deepEqual(f.events,['auth.sendCode','auth.signIn','save','users.getUsers']);
 const record=f.session.exportSession();assert.equal(record.token,token);assert.equal(record.userId,String(user.id));assert.equal(record.deviceMetadataSent,false);assert.equal(f.clients[0].options.imei,record.imei);
 for(const value of [token,record.imei,phone.internationalNumber,'fixture-service-code-hash'])assert.ok(!JSON.stringify(f.session.state).includes(value));assert.ok(!JSON.stringify(f.session.state).includes('"123456"'));
 record.profile.systemVersion='changed';assert.notEqual(f.session.exportSession().profile.systemVersion,'changed');assert.equal(f.session.state.deviceMetadataSent,false);f.session.close();
});
test('pong compatibility is an explicit received-code attempt and never claims a service-issued hash or delivery',async()=>{
 const f=fixture({createRequestId:()=> '7777777777777777777',hook:async m=>m==='auth.sendCode'?{acknowledged:true,codeIssued:false}:undefined});
 assert.deepEqual(await f.session.start(phone),{acknowledged:true,codeRequested:false,deliveryUnconfirmed:true});assert.equal(f.session.state.delivery,'Unconfirmed');assert.equal(f.session.state.codeHashSource,'localCompatibility');assert.equal(f.calls.length,1);
 await assert.rejects(f.session.verify('12345'),{reason:'invalid_code_format'});assert.equal(f.calls.length,1);await f.session.verify('123456');assert.equal(f.calls.find(c=>c.method==='auth.signIn').input.phone_code_hash,'7777777777777777777');assert.equal(f.session.state.signedIn,true);f.session.close();
});
test('password challenge uses the retained received code and observed salt KDF, not a new code request',async()=>{
 let attempts=0;const f=fixture({hook:async(m,input)=>{if(m==='auth.signIn')throw service('SESSION_PASSWORD_NEEDED');if(m==='auth.checkPassword2'&&++attempts===1)throw service('PASSWORD_HASH_INVALID');}});
 await f.session.start(phone);assert.deepEqual(await f.session.verify('123456'),{twoFactorRequired:true});assert.equal(f.session.state.stage,'password');assert.equal(f.session.state.hint,'fixture hint');
 await assert.rejects(f.session.password('fixture-wrong'),{serviceCode:'PASSWORD_HASH_INVALID'});await f.session.password('fixture-رمز');
 const request=f.calls.filter(c=>c.method==='auth.checkPassword2').at(-1);assert.deepEqual(Buffer.from(request.input.password_hash),passwordHash('fixture-رمز',Buffer.alloc(24,0xa5)));assert.equal(request.input.phone_code,'123456');assert.equal(f.calls.filter(c=>c.method==='auth.sendCode').length,1);assert.equal(f.session.state.signedIn,true);assert.ok(!JSON.stringify(f.session.exportSession()).includes('fixture-رمز'));f.session.close();
});
test('unknown password algorithms and expired codes do not silently retry or authenticate',async()=>{
 const f=fixture({hook:async m=>{if(m==='auth.signIn')throw service('SESSION_PASSWORD_NEEDED');if(m==='account.getPassword')return {_:'account.password'};}});await f.session.start(phone);await assert.rejects(f.session.verify('123456'),{reason:'unsupported_password_algorithm'});assert.equal(f.session.state.signedIn,false);assert.equal(f.calls.filter(c=>c.method==='auth.sendCode').length,1);f.session.close();
 const g=fixture({hook:async m=>{if(m==='auth.signIn')throw service('PHONE_CODE_EXPIRED');}});await g.session.start(phone);await assert.rejects(g.session.verify('123456'),{serviceCode:'PHONE_CODE_EXPIRED'});await assert.rejects(g.session.verify('123456'),{reason:'no_pending_code'});g.session.close();
});
test('lost send replies enforce cooldown, invalid phones never reach the service and flood waits are bounded',async()=>{
 const f=fixture({hook:async m=>{if(m==='auth.sendCode')throw new ApiError('network_error');}});await assert.rejects(f.session.start(phone),{reason:'network_error'});assert.equal(f.session.state.stage,'uncertain');await assert.rejects(f.session.start(phone),{reason:'cooldown'});assert.equal(f.calls.length,1);f.session.close();
 const malformed=fixture({hook:async m=>m==='auth.sendCode'?{_:'boolTrue'}:undefined});await assert.rejects(malformed.session.start(phone),{reason:'invalid_auth_response'});assert.equal(malformed.session.state.stage,'uncertain');await assert.rejects(malformed.session.verify('123456'),{reason:'no_pending_code'});assert.equal(malformed.calls.length,1);malformed.session.close();
 const g=fixture();await assert.rejects(g.session.start({...phone,nationalNumber:'123'}),{reason:'invalid_phone'});assert.equal(g.calls.length,0);g.session.close();
 const h=fixture({hook:async()=>{const e=new ApiError('rate_limited');e.waitSeconds=999999;throw e;}});await assert.rejects(h.session.start(phone),{reason:'rate_limited'});assert.equal(h.session.state.retryAfter,86400);h.session.close();
});
test('definite phone rejections clear pending code without claiming an uncertain send or retrying',async()=>{
 for(const code of ['PHONE_NUMBER_INVALID','PHONE_NUMBER_BANNED']){
  const f=fixture({hook:async method=>{if(method==='auth.sendCode')throw service(code);}});
  await assert.rejects(f.session.start(phone),{reason:'service_rejected',serviceCode:code});assert.equal(f.session.state.stage,'idle');assert.equal(f.session.state.error.serviceCode,code);assert.equal(f.session.state.hasSession,false);assert.ok(f.session.state.retryAfter>0);
  await assert.rejects(f.session.verify('123456'),{reason:'no_pending_code'});await assert.rejects(f.session.start(phone),{reason:'cooldown'});assert.equal(f.calls.length,1);f.session.close();
 }
});

test('schema mismatch diagnostics expose only validated numeric fields and cannot authenticate or retry',async()=>{
 const wire=require('../experiments/eitaa/wire.cjs');
 for(const flags of [1,-1,'private-secret']){
  const f=fixture({hook:async method=>{if(method==='auth.sendCode'){const e=new wire.WireError('unknown_flags');e.schemaDiagnostic={constructorId:1577067778,flags,knownMask:6,raw:'private-secret'};throw e;}}});
  await assert.rejects(f.session.start(phone),{reason:'unknown_flags'});const state=f.session.state;assert.equal(state.stage,'uncertain');assert.equal(state.signedIn,false);assert.ok(!JSON.stringify(state).includes('private-secret'));assert.equal(!!state.error.schemaDiagnostic,flags===1);if(flags===1)assert.deepEqual(state.error.schemaDiagnostic,{constructorId:1577067778,flags:1,knownMask:6});assert.equal(f.calls.length,1);f.session.close();
 }
});

test('trailing-data diagnostics validate numeric bounds and redact all supplied response content',async()=>{
 const wire=require('../experiments/eitaa/wire.cjs');
 for(const remaining of [4,-1,'private-secret']){
  const f=fixture({hook:async method=>{if(method==='auth.sendCode'){const e=new wire.WireError('trailing_data');e.trailingDiagnostic={constructorId:3439659286,lastConstructorId:1,consumed:20,total:24,remaining,raw:'private-secret'};throw e;}}});
  await assert.rejects(f.session.start(phone),{reason:'trailing_data'});const state=f.session.state;assert.ok(!JSON.stringify(state).includes('private-secret'));assert.equal(!!state.error.trailingDiagnostic,remaining===4);assert.equal(state.signedIn,false);assert.equal(f.calls.length,1);f.session.close();
 }
});

test('accepted tokens survive a failed disk save and can be sealed on explicit resume without another sign-in',async()=>{
 let fail=true;const f=fixture({save:async()=>{if(fail)throw Error('disk fixture');}});await f.session.start(phone);await assert.rejects(f.session.verify('123456'),{reason:'session_save_failed'});assert.equal(f.session.state.hasSession,true);assert.equal(f.session.state.signedIn,false);assert.equal(f.calls.filter(c=>c.method==='users.getUsers').length,0);
 fail=false;await f.session.resume();assert.equal(f.saved.length,1);assert.equal(f.calls.filter(c=>c.method==='auth.signIn').length,1);assert.equal(f.session.state.signedIn,true);f.session.close();
});
test('restore retains exactly the saved token/device/profile and performs only a pinned protected self read',async()=>{
 const f=fixture();await login(f);const record=f.session.exportSession();f.session.close();const g=fixture();await g.session.restore(record);assert.deepEqual(g.calls.map(c=>c.method),['users.getUsers']);assert.equal(g.calls[0].token,record.token);assert.equal(g.clients[0].options.imei,record.imei);assert.deepEqual(g.clients[0].options.profile,record.profile);assert.equal(g.saved.length,0);g.session.close();
 for(const changed of [{provider:'rubika'},{imei:'invalid'},{token:'secret\n'},{userId:'0'},{userId:'9223372036854775808'},{profile:{deviceModel:'Pretend phone',systemVersion:'x'}}]){const h=fixture();await assert.rejects(h.session.restore({...record,...changed}),{reason:'invalid_saved_session'});assert.equal(h.calls.length,0);h.session.close();}
 const h=fixture({hook:async m=>m==='users.getUsers'?[{...user,id:user.id+1n}]:undefined});await assert.rejects(h.session.restore(record),{reason:'login_account_mismatch'});assert.equal(h.session.state.signedIn,false);h.session.close();
});
test('expired tokens require an explicit refresh; the new token is sealed before confirming the same self',async()=>{
 let expire=false;const f=fixture({hook:async(m)=>{if(m==='users.getUsers'&&expire)throw new ApiError('session_refresh_required');}});await login(f);expire=true;await assert.rejects(f.session.resume(),{reason:'session_refresh_required'});assert.equal(f.session.state.stage,'refresh_required');assert.equal(f.calls.filter(c=>c.method==='eitaaRefreshToken').length,0);
 expire=false;const before=f.events.length;await f.session.refresh();assert.deepEqual(f.events.slice(before),['eitaaRefreshToken','save','users.getUsers']);assert.equal(f.saved.at(-1).token,'fixture-refreshed-token');assert.equal(f.session.state.deviceMetadataSent,true);assert.equal(f.session.state.signedIn,true);f.session.close();
});
test('logout must receive true before local credentials are forgotten; stop preserves them for resume',async()=>{
 let accept=false;const f=fixture({hook:async m=>m==='auth.logOut'?accept:undefined});await login(f);await assert.rejects(f.session.logout(),{reason:'logout_not_confirmed'});assert.equal(f.session.state.hasSession,true);f.session.stop();assert.equal(f.session.state.hasSession,true);await f.session.resume();accept=true;await f.session.logout();assert.equal(f.session.state.hasSession,false);assert.equal(f.session.state.stage,'idle');f.session.close();
});
test('close cancels late callbacks, old completion cannot clear newer busy state and sequential disk writes retain order',async()=>{
 let release;const f=fixture({hook:async m=>m==='auth.sendCode'?new Promise(resolve=>{release=()=>resolve(sent);}):undefined});const pending=f.session.start(phone);await assert.rejects(f.session.start(phone),{reason:'account_busy'});f.session.close();release();await assert.rejects(pending,{reason:'closed'});assert.equal(f.session.state.stage,'idle');assert.equal(f.session.state.hasSession,false);f.session.close();
 let saveRelease;const g=fixture({save:async()=>new Promise(resolve=>{saveRelease=resolve;})});await g.session.start(phone);const verification=g.session.verify('123456');await new Promise(resolve=>setImmediate(resolve));const record=g.session.exportSession();g.session.close();await g.session.restore(record);const resume=g.session.resume();await new Promise(resolve=>setImmediate(resolve));assert.equal(g.session.state.busy,true);saveRelease();await assert.rejects(verification,{reason:'closed'});await new Promise(resolve=>setImmediate(resolve));saveRelease();await resume;assert.equal(g.session.state.signedIn,true);g.session.close();
});
test('local compatibility request IDs match the official format and remain monotonic under repeated/backwards clocks',()=>{
 let now=1793655000123;const ids=requestIds({clock:()=>now,random:()=>42});const first=BigInt(ids());assert.equal(first,(BigInt(Math.floor(now/1000))<<32n)|BigInt(((now%1000)<<21|42<<3|4)>>>0));assert.equal(BigInt(ids()),first+4n);now-=1000;assert.equal(BigInt(ids()),first+8n);assert.throws(()=>requestIds({clock:()=>NaN})(),{reason:'invalid_request'});
});
test('real account wire + sealed vault can restore from disk without another login or OTP against an offline service',async()=>{
 const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),{SessionVault}=require('../experiments/providers/session-vault.cjs'),wire=require('../experiments/eitaa/wire.cjs'),codec=require('../experiments/eitaa/auth-wire.cjs');
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'eitaa-auth-test-')),calls=[],devices=[];let vault=new SessionVault(directory);await vault.unlock('fixture-strong-vault-password');
 const fetchImpl=async(_url,options)=>{const r=new wire.Reader(options.body);assert.equal(r.int(),wire.IDS.eitaaObject);const credential=r.string(),imei=r.string(),p=new wire.Reader(r.bytes());r.int();r.int();r.end();devices.push(imei);const id=p.int();calls.push(id);let response;
  if(id===-1502141361){assert.equal(credential,'');assert.equal(p.string(),phone.internationalNumber);response=codec.object(sent);}
  else if(id===-1126886015){assert.equal(credential,'');assert.equal(p.string(),phone.internationalNumber);assert.equal(p.string(),sent.phone_code_hash);assert.equal(p.string(),'123456');p.end();response=codec.object({_:'auth.authorization',token,user});}
  else if(id===227648840){assert.equal(credential,token);assert.equal(p.int(),481674261);assert.equal(p.int(),1);assert.equal(p.int(),-138301121);p.end();response=Buffer.concat([new wire.Writer().int(481674261).int(1).finish(),codec.object(user)]);}
  else throw Error('Unexpected service fixture request');return new Response(response);
 };
 const options={createClient:args=>new AccountClient({...args,fetchImpl}),saveSession:record=>vault.save('eitaa',1,record)},session=new AuthSession(options);
 try{await session.start(phone);await session.verify('123456');const record=session.exportSession();assert.equal(session.state.signedIn,true);const disk=await fs.readFile(path.join(directory,'eitaa','1.json'),'utf8');for(const secret of [token,record.imei,phone.internationalNumber])assert.ok(!disk.includes(secret));session.close();vault.lock();vault=new SessionVault(directory);await vault.unlock('fixture-strong-vault-password');const restored=new AuthSession(options);await restored.restore(await vault.load('eitaa',1));assert.equal(restored.state.signedIn,true);assert.deepEqual(calls,[-1502141361,-1126886015,227648840,227648840]);assert.equal(new Set(devices).size,1);restored.close();}
 finally{session.close();vault.lock();if(!path.resolve(directory).startsWith(path.resolve(os.tmpdir())+path.sep)||!path.basename(directory).startsWith('eitaa-auth-test-'))throw Error('Unexpected fixture cleanup target');await fs.rm(directory,{recursive:true,force:true});}
});
