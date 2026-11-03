'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {AccountClient,AUTH_RECOVERY_FRAME,deviceProfile}=require('../experiments/eitaa/account-client.cjs');
const {AuthSession}=require('../experiments/eitaa/auth-session.cjs');
const wire=require('../experiments/eitaa/wire.cjs'),codec=require('../experiments/eitaa/auth-wire.cjs');
const phone={country:'IR',nationalNumber:'9120000001',internationalNumber:'+989120000001'},imei='0123456789abcde__web';
const user={_:'user',id:12345n,self:true,phone:'989120000001',first_name:'Fixture'};
const authorization={_:'auth.authorization',token:'fixture-private-recovered-token',user};
const sent={_:'auth.sentCode',type:{_:'auth.sentCodeTypeSms',length:6},phone_code_hash:'fixture-private-hash'};
const recovery=()=>({provider:'eitaa',format:'eitaa-auth-recovery-v1',imei,loginPhone:phone.internationalNumber,profile:deviceProfile(),frame:codec.object(authorization).toString('base64'),method:'auth.signIn',createdAt:Date.now()});
function fake({saveRecovery,saveSession=async()=>{},failure,self=user}={}){const calls=[],options=[];return {calls,options,session:new AuthSession({saveRecovery,saveSession,createClient:o=>{options.push(o);return {setToken(){},close(){},async request(method){calls.push(method);if(method==='auth.sendCode')return sent;if(method==='auth.signIn')throw failure;if(method==='users.getUsers')return [self];throw Error('unexpected fixture RPC');}};}})};}
function parseError(frame){const e=new wire.WireError('trailing_data');Object.defineProperty(e,AUTH_RECOVERY_FRAME,{value:frame});return e;}

test('only opted-in authorization parse failures retain a non-enumerable bounded frame',async()=>{
 for(const enabled of [false,true]){
  const frame=Buffer.concat([codec.object(authorization),Buffer.alloc(4)]),client=new AccountClient({imei,captureAuthRecovery:enabled,fetchImpl:async()=>new Response(frame)});
  try{await assert.rejects(client.request('auth.signIn',{phone_number:phone.internationalNumber,phone_code_hash:'fixture-hash',phone_code:'123456'}),error=>{
   assert.equal(error.reason,'trailing_data');assert.equal(!!error[AUTH_RECOVERY_FRAME],enabled);assert.ok(!JSON.stringify(error).includes(authorization.token));
   if(enabled){assert.equal(Object.getOwnPropertyDescriptor(error,AUTH_RECOVERY_FRAME).enumerable,false);assert.deepEqual(error[AUTH_RECOVERY_FRAME],frame);error[AUTH_RECOVERY_FRAME].fill(0);}return true;
  });}finally{client.close();}
 }
});

test('recovery capture saves no OTP/hash/password, clears pending login and zeroes the private buffer',async()=>{
 const frame=Buffer.concat([codec.object(authorization),Buffer.alloc(4)]),original=Buffer.from(frame);let saved;
 const f=fake({saveRecovery:async r=>{saved=structuredClone(r);},failure:parseError(frame)});
 await f.session.start(phone);await assert.rejects(f.session.verify('123456'),{reason:'trailing_data'});
 assert.equal(f.options[0].captureAuthRecovery,true);assert.equal(saved.frame,original.toString('base64'));assert.equal(saved.method,'auth.signIn');assert.equal(f.session.state.hasRecovery,true);assert.equal(f.session.state.stage,'recovery_required');assert.equal(f.session.state.signedIn,false);assert.ok(frame.every(v=>v===0));
 for(const value of ['123456','fixture-private-hash',authorization.token])assert.ok(!JSON.stringify(f.session.state).includes(value));assert.ok(!JSON.stringify(saved).includes('123456'));assert.ok(!JSON.stringify(saved).includes('fixture-private-hash'));
 await assert.rejects(f.session.verify('123456'),{reason:'no_pending_code'});await assert.rejects(f.session.start(phone),{reason:'recovery_required'});assert.deepEqual(f.calls,['auth.sendCode','auth.signIn']);f.session.close();original.fill(0);
});

test('current-codec recovery seals normal credentials then confirms self without another login RPC',async()=>{
 const events=[],saved=[],f=fake({saveSession:async r=>{events.push('save');saved.push(r);}});
 const record=recovery();assert.deepEqual(await f.session.recoverAuthorization(record),{authenticated:true,selfConfirmed:true});assert.deepEqual(f.calls,['users.getUsers']);assert.deepEqual(events,['save']);assert.equal(saved[0].token,authorization.token);assert.equal(saved[0].imei,record.imei);assert.equal(f.session.state.signedIn,true);assert.equal(f.session.state.hasRecovery,false);assert.ok(!JSON.stringify(f.session.state).includes(authorization.token));f.session.close();
 const mismatch=fake({self:{...user,id:999n}});await assert.rejects(mismatch.session.recoverAuthorization(recovery()),{reason:'login_account_mismatch'});assert.equal(mismatch.session.state.signedIn,false);assert.equal(mismatch.session.state.hasSession,true);mismatch.session.close();
});

test('recovery of an observed flag-10 appendix uses only the original token and verifies self without another OTP',async()=>{
 const record=recovery(),prefix=codec.object(authorization);prefix.writeUInt32LE(1024,4);const opaque='X'.repeat(56);
 record.frame=Buffer.concat([prefix,new wire.Writer().bytes(Buffer.from(opaque)).finish()]).toString('base64');let saved;
 const f=fake({saveSession:async value=>{saved=structuredClone(value);}});await f.session.recoverAuthorization(record);
 assert.deepEqual(f.calls,['users.getUsers']);assert.equal(saved.token,authorization.token);assert.ok(!JSON.stringify(saved).includes(opaque));assert.ok(!JSON.stringify(f.session.state).includes(opaque));assert.equal(f.session.state.selfConfirmed,true);f.session.close();
});

test('invalid or stale recovery metadata cannot issue any request',async()=>{
 for(const changes of [{createdAt:Date.now()-86400001},{createdAt:Date.now()+60000},{method:'auth.sendCode'},{frame:'AA=='},{provider:'rubika'},{imei:'bad'},{loginPhone:'123'},{extra:'private-input'},{frame:'A'.repeat(90000)}]){
  const f=fake();await assert.rejects(f.session.recoverAuthorization({...recovery(),...changes}));assert.deepEqual(f.calls,[]);assert.equal(f.session.state.signedIn,false);f.session.close();
 }
});

test('failed or late encrypted saves cannot authenticate, leak frame bytes or revive a closed account',async()=>{
 const frame=codec.object(authorization),f=fake({saveRecovery:async()=>{throw Error('private persistence failure');},failure:parseError(frame)});
 await f.session.start(phone);await assert.rejects(f.session.verify('123456'),{reason:'recovery_save_failed'});assert.ok(frame.every(v=>v===0));assert.equal(f.session.state.signedIn,false);assert.ok(!JSON.stringify(f.session.state).includes('private persistence failure'));f.session.close();
 let release,entered;const enteredPromise=new Promise(r=>{entered=r;}),lateFrame=codec.object(authorization),late=fake({saveRecovery:async()=>{entered();await new Promise(r=>{release=r;});},failure:parseError(lateFrame)});
 await late.session.start(phone);const pending=late.session.verify('123456');await enteredPromise;late.session.close();release();await assert.rejects(pending,{reason:'closed'});assert.ok(lateFrame.every(v=>v===0));assert.equal(late.session.state.hasRecovery,false);assert.equal(late.session.state.signedIn,false);assert.deepEqual(late.calls,['auth.sendCode','auth.signIn']);
});
