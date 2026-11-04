'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const profiles=require('../experiments/eitaa/client-profile.cjs'),wire=require('../experiments/eitaa/wire.cjs'),authCodec=require('../experiments/eitaa/auth-wire.cjs');
const {AccountClient,deviceProfile}=require('../experiments/eitaa/account-client.cjs'),{AuthSession}=require('../experiments/eitaa/auth-session.cjs');
const {CallClient}=require('../experiments/eitaa/call-client.cjs'),callCodec=require('../experiments/eitaa/call-wire.cjs'),privacyCodec=require('../experiments/eitaa/privacy-wire.cjs');
const {CallSession}=require('../experiments/eitaa/call-session.cjs');
const phone={country:'IR',nationalNumber:'9120000001',internationalNumber:'+989120000001'},token='fixture-private-android-token',user={_:'user',id:41n,self:true,phone:'989120000001',first_name:'Fixture'};
const sent={_:'auth.sentCode',phone_code_hash:'fixture-private-code-hash',type:{_:'auth.sentCodeTypeSms',length:6}},authorization={_:'auth.authorization',token,user};
function service(seen,{badAuthorization=false}={}){return async(url,o)=>{
 const r=new wire.Reader(o.body),constructor=r.int(),credential=r.string(),imei=r.string();let flags,packed,layer,build,language;
 if(constructor===2059302894){flags=r.int();packed=r.bytes();layer=r.int();build=r.int();language=r.string();assert.equal(flags,32);assert.equal(layer,138);assert.equal(build,2637);assert.equal(language,'fa');assert.equal(profiles.validImei(imei,profiles.ANDROID),true);assert.equal(url,profiles.ANDROID_ENDPOINT);assert.deepEqual(o.headers,{'content-type':'text/stream'});}
 else{assert.equal(constructor,2059302893);packed=r.bytes();layer=r.int();flags=r.int();assert.equal(layer,135);assert.equal(flags,128);}
 r.end();const p=new wire.Reader(packed),method=p.int(),entry={method,constructor,credential,imei,layer,flags,build};seen.push(entry);let response;
 if(method===-1502141361){assert.equal(credential,'');assert.equal(p.string(),phone.internationalNumber);entry.apiId=p.int();entry.apiHash=p.string();assert.equal(p.int(),-557924733);assert.equal(p.int(),0);p.end();response=authCodec.object(sent);}
 else if(method===-1126886015){assert.equal(credential,'');assert.equal(p.string(),phone.internationalNumber);assert.equal(p.string(),sent.phone_code_hash);assert.equal(p.string(),'123456');p.end();response=authCodec.object(authorization);if(badAuthorization)response.writeUInt32LE(0x40000000,4);}
 else if(method===227648840){assert.equal(credential,token);response=Buffer.concat([new wire.Writer().int(481674261).int(1).finish(),authCodec.object(user)]);}
 else if(method===-623130288){response=privacyCodec.object({_:'account.privacyRules',rules:[{_:'privacyValueAllowAll'}],chats:[],users:[]});}
 else if(method===651135312){assert.equal(p.int(),0);assert.equal(p.int(),256);p.end();response=callCodec.object({_:'messages.dhConfig',g:3,p:Buffer.alloc(256,0x91),random:Buffer.alloc(256,0x19),version:1});}
 else throw Error('Unexpected fixture method');return new Response(response);
};}
function fixture(options={}){const seen=[],saved=[],recoveries=[],fetchImpl=service(seen,options),session=new AuthSession({createClient:o=>new AccountClient({...o,fetchImpl}),saveSession:async r=>saved.push(structuredClone(r)),saveRecovery:async r=>recoveries.push(structuredClone(r))});return {seen,saved,recoveries,session,fetchImpl};}
test('new Android login uses the exact native public app identity, persistent UUID and corrected APK wrapper over verified HTTPS',async()=>{
 const f=fixture();await f.session.start(phone,{protocolProfile:profiles.ANDROID});await f.session.verify('123456');assert.equal(f.session.state.signedIn,true);assert.equal(f.session.state.protocolProfile,profiles.ANDROID);assert.equal(f.seen[0].apiId,1782360);assert.equal(f.seen[0].apiHash,'0d870902a3e09e7cdc57e5d7bd68da6b');assert.ok(f.seen.every(x=>x.constructor===2059302894));
 const record=f.session.exportSession();assert.equal(record.profile.protocolProfile,profiles.ANDROID);assert.equal(profiles.validImei(record.imei,profiles.ANDROID),true);assert.equal(f.saved[0].token,token);assert.equal(f.saved[0].imei,record.imei);assert.ok(!JSON.stringify(f.session.state).includes(token));assert.ok(!JSON.stringify(f.session.state).includes(record.imei));
 const snapshot=JSON.stringify(record),count=f.seen.length;await assert.rejects(f.session.start(phone,{protocolProfile:'web'}),/already_signed_in/);assert.equal(JSON.stringify(f.session.exportSession()),snapshot);assert.equal(f.seen.length,count);f.session.close();
});
test('Android restoration, call reads and privacy keep the same profile without OTP or native TCP',async()=>{
 const f=fixture();await f.session.start(phone,{protocolProfile:profiles.ANDROID});await f.session.verify('123456');const record=f.session.exportSession();f.session.close();f.seen.length=0;
 const restored=new AuthSession({createClient:o=>new AccountClient({...o,fetchImpl:f.fetchImpl})});await restored.restore(record);assert.deepEqual(restored.exportSession(),record);assert.deepEqual(f.seen.map(x=>x.method),[227648840]);
 const call=new CallClient({provider:'eitaa',token:record.token,imei:record.imei,profile:record.profile,fetchImpl:f.fetchImpl});await call.request('messages.getDhConfig');assert.equal(f.seen.at(-1).constructor,2059302894);call.close();
 assert.equal((await restored.allowAllCalls()).callPrivacy.allowedEveryone,true);assert.equal(f.seen.at(-1).constructor,2059302894);
 const count=f.seen.length;await assert.rejects(restored.refresh(),/profile_refresh_unavailable/);assert.equal(f.seen.length,count);assert.equal(restored.exportSession().token,record.token);restored.close();
});
test('Android auth recovery retains its bounded private response and UUID while excluding the submitted OTP and code hash',async()=>{
 const f=fixture({badAuthorization:true});await f.session.start(phone,{protocolProfile:profiles.ANDROID});await assert.rejects(f.session.verify('123456'),/unknown_flags/);assert.equal(f.recoveries.length,1);const recovery=f.recoveries[0];assert.equal(recovery.profile.protocolProfile,profiles.ANDROID);assert.equal(profiles.validImei(recovery.imei,profiles.ANDROID),true);for(const secret of ['123456','fixture-private-code-hash'])assert.ok(!JSON.stringify(recovery).includes(secret));await assert.rejects(f.session.start(phone,{protocolProfile:'web'}),/recovery_required/);f.session.close();
 recovery.frame=authCodec.object(authorization).toString('base64');f.seen.length=0;const restored=new AuthSession({createClient:o=>new AccountClient({...o,fetchImpl:service(f.seen)})});await restored.recoverAuthorization(recovery);assert.equal(restored.state.signedIn,true);assert.equal(restored.exportSession().imei,recovery.imei);assert.deepEqual(f.seen.map(x=>x.method),[227648840]);restored.close();
});
test('legacy Web sessions and default app parameters remain unchanged while profile and UUID substitution fail before I/O',async()=>{
 const f=fixture();await assert.rejects(f.session.start(phone,{protocolProfile:'unknown'}),/invalid_client_profile/);assert.equal(f.seen.length,0);await f.session.start(phone);await f.session.verify('123456');const record=f.session.exportSession();assert.equal(f.seen[0].apiId,2496);assert.equal(Object.hasOwn(record.profile,'protocolProfile'),false);assert.ok(f.seen.every(x=>x.constructor===2059302893));f.session.close();
 const bad={...record,profile:{...record.profile,protocolProfile:profiles.ANDROID}},restored=new AuthSession({createClient:()=>{throw Error('Must not open');}});await assert.rejects(restored.restore(bad),/invalid_saved_session/);assert.throws(()=>new AccountClient({imei:record.imei,token,profile:deviceProfile(profiles.ANDROID)}),/invalid_credentials/);restored.close();
});
test('Web refresh accepts the exact reviewed native token-update suffix and still rejects truncation',()=>{
 const android=authCodec.forProfile(profiles.ANDROID),value={_:'eitaa_updates_token',token,expire:123,date:100,msg_id:41n,socket_token:'fixture-private-socket-token'},frame=android.object(value);
 assert.deepEqual(android.response(frame,'eitaaRefreshToken'),value);assert.deepEqual(authCodec.response(frame,'eitaaRefreshToken'),value);assert.throws(()=>authCodec.response(Buffer.concat([frame,Buffer.alloc(4)]),'eitaaRefreshToken'));assert.throws(()=>android.response(frame.subarray(0,-4),'eitaaRefreshToken'));
});
test('changing profile and device identity cancels a prepared call owner before any further network request',async()=>{
 const record={provider:'eitaa',token,imei:profiles.createImei(profiles.ANDROID),userId:'41',profile:deviceProfile(profiles.ANDROID)},account={state:{provider:'eitaa',signedIn:true,selfConfirmed:true,userId:'41'},exportSession:()=>structuredClone(record)};let requests=0,closed=false;
 const call=new CallSession(account,{allowedPeers:['42'],createClient:options=>{assert.equal(options.profile.protocolProfile,profiles.ANDROID);return {async request(){requests++;return {_:'updates.state',pts:0,qts:0,date:0,seq:0,unread_count:0};},close(){closed=true;}};}});
 await call.start();record.profile.protocolProfile='web';record.imei='0123456789abcde__web';await assert.rejects(call.pollOnce(),/account_binding_changed/);assert.equal(requests,1);assert.equal(closed,true);call.close();
});
