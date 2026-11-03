'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {AuthSession,APP_ID,createProfile,profileFields}=require('../experiments/igap/auth-session.cjs');
const {RpcError}=require('../experiments/igap/rpc-connection.cjs'),{wire:w}=require('../experiments/igap/signaling.cjs');
const phone={country:'IR',nationalNumber:'9120000001',internationalNumber:'+989120000001'};
function fixture({delay=0,failStart=false,profile}={}){
 const calls=[],rpc={status:{phase:'ready'},async request(action,body=Buffer.alloc(0)){const fields=w.parse(body);calls.push({action,fields});if(action===100){if(failStart)throw new RpcError('rejected',138,0);return {fields:w.parse(Buffer.concat([w.string(2,'fixture-private-user',128),w.field(3,41,0),w.field(6,delay,0),w.field(9,5,0)]))};}if(action===101)return {fields:w.parse(w.string(2,'fixture-private-token',128))};throw Error('Unexpected fixture action');},async login(body){calls.push({action:102,fields:w.parse(body)});return {fields:w.parse(w.field(14,41,0))};},close(){this.status.phase='closed';}};
 return {calls,rpc,session:new AuthSession({connect:async()=>rpc,...profile?{profile}:{}})};
}
test('default registration stays independent and current platform/device enums remain accurate',async()=>{
 const f=fixture();try{const profile=createProfile();assert.equal(profile.appId,APP_ID);assert.equal(profile.platform,({win32:4,linux:5,darwin:3})[process.platform]||0);assert.equal(profile.device,1);await f.session.start(phone);assert.equal(w.one(f.calls[0].fields,5,0),BigInt(APP_ID));assert.equal(f.session.state.registrationProfile,'independent');}finally{f.session.close();}
});
test('explicit Web v3 compatibility changes AppID without claiming the official app name/version',async()=>{
 const f=fixture();try{await f.session.start(phone,{registrationProfile:'web-v3-compat'});assert.equal(w.one(f.calls[0].fields,5,0),1n);assert.equal(w.one(f.calls[0].fields,4,0),0n);assert.equal(f.session.state.registrationProfile,'web-v3-compat');await f.session.verify('12345');const verify=f.calls.find(v=>v.action===101),login=f.calls.find(v=>v.action===102);assert.equal(w.one(verify.fields,6,0),1n);assert.equal(w.one(login.fields,4,0),1n);assert.equal(w.str(verify.fields,5,64),'BaleVPN Provider Lab');assert.equal(w.str(verify.fields,8,64),'0.1.0');assert.equal(w.str(login.fields,3,64),'BaleVPN Provider Lab');assert.equal(f.calls.filter(v=>v.action===100).length,1);assert.equal(f.session.exportSession().profile.registrationProfile,'web-v3-compat');}finally{f.session.close();}
});
test('invalid profile choices and unmarked reserved AppIDs fail before any network action',async()=>{
 for(const mode of ['official','android','__proto__',1,null]){const f=fixture();try{await assert.rejects(f.session.start(phone,{registrationProfile:mode}),/invalid_profile/);assert.equal(f.calls.length,0);}finally{f.session.close();}}
 const profile=createProfile();delete profile.registrationProfile;assert.throws(()=>profileFields({...profile,appId:1},false),/invalid_profile/);assert.throws(()=>profileFields({...profile,registrationProfile:'web-v3-compat'},false),/invalid_profile/);
});
test('cooldown cannot silently switch an existing pending registration profile',async()=>{
 const f=fixture({delay:60});try{await f.session.start(phone);await assert.rejects(f.session.start(phone,{registrationProfile:'web-v3-compat'}),/cooldown/);assert.equal(f.session.state.registrationProfile,'independent');assert.equal(f.calls.length,1);}finally{f.session.close();}
});
test('failure in a selected compatibility profile never retries or falls back to another AppID',async()=>{
 const f=fixture({failStart:true});try{await assert.rejects(f.session.start(phone,{registrationProfile:'web-v3-compat'}),/rejected/);assert.equal(f.calls.length,1);assert.equal(w.one(f.calls[0].fields,5,0),1n);assert.equal(f.session.state.registrationProfile,'web-v3-compat');}finally{f.session.close();}
});
test('legacy sealed profiles and explicit compatibility profiles restore exactly without fresh registration',async()=>{
 for(const mode of ['legacy','web-v3-compat']){const profile=createProfile({registrationProfile:mode==='legacy'?'independent':mode});if(mode==='legacy'){delete profile.registrationProfile;profile.appId=54321;}const record={provider:'igap',userId:'41',token:'fixture-private-token',profile,loginPhone:phone.internationalNumber};const f=fixture();try{await f.session.restore(record);assert.deepEqual(f.session.exportSession().profile,profile);assert.deepEqual(f.calls.map(v=>v.action),[102]);assert.equal(w.one(f.calls[0].fields,4,0),BigInt(profile.appId));}finally{f.session.close();}}
});

test('HTTP registration selection reaches the protocol, rejects invalid values, and cannot bypass cooldown',async()=>{
 const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),{startLab}=require('../experiments/providers/lab.cjs');
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'igap-profile-route-')),accounts=[];let lab;
 try{lab=await startLab({directory:dir,port:0,sessionFactory:()=>{const f=fixture({delay:60});accounts.push(f);return f.session;}});const key=new URL(lab.url).hash.slice(1),request=(route,body)=>fetch(lab.origin+route,{method:body===undefined?'GET':'POST',headers:{Authorization:'Bearer '+key,...body===undefined?{}:{Origin:lab.origin,'Content-Type':'application/json'}},body:body===undefined?undefined:JSON.stringify(body)});
  await request('/api/vault/unlock',{password:'fixture-profile-passphrase'});
  for(const registrationProfile of ['official',1,null,{}]){const response=await request('/api/igap/1/start',{country:'IR',phone:'09120000001',registrationProfile});assert.equal(response.status,400);assert.equal((await response.json()).reason,'invalid_registration_profile');}assert.equal(accounts[0].calls.length,0);
  assert.equal((await request('/api/igap/1/start',{country:'IR',phone:'09120000001',registrationProfile:'web-v3-compat'})).status,200);assert.equal(w.one(accounts[0].calls[0].fields,5,0),1n);
  const blocked=await request('/api/igap/1/start',{country:'IR',phone:'09120000001',registrationProfile:'independent'});assert.equal((await blocked.json()).reason,'cooldown');assert.equal(accounts[0].calls.length,1);
  assert.equal((await request('/api/igap/2/start',{country:'IR',phone:'09120000002'})).status,200);assert.equal(w.one(accounts[1].calls[0].fields,5,0),BigInt(APP_ID));
  const state=await(await request('/api/state')).json();assert.equal(state.accounts[0].registrationProfile,'web-v3-compat');assert.equal(state.accounts[1].registrationProfile,'independent');assert.ok(!JSON.stringify(state).includes('fixture-private-user'));
 }finally{await lab?.close();const resolved=path.resolve(dir);if(!resolved.startsWith(path.resolve(os.tmpdir())+path.sep)||!path.basename(dir).startsWith('igap-profile-route-'))throw Error('Unexpected fixture cleanup target');await fs.rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:100});}
});
