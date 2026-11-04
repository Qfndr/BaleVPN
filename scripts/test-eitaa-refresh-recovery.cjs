'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const {AuthSession}=require('../experiments/eitaa/auth-session.cjs');
const {AccountClient}=require('../experiments/eitaa/account-client.cjs');
const {SessionVault}=require('../experiments/providers/session-vault.cjs');
const codec=require('../experiments/eitaa/auth-wire.cjs');
const wire=require('../experiments/eitaa/wire.cjs');
const recovery=require('../experiments/eitaa/refresh-recovery.cjs');
const profiles=require('../experiments/eitaa/client-profile.cjs');

const oldToken='fixture-old-refresh-token';
const newToken='fixture-new-refresh-token';
const record={provider:'eitaa',format:1,token:oldToken,imei:'0123456789abcde__web',userId:'41',loginPhone:'+989120000001',
 profile:{deviceModel:'Desktop 0123456789ab',systemVersion:'fixture OS'},deviceMetadataSent:true,name:'Fixture'};
const user={_:'user',id:41n,self:true,first_name:'Fixture',phone:'989120000001'};
const update=()=>codec.forProfile(profiles.ANDROID).object({_:'eitaa_updates_token',token:newToken,expire:1000,date:900,msg_id:42n,socket_token:'s'.repeat(56)});
const selfResponse=()=>Buffer.concat([new wire.Writer().int(0x1cb5c415).int(1).finish(),codec.object(user)]);

async function fixture(t,{frame=update(),failArchive=false,failSave=false,failClear=false,failIntent=false,failIntentAfterSave=false,afterArchive=async()=>{},beforeRefreshResponse=async()=>{}}={}){
 const base=path.resolve(os.tmpdir());
 if(process.platform==='win32')assert.match(base,/^E:[\\/]/i);
 const directory=await fs.mkdtemp(path.join(base,'eitaa-refresh-'));
 const vault=new SessionVault(directory),events=[],frames=[];
 await vault.unlock('fixture-refresh-vault-password');
 await vault.save('eitaa',1,record);
 const controls={failArchive,failSave,failClear,failIntent,failIntentAfterSave};
 const session=new AuthSession({
  saveRefreshRecovery:async value=>{events.push('archive');if(controls.failIntent&&value.phase==='requested'||controls.failArchive&&value.phase==='response')throw Error('fixture storage failure');await vault.saveRefreshRecovery('eitaa',1,value);if(controls.failIntentAfterSave&&value.phase==='requested')throw Error('fixture post-write failure');if(value.phase==='response')await afterArchive();},
  clearRefreshRecovery:async value=>{events.push('clear');if(controls.failClear)throw Error('fixture cleanup failure');await vault.removeRefreshRecovery('eitaa',1,value);},
  saveSession:async value=>{events.push('save');if(controls.failSave)throw Error('fixture session failure');await vault.save('eitaa',1,value);},
  createClient:options=>new AccountClient({...options,onRefreshResponse:async bytes=>{frames.push(bytes);return options.onRefreshResponse(bytes);},fetchImpl:async(_url,request)=>{
   const envelope=new wire.Reader(request.body);envelope.int();const token=envelope.string();envelope.string();const payload=envelope.bytes();
   const method=new wire.Reader(payload).int();
   if(method===227648840){events.push('self');assert.ok(token===oldToken||token===newToken);return new Response(selfResponse());}
   events.push('refresh');assert.equal(token,oldToken);await beforeRefreshResponse();return new Response(frame);
  }})
 });
 t.after(async()=>{session.close();vault.lock();const target=path.resolve(directory);assert.ok(target.startsWith(base+path.sep)&&path.basename(target).startsWith('eitaa-refresh-'));await fs.rm(target,{recursive:true,force:true});});
 await session.restore(record);events.length=0;
 return {session,vault,events,frames,controls,directory};
}

test('refresh seals the complete five-field reply before parsing and saves the new token before self confirmation',async t=>{
 const f=await fixture(t);
 await f.session.refresh();
 assert.deepEqual(f.events,['archive','refresh','archive','save','clear','self']);
 assert.equal(f.session.state.signedIn,true);
 assert.equal((await f.vault.load('eitaa',1)).token,newToken);
 assert.equal(await f.vault.hasRefreshRecovery('eitaa',1),false);
 assert.ok(f.frames[0].every(byte=>byte===0));
 assert.equal(f.session.state.hasRefreshRecovery,false);
 assert.ok(!JSON.stringify(f.session.state).includes(newToken));
});

test('an undecodable refresh reply stays encrypted and blocks another refresh without changing the saved session',async t=>{
 const frame=Buffer.concat([update(),Buffer.alloc(4)]),f=await fixture(t,{frame});
 await assert.rejects(f.session.refresh(),{reason:'trailing_data'});
 assert.deepEqual(f.events,['archive','refresh','archive']);
 assert.equal((await f.vault.load('eitaa',1)).token,oldToken);
 const saved=await f.vault.loadRefreshRecovery('eitaa',1);
 const reordered=Object.fromEntries(Object.entries(saved).reverse());
 await f.vault.saveRefreshRecovery('eitaa',1,reordered);
 assert.equal(recovery.same(saved,reordered),true);
 assert.equal(saved.frame,frame.toString('base64'));
 assert.equal(f.session.state.signedIn,false);
 assert.equal(f.session.state.stage,'refresh_recovery_required');
 await assert.rejects(f.session.refresh(),{reason:'refresh_recovery_required'});
 assert.equal(f.events.filter(event=>event==='refresh').length,1);
 const disk=await fs.readFile(path.join(f.directory,'refresh-recovery','eitaa','1.json'),'utf8');
 for(const value of [oldToken,newToken,saved.frame])assert.ok(!disk.includes(value));
 assert.ok(f.frames[0].every(byte=>byte===0));
});

test('failed archive persistence prevents token adoption and can retry from retained bytes without another refresh',async t=>{
 const f=await fixture(t,{failArchive:true});
 await assert.rejects(f.session.refresh(),{reason:'recovery_save_failed'});
 assert.equal(f.session.exportSession().token,oldToken);
 assert.equal((await f.vault.load('eitaa',1)).token,oldToken);
 assert.ok(f.frames[0].every(byte=>byte===0));
 f.controls.failArchive=false;
 await f.session.resume();
 assert.equal(f.events.filter(event=>event==='refresh').length,1);
 assert.equal(f.session.state.signedIn,true);
 assert.equal((await f.vault.load('eitaa',1)).token,newToken);
});

test('an encrypted refresh response survives a new controller and recovers without rotating again',async t=>{
 const f=await fixture(t,{failSave:true});
 await assert.rejects(f.session.refresh(),{reason:'session_save_failed'});
 const saved=await f.vault.loadRefreshRecovery('eitaa',1),original=await f.vault.load('eitaa',1);
 f.session.close();
 let requests=0;
 const restored=new AuthSession({saveRefreshRecovery:value=>f.vault.saveRefreshRecovery('eitaa',1,value),clearRefreshRecovery:value=>f.vault.removeRefreshRecovery('eitaa',1,value),saveSession:value=>f.vault.save('eitaa',1,value),
  createClient:options=>new AccountClient({...options,fetchImpl:async(_url,request)=>{requests++;const envelope=new wire.Reader(request.body);envelope.int();assert.equal(envelope.string(),newToken);return new Response(selfResponse());}})});
 t.after(()=>restored.close());
 await restored.restoreWithRefreshRecovery(original,saved);
 assert.equal(requests,1);
 assert.equal(restored.state.signedIn,true);
 assert.equal(await f.vault.hasRefreshRecovery('eitaa',1),false);
});

test('refresh recovery rejects account or slot substitution and requires explicit durable storage',async t=>{
 const f=await fixture(t,{frame:Buffer.concat([update(),Buffer.alloc(4)])});
 await assert.rejects(f.session.refresh());
 const saved=await f.vault.loadRefreshRecovery('eitaa',1);
 let opened=false;
 const other=new AuthSession({createClient:()=>{opened=true;throw Error('unexpected network');}});
 await assert.rejects(other.restoreWithRefreshRecovery({...record,userId:'42'},saved),{reason:'invalid_refresh_recovery'});
 assert.equal(opened,false);other.close();
 const encoded=await fs.readFile(path.join(f.directory,'refresh-recovery','eitaa','1.json'),'utf8');
 const swapped=JSON.parse(encoded);swapped.slot=2;
 await fs.writeFile(path.join(f.directory,'refresh-recovery','eitaa','2.json'),JSON.stringify(swapped));
 await assert.rejects(f.vault.loadRefreshRecovery('eitaa',2));
 const client=new AccountClient({imei:record.imei,token:oldToken,profile:record.profile,fetchImpl:()=>{throw Error('unexpected network');}});
 await assert.rejects(client.request('eitaaRefreshToken'),{reason:'recovery_storage_required'});client.close();
 assert.equal(recovery.valid({...saved,method:'auth.signIn'}),false);
});

test('failed recovery cleanup remains retryable after the rotated token was saved',async t=>{
 const f=await fixture(t,{failClear:true});
 await assert.rejects(f.session.refresh(),{reason:'recovery_save_failed'});
 assert.equal((await f.vault.load('eitaa',1)).token,newToken);
 assert.equal(f.session.state.signedIn,false);
 assert.equal(await f.vault.hasRefreshRecovery('eitaa',1),true);
 f.controls.failClear=false;
 await f.session.resume();
 assert.equal(f.events.filter(event=>event==='refresh').length,1);
 assert.equal(f.session.state.signedIn,true);
 assert.equal(await f.vault.hasRefreshRecovery('eitaa',1),false);
});

test('closing during response persistence keeps the sealed recovery and prevents late authentication',async t=>{
 let entered,release;
 const captured=new Promise(resolve=>{entered=resolve;});
 const gate=new Promise(resolve=>{release=resolve;});
 const f=await fixture(t,{afterArchive:async()=>{entered();await gate;}});
 const pending=f.session.refresh();
 const rejected=assert.rejects(pending,{reason:'closed'});
 await captured;f.session.close();release();await rejected;
 assert.equal(await f.vault.hasRefreshRecovery('eitaa',1),true);
 assert.equal((await f.vault.load('eitaa',1)).token,oldToken);
 assert.equal(f.session.state.hasSession,false);
 assert.ok(f.frames[0].every(byte=>byte===0));
});

test('a pre-request persistence failure sends no refresh request',async t=>{
 const f=await fixture(t,{failIntent:true});
 await assert.rejects(f.session.refresh(),{reason:'recovery_save_failed'});
 assert.deepEqual(f.events,['archive']);
 assert.equal((await f.vault.load('eitaa',1)).token,oldToken);
 assert.equal(await f.vault.hasRefreshRecovery('eitaa',1),false);
});

test('a post-write persistence failure cannot overwrite its intent or send a second rotation',async t=>{
 const f=await fixture(t,{failIntentAfterSave:true});
 await assert.rejects(f.session.refresh(),{reason:'recovery_save_failed'});
 const saved=await f.vault.loadRefreshRecovery('eitaa',1);
 assert.equal(saved.phase,'requested');
 f.controls.failIntentAfterSave=false;
 await assert.rejects(f.session.refresh(),{reason:'recovery_save_failed'});
 assert.equal(f.events.filter(event=>event==='refresh').length,0);
 assert.equal((await f.vault.loadRefreshRecovery('eitaa',1)).requestId,saved.requestId);
});

test('closing before the HTTP reply leaves a durable pending intent that blocks rotation after restart',async t=>{
 let entered,release;
 const sent=new Promise(resolve=>{entered=resolve;});
 const gate=new Promise(resolve=>{release=resolve;});
 const f=await fixture(t,{beforeRefreshResponse:async()=>{entered();await gate;}});
 const pending=f.session.refresh();
 const rejected=assert.rejects(pending,{reason:'closed'});
 await sent;f.session.close();release();await rejected;
 const saved=await f.vault.loadRefreshRecovery('eitaa',1);
 assert.equal(saved.phase,'requested');
 assert.equal(saved.frame,null);
 assert.equal(f.frames.length,0);
 let requests=0;
 const restored=new AuthSession({saveRefreshRecovery:async()=>{},clearRefreshRecovery:async()=>{},createClient:()=>{requests++;throw Error('unexpected request');}});
 await assert.rejects(restored.restoreWithRefreshRecovery(record,saved),{reason:'refresh_result_unavailable'});
 await assert.rejects(restored.refresh(),{reason:'refresh_recovery_required'});
 assert.equal(requests,0);
 restored.close();
});

test('recovering a native token update preserves its valid socket credential with the rotated token',async()=>{
 const nativeRecord={...record,imei:'ef67ce90-1234-4123-9123-ef67ce901234',profile:{...record.profile,protocolProfile:profiles.ANDROID}};
 const saved=recovery.create(update(),nativeRecord);
 let stored;
 const requests=[];
 const session=new AuthSession({saveRefreshRecovery:async()=>{},clearRefreshRecovery:async()=>{},saveSession:async value=>{stored=value;},createClient:()=>({
  close(){},setToken(){},async request(method){requests.push(method);assert.equal(method,'users.getUsers');return [user];}
 })});
 try{
  await session.restoreWithRefreshRecovery(nativeRecord,saved);
  assert.equal(stored.token,newToken);
  assert.equal(stored.nativeSocketCredential.token,'s'.repeat(56));
  assert.equal(require('../experiments/eitaa/socket-credential.cjs').valid(stored.nativeSocketCredential,stored),true);
  assert.deepEqual(requests,['users.getUsers']);
 }finally{session.close();}
});
