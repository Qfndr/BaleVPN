'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const profiles=require('../experiments/eitaa/client-profile.cjs'),wire=require('../experiments/eitaa/wire.cjs'),codec=require('../experiments/eitaa/auth-wire.cjs');
const {AccountClient,deviceProfile,SOCKET_RECOVERY_FRAME}=require('../experiments/eitaa/account-client.cjs'),{AuthSession}=require('../experiments/eitaa/auth-session.cjs');
const credentials=require('../experiments/eitaa/socket-credential.cjs');
const user={_:'user',id:45n,self:true,phone:'989120000001',first_name:'Fixture'},main='fixture-main-original',rotated='fixture-main-rotated',socket='fixture-socket-distinct';
// Repeated snapshots represent the SAME saved session. New-login device labels
// are random; generating a fresh profile here would compare unrelated sessions.
const fixtureProfile=Object.freeze(deviceProfile(profiles.ANDROID));
const record=()=>({provider:'eitaa',format:1,token:main,imei:'12345678-1234-4123-8123-123456789abc',userId:'45',loginPhone:'+989120000001',profile:{...fixtureProfile},name:'Fixture',deviceMetadataSent:false,authorizationAppendix:{format:'eitaa-auth-appendix-v1',constructorId:3439659286,flags:1024,value:'A'.repeat(56)}});
const update=()=>new wire.Writer().int(-1519642063).string(rotated).int(1900003600).int(1900000000).long(123456789n).string(socket).finish();
function fixture({frame=update(),failSave=false,saveRecovery=true,onSave=async()=>{},onRecovery=async()=>{}}={}){
 const events=[],saved=[],recovered=[],requests=[],frames=[];
 const fetchImpl=async(url,o)=>{assert.equal(url,profiles.ANDROID_ENDPOINT);const r=new wire.Reader(o.body);assert.equal(r.int(),2059302894);const token=r.string(),imei=r.string();assert.equal(imei,record().imei);assert.equal(r.int(),32);const packed=r.bytes();assert.equal(r.int(),138);assert.equal(r.int(),2637);assert.equal(r.string(),'fa');r.end();const method=packed.readInt32LE();requests.push({method,token});
  if(method===1653816932){assert.equal(packed.toString('hex'),'643e9362');events.push('socket');return new Response(frame);}
  assert.equal(method,227648840);events.push('self');return new Response(Buffer.concat([new wire.Writer().int(481674261).int(1).finish(),codec.object(user)]));
 };
 const session=new AuthSession({createClient:o=>{const client=new AccountClient({...o,fetchImpl});return {close:()=>client.close(),setToken:value=>client.setToken(value),async request(...args){const result=await client.request(...args);if(result?.[SOCKET_RECOVERY_FRAME])frames.push(result[SOCKET_RECOVERY_FRAME]);return result;}};},saveSession:async value=>{events.push('save');saved.push(structuredClone(value));if(failSave)throw Error('private disk error');await onSave(value);},...saveRecovery?{saveSocketRecovery:async value=>{events.push('recover');recovered.push(structuredClone(value));await onRecovery(value);}}:{}});
 return {session,events,saved,recovered,requests,fetchImpl,frames};
}

test('explicit native getSocketToken has exact four request bytes and seals distinct typed credentials before protected self read',async()=>{
 const f=fixture();await f.session.restore(record());f.events.length=0;f.requests.length=0;await f.session.obtainSocketCredential();
 assert.deepEqual(f.events,['socket','save','self']);assert.deepEqual(f.requests.map(x=>x.token),[main,rotated]);assert.equal(f.saved.length,1);const saved=f.saved[0];assert.equal(saved.token,rotated);assert.equal(saved.nativeSocketCredential.token,socket);assert.equal(saved.nativeSocketCredential.date,1900000000);assert.equal(saved.nativeSocketCredential.expire,1900003600);assert.equal(saved.nativeSocketCredential.messageId,'123456789');assert.equal(credentials.valid(saved.nativeSocketCredential,saved),true);assert.deepEqual(saved.authorizationAppendix,record().authorizationAppendix);
 assert.equal(f.frames.length,1);assert.ok(f.frames[0].every(v=>v===0));
 for(const secret of [main,rotated,socket,record().imei,'nativeSocketCredential'])assert.ok(!JSON.stringify(f.session.state).includes(secret));
 const exported=f.session.exportSession();exported.nativeSocketCredential.token='mutated';assert.equal(f.session.exportSession().nativeSocketCredential.token,socket);f.session.close();
 const restored=fixture();await restored.session.restore(saved);assert.deepEqual(restored.session.exportSession(),saved);assert.deepEqual(restored.requests.map(x=>x.method),[227648840]);restored.session.close();
});

test('a typed reply with rotated main token but empty socket token is archived privately before semantic rejection, leaving old disk session intact',async()=>{
 const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),{SessionVault}=require('../experiments/providers/session-vault.cjs');
 const base=path.resolve(os.tmpdir()),dir=await fs.mkdtemp(path.join(base,'eitaa-socket-semantic-'));assert.match(dir,/^E:[\\/]/i);const vault=new SessionVault(dir);let f;
 try{await vault.unlock('fixture-semantic-vault-passphrase');await vault.save('eitaa',1,record());const original=await fs.readFile(path.join(dir,'eitaa','1.json'),'utf8');
  const frame=new wire.Writer().int(-1519642063).string(rotated).int(1900003600).int(1900000000).long(123456789n).string('').finish();
  // The second slot is only an isolated encrypted archive fixture, never a
  // runtime account or production recovery route.
  f=fixture({frame,onSave:value=>vault.save('eitaa',1,value),onRecovery:value=>vault.save('eitaa',2,value)});await f.session.restore(await vault.load('eitaa',1));f.events.length=0;
  await assert.rejects(f.session.obtainSocketCredential(),{reason:'invalid_auth_response'});assert.deepEqual(f.events,['socket','recover']);assert.equal(f.saved.length,0);assert.equal(f.session.state.signedIn,false);assert.equal(f.session.state.stage,'socket_recovery_required');assert.equal(f.session.exportSession().token,main);
  assert.equal(await fs.readFile(path.join(dir,'eitaa','1.json'),'utf8'),original);assert.deepEqual(await vault.load('eitaa',1),record());
  const archive=await vault.load('eitaa',2);assert.equal(archive.format,'eitaa-socket-credential-recovery-v1');assert.equal(archive.frame,frame.toString('base64'));assert.equal(archive.imei,record().imei);assert.equal(archive.userId,'45');assert.equal(f.frames.length,1);assert.ok(f.frames[0].every(v=>v===0));
  const disk=await fs.readFile(path.join(dir,'eitaa','2.json'),'utf8');for(const secret of [main,rotated,archive.frame,record().imei])assert.ok(!disk.includes(secret));assert.ok(!JSON.stringify(f.session.state).includes(archive.frame));
 }finally{f?.session.close();vault.lock();const target=path.resolve(dir);if(!target.startsWith(base+path.sep)||!path.basename(target).startsWith('eitaa-socket-semantic-'))throw Error('Unexpected cleanup target');await fs.rm(target,{recursive:true,force:true,maxRetries:5,retryDelay:100});}
});

test('Web default cannot request a native socket credential and no operation runs without private recovery storage',async()=>{
 const client=new AccountClient({imei:'0123456789abcde__web',token:main,fetchImpl:()=>{throw Error('Unexpected I/O');}});await assert.rejects(client.request('eitaaGetSocketToken'),{reason:'profile_refresh_unavailable'});assert.throws(()=>codec.method('eitaaGetSocketToken',{}));client.close();
 const f=fixture({saveRecovery:false});await f.session.restore(record());const count=f.requests.length;await assert.rejects(f.session.obtainSocketCredential(),{reason:'recovery_storage_required'});assert.equal(f.requests.length,count);assert.deepEqual(f.session.exportSession(),record());f.session.close();
});

test('a failed encrypted credential save preserves rotated tokens in memory and cannot issue a self-read or retry',async()=>{
 const f=fixture({failSave:true});await f.session.restore(record());f.events.length=0;await assert.rejects(f.session.obtainSocketCredential(),{reason:'session_save_failed'});assert.deepEqual(f.events,['socket','save']);assert.equal(f.session.state.signedIn,false);assert.equal(f.session.exportSession().token,rotated);assert.equal(f.session.exportSession().nativeSocketCredential.token,socket);await assert.rejects(f.session.obtainSocketCredential(),{reason:'not_authenticated'});assert.deepEqual(f.events,['socket','save']);f.session.close();
});

test('undecodable native credential responses use separate sealed purpose-specific recovery without another account request',async()=>{
 const frame=Buffer.from([0xef,0xbe,0xad,0xde]),f=fixture({frame});await f.session.restore(record());f.events.length=0;await assert.rejects(f.session.obtainSocketCredential());assert.deepEqual(f.events,['socket','recover']);assert.equal(f.recovered.length,1);const archived=f.recovered[0];assert.equal(archived.format,'eitaa-socket-credential-recovery-v1');assert.equal(archived.frame,frame.toString('base64'));assert.equal(archived.userId,'45');assert.equal(archived.imei,record().imei);assert.equal(archived.profile.protocolProfile,profiles.ANDROID);assert.ok(!JSON.stringify(archived).includes(main));assert.equal(f.session.exportSession().token,main);assert.equal(f.session.state.signedIn,false);assert.equal(f.session.state.stage,'socket_recovery_required');assert.ok(!JSON.stringify(f.session.state).includes(archived.frame));f.session.close();
 const client=new AccountClient({imei:record().imei,profile:record().profile,token:main,captureSocketRecovery:true,fetchImpl:f.fetchImpl});await assert.rejects(client.request('eitaaGetSocketToken'),e=>{assert.deepEqual(e[SOCKET_RECOVERY_FRAME],frame);assert.equal(Object.getOwnPropertyDescriptor(e,SOCKET_RECOVERY_FRAME).enumerable,false);e[SOCKET_RECOVERY_FRAME].fill(0);return true;});client.close();
});

test('typed credential substitution, malformed expiry metadata and unexpected fields fail before restore I/O',async()=>{
 const f=fixture();await f.session.restore(record());await f.session.obtainSocketCredential();const saved=f.session.exportSession();f.session.close();
 for(const changes of [{imei:'12345678-1234-4123-9123-123456789abc'},{userId:'99'},{httpTokenSha256:'0'.repeat(64)},{protocolProfile:'web'},{expire:-1},{date:0x80000000},{messageId:'01'},{extra:'bad'},{token:''}]){const s=new AuthSession({createClient:()=>{throw Error('Unexpected I/O');}});await assert.rejects(s.restore({...saved,nativeSocketCredential:{...saved.nativeSocketCredential,...changes}}),{reason:'invalid_saved_session'});s.close();}
});

test('native credential acquisition is single-flight and a late response after close cannot persist or revive an account',async()=>{
 let release,entered;const started=new Promise(r=>{entered=r;}),saved=[];const session=new AuthSession({saveSession:async value=>saved.push(value),saveSocketRecovery:async()=>{},createClient:()=>({setToken(){},close(){},async request(name){if(name==='users.getUsers')return [user];assert.equal(name,'eitaaGetSocketToken');entered();return new Promise(r=>{release=()=>r(codec.forProfile(profiles.ANDROID).response(update(),'eitaaGetSocketToken'));});}})});
 await session.restore(record());const pending=session.obtainSocketCredential();await started;await assert.rejects(session.obtainSocketCredential(),{reason:'account_busy'});session.close();release();await assert.rejects(pending,{reason:'closed'});assert.deepEqual(saved,[]);assert.equal(session.state.hasSession,false);assert.equal(session.state.signedIn,false);
});

test('a failed socket response recovery save stays disconnected, wipes the captured buffer and sends no further request',async()=>{
 const privateFrame=Buffer.from([0xef,0xbe,0xad,0xde]),failure=new wire.WireError('unknown_constructor');Object.defineProperty(failure,SOCKET_RECOVERY_FRAME,{value:privateFrame});const calls=[];
 const s=new AuthSession({saveSocketRecovery:async()=>{throw Error('private archive failure');},createClient:()=>({setToken(){},close(){},async request(name){calls.push(name);if(name==='users.getUsers')return [user];throw failure;}})});await s.restore(record());await assert.rejects(s.obtainSocketCredential(),{reason:'recovery_save_failed'});assert.deepEqual(calls,['users.getUsers','eitaaGetSocketToken']);assert.ok(privateFrame.every(v=>v===0));assert.equal(s.state.signedIn,false);assert.equal(s.exportSession().token,main);assert.ok(!JSON.stringify(s.state).includes('private archive failure'));s.close();
});
