const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {startLab,startupOptions}=require('../experiments/providers/lab.cjs');
const {FakeCallAuth,FakeNasimAuth,FakeRubikaAuth,eitaaFixture,fakeBridgeFactory,fakeNasimBridgeFactory}=require('./provider-lab-fixture.cjs');

async function fixture(fn,{native=false,nasimNative=false,nasimOpenBridge,nasimAsymmetric=false,eitaaNative=false,privacyOperation=require('./provider-privacy-fixture.cjs').allow}={}){const dir=await fs.mkdtemp(path.join(os.tmpdir(),'provider-lab-test-')),calls=[],eitaaHarness=require('./eitaa-lab-call-fixture.cjs').fixture(calls);const lab=await startLab({privacyOperation,directory:dir,port:0,nasimAsymmetric,...native?{bridgeExecutable:path.resolve('fixture-native-helper'),openBridge:fakeBridgeFactory()}:{},...nasimNative?{nasimBridgeExecutable:path.resolve('fixture-nasim-helper'),nasimOpenBridge:nasimOpenBridge||fakeNasimBridgeFactory()}:{},...eitaaNative?{eitaaBridgeExecutable:path.resolve('fixture-eitaa-helper'),eitaaOpenBridge:eitaaHarness.open,eitaaCallClientFactory:eitaaHarness.createClient,eitaaAccountClientFactory:eitaaHarness.createAccountClient}:{},eitaaSessionFactory:(slot,options)=>eitaaFixture(slot,calls,options,{ack:slot===1,challenge:slot===2}),rubikaSessionFactory:(slot,options)=>new FakeRubikaAuth(slot,calls,options),nasimSessionFactory:slot=>new FakeNasimAuth(slot,calls),sessionFactory:(slot,onPush)=>new FakeCallAuth(slot,calls,onPush)});const key=new URL(lab.url).hash.slice(1);
 const request=async(route,body,headers={})=>fetch(lab.origin+route,{method:body===undefined?'GET':'POST',headers:{Authorization:'Bearer '+key,...body===undefined?{}:{Origin:lab.origin,'Content-Type':'application/json'},...headers},body:body===undefined?undefined:JSON.stringify(body)});
 try{await fn({lab,request,dir,calls,key,eitaaHarness});}finally{await lab.close();if(!path.resolve(dir).startsWith(path.resolve(os.tmpdir())+path.sep)||!path.basename(dir).startsWith('provider-lab-test-'))throw Error('Unexpected fixture cleanup target');await fs.rm(dir,{recursive:true,force:true,maxRetries:5,retryDelay:100});}
}

test('Nasim asymmetric startup requires its own absolute helper and explicit flag',async()=>{
 const directory=path.join(os.tmpdir(),'provider-lab-unused'),helper=path.resolve('fixture-nasim-helper'),base=['--data-dir',directory];
 assert.equal(startupOptions([...base,'--nasim-bridge',helper]).nasimAsymmetric,false);
 assert.equal(startupOptions([...base,'--nasim-bridge',helper,'--nasim-asymmetric']).nasimAsymmetric,true);
 assert.throws(()=>startupOptions([...base,'--nasim-asymmetric','--bridge',helper]));
 assert.throws(()=>startupOptions([...base,'--nasim-asymmetric','--nasim-bridge','relative-helper']));
 await assert.rejects(startLab({directory,port:0,nasimAsymmetric:true}),/Nasim asymmetric mode requires/);
});

test('Nasim opt-in reports its same-host reference scope without changing other provider capabilities',async()=>{
 let strict;
 await fixture(async({request})=>{strict=await(await request('/api/state')).json();},{nasimNative:true});
 assert.equal(strict.nasimMedia.routeMode,'relay-only');assert.equal(strict.nasimMedia.referenceTransferScope,null);
 await fixture(async({request,calls})=>{
  const state=await(await request('/api/state')).json();
  assert.equal(state.nasimMedia.routeMode,'client-relay/server-public');assert.equal(state.nasimMedia.referenceTransferScope,'same-host');
  assert.equal(state.nasimMedia.vpsVerified,false);assert.equal(state.nasimMedia.billingVerified,false);assert.equal(state.nasimMedia.internationalOutageVerified,false);
  for(const field of ['capabilities','media','eitaaMedia','rubikaMedia'])assert.deepEqual(state[field],strict[field]);
  assert.equal(calls.length,0);
 },{nasimNative:true,nasimAsymmetric:true});
});

test('Nasim cleanup does not need a native helper after a saved-intent restart',()=>fixture(async({request,calls,dir})=>{
 const password='fixture-passphrase-123';await request('/api/vault/unlock',{password});
 for(const slot of [1,2]){await request('/api/nasim/'+slot+'/start',{country:'IR',phone:'09120000001'});await request('/api/nasim/'+slot+'/verify',{code:'12345'});}
 const {SessionVault}=require('../experiments/providers/session-vault.cjs'),{CleanupIntent}=require('../experiments/nasim/cleanup-intent.cjs');
 const seed=new SessionVault(dir);await seed.unlock(password);
 try{const record=await seed.load('nasim',1),account={state:{...record,signedIn:true},exportSession:()=>record};
  const manager=new CleanupIntent(account,{saveIntent:value=>seed.saveCleanupIntent('nasim',1,value),loadIntent:()=>seed.loadCleanupIntent('nasim',1),clearIntent:value=>seed.removeCleanupIntent('nasim',1,value)});
  await manager.capture({peerId:'42',callUUID:'fixture-restarted-call'});
 }finally{seed.lock();}
 const before=await(await request('/api/state')).json();assert.equal(before.nasimMedia.available,false);assert.equal(before.providerAccounts.nasim[0].cleanupStored,true);
 const response=await request('/api/nasim/media/cleanup',{slot:1});assert.equal(response.status,200);assert.equal((await response.json()).serviceAcknowledged,true);
 const after=await(await request('/api/state')).json();assert.equal(after.providerAccounts.nasim[0].cleanupStored,false);
 assert.deepEqual(calls.filter(c=>c.action==='nasim-signal').map(c=>c.type),['bye']);
}));

test('Nasim reset preserves sealed cleanup intents and blocks a fresh call until explicit cleanup',()=>fixture(async({request,calls})=>{
 await request('/api/vault/unlock',{password:'fixture-passphrase-123'});
 for(const slot of [1,2]){await request('/api/nasim/'+slot+'/start',{country:'IR',phone:'09120000001'});await request('/api/nasim/'+slot+'/verify',{code:'12345'});}
 assert.equal((await request('/api/nasim/media/prepare',{clientSlot:1,socksPort:1090})).status,200);
 assert.equal((await request('/api/nasim/media/dial',{slot:1})).status,200);
 await waitForLab(request,s=>s.providerAccounts.nasim.every(a=>a.cleanupStored));await request('/api/nasim/media/reset',{});
 const blocked=await request('/api/nasim/media/prepare',{clientSlot:1,socksPort:1090});assert.equal(blocked.status,400);assert.equal((await blocked.json()).reason,'cleanup_pending');
 const before=calls.filter(c=>c.action==='nasim-signal').length;
 for(const slot of [1,2]){const response=await request('/api/nasim/media/cleanup',{slot});assert.equal(response.status,200);assert.equal((await response.json()).serviceAcknowledged,true);}
 assert.equal(calls.filter(c=>c.action==='nasim-signal').length,before+2);
 const state=await(await request('/api/state')).json();assert.ok(state.providerAccounts.nasim.every(a=>!a.cleanupStored));
 assert.equal((await request('/api/nasim/media/prepare',{clientSlot:1,socksPort:1090})).status,200);
},{nasimNative:true}));

test('every provider blocks a new login over an unloaded encrypted session without any account request or file replacement',()=>fixture(async({request,calls,dir})=>{
 const {SessionVault}=require('../experiments/providers/session-vault.cjs'),seed=new SessionVault(dir),providers=['igap','nasim','rubika','eitaa'],password='fixture-retained-session-passphrase',originals=new Map();
 try{await seed.unlock(password);for(const provider of providers){const record={provider,token:'fixture-retained-private-'+provider,fixture:'unloaded-session'};await seed.save(provider,1,record);const disk=await fs.readFile(path.join(dir,provider,'1.json'),'utf8');assert.ok(!disk.includes(record.token));originals.set(provider,{record,disk});}}finally{seed.lock();}
 for(const provider of providers)assert.equal((await request('/api/'+provider+'/1/start',{country:'IR',phone:'09120000001'})).status,423);
 assert.equal(calls.length,0);await request('/api/vault/unlock',{password});const state=await(await request('/api/state')).json();
 for(const provider of providers){const account=provider==='igap'?state.accounts[0]:state.providerAccounts[provider][0];assert.equal(account.hasSession,false);assert.equal(account.stored,true);
  const result=await request('/api/'+provider+'/1/start',{country:'IR',phone:'09120000001',...provider==='eitaa'?{protocolProfile:'android-7.1.8-compat'}:provider==='rubika'?{protocolProfile:'android-4.1.1-compat'}:{}});assert.equal(result.status,400);assert.equal((await result.json()).reason,'already_signed_in');assert.equal(calls.length,0);assert.equal(await fs.readFile(path.join(dir,provider,'1.json'),'utf8'),originals.get(provider).disk);
 }
 await request('/api/vault/lock',{});try{await seed.unlock(password);for(const provider of providers)assert.deepEqual(await seed.load(provider,1),originals.get(provider).record);}finally{seed.lock();}
}));

test('two Eitaa HTTP accounts distinguish bare acknowledgement, handle password and restore sealed identities without another login',()=>fixture(async({request,calls,dir})=>{
 assert.equal((await request('/api/eitaa/1/start',{country:'IR',phone:'09120000001'})).status,423);assert.equal(calls.length,0);
 await request('/api/vault/unlock',{password:'fixture-passphrase-123'});
 const start=await(await request('/api/eitaa/1/start',{country:'IR',phone:'09120000001'})).json();assert.equal(start.acknowledged,true);assert.equal(start.codeRequested,false);
 let state=await(await request('/api/state')).json();assert.equal(state.providerAccounts.eitaa[0].codeHashSource,'localCompatibility');assert.equal(state.providerAccounts.eitaa[0].signedIn,false);
 assert.equal((await request('/api/eitaa/1/verify',{code:'123456'})).status,200);
 await request('/api/eitaa/2/start',{country:'IR',phone:'09120000002'});const challenge=await(await request('/api/eitaa/2/verify',{code:'123456'})).json();assert.equal(challenge.twoFactorRequired,true);assert.equal((await request('/api/eitaa/2/password',{password:'fixture-password'})).status,200);
 state=await(await request('/api/state')).json();assert.ok(state.providerAccounts.eitaa.every(a=>a.signedIn&&a.stored));assert.ok(state.accounts.every(a=>!a.signedIn));assert.ok(state.providerAccounts.rubika.every(a=>!a.signedIn));assert.equal(state.capabilities.eitaa.tunnelReady,false);assert.equal((await request('/api/eitaa/1/call/dial',{})).status,404);
 const publicState=JSON.stringify(state);for(const secret of ['fixture-eitaa-token','fixture-eitaa-code-hash','fixture-password','+989120000001','"imei"'])assert.ok(!publicState.includes(secret));
 for(const slot of [1,2]){const disk=await fs.readFile(path.join(dir,'eitaa',slot+'.json'),'utf8');assert.ok(!disk.includes('fixture-eitaa-token'));}
 await request('/api/vault/lock',{});state=await(await request('/api/state')).json();assert.ok(state.providerAccounts.eitaa.every(a=>!a.hasSession&&a.stored));await request('/api/vault/unlock',{password:'fixture-passphrase-123'});
 const storedBefore=await fs.readFile(path.join(dir,'eitaa','1.json'),'utf8'),callsBefore=calls.length;
 assert.equal((await(await request('/api/eitaa/1/start',{country:'IR',phone:'09120000001',protocolProfile:'android-7.1.8-compat'})).json()).reason,'already_signed_in');assert.equal(calls.length,callsBefore);assert.equal(await fs.readFile(path.join(dir,'eitaa','1.json'),'utf8'),storedBefore);
 for(const slot of [1,2])assert.equal((await request('/api/eitaa/'+slot+'/resume',{})).status,200);
 assert.equal(calls.filter(c=>c.action==='eitaa-auth.sendCode').length,2);assert.equal(calls.filter(c=>c.action==='eitaa-auth.signIn').length,2);assert.equal(calls.filter(c=>c.action==='eitaa-users.getUsers').length,4);
 await request('/api/eitaa/1/forget',{});state=await(await request('/api/state')).json();assert.equal(state.providerAccounts.eitaa[0].stored,false);assert.equal(state.providerAccounts.eitaa[1].signedIn,true);
}));

test('Eitaa HTTP resume recovers a sealed refresh response before any new token rotation',()=>fixture(async({request,calls,dir})=>{
 const password='fixture-refresh-http-passphrase';
 await request('/api/vault/unlock',{password});
 await request('/api/eitaa/1/start',{country:'IR',phone:'09120000001'});
 await request('/api/eitaa/1/verify',{code:'123456'});
 const {SessionVault}=require('../experiments/providers/session-vault.cjs');
 const {create}=require('../experiments/eitaa/refresh-recovery.cjs');
 const codec=require('../experiments/eitaa/auth-wire.cjs');
 const vault=new SessionVault(dir);
 await vault.unlock(password);
 try{
  const record=await vault.load('eitaa',1);
  const frame=codec.object({_:'eitaa_updates_token',token:'fixture-recovered-refresh-token',date:100,expire:200});
  await vault.saveRefreshRecovery('eitaa',1,create(frame,record));
 }finally{vault.lock();}
 await request('/api/vault/lock',{});
 await request('/api/vault/unlock',{password});
 const before=calls.length;
 assert.equal((await(await request('/api/eitaa/1/refresh',{})).json()).reason,'refresh_recovery_required');
 assert.equal(calls.length,before);
 const response=await request('/api/eitaa/1/resume',{});
 assert.equal(response.status,200);
 const state=await(await request('/api/state')).json();
 assert.equal(state.providerAccounts.eitaa[0].signedIn,true);
 assert.equal(state.providerAccounts.eitaa[0].refreshRecoveryStored,false);
 assert.deepEqual(calls.slice(before).map(call=>call.action),['eitaa-users.getUsers']);
 assert.ok(!JSON.stringify(state).includes('fixture-recovered-refresh-token'));
}));

test('call privacy routes require vault, account and same-origin access and auto-check both call accounts',async()=>{
 const operations=[];await fixture(async({request})=>{
  assert.equal((await request('/api/igap/1/call-privacy')).status,423);await request('/api/vault/unlock',{password:'fixture-passphrase-123'});assert.equal((await request('/api/igap/1/call-privacy')).status,400);
  for(const slot of [1,2]){await request('/api/igap/'+slot+'/start',{country:'IR',phone:'09120000001'});await request('/api/igap/'+slot+'/verify',{code:'12345'});}
  assert.equal((await request('/api/igap/1/allow-calls',{}, {Origin:'https://foreign.invalid'})).status,403);assert.equal((await request('/api/igap/1/allow-calls',{settings:{anything:true}})).status,400);assert.equal(operations.length,0);
  const read=await(await request('/api/igap/1/call-privacy')).json();assert.equal(read.callPrivacy.mode,'contacts');await request('/api/igap/1/allow-calls',{});let state=await(await request('/api/state')).json();assert.equal(state.accounts[0].callPrivacy.allowedForEveryone,true);assert.equal(state.accounts[1].callPrivacy,null);
  assert.equal((await request('/api/igap/1/call/dial',{targetSlot:2})).status,200);assert.deepEqual(operations.map(v=>v.allow),[false,true,true]);assert.notEqual(operations[1].userId,operations[2].userId);
  await request('/api/igap/1/stop',{});state=await(await request('/api/state')).json();assert.equal(state.accounts[0].callPrivacy,null);
 },{privacyOperation:async(provider,account,{allow})=>{operations.push({provider,userId:account.state.userId,allow});return {supported:true,verified:true,mode:allow?'everyone':'contacts',allowedForEveryone:allow,changed:allow};}});
});

test('unverified call permission blocks dialing without sending a call',()=>fixture(async({request,calls})=>{
 await request('/api/vault/unlock',{password:'fixture-passphrase-123'});for(const slot of [1,2]){await request('/api/igap/'+slot+'/start',{country:'IR',phone:'09120000001'});await request('/api/igap/'+slot+'/verify',{code:'12345'});}const before=calls.length;
 const reply=await(await request('/api/igap/1/call/dial',{targetSlot:2})).json();assert.equal(reply.reason,'privacy_not_applied');assert.equal(calls.length,before);
},{privacyOperation:async()=>({supported:true,verified:false,mode:'everyone',allowedForEveryone:true,changed:true})}));

test('a late privacy response after vault lock and same-account restore cannot populate the cache',async()=>{
 let resolve,signal,first=true;await fixture(async({request})=>{
  await request('/api/vault/unlock',{password:'fixture-passphrase-123'});await request('/api/igap/1/start',{country:'IR',phone:'09120000001'});await request('/api/igap/1/verify',{code:'12345'});
  const pending=request('/api/igap/1/allow-calls',{});const deadline=Date.now()+2000;while(!resolve){if(Date.now()>deadline)throw Error('Privacy fixture did not start');await new Promise(r=>setTimeout(r,5));}
  await request('/api/vault/lock',{});assert.equal(signal.aborted,true);await request('/api/vault/unlock',{password:'fixture-passphrase-123'});await request('/api/igap/1/resume',{});resolve({supported:true,verified:true,mode:'everyone',allowedForEveryone:true});assert.equal((await(await pending).json()).reason,'account_binding_changed');const state=await(await request('/api/state')).json();assert.equal(state.accounts[0].callPrivacy,null);assert.equal((await request('/api/igap/1/call-privacy')).status,200);
 },{privacyOperation:async(_provider,_account,options)=>{if(first){first=false;signal=options.signal;return new Promise(r=>{resolve=r;});}return {supported:true,verified:true,mode:'everyone',allowedForEveryone:true};}});
});

test('changing account one while account two privacy is pending cannot authorize a dial',async()=>{
 let resolve;await fixture(async({request,calls})=>{
  await request('/api/vault/unlock',{password:'fixture-passphrase-123'});for(const slot of [1,2]){await request('/api/igap/'+slot+'/start',{country:'IR',phone:'09120000001'});await request('/api/igap/'+slot+'/verify',{code:'12345'});}
  const pending=request('/api/igap/1/call/dial',{targetSlot:2}),deadline=Date.now()+2000;while(!resolve){if(Date.now()>deadline)throw Error('Second permission check did not start');await new Promise(r=>setTimeout(r,5));}
  await request('/api/igap/1/resume',{});const before=calls.length;resolve({supported:true,verified:true,mode:'everyone',allowedForEveryone:true});assert.equal((await(await pending).json()).reason,'account_binding_changed');assert.equal(calls.length,before);
 },{privacyOperation:async(_provider,account)=>account.state.userId==='2'?new Promise(r=>{resolve=r;}):{supported:true,verified:true,mode:'everyone',allowedForEveryone:true}});
});

async function waitForLab(request,predicate){const deadline=Date.now()+2000;while(true){const state=await(await request('/api/state')).json();if(predicate(state))return state;if(Date.now()>deadline)throw Error('Laboratory call state timed out');await new Promise(r=>setTimeout(r,5));}}
async function eitaaLogin(request){await request('/api/vault/unlock',{password:'fixture-passphrase-123'});for(const slot of [1,2]){await request('/api/eitaa/'+slot+'/start',{country:'IR',phone:'0912000000'+slot});await request('/api/eitaa/'+slot+'/verify',{code:'123456'});if(slot===2)await request('/api/eitaa/2/password',{password:'fixture-password'});}}
test('Eitaa HTTP media uses local two-account targets and explicit call/accept, without exposing hashes, certificates or relay data',()=>fixture(async({request,calls,eitaaHarness})=>{
 assert.equal((await request('/api/eitaa/media/prepare',{})).status,423);await eitaaLogin(request);
 assert.equal((await request('/api/eitaa/media/prepare',{clientSlot:1,socksPort:1091,throughput:true})).status,200);assert.equal(calls.filter(c=>c.action==='eitaa-call-phone.requestCall').length,0);
 assert.equal((await request('/api/eitaa/media/dial',{slot:1})).status,200);let state=await(await request('/api/state')).json();assert.equal(state.eitaaMedia.accounts[1].phase,'ringing');assert.equal(calls.filter(c=>c.action==='eitaa-call-phone.acceptCall').length,0);
 assert.equal((await request('/api/eitaa/media/accept',{slot:2})).status,200);state=await(await request('/api/state')).json();assert.equal(state.eitaaMedia.phase,'connected');assert.equal(state.eitaaMedia.accounts[0].media.socksAddress,'127.0.0.1:1091');assert.equal(state.eitaaMedia.accounts[1].media.serverReady,true);assert.equal(state.eitaaMedia.accounts[1].media.proxyReady,false);
 for(const value of ['fixture-turn','fixture-eitaa-token','__web','publicCertificate','trustedCertificates','accessHash','-1001'])assert.ok(!JSON.stringify(state).includes(value));
 await request('/api/rubika/1/stop',{});state=await(await request('/api/state')).json();assert.equal(state.eitaaMedia.phase,'connected');
 assert.equal((await request('/api/vault/lock',{})).status,200);state=await(await request('/api/state')).json();assert.equal(state.eitaaMedia.phase,'uncertain');assert.equal(state.eitaaMedia.canPrepare,false);assert.ok(eitaaHarness.natives.every(n=>n.state.phase==='closed'));assert.ok(state.providerAccounts.eitaa.every(a=>!a.signedIn&&a.stored));
},{eitaaNative:true}));
test('Eitaa media HTTP rejects injected trust/SDP, invalid slots and unsigned accounts; auth stop invalidates both call owners',()=>fixture(async({request,eitaaHarness})=>{
 await request('/api/vault/unlock',{password:'fixture-passphrase-123'});assert.equal((await request('/api/eitaa/media/prepare',{})).status,400);await eitaaLogin(request);
 for(const body of [{clientSlot:1,socksPort:80},{clientSlot:1,token:'private'},{clientSlot:1,trustedCertificates:['private']},{clientSlot:3}])assert.equal((await request('/api/eitaa/media/prepare',body)).status,400);
 assert.equal((await request('/api/eitaa/media/prepare',{clientSlot:2,socksPort:1092})).status,200);assert.equal((await request('/api/eitaa/media/dial',{slot:3})).status,400);assert.equal((await request('/api/eitaa/media/dial',{slot:1,sdp:'private'})).status,400);
 await request('/api/eitaa/1/stop',{});const state=await(await request('/api/state')).json();assert.equal(state.eitaaMedia.phase,'ended');assert.ok(eitaaHarness.natives.every(n=>n.state.phase==='closed'));assert.equal(state.providerAccounts.eitaa[1].signedIn,true);
},{eitaaNative:true}));
test('Rubika accounts seal private keys independently and restore without creating another login or touching the other providers',()=>fixture(async({request,dir,calls})=>{
 assert.equal((await request('/api/rubika/1/start',{country:'IR',phone:'09120000001'})).status,423);
 await request('/api/vault/unlock',{password:'fixture-passphrase-123'});
 for(const provider of ['rubika','igap','nasim'])for(const slot of [1,2]){
  assert.equal((await request('/api/'+provider+'/'+slot+'/start',{country:'IR',phone:'09120000001'})).status,200);
  assert.equal((await request('/api/'+provider+'/'+slot+'/verify',{code:provider==='rubika'?'123456':'12345'})).status,200);
 }
 let state=await(await request('/api/state')).json();assert.ok(state.providerAccounts.rubika.every(a=>a.signedIn&&a.stored));assert.equal(state.capabilities.rubika.loginLab,true);assert.equal(state.capabilities.rubika.tunnelReady,false);
 for(const slot of [1,2]){const encrypted=await fs.readFile(path.join(dir,'rubika',slot+'.json'),'utf8');assert.ok(!encrypted.includes('fixture-rubika-private-key'));assert.ok(!encrypted.includes('fixture-rubika-auth'));}
 for(const secret of ['fixture-rubika-private-key','fixture-rubika-auth','989120000001'])assert.ok(!JSON.stringify(state).includes(secret));
 await request('/api/rubika/1/stop',{});state=await(await request('/api/state')).json();assert.equal(state.providerAccounts.rubika[0].hasSession,true);assert.equal(state.providerAccounts.rubika[0].signedIn,false);
 assert.ok(state.accounts.every(a=>a.signedIn));assert.ok(state.providerAccounts.nasim.every(a=>a.signedIn));
 await request('/api/vault/lock',{});await request('/api/vault/unlock',{password:'fixture-passphrase-123'});
 assert.equal((await request('/api/rubika/1/resume',{})).status,200);assert.equal(calls.filter(c=>c.action==='rubika-start').length,2);assert.equal(calls.filter(c=>c.action==='rubika-verify').length,2);assert.equal(calls.at(-1).action,'rubika-restore');
 await request('/api/rubika/2/forget',{});state=await(await request('/api/state')).json();assert.equal(state.providerAccounts.rubika[1].stored,false);assert.ok(state.accounts.every(a=>a.stored));assert.ok(state.providerAccounts.nasim.every(a=>a.stored));
 assert.equal((await request('/api/rubika/1/events/connect',{})).status,404);assert.equal((await request('/api/rubika/1/call/dial',{})).status,404);
}));
test('Nasim media control prepares only local distinct accounts, needs explicit call/accept and keeps all transport secrets private',()=>fixture(async({request,calls})=>{
 assert.equal((await request('/api/nasim/media/prepare',{clientSlot:1,socksPort:1090,throughput:true})).status,423);
 await request('/api/vault/unlock',{password:'fixture-passphrase-123'});
 assert.equal((await request('/api/nasim/media/prepare',{})).status,400);
 for(const provider of ['nasim','igap'])for(const slot of [1,2]){await request('/api/'+provider+'/'+slot+'/start',{country:'IR',phone:'09120000001'});await request('/api/'+provider+'/'+slot+'/verify',{code:'12345'});}
 for(const body of [{clientSlot:3},{socksPort:80},{throughput:'true'},{url:'turn:foreign.invalid'}])assert.equal((await request('/api/nasim/media/prepare',body)).status,400);
 assert.equal((await request('/api/nasim/media/prepare',{clientSlot:1,socksPort:1090,throughput:true})).status,200);
 let state=await waitForLab(request,s=>s.nasimMedia.accounts.every(c=>c.phase==='ready'));assert.ok(state.accounts.every(a=>a.signedIn));
 assert.equal(calls.filter(c=>c.action==='nasim-signal').length,0);
 assert.equal((await request('/api/nasim/media/accept',{slot:2})).status,400);
 assert.equal((await request('/api/nasim/media/dial',{slot:1})).status,200);
 state=await waitForLab(request,s=>s.nasimMedia.accounts[1].phase==='incoming');assert.equal(state.nasimMedia.accounts[1].media.phase,'prepared');
 assert.equal((await request('/api/nasim/media/accept',{slot:2})).status,200);
 state=await waitForLab(request,s=>s.nasimMedia.accounts.every(c=>c.phase==='connected'));
 assert.equal(state.nasimMedia.accounts[0].media.socksAddress,'127.0.0.1:1090');
 assert.equal(state.capabilities.nasim.tunnelReady,false);assert.equal(state.nasimMedia.billingVerified,false);
 for(const secret of ['fixture-private-turn-password','fixture-private-turn-user','ice-pwd','fingerprint','trustedCertificates','iceServers','fixture-nasim-secret'])assert.ok(!JSON.stringify(state).includes(secret));
 assert.deepEqual(calls.filter(c=>c.action==='nasim-signal').map(c=>c.type),['callRequest','accept','offer','answer']);
 await request('/api/nasim/media/end',{slot:1});state=await waitForLab(request,s=>s.nasimMedia.accounts.every(c=>['idle','ended'].includes(c.phase)));
 assert.ok(state.accounts.every(a=>a.signedIn));assert.ok(state.nasimMedia.accounts.every(c=>c.media===null));
 assert.equal((await request('/api/nasim/media/prepare',{clientSlot:2,socksPort:1091,throughput:false})).status,200);
 await request('/api/vault/lock',{});state=await(await request('/api/state')).json();assert.ok(state.nasimMedia.accounts.every(c=>c.media===null));
 assert.ok(state.providerAccounts.nasim.every(a=>!a.signedIn));
},{nasimNative:true}));

for(const stopRoute of ['/api/nasim/media/reset','/api/nasim/1/stop'])test('Nasim cancellation closes both late helpers via '+stopRoute,async()=>{
 const pending=[];let closed=0;
 await fixture(async({request})=>{
  await request('/api/vault/unlock',{password:'fixture-passphrase-123'});
  for(const slot of [1,2]){await request('/api/nasim/'+slot+'/start',{country:'IR',phone:'09120000001'});await request('/api/nasim/'+slot+'/verify',{code:'12345'});}
  const preparing=request('/api/nasim/media/prepare',{clientSlot:1,socksPort:1090});
  const deadline=Date.now()+2000;while(pending.length!==2){if(Date.now()>deadline)throw Error('Helpers were not requested');await new Promise(r=>setTimeout(r,5));}
  assert.equal((await request(stopRoute,{})).status,200);
  for(const resolve of pending)resolve({publicCertificate:'aa'.repeat(80),state:{phase:'prepared'},close(){closed++;}});
  assert.equal((await preparing).status,400);assert.equal(closed,2);
  const state=await(await request('/api/state')).json();assert.equal(state.nasimMedia.phase,stopRoute.endsWith('/reset')?'idle':'ended');assert.ok(state.nasimMedia.accounts.every(c=>c.media===null));
 },{nasimNative:true,nasimOpenBridge:()=>new Promise(resolve=>pending.push(resolve))});
});
test('loopback HTTP management rejects missing nonce, cross-origin writes, rebinding and unsupported provider actions',()=>fixture(async({lab,request,calls,key})=>{
 assert.equal((await fetch(lab.origin+'/api/state')).status,401);
 assert.equal((await request('/api/vault/unlock',{password:'fixture-passphrase-123'},{Origin:'https://attacker.invalid'})).status,403);
 assert.equal((await request('/api/vault/unlock',{password:'fixture-passphrase-123'},{Origin:'null'})).status,403);
 const rebound=await new Promise((resolve,reject)=>{require('node:http').get(lab.origin+'/api/state',{headers:{Host:'attacker.invalid',Authorization:'Bearer '+key}},res=>{res.resume();resolve(res.statusCode);}).on('error',reject);});assert.equal(rebound,403);
 const page=await fetch(lab.origin+'/');assert.match(page.headers.get('content-security-policy'),/frame-ancestors 'none'/);const html=await page.text();assert.equal(html.includes(key),false);
 assert.match(html,/data-provider="rubika" data-help="rubikaBillingHelp"/);
 const ui=await(await fetch(lab.origin+'/lab-ui.cjs')).text();
 assert.match(ui,/تعرفهٔ اعلامی روبیکا تمام‌بهاست/);assert.match(ui,/هزینهٔ واقعی تونل هنوز اندازه‌گیری نشده/);
 assert.match(ui,/Rubika publishes full-price data billing/);assert.match(ui,/Actual tunnel billing has not been measured/);
 const before=await(await request('/api/state')).json();assert.equal(before.vault.unlocked,false);assert.deepEqual(Object.keys(before.capabilities),['igap','eitaa','nasim','rubika']);assert.ok(Object.values(before.capabilities).every(p=>!p.tunnelReady));
 assert.equal((await request('/api/igap/1/start',{country:'IR',phone:'09120000001'})).status,423);assert.equal(calls.length,0);
 await request('/api/vault/unlock',{password:'fixture-passphrase-123'});
 for(const route of ['/api/eitaa/3/start','/api/rubika/3/start','/api/bale/1/start','/api/igap/3/start'])assert.equal((await request(route,{phone:'09120000001'})).status,404);
 assert.equal(calls.length,0);
}));

test('Nasim and iGap HTTP accounts stay namespaced through sign-in, encrypted storage, local removal, lock and restore',()=>fixture(async({request,dir,calls})=>{
 await request('/api/vault/unlock',{password:'fixture-passphrase-123'});
 for(const provider of ['igap','nasim'])for(const slot of [1,2]){
  assert.equal((await request('/api/'+provider+'/'+slot+'/start',{country:'IR',phone:'09120000001'})).status,200);
  assert.equal((await request('/api/'+provider+'/'+slot+'/verify',{code:'12345'})).status,200);
 }
 let state=await(await request('/api/state')).json();assert.equal(state.providerAccounts.nasim.length,2);
 assert.ok(state.providerAccounts.igap.every(a=>a.signedIn));assert.ok(state.providerAccounts.nasim.every(a=>a.signedIn));
 assert.equal((await request('/api/nasim/1/events/connect',{})).status,200);
 state=await(await request('/api/state')).json();assert.equal(state.providerAccounts.nasim[0].events.phase,'connected');
 assert.equal(state.capabilities.nasim.tunnelReady,false);assert.equal(state.capabilities.nasim.liveCallVerified,false);
 assert.equal((await request('/api/igap/1/events/connect',{})).status,404);
 for(const provider of ['igap','nasim'])for(const slot of [1,2]){const file=await fs.readFile(path.join(dir,provider,slot+'.json'),'utf8');assert.ok(!file.includes('fixture-secret'));assert.ok(!file.includes('fixture-nasim-secret'));}
 assert.equal((await request('/api/nasim/1/call/dial',{targetSlot:2})).status,404);
 await request('/api/nasim/1/forget',{});state=await(await request('/api/state')).json();
 assert.ok(state.accounts.every(a=>a.signedIn));assert.equal(state.providerAccounts.nasim[0].hasSession,false);assert.equal(state.providerAccounts.nasim[1].signedIn,true);
 assert.equal(state.providerAccounts.nasim[0].events.phase,'closed');
 await request('/api/vault/lock',{});state=await(await request('/api/state')).json();
 assert.ok(Object.values(state.providerAccounts).flat().every(a=>!a.signedIn));
 await request('/api/vault/unlock',{password:'fixture-passphrase-123'});await request('/api/nasim/2/resume',{});
 state=await(await request('/api/state')).json();assert.equal(state.providerAccounts.nasim[1].signedIn,true);
 assert.equal(calls.filter(c=>c.action==='nasim-start').length,2);assert.equal(calls.at(-1).action,'nasim-restore');
 const publicState=JSON.stringify(state);assert.ok(!publicState.includes('fixture-nasim-secret-token'));assert.ok(!publicState.includes('09120000001'));
}));

test('media endpoints require joined accounts, keep native tokens private and stop both sides when the vault locks',()=>fixture(async({request})=>{
 assert.equal((await request('/api/igap/media/start',{})).status,423);
 await request('/api/vault/unlock',{password:'fixture-passphrase-123'});
 assert.equal((await request('/api/igap/media/start',{})).status,400);
 for(const slot of [1,2]){await request('/api/igap/'+slot+'/start',{country:'IR',phone:'09120000001'});await request('/api/igap/'+slot+'/verify',{code:'12345'});}
 await request('/api/igap/1/call/dial',{targetSlot:2});
 await request('/api/igap/2/call/join',{});await request('/api/igap/1/call/join',{});
 const response=await request('/api/igap/media/start',{clientSlot:1,socksPort:1089,throughput:true});assert.equal(response.status,200);
 const result=await response.json();assert.equal(result.media.phase,'running');assert.equal(result.media.billingVerified,false);
 assert.ok(!JSON.stringify(result).includes('fixture.payload.signature'));
 assert.equal((await request('/api/igap/media/start',{clientSlot:2})).status,400);
 await request('/api/vault/lock',{});
 const state=await(await request('/api/state')).json();assert.equal(state.media.phase,'stopped');assert.ok(state.media.bridges.every(b=>b.phase==='closed'));
},{native:true}));

test('HTTP call flow allows only two signed-in local accounts and returns no room credentials',()=>fixture(async({request,calls})=>{
 await request('/api/vault/unlock',{password:'fixture-passphrase-123'});
 const call=(slot,action,body={})=>request('/api/igap/'+slot+'/call/'+action,body);
 assert.equal((await call(1,'dial',{targetSlot:2})).status,400);
 for(const slot of [1,2]){await request('/api/igap/'+slot+'/start',{country:'IR',phone:'09120000001'});await request('/api/igap/'+slot+'/verify',{code:'12345'});}
 assert.equal((await call(1,'dial',{targetSlot:1})).status,400);
 assert.equal((await call(1,'dial',{targetSlot:'2'})).status,400);
 assert.equal((await call(1,'dial',{targetSlot:2})).status,200);
 let state=await(await request('/api/state')).json();assert.deepEqual(state.accounts.map(a=>a.call.phase),['outgoing','incoming']);
 assert.equal((await call(1,'dial',{targetSlot:2})).status,409);
 assert.equal((await call(2,'ring')).status,200);
 assert.equal((await call(2,'join')).status,200);
 assert.equal((await call(1,'join')).status,200);
 const publicState=await(await request('/api/state')).text();assert.ok(!publicState.includes('fixture.payload.signature'));assert.ok(!publicState.includes('fixture-secret-token'));
 state=JSON.parse(publicState);assert.ok(state.accounts.every(a=>a.call.phase==='joined'&&a.call.credentialReady&&!a.call.tunnelReady));
 assert.equal((await call(1,'reset')).status,409,'an active call must be left explicitly');
 assert.equal((await call(2,'leave')).status,200);
 state=await(await request('/api/state')).json();assert.ok(state.accounts.every(a=>a.call.phase==='ended'&&!a.call.credentialReady));
 assert.deepEqual(calls.filter(c=>typeof c.action==='number').map(c=>c.action),[913,915,916,914,918]);
}));
test('local login endpoints isolate accounts, persist sealed sessions and restore without OTP or public secret output',()=>fixture(async({request,dir,calls})=>{
 const password='fixture-passphrase-123';assert.equal((await request('/api/vault/unlock',{password})).status,200);
 for(const slot of [1,2]){assert.equal((await request('/api/igap/'+slot+'/start',{country:'IR',phone:'۰۹۱۲۰۰۰۰۰۰۱'})).status,200);const result=await(await request('/api/igap/'+slot+'/verify',{code:'12345'})).json();assert.equal(result.authenticated,true);assert.ok(!JSON.stringify(result).includes('token'));}
 const publicState=JSON.stringify(await(await request('/api/state')).json());for(const secret of [password,'12345','fixture-secret-token','989120000001'])assert.ok(!publicState.includes(secret));
 assert.equal(calls.filter(x=>x.action==='start').length,2);assert.equal(calls[0].phone.nationalNumber,'9120000001');
 assert.ok(!(await fs.readFile(path.join(dir,'igap/1.json'),'utf8')).includes('fixture-secret-token'));
 await request('/api/vault/lock',{});await request('/api/vault/unlock',{password});assert.equal((await request('/api/igap/1/resume',{})).status,200);assert.equal(calls.at(-1).action,'restore');assert.equal(calls.filter(x=>x.action==='start').length,2);
 await request('/api/igap/1/forget',{});assert.equal((await(await request('/api/state')).json()).accounts.find(x=>x.slot===1).stored,false);assert.equal((await(await request('/api/state')).json()).accounts.find(x=>x.slot===2).stored,true);
}));
