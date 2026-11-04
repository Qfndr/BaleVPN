const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {startLab}=require('../experiments/providers/lab.cjs'),{fixture}=require('./rubika-lab-call-fixture.cjs');
async function run(fn,{helper=true,brokerOptions}={}){
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'rubika-lab-test-')),f=await fixture(brokerOptions);let lab;
 try{
  lab=await startLab({privacyOperation:require('./provider-privacy-fixture.cjs').allow,directory,port:0,...helper?{rubikaBridgeExecutable:path.resolve('fixture-rubika-helper'),rubikaOpenBridge:f.open}: {},rubikaCallClientFactory:f.createClient,rubikaSessionPollInterval:0,rubikaSessionFactory:slot=>f.accounts.get(slot)});
  const key=new URL(lab.url).hash.slice(1),request=(url,body,headers={})=>fetch(lab.origin+'/api/'+url,{method:body===undefined?'GET':'POST',headers:{Authorization:'Bearer '+key,...body===undefined?{}:{Origin:lab.origin,'Content-Type':'application/json'},...headers},body:body===undefined?undefined:JSON.stringify(body)});
  await fn({lab,request,directory,...f});
 }finally{await lab?.close();f.broker.close();if(!path.resolve(directory).startsWith(path.resolve(os.tmpdir())+path.sep)||!path.basename(directory).startsWith('rubika-lab-test-'))throw Error('Unexpected fixture cleanup target');await fs.rm(directory,{recursive:true,force:true,maxRetries:5,retryDelay:100});}
}
test('Rubika call routes require an unlocked vault, exact options and same-origin authenticated requests',()=>run(async({request})=>{
 assert.equal((await request('rubika/media/prepare',{})).status,423);await request('vault/unlock',{password:'fixture-vault-password'});
 assert.equal((await request('rubika/media/prepare',{token:'private'})).status,400);assert.equal((await request('rubika/media/prepare',{}, {Origin:'https://attacker.invalid'})).status,403);
 assert.equal((await request('rubika/media/prepare',{}, {Authorization:'Bearer wrong'})).status,401);assert.equal((await request('rubika/media/prepare',{socksPort:1092})).status,200);
}));
test('HTTP call lifecycle keeps account/key details private and never claims verified service routing or billing',()=>run(async({request,broker,natives})=>{
 await request('vault/unlock',{password:'fixture-vault-password'});assert.equal((await request('rubika/media/prepare',{clientSlot:1,socksPort:1092})).status,200);
 assert.equal((await request('rubika/media/dial',{slot:1})).status,200);let s=await(await request('state')).json();assert.equal(s.providerAccounts.rubika[1].call.phase,'ringing');
 assert.ok(s.providerAccounts.rubika.every(a=>a.callRecoveryStored===false),'healthy adopted call clears its diagnostic response');
 assert.equal((await request('rubika/media/accept',{slot:2})).status,200);
 // Timer-free HTTP fixture: one extra poll is not exposed as a raw RPC route.
 assert.equal(s.capabilities.rubika.tunnelReady,false);s=await(await request('state')).json();
 for(const flag of ['liveCallVerified','providerPathVerified','billingVerified'])assert.equal(s.rubikaMedia[flag],false);
 for(const secret of [broker.key,broker.records[0].privateKey,'fixture-private-password','trustedCertificates'])assert.ok(!JSON.stringify(s).includes(secret));
 assert.equal((await request('rubika/media/end',{slot:1})).status,200);assert.ok(natives.every(n=>n.closed===1));assert.ok(broker.accountStates.every(a=>a.signedIn));
}));
test('locking the vault or stopping a Rubika account closes the whole pair',()=>run(async({request,natives})=>{
 await request('vault/unlock',{password:'fixture-vault-password'});await request('rubika/media/prepare',{});await request('rubika/1/stop',{});assert.ok(natives.every(n=>n.closed===1));
 const state=await(await request('state')).json();assert.equal(state.rubikaMedia.phase,'ended');await request('vault/lock',{});assert.equal((await(await request('state')).json()).vault.unlocked,false);
}));
test('a missing explicit native helper keeps the lab unavailable without running a call',()=>run(async({request,broker})=>{
 await request('vault/unlock',{password:'fixture-vault-password'});assert.equal((await request('rubika/media/prepare',{})).status,503);assert.equal(broker.calls.length,0);
},{helper:false}));

test('a created call with unknown response shape stays sealed across vault locking and blocks another dial',()=>run(async({request,broker,directory})=>{
 await request('vault/unlock',{password:'fixture-vault-password'});assert.equal((await request('rubika/media/prepare',{})).status,200);
 assert.equal((await request('rubika/media/dial',{slot:1})).status,400);
 let state=await(await request('state')).json();
 assert.equal(state.providerAccounts.rubika[0].callRecoveryStored,true);assert.equal(state.providerAccounts.rubika[1].callRecoveryStored,false);
 assert.deepEqual(state.rubikaMedia.diagnostic.schemaDiagnostic,{field:'call_update.type',kind:'missing'});
 assert.equal(state.rubikaMedia.diagnostic.recoveryStored,true);
 const sealed=await fs.readFile(path.join(directory,'call-recovery','rubika','1.json'),'utf8');
 for(const secret of ['fixture-created-call-secret','fixture-private-reply',broker.records[0].auth,broker.records[0].privateKey]){
  assert.ok(!sealed.includes(secret));assert.ok(!JSON.stringify(state).includes(secret));
 }
 await request('vault/lock',{});await request('vault/unlock',{password:'fixture-vault-password'});
 for(const action of ['prepare','dial']){const blocked=await request('rubika/media/'+action,action==='dial'?{slot:1}:{});assert.equal(blocked.status,400);assert.equal((await blocked.json()).reason,'call_recovery_available');}
 assert.equal(broker.calls.filter(c=>c.method==='requestCall').length,1);
 state=await(await request('state')).json();assert.equal(state.providerAccounts.rubika[0].callRecoveryStored,true);
},{brokerOptions:{hook:async(slot,method)=>{
 if(method==='requestCall')return {call_type:'WebRtc',call_update:{call_id:'fixture-created-call-secret',action:'New',timestamp:Math.floor(Date.now()/1000),
  object_guid:'fixture_account_02',call:{call_id:'fixture-created-call-secret',call_type:'Voice',state:'Waiting'}},private_reply:'fixture-private-reply'};
}}}));

test('a decoded response rejected before local call adoption also retains its sealed recovery candidate',()=>run(async({request,broker})=>{
 await request('vault/unlock',{password:'fixture-vault-password'});await request('rubika/media/prepare',{});
 assert.equal((await request('rubika/media/dial',{slot:1})).status,400);
 const state=await(await request('state')).json();assert.equal(state.providerAccounts.rubika[0].callRecoveryStored,true);
 assert.equal(state.rubikaMedia.reason,'stale_call');assert.equal(broker.calls.filter(c=>c.method==='requestCall').length,1);
 const blocked=await request('rubika/media/prepare',{});assert.equal((await blocked.json()).reason,'call_recovery_available');
},{brokerOptions:{hook:async(slot,method)=>{
 if(method==='requestCall')return {call_type:'WebRtc',call_update:{call_id:'fixture_created_call',action:'New',timestamp:1,type:'User',object_guid:'fixture_account_02',
  call:{call_id:'fixture_created_call',call_type:'Voice',state:'Waiting'}}};
}}}));
