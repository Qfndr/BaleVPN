const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {startLab}=require('../experiments/providers/lab.cjs'),{fixture}=require('./rubika-lab-call-fixture.cjs');
async function run(fn,{helper=true}={}){
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'rubika-lab-test-')),f=await fixture();let lab;
 try{
  lab=await startLab({privacyOperation:require('./provider-privacy-fixture.cjs').allow,directory,port:0,...helper?{rubikaBridgeExecutable:path.resolve('fixture-rubika-helper'),rubikaOpenBridge:f.open}: {},rubikaCallClientFactory:f.createClient,rubikaSessionPollInterval:0,rubikaSessionFactory:slot=>f.accounts.get(slot)});
  const key=new URL(lab.url).hash.slice(1),request=(url,body,headers={})=>fetch(lab.origin+'/api/'+url,{method:body===undefined?'GET':'POST',headers:{Authorization:'Bearer '+key,...body===undefined?{}:{Origin:lab.origin,'Content-Type':'application/json'},...headers},body:body===undefined?undefined:JSON.stringify(body)});
  await fn({lab,request,...f});
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
