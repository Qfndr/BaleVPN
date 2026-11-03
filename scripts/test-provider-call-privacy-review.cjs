'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {startLab}=require('../experiments/providers/lab.cjs'),privacy=require('../experiments/providers/call-privacy.cjs');
const {FakeNasimAuth}=require('./provider-lab-fixture.cjs'),{fixture:rubikaFixture}=require('./rubika-lab-call-fixture.cjs');
async function run(fn,options={}){
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'privacy-review-'));let lab;
 try{lab=await startLab({directory,port:0,...options});const key=new URL(lab.url).hash.slice(1),request=(route,body)=>fetch(lab.origin+'/api/'+route,{method:body===undefined?'GET':'POST',headers:{Authorization:'Bearer '+key,...body===undefined?{}:{Origin:lab.origin,'Content-Type':'application/json'}},body:body===undefined?undefined:JSON.stringify(body)});await request('vault/unlock',{password:'fixture-review-passphrase'});await fn({request,lab});}
 finally{await lab?.close();if(!path.resolve(directory).startsWith(path.resolve(os.tmpdir())+path.sep)||!path.basename(directory).startsWith('privacy-review-'))throw Error('Unexpected privacy fixture cleanup target');await fs.rm(directory,{recursive:true,force:true,maxRetries:5,retryDelay:100});}
}
test('unsupported Nasim privacy read/allow routes never issue a fabricated provider RPC',async()=>{
 const calls=[];await run(async({request})=>{
  await request('nasim/1/start',{country:'IR',phone:'09120000001'});await request('nasim/1/verify',{code:'12345'});const before=calls.length;
  for(const [route,body]of [['nasim/1/call-privacy',undefined],['nasim/1/allow-calls',{}]]){const response=await request(route,body);assert.equal(response.status,200);const result=(await response.json()).callPrivacy;assert.equal(result.supported,false);assert.equal(result.verified,false);assert.equal(result.allowedForEveryone,false);}
  assert.equal(calls.length,before,'unsupported privacy must not send a provider request');const state=await(await request('state')).json();assert.equal(state.providerAccounts.nasim[0].callPrivacySupported,false);
 },{nasimSessionFactory:slot=>new FakeNasimAuth(slot,calls)});
});
test('malformed and repeated Rubika dial requests cannot trigger privacy writes before rejection',async()=>{
 const f=await rubikaFixture(),operations=[];let current='everyone';
 try{await run(async({request})=>{
  assert.equal((await request('rubika/media/dial',{slot:1})).status,400);assert.equal(operations.length,0);
  assert.equal((await request('rubika/media/prepare',{})).status,200);
  for(const slot of [undefined,0,3,'1']){assert.equal((await request('rubika/media/dial',slot===undefined?{}:{slot})).status,400);assert.equal(operations.length,0);}
  assert.equal((await request('rubika/media/dial',{slot:1})).status,200);assert.equal(operations.filter(x=>x.allow).length,2);assert.equal(f.broker.calls.filter(c=>c.method==='requestCall').length,1);
  // A fresh read now says permission is denied. A buggy repeated-dial path
  // would invoke allow again rather than being hidden by the warm cache.
  current='nobody';assert.equal((await request('rubika/1/call-privacy')).status,200);const writes=operations.filter(x=>x.allow).length;
  for(const slot of [1,2])assert.equal((await request('rubika/media/dial',{slot})).status,400);
  assert.equal(operations.filter(x=>x.allow).length,writes);assert.equal(f.broker.calls.filter(c=>c.method==='requestCall').length,1);
 },{rubikaBridgeExecutable:path.resolve('fixture-rubika-helper'),rubikaOpenBridge:f.open,rubikaCallClientFactory:f.createClient,rubikaSessionPollInterval:0,rubikaSessionFactory:slot=>f.accounts.get(slot),privacyOperation:async(provider,account,{allow})=>{operations.push({provider,userId:account.state.userId,allow});return {supported:true,verified:true,mode:current,allowedForEveryone:current==='everyone',changed:false};}});}finally{f.broker.close();}
});
test('generic Eitaa adapter rejects a late permission reply after cancellation without claiming verification',async()=>{
 let release,writes=0;const account={state:{signedIn:true,userId:'fixture-user'},getCallPrivacy(){return new Promise(resolve=>{release=resolve;});},async allowAllCalls(){writes++;throw Error('Unexpected setting mutation');}};
 const abort=new AbortController(),pending=privacy.operate('eitaa',account,{signal:abort.signal});while(!release)await Promise.resolve();abort.abort();release({callPrivacy:{mode:'everyone',allowedEveryone:true}});await assert.rejects(pending,/account_binding_changed/);assert.equal(writes,0);
});
test('generic Rubika adapter preserves failed non-call-exception verification and redacts private settings',async()=>{
 const wire=require('../experiments/rubika/wire.cjs'),identity=await wire.createIdentity(),record={provider:'rubika',userId:'fixture_review_01',auth:wire.temporarySession(),...identity},account={state:{provider:'rubika',signedIn:true,selfConfirmed:true,userId:record.userId},exportSession(){return {...record};}};
 const original=globalThis.fetch;let reads=0,writes=0;
 globalThis.fetch=async(_url,options)=>{const envelope=JSON.parse(options.body);if(envelope.method==='getDCs')return Response.json({status:'OK',data:{default_api_urls:['https://messengerg2c1.iranlms.ir/']}});const request=wire.decrypt(envelope.data_enc,record.auth);let result;
  if(request.method==='getPrivacySetting'){reads++;result={privacy_setting:{can_called_by:reads===1?'Nobody':'Everybody',exceptions:reads===1?[{setting_type:'CanCalled',exclude_users:['fixture-caller']},{setting_type:'ShowPhone',exclude_users:['private-unchanged-guid']}]:[{setting_type:'ShowPhone',exclude_users:['private-server-changed-guid']}],show_my_phone_number:'Nobody'}};}
  else{assert.equal(request.method,'setSetting');writes++;assert.deepEqual(request.input.update_parameters,['can_called_by','exceptions']);result={};}
  return Response.json({data_enc:wire.encrypt({status:'OK',data:result},record.auth)});
 };
 try{const result=await privacy.operate('rubika',account,{allow:true});assert.equal(result.allowedForEveryone,true);assert.equal(result.verified,false);assert.equal(writes,1);assert.equal(reads,2);for(const value of ['private-','show_my_phone_number',record.auth,record.privateKey])assert.ok(!JSON.stringify(result).includes(value));}finally{globalThis.fetch=original;}
});
