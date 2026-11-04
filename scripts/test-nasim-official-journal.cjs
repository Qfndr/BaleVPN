'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {SessionVault}=require('../experiments/providers/session-vault.cjs');
const {OfficialCallGate}=require('../experiments/nasim/official-call-gate.cjs');
const {CleanupIntent}=require('../experiments/nasim/cleanup-intent.cjs');
const {OfficialCallTransport,ENDPOINT}=require('../experiments/nasim/official-call-transport.cjs');
const {runOfficialReference}=require('../experiments/nasim/official-reference-runner.cjs');
const wire=require('../experiments/nasim/wire.cjs');
const PASSWORD='synthetic-official-journal-test-password';
const request={type:'callRequest',callData:{method:'audio'}};
const reply={data:{callUUID:'synthetic-private-call',callData:{method:'audio',participants:[{userID:'41'},{userID:'42'}]}}};
async function fixture(t){
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'nasim-official-journal-'));
 const vault=new SessionVault(dir);await vault.unlock(PASSWORD);
 const journal=await vault.openNasimOfficialCallJournal();
 t.after(async()=>{await journal.close();vault.lock();const target=await fs.realpath(dir),temp=await fs.realpath(os.tmpdir());
  if(path.dirname(target)===temp)await fs.rm(target,{recursive:true,force:true,maxRetries:3,retryDelay:50});});
 const accounts=new Map([1,2].map(slot=>[slot,{
  state:{provider:'nasim',signedIn:true,userId:String(40+slot),clientId:'client-'+slot},
  exportSession(){return {...this.state,token:'synthetic-private-token-'+slot,deviceId:'web.synthetic-device-'+slot};}
 }]));
 function makeGate(store=journal){const cleanups=new Map([1,2].map(slot=>[slot,new CleanupIntent(accounts.get(slot),{
  saveIntent:value=>vault.saveCleanupIntent('nasim',slot,value),loadIntent:()=>vault.loadCleanupIntent('nasim',slot),
  clearIntent:value=>vault.removeCleanupIntent('nasim',slot,value)
 })]));return new OfficialCallGate(accounts,cleanups,store);}
 return {dir,vault,journal,makeGate,accounts,file:path.join(dir,'nasim-official-call','pair.json')};
}
test('only one journal owner, including another vault instance, can act at a time',async t=>{
 const f=await fixture(t),other=new SessionVault(f.dir);await other.unlock(PASSWORD);
 await assert.rejects(other.openNasimOfficialCallJournal(),e=>e.reason==='official_call_owner_busy');
 await f.journal.close();const reopened=await other.openNasimOfficialCallJournal();
 try{assert.equal(await reopened.load(),null);await assert.rejects(f.journal.load(),e=>e.reason==='locked');}
 finally{await reopened.close();other.lock();}
});
test('CAS, raw-frame bound and immutable first response survive journal reopen',async t=>{
 const f=await fixture(t),gate=f.makeGate();await gate.begin();const prepared=await f.journal.load();
 await gate.outgoing(1,request);const intent=await f.journal.load();
 await assert.rejects(f.journal.save(intent,prepared,()=>{}),e=>e.reason==='official_call_intent_conflict');
 assert.throws(()=>f.journal.stageResponse(intent.operationId,Buffer.alloc(65537),200),e=>e.reason==='invalid_official_call_response');
 const raw=Buffer.from('synthetic-private-raw-response');await f.journal.stageResponse(intent.operationId,raw,200);
 await f.journal.stageResponse(intent.operationId,raw,200);
 await assert.rejects(f.journal.stageResponse(intent.operationId,Buffer.from('different'),200),e=>e.reason==='official_call_response_exists');
 const disk=await fs.readFile(f.file,'utf8');assert.equal(disk.includes(raw.toString()),false);assert.equal(disk.includes(intent.operationId),false);
 await f.journal.close();const reopened=await f.vault.openNasimOfficialCallJournal();
 try{assert.deepEqual(await reopened.load(),intent);assert.deepEqual(await reopened.loadResponse(intent.operationId),{status:200,body:raw});
  await assert.rejects(reopened.loadResponse('wrong'),e=>e.reason==='official_call_intent_conflict');}
 finally{await reopened.close();raw.fill(0);}
});
test('binding requires archived bytes and unknown-outcome restart blocks a new dial',async t=>{
 const f=await fixture(t),gate=f.makeGate();await gate.begin();await gate.outgoing(1,request);
 await assert.rejects(gate.bindResponse(1,reply),e=>e.reason==='official_call_intent_conflict');
 assert.equal((await f.journal.load()).phase,'requested');
 const restored=f.makeGate();assert.equal(await restored.restore(),true);
 await assert.rejects(restored.outgoing(1,request),e=>e.reason==='cleanup_pending');
 const intent=await f.journal.load();await f.journal.stageResponse(intent.operationId,Buffer.from(JSON.stringify(reply)),200);
 await restored.bindResponse(1,reply);assert.equal((await f.journal.load()).phase,'bound');
 assert.equal(await f.vault.hasCleanupIntent('nasim',1),true);assert.equal(await f.vault.hasCleanupIntent('nasim',2),true);
});
test('only matched final evidence clears the encrypted pair and raw response',async t=>{
 const f=await fixture(t),gate=f.makeGate();await gate.begin();await gate.outgoing(1,request);
 const intent=await f.journal.load();await f.journal.stageResponse(intent.operationId,Buffer.from(JSON.stringify(reply)),200);await gate.bindResponse(1,reply);
 await assert.rejects(f.journal.clear(await f.journal.load(),()=>{}),e=>e.reason==='official_call_intent_conflict');
 await gate.acknowledgeTerminal(1,{acknowledged:true,terminalAcknowledgement:{type:'bye',callUUID:reply.data.callUUID,peerId:'42'}});
 await gate.terminalEvent(2,{type:'msgGroupCall',data:{type:'bye',callUUID:reply.data.callUUID,callData:null},from:{id:'41'},senderClientID:'client-1'});
 assert.equal(await f.journal.load(),null);await assert.rejects(fs.stat(f.file),{code:'ENOENT'});
 assert.equal(await f.vault.hasCleanupIntent('nasim',1),false);assert.equal(await f.vault.hasCleanupIntent('nasim',2),false);
});
function browserRequest(packet={type:'msgGroupCall',data:request}){
 const token='synthetic-private-token-1';
 return {url:ENDPOINT,method:'POST',headers:{'api-version':'v2.5','x-token':token,'x-clientid':'client-1',
  project:'nasimrezvan','content-type':'application/json','x-topic':'u/42/41'},
  body:wire.encryptBytes(Buffer.from(JSON.stringify(packet)),token)};
}
test('official HTTP gate archives complete bytes and bounds deferred events before browser delivery',async t=>{
 const f=await fixture(t),gate=f.makeGate(),delivered=[],token='synthetic-private-token-1';let fetches=0;
 const body=wire.encryptBytes(Buffer.from(JSON.stringify(reply)),token);
 const transport=new OfficialCallTransport({accounts:f.accounts,gate,journal:f.journal,deliver:async(...args)=>delivered.push(args),
  fetchImpl:async(url,options)=>{
   fetches++;assert.equal(url,ENDPOINT);assert.equal(options.redirect,'error');assert.equal((await f.journal.load()).phase,'requested');
   return new Response(body);
  }});
 t.after(()=>transport.close());await gate.begin();
 const event={type:'msgGroupCall',data:{type:'accept',callUUID:reply.data.callUUID},from:{id:'42'},senderClientID:'client-2'};
 assert.equal(await transport.incoming(1,event),false);assert.equal(delivered.length,0);
 assert.deepEqual((await transport.forward(1,browserRequest())).body,body);
 const intent=await f.journal.load();assert.equal(intent.phase,'bound');assert.deepEqual(await f.journal.loadResponse(intent.operationId),{status:200,body});
 assert.equal(delivered.length,0);await transport.releaseEvents();assert.deepEqual(delivered,[[1,event]]);
 await assert.rejects(transport.forward(1,browserRequest()),e=>e.reason==='duplicate_call_request');assert.equal(fetches,1);
});
test('wrong browser destination, identity, topic and extra packet fields cannot consume call intent',async t=>{
 const f=await fixture(t),gate=f.makeGate();let fetches=0;
 const transport=new OfficialCallTransport({accounts:f.accounts,gate,journal:f.journal,deliver:async()=>{},fetchImpl:async()=>{fetches++;throw Error('unexpected');}});
 t.after(()=>transport.close());await gate.begin();const input=browserRequest();
 for(const invalid of [{...input,url:ENDPOINT+'other'},{...input,method:'GET'},
  {...input,headers:{...input.headers,'x-clientid':'other'}},{...input,headers:{...input.headers,'x-topic':'u/43/41'}},
  browserRequest({type:'msgGroupCall',data:request,privateExtra:'never-forward'})])await assert.rejects(transport.forward(1,invalid));
 assert.equal(fetches,0);assert.equal((await f.journal.load()).phase,'prepared');
});
test('malformed first HTTP reply remains sealed and never triggers a second provider request',async t=>{
 const f=await fixture(t),gate=f.makeGate();let fetches=0;
 const raw=Buffer.from('malformed-private-fixture');
 const transport=new OfficialCallTransport({accounts:f.accounts,gate,journal:f.journal,deliver:async()=>{},fetchImpl:async()=>{fetches++;return new Response(raw);}});
 t.after(()=>transport.close());await gate.begin();
 await assert.rejects(transport.forward(1,browserRequest()),e=>e.reason==='invalid_call_packet');
 const intent=await f.journal.load();assert.equal(intent.phase,'requested');assert.deepEqual(await f.journal.loadResponse(intent.operationId),{status:200,body:raw});
 await assert.rejects(transport.forward(1,browserRequest()),e=>e.reason==='duplicate_call_request');
 await assert.rejects(transport.recoverResponse(1),e=>e.reason==='invalid_call_packet');assert.equal(fetches,1);
});
test('a rejected HTTP response is archived with its status and cannot bind on restart',async t=>{
 const f=await fixture(t),gate=f.makeGate(),token='synthetic-private-token-1';
 const raw=wire.encryptBytes(Buffer.from(JSON.stringify(reply)),token);
 const transport=new OfficialCallTransport({accounts:f.accounts,gate,journal:f.journal,deliver:async()=>{},fetchImpl:async()=>new Response(raw,{status:404})});
 t.after(()=>transport.close());await gate.begin();
 await assert.rejects(transport.forward(1,browserRequest()),e=>e.reason==='call_rejected');
 const intent=await f.journal.load();assert.equal(intent.phase,'requested');assert.deepEqual(await f.journal.loadResponse(intent.operationId),{status:404,body:raw});
 await assert.rejects(transport.recoverResponse(1),e=>e.reason==='call_rejected');
 await assert.rejects(gate.abandonPrepared(),e=>e.reason==='cleanup_pending');
});
test('only an intent that never reached request admission can be abandoned',async t=>{
 const f=await fixture(t),gate=f.makeGate();await gate.begin();await gate.abandonPrepared();
 assert.equal(await f.journal.load(),null);await gate.begin();await gate.outgoing(1,request);
 await assert.rejects(gate.abandonPrepared(),e=>e.reason==='cleanup_pending');assert.equal((await f.journal.load()).phase,'requested');
});
test('runner with pending request or mismatched saved identity never starts a browser or provider read',async t=>{
 const f=await fixture(t),gate=f.makeGate();let launches=0,requests=0;
 for(const slot of [1,2])await f.vault.save('nasim',slot,f.accounts.get(slot).exportSession());
 await gate.begin();await gate.outgoing(1,request);await f.journal.close();
 const options={vault:f.vault,accounts:f.accounts,directory:f.dir,mediaGuard:{checkSignal(){},checkServers(){},capture(){}},
  chromium:{launch(){launches++;throw Error('unexpected browser');}},fetchImpl:()=>{requests++;throw Error('unexpected provider read');},checkIdle:async()=>true};
 assert.deepEqual(await runOfficialReference(options),{ok:false,reason:'cleanup_pending',cleanupPending:true,phase:'requested',uuidKnown:false});
 await f.vault.save('nasim',1,{...f.accounts.get(1).exportSession(),token:'different-synthetic-token'});
 const mismatch=await runOfficialReference(options);assert.equal(mismatch.reason,'account_binding_changed');
 assert.equal(launches,0);assert.equal(requests,0);
});
