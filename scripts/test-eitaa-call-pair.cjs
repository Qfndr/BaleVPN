'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {CallPair}=require('../experiments/eitaa/call-pair.cjs'),{fixture}=require('./eitaa-lab-call-fixture.cjs');
const {state:serviceState}=require('./eitaa-call-fixtures.cjs');
const {SessionVault}=require('../experiments/providers/session-vault.cjs');
function create(t,{open}={}){const f=fixture(),accounts=new Map([1,2].map(slot=>[slot,{signed:true,get state(){return {provider:'eitaa',signedIn:this.signed,selfConfirmed:this.signed,userId:String(8000000+slot)};},exportSession(){return {provider:'eitaa',userId:String(8000000+slot),token:'fixture-eitaa-token-'+slot,imei:(slot===1?'0123456789abcde':'fedcba987654321')+'__web'};}}])),pair=new CallPair(accounts,{executable:'fixture',open:open?()=>open(f):f.open,createClient:f.createClient,createAccountClient:f.createAccountClient});t.after(()=>pair.invalidate());return {...f,accounts,pair};}
test('local pair resolves caller-specific targets, privately pairs fresh identities and requires explicit call and acceptance',async t=>{
 const f=create(t);await f.pair.prepare({clientSlot:1,socksPort:1091});assert.equal(f.pair.state.phase,'ready');assert.equal(f.api.calls.some(c=>c.method==='phone.requestCall'),false);f.api.override=({self,method,input})=>{if(method==='phone.requestCall')assert.equal(input.user_id.access_hash,-1001n);};await f.pair.dial(1);assert.equal(f.pair.getCall(2).phase,'ringing');assert.equal(f.api.calls.some(c=>c.method==='phone.acceptCall'),false);await f.pair.accept(2);assert.equal(f.pair.state.phase,'connected');assert.equal(f.pair.getCall(1).media.socksAddress,'127.0.0.1:1091');assert.equal(f.pair.getCall(2).media.proxyReady,false);assert.equal(f.pair.getCall(2).media.serverReady,true);
 const text=JSON.stringify(f.pair.state);for(const value of ['fixture-turn','__web','fixture-eitaa-token','trustedCertificates','publicCertificate','accessHash','-1001'])assert.ok(!text.includes(value));await f.pair.end(1);assert.equal(f.pair.state.phase,'ended');assert.ok(f.natives.every(n=>n.state.phase==='closed'));assert.ok([...f.accounts.values()].every(a=>a.state.signedIn));
});
test('either account may dial while its transport role stays independent',async t=>{const f=create(t);await f.pair.prepare({clientSlot:1,socksPort:1092});await f.pair.dial(2);await f.pair.accept(1);assert.equal(f.pair.state.phase,'connected');assert.equal(f.pair.getCall(1).media.role,'client');assert.equal(f.pair.getCall(2).media.role,'server');});
test('reset during preparation closes late workers without disturbing a later prepared generation',async t=>{
 let waiting=0,release,entered;const gate=new Promise(r=>{entered=r;});const f=create(t,{open:async harness=>{const bridge=await harness.open();if(++waiting<=2)await new Promise(r=>{const previous=release;release=()=>{previous?.();r();};if(waiting===2)entered();});return bridge;}});
 const preparing=f.pair.prepare();await gate;f.pair.reset();await f.pair.prepare();release();await assert.rejects(preparing,{reason:'call_cancelled'});assert.equal(f.pair.state.phase,'ready');assert.ok(f.natives.slice(0,2).every(n=>n.state.phase==='closed'));assert.ok(f.natives.slice(2).every(n=>n.state.phase==='prepared'));
});
test('unconfirmed remote end still closes local media and preserves a visible uncertain outcome',async t=>{
 const f=create(t);await f.pair.prepare();await f.pair.dial(1);await f.pair.accept(2);f.api.override=({method})=>{if(method==='phone.discardCall')throw Object.assign(Error('private backend detail'),{reason:'network_error'});};await assert.rejects(f.pair.end(1));assert.equal(f.pair.state.phase,'uncertain');assert.equal(f.pair.state.reason,'call_end_uncertain');assert.ok(f.natives.every(n=>n.state.phase==='closed'));assert.ok(!JSON.stringify(f.pair.state).includes('private backend'));
 assert.equal(f.pair.state.canPrepare,false);assert.throws(()=>f.pair.reset(),{reason:'call_end_uncertain'});
 await assert.rejects(f.pair.prepare(),{reason:'call_end_uncertain'});
 assert.equal(f.pair.state.canRecover,true);
 const id=f.api.call.base.id,discarded=id=>({_:'updatePhoneCall',phone_call:{_:'phoneCallDiscarded',id}});
 for(const result of [{_:'updates.differenceEmpty'},{_:'updates.differenceTooLong',pts:30},
  {_:'updates.differenceSlice',other_updates:[discarded(id)]},
  {_:'updates.difference',state:{...serviceState,pts:0,seq:0},other_updates:[discarded(id)]},
  {_:'updates.difference',state:{...serviceState,pts:30,seq:30},other_updates:[discarded(id+1n)]}]){
  f.api.override=({method})=>{assert.equal(method,'updates.getDifference');return result;};
  await assert.rejects(f.pair.recover(),{reason:'call_end_uncertain'});
  assert.equal(f.pair.state.canPrepare,false);
 }
 f.api.override=({method,input})=>{
  assert.equal(method,'updates.getDifference');assert.equal(input.date,serviceState.date);
  return {_:'updates.difference',state:{...serviceState,pts:30,seq:30},other_updates:[discarded(id)]};
 };
 f.accounts.get(2).signed=false;
 const before=f.api.calls.length;await assert.rejects(f.pair.recover(),{reason:'both_accounts_required'});
 assert.equal(f.api.calls.length,before);
 f.accounts.get(2).signed=true;
 const account=f.accounts.get(2),exportSession=account.exportSession;
 account.exportSession=()=>({...exportSession(),token:'fixture-replacement-token'});
 await assert.rejects(f.pair.recover(),{reason:'account_binding_changed'});
 assert.equal(f.api.calls.length,before);
 account.exportSession=exportSession;
 assert.deepEqual(await f.pair.recover(),{ended:true,remoteConfirmed:true});
 assert.equal(f.pair.state.canPrepare,true);assert.equal(f.pair.state.canRecover,false);
 assert.equal(f.api.calls.filter(call=>call.method==='phone.discardCall').length,1);
});
test('in-flight dial rejects end and reset, and a lost request response fences another call',async t=>{
 const f=create(t);await f.pair.prepare();
 let entered,release;const sent=new Promise(resolve=>{entered=resolve;});
 f.api.override=async({method})=>{
  if(method!=='phone.requestCall')return;
  await new Promise(resolve=>{release=resolve;entered();});
  throw Object.assign(Error('fixture response lost'),{reason:'network_error'});
 };
 const dialing=f.pair.dial(1);
 await sent;
 try{
  await assert.rejects(f.pair.end(1),{reason:'call_busy'});
  assert.throws(()=>f.pair.reset(),{reason:'call_busy'});
 }finally{release();}
 await assert.rejects(dialing,{reason:'network_error'});
 assert.equal(f.pair.state.phase,'uncertain');assert.equal(f.pair.state.canPrepare,false);
 assert.equal(f.pair.state.canRecover,false);
 await assert.rejects(f.pair.recover(),{reason:'call_end_uncertain'});
 f.pair.invalidate();assert.equal(f.pair.state.phase,'uncertain');
 await assert.rejects(f.pair.prepare(),{reason:'call_end_uncertain'});
 assert.equal(f.api.calls.filter(call=>call.method==='phone.requestCall').length,1);
});
test('invalidation during discard retains the known checkpoint without trusting the late reply',async t=>{
 const f=create(t);await f.pair.prepare();await f.pair.dial(1);
 const id=f.api.call.base.id,terminal={_:'updatePhoneCall',phone_call:{_:'phoneCallDiscarded',id}};
 let release,entered;const sent=new Promise(resolve=>{entered=resolve;});
 f.api.override=async({method})=>{
  if(method!=='phone.discardCall')return;
  await new Promise(resolve=>{release=resolve;entered();});
  return {_:'updates',updates:[terminal]};
 };
 const ending=f.pair.end(1);
 await sent;
 try{
  f.pair.invalidate();
  assert.equal(f.pair.state.canRecover,true);assert.equal(f.pair.state.canPrepare,false);
 }finally{release();}
 await assert.rejects(ending,{reason:'call_cancelled'});
 assert.equal(f.pair.state.canRecover,true);assert.equal(f.pair.state.canPrepare,false);
 await assert.rejects(f.pair.recover(),{reason:'call_end_uncertain'});
 f.api.queues.get(8000001).push(terminal);
 assert.deepEqual(await f.pair.recover(),{ended:true,remoteConfirmed:true});
 assert.equal(f.api.calls.filter(call=>call.method==='phone.discardCall').length,1);
});
test('failure before phone.requestCall does not fence a new preparation',async t=>{
 const f=create(t);await f.pair.prepare();
 f.api.override=({method})=>{if(method==='messages.getDhConfig')throw Object.assign(Error('fixture DH rejected'),{reason:'service_rejected'});};
 await assert.rejects(f.pair.dial(1),{reason:'service_rejected'});
 assert.equal(f.pair.state.canPrepare,true);
 assert.equal(f.api.calls.some(call=>call.method==='phone.requestCall'),false);
 await f.pair.prepare();
});
test('durable Eitaa pair fences before request and recovers exact known terminal history after reopening',async t=>{
 const root=path.resolve(os.tmpdir()),directory=await fs.mkdtemp(path.join(root,'eitaa-pair-journal-'));
 t.after(async()=>{assert.equal(path.dirname(directory),root);assert.match(path.basename(directory),/^eitaa-pair-journal-/);await fs.rm(directory,{recursive:true,force:true});});
 const f=create(t),password='fixture-eitaa-pair-passphrase';
 const make=vault=>new CallPair(f.accounts,{executable:'fixture',open:f.open,createClient:f.createClient,
  createAccountClient:f.createAccountClient,openJournal:()=>vault.openEitaaCallJournal()});
 const read=async vault=>{const journal=await vault.openEitaaCallJournal();try{return await journal.load();}finally{await journal.close();}};
 const original=new SessionVault(directory);await original.unlock(password);
 const pair=make(original);
 try{
  const owner=await original.openEitaaCallJournal();
  try{
   await assert.rejects(pair.loadJournal(),{reason:'eitaa_call_owner_busy'});
   assert.equal(pair.state.canPrepare,false);
  }finally{await owner.close();}
  await pair.loadJournal();
  assert.equal(pair.state.canPrepare,true);
  await pair.prepare();
  f.api.override=async({method})=>{
   if(method==='phone.requestCall'){
    const saved=await read(original);assert.equal(saved.phase,'requested');assert.equal(saved.callId,null);
   }
   if(method==='phone.receivedCall'){
    const saved=await read(original);assert.equal(saved.phase,'bound');assert.equal(saved.callId,String(f.api.call.base.id));
   }
  };
  await pair.dial(1);
  assert.equal(pair.getCall(2).phase,'ringing');
  assert.equal((await read(original)).phase,'bound');
 }finally{pair.invalidate();await pair.settleJournal();original.lock();}
 const reopened=new SessionVault(directory);await reopened.unlock(password);
 const next=make(reopened);
 try{
  await next.loadJournal();assert.equal(next.state.canPrepare,false);assert.equal(next.state.canRecover,true);
  await assert.rejects(next.prepare(),{reason:'call_end_uncertain'});
  await assert.rejects(next.recover(),{reason:'call_end_uncertain'});
  f.api.queues.get(8000001).push({_:'updatePhoneCall',phone_call:{_:'phoneCallDiscarded',id:f.api.call.base.id}});
  assert.deepEqual(await next.recover(),{ended:true,remoteConfirmed:true});
  assert.equal(await read(reopened),null);assert.equal(next.state.canPrepare,true);
  assert.equal(f.api.calls.filter(call=>call.method==='phone.requestCall').length,1);
  assert.equal(f.api.calls.some(call=>call.method==='phone.discardCall'),false);
  await next.prepare();
  f.api.override=({method})=>{if(method==='phone.requestCall')throw Object.assign(Error('fixture reply lost'),{reason:'network_error'});};
  await assert.rejects(next.dial(1),{reason:'network_error'});
  assert.equal((await read(reopened)).phase,'requested');
 }finally{next.invalidate();await next.settleJournal();reopened.lock();}
 const afterLoss=new SessionVault(directory);await afterLoss.unlock(password);
 const blocked=make(afterLoss);
 try{
  const owner=await afterLoss.openEitaaCallJournal();
  try{
   await assert.rejects(blocked.loadJournal(),{reason:'eitaa_call_owner_busy'});
   assert.equal(blocked.state.canPrepare,false);
  }finally{await owner.close();}
  await blocked.loadJournal();
  assert.equal(blocked.state.canRecover,false);
  await assert.rejects(blocked.recover(),{reason:'call_end_uncertain'});
  await assert.rejects(blocked.prepare(),{reason:'call_end_uncertain'});
  assert.equal((await read(afterLoss)).phase,'requested');
 }finally{blocked.invalidate();await blocked.settleJournal();afterLoss.lock();}
});
