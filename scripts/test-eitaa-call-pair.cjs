'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {CallPair}=require('../experiments/eitaa/call-pair.cjs'),{fixture}=require('./eitaa-lab-call-fixture.cjs');
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
 f.pair.invalidate();assert.equal(f.pair.state.phase,'uncertain');
 await assert.rejects(f.pair.prepare(),{reason:'call_end_uncertain'});
 assert.equal(f.api.calls.filter(call=>call.method==='phone.requestCall').length,1);
});
test('failure before phone.requestCall does not fence a new preparation',async t=>{
 const f=create(t);await f.pair.prepare();
 f.api.override=({method})=>{if(method==='messages.getDhConfig')throw Object.assign(Error('fixture DH rejected'),{reason:'service_rejected'});};
 await assert.rejects(f.pair.dial(1),{reason:'service_rejected'});
 assert.equal(f.pair.state.canPrepare,true);
 assert.equal(f.api.calls.some(call=>call.method==='phone.requestCall'),false);
 await f.pair.prepare();
});
