'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {CallPair}=require('../experiments/rubika/call-pair.cjs'),{fixture}=require('./rubika-lab-call-fixture.cjs');
async function create(t,options={}){const f=await fixture(options),pair=new CallPair(f.accounts,{executable:'fixture',open:f.open,createClient:f.createClient,pollInterval:0});t.after(()=>{pair.reset();f.broker.close();});return {...f,pair};}

test('a rejected live-update request retains only whitelisted operation diagnostics after closing workers',async t=>{
 const {ApiError}=require('../experiments/rubika/http-client.cjs');
 const f=await create(t,{hook:async(_slot,method)=>{if(method==='getUpdate'){const e=new ApiError('service_rejected',400,'INVALID_INPUT');e.privateBody='private-response';throw e;}}});
 await f.pair.prepare();await assert.rejects(f.pair.pollOnce(),/service_rejected/);assert.equal(f.pair.state.phase,'failed');assert.deepEqual(f.pair.state.diagnostic,{serviceCode:'INVALID_INPUT',statusCode:400,operation:'getUpdate'});assert.ok(!JSON.stringify(f.pair.state).includes('private-response'));f.pair.reset();assert.equal(f.pair.state.diagnostic,null);
});
test('local pair prepares without dialing, requires manual acceptance and exchanges only locally owned QUIC pins',async t=>{
 const f=await create(t);await f.pair.prepare({clientSlot:1,socksPort:1092});assert.equal(f.pair.state.phase,'ready');assert.equal(f.broker.calls.some(x=>x.method==='requestCall'),false);
 await f.pair.dial(1);assert.equal(f.pair.getCall(2).phase,'ringing');assert.equal(f.broker.calls.some(x=>x.method==='acceptCall'),false);
 await f.pair.accept(2);await f.pair.pollOnce();assert.equal(f.pair.state.phase,'connected');assert.equal(f.pair.getCall(1).media.socksAddress,'127.0.0.1:1092');assert.equal(f.pair.getCall(2).media.serverReady,true);
 assert.deepEqual(f.broker.started,[1,1]);for(const secret of [f.broker.key,f.broker.records[0].privateKey,'fixture-private-password','trustedCertificates','publicCertificate'])assert.ok(!JSON.stringify(f.pair.state).includes(secret));
 await f.pair.end(1);assert.equal(f.pair.state.phase,'ended');assert.ok(f.natives.every(n=>n.closed===1));assert.ok([...f.accounts.values()].every(a=>a.state.signedIn));
});
test('either account may dial independently of client/server transport roles',async t=>{
 const f=await create(t);await f.pair.prepare({clientSlot:1,socksPort:1093});await f.pair.dial(2);await f.pair.accept(1);await f.pair.pollOnce();assert.equal(f.pair.state.phase,'connected');assert.equal(f.pair.getCall(1).media.role,'client');assert.equal(f.pair.getCall(2).media.role,'server');
});
test('acceptance arriving before the final key update waits without consuming a lease or failing the pair',async t=>{
 let f,late;f=await create(t,{hook:async(slot,method)=>{
  if(slot===0&&method==='getUpdate'&&!late){const accepted=f.broker.events[0].find(u=>u.call?.state==='Accepted');if(accepted){late=structuredClone(accepted);delete accepted.call.key;accepted.updated_parameters=accepted.updated_parameters.filter(k=>k!=='key');}}
 }});
 await f.pair.prepare();await f.pair.dial(1);await f.pair.accept(2);assert.equal(f.pair.getCall(1).phase,'negotiating');assert.ok(f.natives.every(n=>n.options===null));
 late.timestamp++;late.updated_parameters=['key'];f.broker.events[0].push(late);await f.pair.pollOnce();await f.pair.pollOnce();assert.equal(f.pair.state.phase,'connected');assert.deepEqual(f.broker.started,[1,1]);
});
test('reset closes late preparation workers without reviving an old pair or changing authenticated accounts',async t=>{
 const f=await fixture();let entered,release,count=0;const gate=new Promise(r=>{entered=r;}),pair=new CallPair(f.accounts,{executable:'fixture',createClient:f.createClient,pollInterval:0,open:async()=>{
  const b=await f.open();if(++count<=2)await new Promise(r=>{const previous=release;release=()=>{previous?.();r();};if(count===2)entered();});return b;
 }});t.after(()=>{pair.reset();f.broker.close();});const preparing=pair.prepare();await gate;pair.reset();release();await assert.rejects(preparing);
 assert.equal(pair.state.phase,'idle');assert.ok(f.natives.every(n=>n.closed===1));assert.ok([...f.accounts.values()].every(a=>a.state.signedIn));
});
test('account revocation or duplicate accounts fail closed and cannot keep a local proxy alive',async t=>{
 const f=await create(t);await f.pair.prepare();await f.pair.dial(1);await f.pair.accept(2);await f.pair.pollOnce();f.broker.accountStates[0].signedIn=false;
 assert.equal(f.pair.state.phase,'failed');assert.ok(f.natives.every(n=>n.closed===1));
 const duplicate=new Map([[1,f.accounts.get(2)],[2,f.accounts.get(2)]]),p=new CallPair(duplicate,{executable:'fixture'});t.after(()=>p.reset());await assert.rejects(p.prepare(),/distinct_accounts_required/);
});
test('uncertain remote hangup still closes local workers and preserves a visible uncertain state',async t=>{
 const f=await create(t,{hook:async(slot,method)=>{if(method==='discardCall')throw new(require('../experiments/rubika/http-client.cjs').ApiError)('network_error');}});
 await f.pair.prepare();await f.pair.dial(1);await f.pair.accept(2);await f.pair.pollOnce();await assert.rejects(f.pair.end(1),/call_end_uncertain/);
 assert.equal(f.pair.state.phase,'uncertain');assert.ok(f.natives.every(n=>n.closed===1));assert.ok(f.broker.accountStates.every(a=>a.signedIn));
});
test('a remote end during periodic reception closes both media owners without logging out either account',async t=>{
 const f=await create(t);await f.pair.prepare();await f.pair.dial(1);await f.pair.accept(2);await f.pair.pollOnce();
 f.broker.events[0].push({action:'Delete',call_id:f.broker.callId,timestamp:f.broker.update(0,'Accepted').timestamp+1});
 assert.deepEqual(await f.pair.pollOnce(),{ended:true});assert.equal(f.pair.state.phase,'ended');assert.ok(f.natives.every(n=>n.closed===1));assert.ok(f.broker.accountStates.every(a=>a.signedIn));
});
