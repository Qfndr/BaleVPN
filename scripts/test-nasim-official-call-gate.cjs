'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {OfficialCallGate,validateOfficialIntent}=require('../experiments/nasim/official-call-gate.cjs');
const {CleanupIntent}=require('../experiments/nasim/cleanup-intent.cjs');
function fixture(){
 let saved=null,failure=null,cleanupFailure=null;const cleanupSaved=new Map(),events=[];
 const accounts=new Map([1,2].map(slot=>[slot,{
  state:{provider:'nasim',signedIn:true,userId:String(40+slot),clientId:'client-'+slot},
  token:'fixture-private-token-'+slot,deviceId:'web.fixture-device-'+slot,
  exportSession(){return {...this.state,token:this.token,deviceId:this.deviceId};}
 }]));
 const store={async load(){return saved&&structuredClone(saved);},async save(next,previous,guard){
  guard();assert.deepEqual(previous,saved);if(failure==='before')throw Error('disk');saved=structuredClone(next);events.push('saved-'+next.phase);
  if(failure==='after')throw Error('disk');guard();
 },async clear(expected,guard){guard();assert.deepEqual(expected,saved);saved=null;}};
 function gate(){const cleanups=new Map([1,2].map(slot=>[slot,new CleanupIntent(accounts.get(slot),{
  async loadIntent(){return cleanupSaved.get(slot)||null;},
  async saveIntent(value,guard){guard();if(cleanupFailure===slot)throw Error('disk');cleanupSaved.set(slot,structuredClone(value));events.push('cleanup-'+slot);},
  async clearIntent(value,guard){guard();assert.deepEqual(value,cleanupSaved.get(slot));cleanupSaved.delete(slot);}
 })]));return new OfficialCallGate(accounts,cleanups,store);}
 return {accounts,gate,saved:()=>saved,events,setFailure:v=>{failure=v;},setCleanupFailure:v=>{cleanupFailure=v;},cleanupSaved};
}
const request={type:'callRequest',callData:{method:'audio'}};
const response={data:{callUUID:'fixture-call-uuid',callData:{method:'audio',participants:[{userID:'41'},{userID:'42'}]}}};
const ack=slot=>({acknowledged:true,terminalAcknowledgement:{type:'bye',callUUID:'fixture-call-uuid',peerId:slot===1?'42':'41'}});
async function bound(f){const gate=f.gate();await gate.begin();await gate.outgoing(1,request);await gate.bindResponse(1,response);return gate;}
test('durable request and both cleanup records precede admission; exact terminal acks clear',async()=>{
 const f=fixture(),gate=await bound(f);
 assert.deepEqual(f.events,['saved-prepared','saved-requested','saved-bound','cleanup-1','cleanup-2']);
 assert.equal(JSON.stringify(f.saved()).includes('fixture-private-token'),false);
 assert.equal(JSON.stringify(f.saved()).includes('fixture-device'),false);
 assert.equal((await gate.outgoing(2,{type:'accept',callUUID:'fixture-call-uuid',callData:{}})).topic,'u/41/42');
 await gate.acknowledgeTerminal(1,ack(1));assert.ok(f.saved());
 await gate.acknowledgeTerminal(2,ack(2));assert.equal(f.saved(),null);assert.equal(gate.state.pending,false);
});
test('request retries and wrong directions are denied before another network admission',async()=>{
 const f=fixture(),gate=f.gate();await gate.begin();
 await assert.rejects(gate.outgoing(2,request),e=>e.reason==='duplicate_call_request');
 await Promise.all([gate.outgoing(1,request),assert.rejects(gate.outgoing(1,request),e=>e.reason==='duplicate_call_request')]);
 await gate.bindResponse(1,response);
 await assert.rejects(gate.outgoing(1,{type:'accept',callUUID:'fixture-call-uuid',callData:{}}),e=>e.reason==='wrong_call_direction');
});
test('write failure before or after persistence cannot enable a request',async()=>{
 for(const failure of ['before','after']){
  const f=fixture(),gate=f.gate();f.setFailure(failure);await assert.rejects(gate.begin());
  await assert.rejects(gate.outgoing(1,request),e=>e.reason==='intent_save_failed');
  await assert.rejects(gate.begin(),e=>e.reason==='cleanup_pending');
 }
});
test('token or device changes and stop invalidate admission',async()=>{
 for(const field of ['token','deviceId']){
  const f=fixture(),gate=f.gate();await gate.begin();f.accounts.get(2)[field]+='changed';
  await assert.rejects(gate.outgoing(1,request),e=>e.reason==='account_binding_changed');
 }
 const f=fixture(),gate=f.gate();await gate.begin();gate.stop();
 await assert.rejects(gate.outgoing(1,request),e=>e.reason==='cancelled');
});
test('unbound and conflicting response UUIDs never release call media',async()=>{
 const f=fixture(),gate=f.gate();await gate.begin();await gate.outgoing(1,request);
 await assert.rejects(gate.bindResponse(1,{data:{}}),e=>e.reason==='call_uuid_missing');
 await assert.rejects(gate.outgoing(2,{type:'accept',callUUID:'fixture-call-uuid',callData:{}}));
 await gate.bindResponse(1,response);
 await assert.rejects(gate.bindResponse(1,{data:{...response.data,callUUID:'another-call'}}),e=>e.reason==='call_uuid_mismatch');
});
test('incoming peer and device are bound; known events wait for durable response',async()=>{
 const f=fixture(),gate=f.gate();await gate.begin();await gate.outgoing(1,request);
 const message={type:'msgGroupCall',data:{type:'accept',callUUID:'fixture-call-uuid'},from:{id:'42'},senderClientID:'client-2'};
 assert.deepEqual(await gate.incoming(1,message),{defer:true});await gate.bindResponse(1,response);
 assert.equal((await gate.incoming(1,message)).defer,false);
 await assert.rejects(gate.incoming(1,{...message,senderClientID:'other-client'}),e=>e.reason==='wrong_peer');
 await assert.rejects(gate.incoming(1,{...message,data:{...message.data,callUUID:'wrong'}}),e=>e.reason==='call_uuid_mismatch');
});
test('restart never makes another call from prepared or requested intent',async()=>{
 for(const requested of [false,true]){
  const f=fixture(),gate=f.gate();await gate.begin();if(requested)await gate.outgoing(1,request);
  const restored=f.gate();assert.equal(await restored.restore(),true);
  await assert.rejects(restored.begin(),e=>e.reason==='cleanup_pending');
  await assert.rejects(restored.outgoing(1,request),e=>e.reason==='cleanup_pending');
 }
});
test('bound restart retains cleanup and refuses generic or mismatched acknowledgements',async()=>{
 const f=fixture();await bound(f);const restored=f.gate();await restored.restore();
 await assert.rejects(restored.acknowledgeTerminal(1,{acknowledged:true}),e=>e.reason==='cleanup_unconfirmed');
 await assert.rejects(restored.acknowledgeTerminal(1,ack(2)),e=>e.reason==='cleanup_unconfirmed');
 await restored.outgoing(1,{type:'bye',callUUID:'fixture-call-uuid',callData:null});
 await restored.acknowledgeTerminal(1,ack(1));await restored.acknowledgeTerminal(2,ack(2));assert.equal(f.saved(),null);
});
test('journal validation rejects substituted source, account and invalid phase',async()=>{
 const f=fixture(),gate=f.gate();await gate.begin();const stored=f.saved();
 for(const value of [{...stored,sourceHash:'0'.repeat(64)},{...stored,phase:'bound'},
  {...stored,accounts:[stored.accounts[0],stored.accounts[0]]}])assert.throws(()=>validateOfficialIntent(value));
});
test('partial per-account cleanup persistence blocks media and retains the known UUID',async()=>{
 const f=fixture(),gate=f.gate();await gate.begin();await gate.outgoing(1,request);f.setCleanupFailure(2);
 await assert.rejects(gate.bindResponse(1,response));assert.equal(f.saved().callUUID,'fixture-call-uuid');
 await assert.rejects(gate.outgoing(2,{type:'accept',callUUID:'fixture-call-uuid',callData:{}}));
 f.setCleanupFailure(null);const recovered=f.gate();await recovered.restore();
 assert.equal(f.cleanupSaved.size,2);
 await assert.rejects(recovered.outgoing(1,request),e=>e.reason==='cleanup_pending');
});
test('same-device echo is dropped without treating it as a remote participant',async()=>{
 const f=fixture(),gate=await bound(f);
 assert.deepEqual(await gate.incoming(1,{type:'msgGroupCall',data:{type:'accept',callUUID:'fixture-call-uuid'},
  from:{id:'41'},senderClientID:'client-1'}),{defer:false,drop:true});
});
test('a recovered terminal journal can clear without permitting another call',async()=>{
 const f=fixture(),gate=await bound(f);await gate.acknowledgeTerminal(1,ack(1));
 const restored=f.gate();await restored.restore();await restored.acknowledgeTerminal(2,ack(2));
 assert.equal(f.saved(),null);await restored.begin();await restored.outgoing(1,request);
 assert.equal(f.saved().phase,'requested');
});
const peerBye=slot=>({type:'msgGroupCall',data:{type:'bye',callUUID:'fixture-call-uuid',callData:null},
 from:{id:slot===1?'42':'41'},senderClientID:slot===1?'client-2':'client-1'});
test('one HTTP acknowledgement and the other account peer bye complete cleanup',async()=>{
 const f=fixture(),gate=await bound(f);await gate.acknowledgeTerminal(1,ack(1));
 assert.deepEqual(f.saved().terminalEvents,[{slot:1,source:'http-ack'}]);
 await gate.terminalEvent(2,peerBye(2));assert.equal(f.saved(),null);assert.equal(f.cleanupSaved.size,0);
 const second=fixture(),other=await bound(second);await other.terminalEvent(2,peerBye(2));
 assert.deepEqual(second.saved().terminalEvents,[{slot:2,source:'peer-bye'}]);
 await other.acknowledgeTerminal(1,ack(1));assert.equal(second.saved(),null);
});
test('stale, wrong-peer, wrong-device and own-echo bye cannot clear cleanup',async()=>{
 const f=fixture(),gate=await bound(f),valid=peerBye(2);
 for(const message of [{...valid,data:{...valid.data,callUUID:'old-call'}},{...valid,from:{id:'43'}},
  {...valid,senderClientID:'wrong-device'},{...valid,from:{id:'42'},senderClientID:'client-2'}]){
  await assert.rejects(gate.terminalEvent(2,message),e=>e.reason==='cleanup_unconfirmed');
  assert.equal(f.cleanupSaved.size,2);assert.deepEqual(f.saved().terminalEvents,[]);
 }
});
test('terminal SSE write failure retains cleanup and preserves the evidence kind after recovery',async()=>{
 for(const failure of ['before','after']){
  const f=fixture(),gate=await bound(f);f.setFailure(failure);
  await assert.rejects(gate.terminalEvent(2,peerBye(2)));assert.equal(f.cleanupSaved.size,2);
  assert.equal(gate.state.pending,true);f.setFailure(null);
  const restored=f.gate();await restored.restore();
  if(failure==='after')assert.deepEqual(f.saved().terminalEvents,[{slot:2,source:'peer-bye'}]);
  else await restored.terminalEvent(2,peerBye(2));
  await restored.acknowledgeTerminal(1,ack(1));assert.equal(f.saved(),null);
 }
});
