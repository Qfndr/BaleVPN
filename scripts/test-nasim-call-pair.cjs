'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {CallPair}=require('../experiments/nasim/call-pair.cjs');
const {ApiError}=require('../experiments/nasim/http-client.cjs');
function failingPair(connect){
 let sends=0,opens=0;
 const accounts=new Map([1,2].map(slot=>[slot,{
  get state(){return {provider:'nasim',signedIn:true,userId:String(40+slot),clientId:'client-'+slot,events:{phase:'idle'}};},
  connectSignals(){return connect(slot);},disconnectSignals(){},
  get signalConnection(){return {send:async()=>{sends++;return {acknowledged:true};}};}
 }]));
 const pair=new CallPair(accounts,{executable:'fixture',open:async()=>{opens++;throw Error('must not open media before streams');}});
 return {pair,get sends(){return sends;},get opens(){return opens;}};
}
test('stream prepare timeout is retained safely and failed prepare cannot dial',async()=>{
 const fixture=failingPair(async()=>{throw new ApiError('stream_connect_timeout',503,'private-service-value');});
 await assert.rejects(fixture.pair.prepare(),e=>e.reason==='stream_connect_timeout'&&e.statusCode===undefined&&e.serviceType===undefined);
 assert.equal(fixture.pair.state.reason,'stream_connect_timeout');
 await assert.rejects(fixture.pair.dial(),{reason:'call_not_ready'});
 assert.equal(fixture.sends,0);assert.equal(fixture.opens,0);
 fixture.pair.reset();
});
test('unknown and untyped prepare errors never expose provider details',async()=>{
 for(const failure of [new ApiError('private-provider-value'),Object.assign(Error('private-error-text'),{reason:'stream_connect_timeout'})]){
  const {pair}=failingPair(async()=>{throw failure;});
  await assert.rejects(pair.prepare(),{reason:'call_prepare_failed'});
  assert.equal(pair.state.reason,'call_prepare_failed');pair.reset();
 }
});
test('reset during stream prepare keeps cancellation and cannot revive the pair',async()=>{
 let settle;const pending=new Promise(resolve=>{settle=resolve;});
 const fixture=failingPair(()=>pending);const preparing=fixture.pair.prepare();
 fixture.pair.reset();settle({eventsConnected:true});
 await assert.rejects(preparing,{reason:'call_cancelled'});
 assert.equal(fixture.pair.state.phase,'idle');assert.equal(fixture.pair.state.reason,null);
 await assert.rejects(fixture.pair.dial(),{reason:'call_not_ready'});
 assert.equal(fixture.sends,0);assert.equal(fixture.opens,0);
});
test('preparing after end retires stale event bindings before reconnecting either account',async()=>{
 const accounts=new Map();let certificates=0;
 for(const slot of [1,2]){const account={phase:'idle',rpc:null,connections:0,get state(){return {provider:'nasim',signedIn:true,userId:String(40+slot),clientId:'client-'+slot,events:{phase:this.phase}};},get signalConnection(){if(this.phase!=='connected')throw Error('Old stream ended');return this.rpc;},async connectSignals(){this.connections++;this.phase='connected';this.rpc={send:async()=>({acknowledged:true}),close(){}};return {eventsConnected:true};},disconnectSignals(){this.phase='closed';this.rpc=null;}};accounts.set(slot,account);}
 const pair=new CallPair(accounts,{executable:'fixture',open:async()=>({publicCertificate:(++certificates).toString(16).padStart(2,'0').repeat(80),state:{phase:'prepared'},close(){}})});
 try{await pair.prepare();await pair.end(1);accounts.get(1).phase='failed';await pair.prepare({clientSlot:2});assert.equal(pair.state.phase,'ready');assert.equal(accounts.get(1).connections,2);assert.equal(accounts.get(2).connections,2);}finally{pair.reset();}
});
