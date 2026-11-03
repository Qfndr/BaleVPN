'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {CallPair}=require('../experiments/nasim/call-pair.cjs');
test('preparing after end retires stale event bindings before reconnecting either account',async()=>{
 const accounts=new Map();let certificates=0;
 for(const slot of [1,2]){const account={phase:'idle',rpc:null,connections:0,get state(){return {provider:'nasim',signedIn:true,userId:String(40+slot),clientId:'client-'+slot,events:{phase:this.phase}};},get signalConnection(){if(this.phase!=='connected')throw Error('Old stream ended');return this.rpc;},async connectSignals(){this.connections++;this.phase='connected';this.rpc={send:async()=>({acknowledged:true}),close(){}};return {eventsConnected:true};},disconnectSignals(){this.phase='closed';this.rpc=null;}};accounts.set(slot,account);}
 const pair=new CallPair(accounts,{executable:'fixture',open:async()=>({publicCertificate:(++certificates).toString(16).padStart(2,'0').repeat(80),state:{phase:'prepared'},close(){}})});
 try{await pair.prepare();await pair.end(1);accounts.get(1).phase='failed';await pair.prepare({clientSlot:2});assert.equal(pair.state.phase,'ready');assert.equal(accounts.get(1).connections,2);assert.equal(accounts.get(2).connections,2);}finally{pair.reset();}
});
