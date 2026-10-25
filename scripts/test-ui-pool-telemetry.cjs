const {test}=require('node:test'),assert=require('node:assert/strict');
const {create,sample,link,grade}=require('../bale-vpn-rust/bale-vpn/assets/pool-telemetry.js');
const state=(rtt,sent,lost,session=1)=>({clientRoomReady:true,metrics:{rttMs:rtt,sentPackets:sent,lostPackets:lost},traffic:{sessionId:session}});
const pool=(rx,instance=1)=>({instance,running:true,paths:[{profileId:1,name:'One',receivedBytes:rx,sentBytes:rx/10,active:1},{profileId:2,name:'Two',receivedBytes:rx*2,sentBytes:rx/5,active:2}]});
test('pool rates use measured elapsed time, counters and independent path totals',()=>{
 const m=create(),t=new Map([[1,state(50,100,1)],[2,state(150,300,3)]]);
 sample(m,pool(100),t,1000);assert.equal(m.rx,null);sample(m,pool(2100),t,3000);
 assert.equal(m.rx,3000);assert.equal(m.tx,300);assert.equal(m.rows.get(1).rx,1000);assert.equal(m.points.at(-1).rtt,100);assert.equal(m.points.at(-1).loss,1);
});
test('missing/disconnected sources and impossible loss counters remain unknown, not zero',()=>{
 const m=create();sample(m,pool(100),new Map([[1,state(50,100,0)]]),1000);
 assert.equal(m.rows.get(2).link.loss,null);assert.equal(m.points.at(-1).loss,null);assert.equal(m.points.at(-1).coverage,1);
 assert.equal(link(state(50,0,0),null,1).loss,null);assert.equal(link(state(50,10,11),null,1).loss,null);
 assert.equal(link({clientRoomReady:false,metrics:{rttMs:50,sentPackets:100,lostPackets:0}},null,1).rtt,null);
});
test('gaps, pool restarts and counter resets cannot invent rates or retain another session RTT variation',()=>{
 const m=create(),t=new Map([[1,state(20,100,0)],[2,state(40,100,0)]]);
 sample(m,pool(100),t,1000);sample(m,pool(200),t,2000);assert.equal(m.rx,300);
 sample(m,pool(900),t,12000);assert.equal(m.rx,null);assert.equal(m.points.at(-1).gap,true);
 sample(m,pool(1,2),t,13000);assert.equal(m.points.length,1);assert.equal(m.rx,null);
 const first=link(state(20,100,1),null,1000),second=link(state(60,110,1),first,2000);assert.equal(second.variation,10);
 assert.equal(link(state(90,1,0,2),second,3000).variation,null);
});
test('bounded charts, duplicate poll rejection and explicit quality thresholds',()=>{
 const m=create(),t=new Map([[1,state(20,100,0)],[2,state(40,100,0)]]);
 for(let i=0;i<1000;i++)sample(m,pool(i),t,i*1000);assert.equal(m.points.length,301);
 const n=m.points.length;sample(m,pool(1001),t,999100);assert.equal(m.points.length,n);
 assert.equal(grade(m.rows.get(1)),'Good');assert.equal(grade({link:link(state(500,100,0),null,1)}),'Degraded');assert.equal(grade({link:link(state(20,0,0),null,1)}),'RTT only');
});
