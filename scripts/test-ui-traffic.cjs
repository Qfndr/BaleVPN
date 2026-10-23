const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const html=fs.readFileSync(path.join(__dirname,'../bale-vpn-rust/bale-vpn/assets/index.html'),'utf8');
const source=html.slice(html.indexOf('// ── Bounded traffic model'),html.indexOf('// ── Traffic rendering'));
function model(){const context=vm.createContext({_trafficUnits:'bytes'});vm.runInContext(source,context);return context;}
const snapshot=(rx,tx,elapsed=10000,id=1,active=true)=>({sessionId:id,receivedBytes:rx,sentBytes:tx,sessionElapsedMs:elapsed,processReceivedBytes:rx,processSentBytes:tx,active});
test('rates use byte deltas and actual sample time, not render count',()=>{
 const c=model(),m=c.newTrafficModel();c.sampleTraffic(m,snapshot(100,50),1000,{rttMs:100});
 c.sampleTraffic(m,snapshot(2100,1050),3000,{rttMs:120});
 assert.equal(m.rxRate,1000);assert.equal(m.txRate,500);assert.equal(m.rxPeak,1000);
 c.sampleTraffic(m,snapshot(2100,1050),3010,{rttMs:120});assert.equal(m.rxRate,1000);
 c.sampleTraffic(m,snapshot(2100,1050),5000,{rttMs:120});assert.equal(m.rxRate,0);assert.equal(m.rxPeak,1000);
});
test('counter restart, reconnect and hidden-page gaps never create spikes',()=>{
 const c=model(),m=c.newTrafficModel();c.sampleTraffic(m,snapshot(9000,6000),1000,{});
 c.sampleTraffic(m,snapshot(1,1),3000,{});assert.equal(m.rxRate,0);assert.ok(m.points.at(-1).gap);
 c.sampleTraffic(m,snapshot(1000000,1),30000,{});assert.equal(m.rxRate,0);assert.ok(m.points.at(-1).gap);
 c.sampleTraffic(m,snapshot(30,10,100,2),32000,{});assert.equal(m.points.length,1);assert.equal(m.rxPeak,0);
});
test('ended session retains totals while current speed becomes zero',()=>{
 const c=model(),m=c.newTrafficModel();c.sampleTraffic(m,snapshot(0,0),0,{});
 c.sampleTraffic(m,snapshot(2000,1000),2000,{});c.sampleTraffic(m,snapshot(2000,1000,10000,1,false),4000,{});
 assert.equal(m.rxRate,0);assert.equal(m.snapshot.receivedBytes,2000);assert.equal(m.rxPeak,1000);
});
test('history is bounded and CSV exports numeric samples with no account data',()=>{
 const c=model(),m=c.newTrafficModel();for(let i=0;i<1000;i++)c.sampleTraffic(m,snapshot(i*2000,i*1000),i*2000,{rttMs:30});
 assert.equal(m.points.length,451);const csv=c.trafficCSV(m);assert.equal(csv.split('\n').length,452);
 assert.ok(csv.startsWith('elapsed_seconds,download_bytes_per_second,upload_bytes_per_second,rtt_ms,gap\n'));
 assert.ok(!csv.includes('sessionId'));assert.ok(!csv.includes('NaN'));
});
test('malformed values cannot produce invalid graph coordinates',()=>{
 const c=model(),m=c.newTrafficModel();c.sampleTraffic(m,snapshot(Infinity,-1),1000,{});
 c.sampleTraffic(m,snapshot(NaN,100),3000,{});assert.equal(m.rxRate,0);assert.equal(m.txRate,50);
 assert.equal(c.trafficVolume(400000),'400 KB');assert.equal(c.trafficDuration(3661000),'01:01:01');
});
