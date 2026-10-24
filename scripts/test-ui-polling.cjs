const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const html=fs.readFileSync(path.join(__dirname,'../bale-vpn-rust/bale-vpn/assets/index.html'),'utf8'),source=html.slice(html.indexOf('const _pollWaiters='),html.indexOf('function applyState()'));
test('forced refresh waits for an older pending poll, then fetches fresh state',async()=>{
 let release,count=0;const observed=[],noop=()=>{};
 const c=vm.createContext({_pollInFlight:false,_state:null,_trafficStatusStale:false,_telemetry:{},document:{hidden:false},embeddedActive:true,_desktopHidden:false,AbortController,setTimeout,clearTimeout,performance:{now:()=>0},sampleTraffic:noop,sampleAggregate:noop,applyState:()=>observed.push(c._state.version),fetch:async()=>{if(++count===1)return new Promise(resolve=>release=()=>resolve({ok:true,json:async()=>({version:1})}));return{ok:true,json:async()=>({version:2})};}});
 vm.runInContext(source,c);const pending=c.pollState(),forced=c.pollState(true);assert.equal(count,1);release();await Promise.all([pending,forced]);assert.equal(count,2);assert.deepEqual(observed,[1,2]);
});
test('hidden desktop and inactive account views do not poll periodically',async()=>{
 let count=0;const c=vm.createContext({_pollInFlight:false,_state:{},_desktopHidden:true,embeddedActive:true,document:{hidden:false},fetch:()=>{count++;}});vm.runInContext(source,c);await c.pollState();assert.equal(count,0);c._desktopHidden=false;c.embeddedActive=false;await c.pollState();assert.equal(count,0);
});
