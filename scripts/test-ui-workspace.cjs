const {test}=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs'),path=require('node:path');
const html=fs.readFileSync(path.join(__dirname,'../bale-vpn-rust/bale-vpn/assets/index.html'),'utf8');
const code=html.slice(html.indexOf('// ── Workspace navigation'),html.indexOf('const dot        ='));
const keys=['connection','traffic','clients','security','performance','appearance'];
function harness(rtl=false){
 const elements=new Map(),focus={id:null};
 function get(id){if(!elements.has(id))elements.set(id,{id,hidden:false,dataset:{},textContent:'',value:'unsaved',listeners:{},attrs:{},setAttribute(key,value){this.attrs[key]=value;},getAttribute(key){return this.attrs[key];},querySelector(){return {textContent:this.id.replace('tab-','')};},focus(){focus.id=this.id;},addEventListener(event,handler){this.listeners[event]=handler;}});return elements.get(id);}
 const tabs=keys.map(key=>{const tab=get('tab-'+key);tab.dataset.tab=key;tab.attrs['aria-controls']='panel-'+key;return tab;});
 const document={documentElement:{dir:rtl?'rtl':'ltr'},getElementById:get,querySelector:()=>get('intro'),querySelectorAll:selector=>selector==='[data-tab]'?tabs:[]};
 const context=vm.createContext({document,_trafficStatusStale:false,translated:(en,fa)=>rtl?fa:en,fetch:()=>{throw new Error('Navigation must not access the network');}});
 vm.runInContext(code,context);context.initializeWorkspace();return {context,get,focus};
}
test('workspace tabs expose one panel, keep edits, and show save actions only where relevant',()=>{
 const h=harness();h.get('serverCode').value='unsaved-code';
 for(const key of keys){h.context.setWorkspaceTab(key);for(const candidate of keys){assert.equal(h.get('panel-'+candidate).hidden,candidate!==key);assert.equal(h.get('tab-'+candidate).getAttribute('aria-selected'),String(candidate===key));assert.equal(h.get('tab-'+candidate).tabIndex,candidate===key?0:-1);}assert.equal(h.get('workspaceSettingsFooter').hidden,!['security','performance'].includes(key));}
 assert.equal(h.get('serverCode').value,'unsaved-code');
});
test('unknown navigation keys cannot expose arbitrary elements or mutate selected panels',()=>{
 const h=harness();h.context.setWorkspaceTab('security');for(const key of ['constructor','__proto__','<img onerror=alert(1)>',null])h.context.setWorkspaceTab(key);
 assert.equal(h.get('panel-security').hidden,false);assert.equal(h.get('panel-connection').hidden,true);
});
test('keyboard navigation follows language direction and supports Home and End',()=>{
 for(const rtl of [false,true]){const h=harness(rtl);let prevented=0;const press=(id,key)=>h.get('tab-'+id).listeners.keydown({key,preventDefault(){prevented++;}});
  press('connection',rtl?'ArrowLeft':'ArrowRight');assert.equal(h.focus.id,'tab-traffic');
  press('traffic','End');assert.equal(h.focus.id,'tab-appearance');
  press('appearance','Home');assert.equal(h.focus.id,'tab-connection');
  press('connection','ArrowUp');assert.equal(h.focus.id,'tab-appearance');assert.equal(prevented,4);
 }
});
test('workspace status uses real client/server readiness, detects stale state and restores empty views on logout',()=>{
 const h=harness();h.context.syncWorkspace({mode:'client',tokenSet:true,wsReady:true,clientRoomReady:false});assert.equal(h.get('workspaceStatus').textContent,'Ready to connect');
 h.context.syncWorkspace({mode:'client',tokenSet:true,wsReady:false,clientRoomReady:true});assert.equal(h.get('workspaceStatus').textContent,'Tunnel ready');assert.equal(h.get('trafficAnalytics').hidden,false);
 h.context.syncWorkspace({mode:'server',tokenSet:true,wsReady:true});assert.equal(h.get('workspaceStatus').textContent,'Accepting clients');assert.equal(h.get('clientsEmpty').hidden,true);assert.equal(h.get('trafficAnalytics').hidden,true);
 h.context._trafficStatusStale=true;h.context.syncWorkspace({mode:'server',tokenSet:true,wsReady:true});assert.equal(h.get('workspaceStatus').textContent,'Status unavailable');assert.equal(h.get('wsStateText').textContent,'Status unavailable');
 h.context._trafficStatusStale=false;h.context.syncWorkspace({mode:null,tokenSet:false,wsReady:false});assert.equal(h.get('workspaceStatus').textContent,'Not signed in');assert.equal(h.get('clientsEmpty').hidden,false);assert.equal(h.get('trafficEmpty').hidden,false);
});
