const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {CleanupIntent,validateIntent}=require('../experiments/nasim/cleanup-intent.cjs');
const {SessionVault}=require('../experiments/providers/session-vault.cjs');
const {fixture:callFixture,waitFor}=require('./nasim-call-fixture.cjs');
function fixture(){
 let saved=null,clears=0,failSave=false,reply=null;const sent=[];
 const account={state:{provider:'nasim',signedIn:true,userId:'41',clientId:'client-41'},token:'fixture-private-token',
  exportSession(){return {...this.state,token:this.token};}};
 account.signalConnection={async send(signal,{peerId}){sent.push({signal,peerId});if(reply instanceof Error)throw reply;return reply;}};
 const store={async saveIntent(record,guard){guard();if(failSave)throw Error('disk');saved=structuredClone(record);guard();},
  async loadIntent(){return saved&&structuredClone(saved);},async clearIntent(record,guard){guard();assert.deepEqual(record,saved);saved=null;clears++;guard();}};
 return {account,sent,store,manager:new CleanupIntent(account,store),saved:()=>saved,clears:()=>clears,
  failSave:value=>{failSave=value;},reply:value=>{reply=value;}};
}
const call={peerId:'42',callUUID:'fixture-private-call'};
const ack=(uuid=call.callUUID,peerId='42')=>({acknowledged:true,terminalAcknowledgement:{type:'bye',callUUID:uuid,peerId}});

test('capture is private, restore never sends and explicit matched bye acknowledgement clears',async()=>{
 const f=fixture();await f.manager.capture(call);const record=f.saved();assert.equal(record.callUUID,call.callUUID);
 assert.ok(!JSON.stringify(record).includes(f.account.token));assert.equal(f.sent.length,0);
 const restored=new CleanupIntent(f.account,f.store);assert.equal(await restored.restore(),true);assert.equal(f.sent.length,0);
 await assert.rejects(restored.ensureClear(),e=>e.reason==='cleanup_pending');f.reply(ack());
 assert.deepEqual(await restored.cleanup(),{cleanupPending:false,serviceAcknowledged:true,remoteEndedVerified:false});
 assert.deepEqual(f.sent,[{signal:{type:'bye',callUUID:call.callUUID,callData:null},peerId:'42'}]);assert.equal(f.clears(),1);
});
test('generic, wrong-call, wrong-peer and missing acknowledgement never clear intent',async()=>{
 const f=fixture();await f.manager.capture(call);
 for(const response of [{acknowledged:true},ack('wrong-call'),ack(call.callUUID,'43'),{...ack(),acknowledged:false},null]){
  f.reply(response);await assert.rejects(f.manager.cleanup(),e=>e.reason==='cleanup_unconfirmed');assert.ok(f.saved());
 }
 f.reply(Object.assign(Error('timeout'),{reason:'timeout'}));await assert.rejects(f.manager.cleanup());assert.equal(f.clears(),0);
});
test('failed persistence and reset cannot silently enable another call',async()=>{
 const f=fixture();f.failSave(true);await assert.rejects(f.manager.capture(call),e=>e.reason==='cleanup_save_failed');
 f.manager.forgetMemory();await assert.rejects(f.manager.ensureClear(),e=>e.reason==='cleanup_pending');
 await assert.rejects(f.manager.capture({peerId:'43',callUUID:'new-call'}),e=>e.reason==='cleanup_pending');assert.equal(f.sent.length,0);
});
test('wrong account/device and changed connection cannot acknowledge old cleanup',async()=>{
 const f=fixture();await f.manager.capture(call);f.account.token='other-token';await assert.rejects(new CleanupIntent(f.account,f.store).restore(),e=>e.reason==='account_binding_changed');
 f.account.token='fixture-private-token';const old=f.account.signalConnection;
 old.send=async()=>{f.account.signalConnection={};return ack();};await assert.rejects(f.manager.cleanup(),e=>e.reason==='account_binding_changed');assert.equal(f.clears(),0);
});
test('only exact peer terminal confirmation clears the captured call',async()=>{
 const f=fixture();await f.manager.capture(call);
 await f.manager.peerEnded({peerId:'43',callUUID:call.callUUID});await f.manager.peerEnded({peerId:'42',callUUID:'other-call'});assert.equal(f.clears(),0);
 await f.manager.peerEnded(call);assert.equal(f.clears(),1);
});
test('initial media failure preserves both captured intents after the call context is cleared',async()=>{
 const saved=new Map();
 const f=callFixture({cleanupFactory:account=>new CleanupIntent(account,{
  async saveIntent(value,guard){guard();saved.set(account.state.userId,structuredClone(value));},
  async loadIntent(){return saved.get(account.state.userId)||null;},
  async clearIntent(value,guard){guard();saved.delete(account.state.userId);},
 })});
 try{const {a,b}=await f.prepare();await a.dial('42');await waitFor(()=>saved.size===2&&b.state.phase==='incoming');
  assert.equal(f.natives[1].ops.length,0); // captured before any media config/SDP
  f.natives[1].latest={phase:'failed',reason:'ice_failed'};await waitFor(()=>b.state.phase==='uncertain');
  assert.equal(b.state.callUUID,null);assert.equal(b.state.cleanup.pending,true);assert.equal(saved.size,2);
  b.reset();assert.equal(saved.get('42').callUUID,'fixture-call-1');
 }finally{f.close();}
});

test('correlated call response wins queued old config and conflicting configs cannot replace cleanup identity',async()=>{
 const saved=new Map();let writes=0;
 const f=callFixture({
  cleanupFactory:account=>new CleanupIntent(account,{
   async saveIntent(value,guard){guard();writes++;saved.set(account.state.userId,structuredClone(value));},
   async loadIntent(){return saved.get(account.state.userId)||null;},
   async clearIntent(value,guard){guard();saved.delete(account.state.userId);},
  }),
  sendHook:async({sender,peerId,signal})=>{
   if(signal.type!=='callRequest')return;
   f.deliver(sender,f.config(sender,sender,'old-call'));
   f.deliver(sender,f.config(sender,sender,'current-call'));
   f.deliver(peerId,f.config(peerId,sender,'current-call'));
   return {acknowledged:true,reply:null,requestCallUUID:'current-call'};
  },
 });
 try{
  const {a,b}=await f.prepare();await a.dial('42');
  await waitFor(()=>saved.size===2&&!a.state.busy&&b.state.phase==='incoming');
  assert.equal(a.state.callUUID,'current-call');assert.equal(b.state.callUUID,'current-call');
  assert.equal(a.state.signaling.requestedCallBound,true);assert.equal(a.state.signaling.wrongCall,1);
  for(const id of ['41','42']){
   f.deliver(id,f.config(id,'41','current-call'));
   f.deliver(id,f.config(id,'41','unrelated-call'));
  }
  await waitFor(()=>!a.state.busy&&!b.state.busy&&a.state.signaling.wrongCall===2&&b.state.signaling.wrongCall===1);
  assert.equal(a.state.phase,'outgoing');assert.equal(b.state.phase,'incoming');
  assert.equal(writes,2);assert.ok([...saved.values()].every(value=>value.callUUID==='current-call'));
  assert.ok(f.sent.every(event=>!['bye','reject'].includes(event.signal.type)));
  await b.accept();await waitFor(()=>a.state.phase==='connected'&&b.state.phase==='connected');
  assert.equal(a.state.reason,null);assert.equal(b.state.reason,null);
  a.reset();assert.equal(a.state.signaling.requestedCallBound,false);
 }finally{f.close();}
});
test('intent schema rejects unknown fields and malformed identity without expiry deletion',()=>{
 const record={format:'nasim-cleanup-intent-v1',provider:'nasim',accountBinding:'ab'.repeat(32),selfId:'41',selfClientId:'device',peerId:'42',callUUID:'old-call',capturedAt:1};
 assert.deepEqual(validateIntent(record),record);
 for(const bad of [{...record,token:'secret'},{...record,selfId:'041'},{...record,callUUID:undefined},{...record,selfClientId:undefined},{...record,capturedAt:Date.now()+120000}])assert.throws(()=>validateIntent(bad));
});
test('vault seals separate cleanup purpose, prevents overwrite, swaps and wrong-call removal',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'nasim-cleanup-vault-'));const vault=new SessionVault(dir);
 try{
  await vault.unlock('fixture-vault-passphrase');const f=fixture();await f.manager.capture(call);const record=f.saved();
  await vault.save('nasim',1,{provider:'nasim',token:'existing-session'});await vault.saveCleanupIntent('nasim',1,record);
  const file=path.join(dir,'cleanup-intents/nasim/1.json'),sealed=await fs.readFile(file,'utf8');assert.ok(!sealed.includes(call.callUUID));assert.ok(!sealed.includes(record.accountBinding));
  await assert.rejects(vault.saveCleanupIntent('nasim',1,{...record,callUUID:'new-call'}));
  await assert.rejects(vault.removeCleanupIntent('nasim',1,{...record,callUUID:'wrong-call'}));assert.deepEqual(await vault.loadCleanupIntent('nasim',1),record);
  await fs.copyFile(file,path.join(dir,'cleanup-intents/nasim/2.json'));await assert.rejects(vault.loadCleanupIntent('nasim',2));
  assert.equal((await vault.load('nasim',1)).token,'existing-session');vault.lock();await assert.rejects(vault.loadCleanupIntent('nasim',1),e=>e.reason==='locked');
  await vault.unlock('fixture-vault-passphrase');assert.deepEqual(await vault.loadCleanupIntent('nasim',1),record);
  await vault.removeCleanupIntent('nasim',1,record);assert.equal(await vault.hasCleanupIntent('nasim',1),false);
 }finally{vault.lock();await fs.rm(dir,{recursive:true,force:true});}
});
