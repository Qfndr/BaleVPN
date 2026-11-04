'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {SessionVault}=require('../experiments/providers/session-vault.cjs');
const password='fixture-eitaa-journal-passphrase';
const check=()=>{};
const requested={operationId:'a'.repeat(32),bindings:['b'.repeat(64),'c'.repeat(64)],slot:1,
 phase:'requested',callId:null,cursor:null,terminalProof:null};
const bound={...requested,phase:'bound',callId:'9223372036854775807',cursor:{pts:11,date:12,qts:13,seq:14}};
const terminal={...bound,phase:'terminal',terminalProof:'event-history'};
async function fixture(t){
 const root=path.resolve(os.tmpdir()),directory=await fs.mkdtemp(path.join(root,'eitaa-call-journal-'));
 const vault=new SessionVault(directory);
 t.after(async()=>{
  vault.lock();
  assert.equal(path.dirname(directory),root);assert.match(path.basename(directory),/^eitaa-call-journal-/);
  await fs.rm(directory,{recursive:true,force:true,maxRetries:3,retryDelay:50});
 });
 await vault.unlock(password);
 return {vault,directory,file:path.join(directory,'eitaa-call','pair.json')};
}
test('encrypted Eitaa call journal survives reopen and clears only after exact terminal CAS',async t=>{
 const {vault,directory,file}=await fixture(t),journal=await vault.openEitaaCallJournal();
 assert.equal(await journal.load(),null);
 await journal.save(requested,null,check);
 await assert.rejects(journal.clear(requested,check),{reason:'eitaa_call_intent_conflict'});
 await journal.save(bound,requested,check);
 const sealed=await fs.readFile(file,'utf8');
 for(const value of [bound.operationId,...bound.bindings,bound.callId,password])assert.ok(!sealed.includes(value));
 await journal.close();vault.lock();
 const reopened=new SessionVault(directory);await reopened.unlock(password);
 try{
  const next=await reopened.openEitaaCallJournal();
  try{
   assert.deepEqual(await next.load(),bound);
   await assert.rejects(next.save({...terminal,callId:'123'},bound,check),{reason:'eitaa_call_intent_conflict'});
   await assert.rejects(next.save(terminal,requested,check),{reason:'eitaa_call_intent_conflict'});
   await next.save(terminal,bound,check);
   await assert.rejects(next.clear({...terminal,terminalProof:'discard-ack'},check),{reason:'eitaa_call_intent_conflict'});
   await next.clear(terminal,check);
   assert.equal(await next.load(),null);
  }finally{await next.close();}
 }finally{reopened.lock();}
});
test('Eitaa journal refuses concurrent owners, forged shapes and stale vault handles',async t=>{
 const {vault,directory}=await fixture(t),journal=await vault.openEitaaCallJournal();
 const other=new SessionVault(directory);await other.unlock(password);
 try{
  await assert.rejects(other.openEitaaCallJournal(),{reason:'eitaa_call_owner_busy'});
  for(const candidate of [{...requested,token:'forbidden'},{...requested,bindings:['b'.repeat(64),'b'.repeat(64)]},
   {...bound,callId:'9223372036854775808'},{...bound,cursor:{...bound.cursor,date:-1}}])
   await assert.rejects(journal.save(candidate,null,check),{reason:'invalid_eitaa_call_intent'});
  await assert.rejects(journal.save(bound,null,check),{reason:'eitaa_call_intent_conflict'});
  vault.lock();
  await assert.rejects(journal.load(),{reason:'locked'});
  await journal.close();
  const next=await other.openEitaaCallJournal();try{assert.equal(await next.load(),null);}finally{await next.close();}
 }finally{other.lock();}
});
test('prewrite failure leaves no intent, while postwrite ownership failure preserves pending work',async t=>{
 const {vault,file}=await fixture(t),journal=await vault.openEitaaCallJournal();
 try{
  const stopped=Error('fixture epoch changed');
  await assert.rejects(journal.save(requested,null,()=>{throw stopped;}),stopped);
  assert.equal(await journal.load(),null);
  let checks=0;
  await assert.rejects(journal.save(requested,null,()=>{if(++checks===2)throw stopped;}),stopped);
  assert.deepEqual(await journal.load(),requested);
  await assert.rejects(journal.save(requested,null,check),{reason:'eitaa_call_intent_conflict'});
  const sealed=JSON.parse(await fs.readFile(file,'utf8'));
  await fs.writeFile(file,JSON.stringify({...sealed,purpose:'nasim-official-call-journal-v1'}));
  await assert.rejects(journal.load(),{reason:'provider_mismatch'});
  await fs.writeFile(file,JSON.stringify({...sealed,tag:(sealed.tag[0]==='0'?'1':'0')+sealed.tag.slice(1)}));
  await assert.rejects(journal.load(),{reason:'read_failed'});
 }finally{await journal.close();}
});
