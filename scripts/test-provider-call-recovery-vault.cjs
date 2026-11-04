'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {SessionVault}=require('../experiments/providers/session-vault.cjs');
const {validateCallRecovery,CALL_RECOVERY_TTL_MS}=require('../experiments/rubika/call-recovery.cjs');
const password='fixture-call-recovery-passphrase';
function candidate(){return {provider:'rubika',operation:'requestCall',selfId:'u0fixture_self',peerId:'u0fixture_peer',accountBinding:'a'.repeat(64),capturedAt:Date.now(),response:{call_type:'Voice',call_update:{call_id:'fixture-call-id',primaryPhoneConnection:{constructor:812830625,turn_username:'fixture-private-turn-user',turn_password:'fixture-private-turn-secret'},key:'fixture-private-call-key'}}};}
async function fixture(work){
 const base=path.resolve(os.tmpdir()),dir=await fs.mkdtemp(path.join(base,'provider-call-recovery-')),vault=new SessionVault(dir);
 try{await vault.unlock(password);await work(vault,dir);}finally{
  vault.lock();const resolved=path.resolve(dir);
  if(!resolved.startsWith(base+path.sep)||!path.basename(resolved).startsWith('provider-call-recovery-'))throw Error('Unexpected cleanup target');
  await fs.rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:100});
 }
}
const reason=expected=>error=>error.reason===expected;

test('call recovery is sealed independently, preserves native constructor data and survives locked restart',()=>fixture(async(vault,dir)=>{
 const normal={provider:'rubika',token:'fixture-normal-rubika-session'},auth={provider:'eitaa',format:'eitaa-auth-recovery-v1',frame:'fixture-auth-frame'};
 await vault.save('rubika',1,normal);await vault.saveRecovery('eitaa',1,auth);const record=candidate();await vault.saveCallRecovery('rubika',1,record);
 const file=await fs.readFile(path.join(dir,'call-recovery/rubika/1.json'),'utf8');
 for(const secret of [record.selfId,record.peerId,record.accountBinding,record.response.call_update.key,record.response.call_update.primaryPhoneConnection.turn_password,password,normal.token])assert.ok(!file.includes(secret));
 assert.deepEqual(await vault.loadCallRecovery('rubika',1),record);assert.deepEqual(await vault.load('rubika',1),normal);assert.deepEqual(await vault.loadRecovery('eitaa',1),auth);
 vault.lock();assert.equal(await vault.hasCallRecovery('rubika',1),true);
 await assert.rejects(vault.loadCallRecovery('rubika',1),reason('locked'));await assert.rejects(vault.saveCallRecovery('rubika',1,record),reason('locked'));await assert.rejects(vault.removeCallRecovery('rubika',1),reason('locked'));
 const reopened=new SessionVault(dir);try{await reopened.unlock(password);assert.deepEqual(await reopened.loadCallRecovery('rubika',1),record);await reopened.removeCallRecovery('rubika',1);await reopened.removeCallRecovery('rubika',1);assert.equal(await reopened.hasCallRecovery('rubika',1),false);assert.equal(await reopened.loadCallRecovery('rubika',1),null);assert.deepEqual(await reopened.load('rubika',1),normal);assert.deepEqual(await reopened.loadRecovery('eitaa',1),auth);}finally{reopened.lock();}
}));

test('call recovery ciphertext rejects slot, purpose, normal-session and auth-recovery transplants',()=>fixture(async(vault,dir)=>{
 await vault.saveCallRecovery('rubika',1,candidate());const file=path.join(dir,'call-recovery/rubika/1.json'),raw=await fs.readFile(file,'utf8'),original=JSON.parse(raw);
 await fs.writeFile(path.join(dir,'call-recovery/rubika/2.json'),JSON.stringify({...original,slot:2}));await assert.rejects(vault.loadCallRecovery('rubika',2),reason('read_failed'));
 await fs.mkdir(path.join(dir,'rubika'),{recursive:true});await fs.writeFile(path.join(dir,'rubika/1.json'),raw);await assert.rejects(vault.load('rubika',1),reason('read_failed'));
 await vault.save('rubika',2,{provider:'rubika',token:'fixture-normal-token'});const normal=JSON.parse(await fs.readFile(path.join(dir,'rubika/2.json'),'utf8'));
 await fs.writeFile(path.join(dir,'call-recovery/rubika/2.json'),JSON.stringify({...normal,purpose:original.purpose}));await assert.rejects(vault.loadCallRecovery('rubika',2),reason('read_failed'));
 await fs.mkdir(path.join(dir,'recovery/eitaa'),{recursive:true});await fs.writeFile(path.join(dir,'recovery/eitaa/1.json'),JSON.stringify({...original,provider:'eitaa'}));await assert.rejects(vault.loadRecovery('eitaa',1),reason('read_failed'));
 await fs.writeFile(file,JSON.stringify({...original,purpose:'eitaa-auth-recovery-v1'}));await assert.rejects(vault.loadCallRecovery('rubika',1),reason('provider_mismatch'));
 await fs.writeFile(file,JSON.stringify({...original,tag:(original.tag[0]==='0'?'1':'0')+original.tag.slice(1)}));await assert.rejects(vault.loadCallRecovery('rubika',1),reason('read_failed'));
 await vault.removeCallRecovery('rubika',1);assert.equal(await vault.hasCallRecovery('rubika',1),false);
}));

test('candidate wrapper and tree validation do not execute code or overwrite a previous candidate',()=>fixture(async(vault)=>{
 const original=candidate();await vault.saveCallRecovery('rubika',1,original);
 const bad=[{...candidate(),operation:'acceptCall'},{...candidate(),provider:'eitaa'},{...candidate(),selfId:'short'},{...candidate(),peerId:original.selfId},{...candidate(),accountBinding:'A'.repeat(64)},
  {...candidate(),capturedAt:Date.now()+61000},{...candidate(),token:'not-a-wrapper-field'},{...candidate(),response:'raw-string'},
  {...candidate(),response:{value:NaN}},{...candidate(),response:{value:1n}},{...candidate(),response:{value:undefined}},{...candidate(),response:new Date()},
  {...candidate(),response:JSON.parse('{"__proto__":{"polluted":true}}')},{...candidate(),response:{prototype:{value:1}}}];
 const cycle={};cycle.value=cycle;bad.push({...candidate(),response:cycle});
 let executed=0;const accessor={};Object.defineProperty(accessor,'private',{enumerable:true,get(){executed++;return 'private';}});bad.push({...candidate(),response:accessor});
 bad.push({...candidate(),response:{toJSON(){executed++;return {};}}});bad.push({...candidate(),response:new Proxy({},{ownKeys(){executed++;return [];}})});
 for(const input of bad)await assert.rejects(vault.saveCallRecovery('rubika',1,input),reason('invalid_call_recovery'));
 assert.equal(executed,0);assert.deepEqual(await vault.loadCallRecovery('rubika',1),original);
 for(const [provider,slot]of [['eitaa',1],['igap',1],['../rubika',1],['rubika',0],['rubika',3],['rubika','1']]){
  await assert.rejects(vault.saveCallRecovery(provider,slot,candidate()),reason('invalid_account'));await assert.rejects(vault.loadCallRecovery(provider,slot),reason('invalid_account'));await assert.rejects(vault.hasCallRecovery(provider,slot),reason('invalid_account'));await assert.rejects(vault.removeCallRecovery(provider,slot),reason('invalid_account'));
 }
}));

test('call recovery expires after 24 hours and removes only its own encrypted candidate',()=>fixture(async(vault)=>{
 const record=candidate();record.capturedAt-=CALL_RECOVERY_TTL_MS-1000;
 await vault.save('rubika',1,{provider:'rubika',token:'preserved'});await vault.saveCallRecovery('rubika',1,record);await vault.saveCallRecovery('rubika',2,candidate());
 const realNow=Date.now;try{Date.now=()=>realNow()+2000;assert.equal(await vault.loadCallRecovery('rubika',1),null);assert.equal(await vault.hasCallRecovery('rubika',1),false);assert.ok(await vault.loadCallRecovery('rubika',2));}finally{Date.now=realNow;}
 assert.equal((await vault.load('rubika',1)).token,'preserved');const expired=candidate();expired.capturedAt-=CALL_RECOVERY_TTL_MS+1000;
 await assert.rejects(vault.saveCallRecovery('rubika',1,expired),reason('call_recovery_expired'));assert.equal(await vault.hasCallRecovery('rubika',1),false);
}));

test('candidate size, depth, node and JSON escaping limits are checked before storage',()=>fixture(async(vault)=>{
 const original=candidate();await vault.saveCallRecovery('rubika',1,original);
 await assert.rejects(vault.saveCallRecovery('rubika',1,{...candidate(),response:{call_update:{private:'x'.repeat(65536)}}}),reason('record_too_large'));
 await assert.rejects(vault.saveCallRecovery('rubika',1,{...candidate(),response:{call_update:{private:'\u0000'.repeat(12000)}}}),reason('record_too_large'));
 let deep={value:0};for(let n=0;n<20;n++)deep={value:deep};assert.throws(()=>validateCallRecovery({...candidate(),response:{call_update:deep}}),reason('invalid_call_recovery'));
 assert.throws(()=>validateCallRecovery({...candidate(),response:{call_update:{list:Array(4100).fill(0)}}}),reason('invalid_call_recovery'));
 assert.throws(()=>validateCallRecovery({...candidate(),response:{call_update:{list:Array(2)}}}),reason('invalid_call_recovery'));
 assert.deepEqual(await vault.loadCallRecovery('rubika',1),original);
}));

test('same-slot writes are serialized and lock cancels work which has not started',()=>fixture(async(vault)=>{
 const first=candidate(),last=candidate();last.response={call_update:{winner:'second'}};
 await Promise.all([vault.saveCallRecovery('rubika',1,first),vault.saveCallRecovery('rubika',1,last)]);assert.deepEqual(await vault.loadCallRecovery('rubika',1),last);
 const pending=vault.saveCallRecovery('rubika',2,candidate());vault.lock();await assert.rejects(pending,reason('locked'));
 await vault.unlock(password);assert.equal(await vault.hasCallRecovery('rubika',2),false);assert.deepEqual(await vault.loadCallRecovery('rubika',1),last);
}));

test('storage accepts only call response fields while preserving their absence, nulls and unknown nested call data',()=>fixture(async(vault)=>{
 for(const response of [{},{call_type:null},{call_update:null},{call_type:null,call_update:null},
  {call_type:'Voice',call_update:{primaryPhoneConnection:{constructor:812830625},unknown_call_field:{value:'private-fixture'}}}]){
  const record={...candidate(),response};await vault.saveCallRecovery('rubika',1,record);assert.deepEqual((await vault.loadCallRecovery('rubika',1)).response,response);
 }
 const previous=await vault.loadCallRecovery('rubika',1);
 for(const key of ['chat_update','message_update','auth','token','private_key','unrelated'])await assert.rejects(vault.saveCallRecovery('rubika',1,{...candidate(),response:{call_type:'Voice',call_update:null,[key]:{private:'must-not-be-captured'}}}),reason('invalid_call_recovery'));
 assert.deepEqual(await vault.loadCallRecovery('rubika',1),previous);
}));
