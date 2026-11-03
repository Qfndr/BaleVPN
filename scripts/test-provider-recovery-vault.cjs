'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {SessionVault}=require('../experiments/providers/session-vault.cjs');
const record={provider:'eitaa',format:'eitaa-auth-recovery-v1',frame:Buffer.from('fixture-private-authorization-response').toString('base64'),createdAt:12345};
async function fixture(work){const dir=await fs.mkdtemp(path.join(os.tmpdir(),'provider-recovery-'));const vault=new SessionVault(dir);try{await vault.unlock('fixture-recovery-passphrase');await work(vault,dir);}finally{vault.lock();const target=path.resolve(dir),base=path.resolve(os.tmpdir())+path.sep;if(!target.startsWith(base)||!path.basename(target).startsWith('provider-recovery-'))throw Error('Unexpected cleanup target');await fs.rm(target,{recursive:true,force:true,maxRetries:5,retryDelay:100});}}
test('recovery is sealed separately from normal sessions and survives a locked restart',()=>fixture(async(vault,dir)=>{
 const normal={provider:'eitaa',token:'fixture-normal-session-token'};await vault.save('eitaa',1,normal);await vault.saveRecovery('eitaa',1,record);
 const file=await fs.readFile(path.join(dir,'recovery','eitaa','1.json'),'utf8');for(const secret of [record.frame,'fixture-private-authorization-response',normal.token])assert.ok(!file.includes(secret));
 assert.deepEqual(await vault.load('eitaa',1),normal);assert.equal(await vault.hasRecovery('eitaa',1),true);vault.lock();await assert.rejects(vault.loadRecovery('eitaa',1),/locked/);await assert.rejects(vault.removeRecovery('eitaa',1),/locked/);
 const reopened=new SessionVault(dir);try{await reopened.unlock('fixture-recovery-passphrase');assert.deepEqual(await reopened.loadRecovery('eitaa',1),record);await reopened.removeRecovery('eitaa',1);assert.equal(await reopened.hasRecovery('eitaa',1),false);assert.deepEqual(await reopened.load('eitaa',1),normal);}finally{reopened.lock();}
}));
test('recovery ciphertext cannot be transplanted into a normal session or another account',()=>fixture(async(vault,dir)=>{
 await vault.saveRecovery('eitaa',1,record);const raw=await fs.readFile(path.join(dir,'recovery','eitaa','1.json'),'utf8'),envelope=JSON.parse(raw);
 await fs.mkdir(path.join(dir,'eitaa'),{recursive:true});await fs.writeFile(path.join(dir,'eitaa','1.json'),raw);await assert.rejects(vault.load('eitaa',1),/read_failed/);
 envelope.slot=2;await fs.writeFile(path.join(dir,'recovery','eitaa','2.json'),JSON.stringify(envelope));await assert.rejects(vault.loadRecovery('eitaa',2),/read_failed/);
 envelope.slot=1;envelope.tag=(envelope.tag[0]==='0'?'1':'0')+envelope.tag.slice(1);await fs.writeFile(path.join(dir,'recovery','eitaa','1.json'),JSON.stringify(envelope));await assert.rejects(vault.loadRecovery('eitaa',1),/read_failed/);
}));
test('recovery rejects other providers, slot paths, oversized input and replaces only its own bounded record',()=>fixture(async(vault)=>{
 await assert.rejects(vault.saveRecovery('igap',1,{...record,provider:'igap'}),/invalid_account/);await assert.rejects(vault.saveRecovery('eitaa','../1',record),/invalid_account/);await assert.rejects(vault.saveRecovery('eitaa',1,{...record,frame:'x'.repeat(128*1024)}),/record_too_large/);
 await vault.saveRecovery('eitaa',1,record);const latest={...record,createdAt:23456};await vault.saveRecovery('eitaa',1,latest);assert.deepEqual(await vault.loadRecovery('eitaa',1),latest);assert.equal(await vault.loadRecovery('eitaa',2),null);
}));
