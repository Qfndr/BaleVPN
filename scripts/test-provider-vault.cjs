const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {SessionVault}=require('../experiments/providers/session-vault.cjs');
const password='fixture-vault-passphrase-1234';
async function fixture(fn){const dir=await fs.mkdtemp(path.join(os.tmpdir(),'provider-vault-fixture-'));try{await fn(dir);}finally{await fs.rm(dir,{recursive:true,force:true});}}
test('sessions survive restarts encrypted, with separate slots/providers and no plaintext secrets',()=>fixture(async dir=>{
 const v=new SessionVault(dir);await v.unlock(password);for(const [provider,slot]of [['igap',1],['igap',2],['eitaa',1],['nasim',1],['rubika',1]])await v.save(provider,slot,{provider,userId:String(slot),token:'secret-token-'+provider+'-'+slot});
 const encrypted=await fs.readFile(path.join(dir,'igap/1.json'),'utf8');assert.ok(!encrypted.includes('secret-token'));assert.ok(!encrypted.includes(password));assert.equal(await v.has('igap',2),true);v.lock();await assert.rejects(v.load('igap',1),e=>e.reason==='locked');
 const restored=new SessionVault(dir);await restored.unlock(password);assert.equal((await restored.load('igap',1)).token,'secret-token-igap-1');assert.equal((await restored.load('igap',2)).token,'secret-token-igap-2');assert.equal((await restored.load('rubika',1)).token,'secret-token-rubika-1');assert.equal(await restored.load('nasim',2),null);restored.lock();
}));
test('wrong password, ciphertext tampering and cross-account/cross-provider swapping fail closed',()=>fixture(async dir=>{
 const v=new SessionVault(dir);await v.unlock(password);await v.save('igap',1,{provider:'igap',token:'fixture'});v.lock();const wrong=new SessionVault(dir);await assert.rejects(wrong.unlock('a-different-passphrase'),e=>e.reason==='unlock_failed');assert.equal(wrong.unlocked,false);
 const good=new SessionVault(dir);await good.unlock(password);const file=path.join(dir,'igap/1.json'),original=JSON.parse(await fs.readFile(file,'utf8'));
 await fs.writeFile(path.join(dir,'igap/2.json'),JSON.stringify({...original,slot:2}));await assert.rejects(good.load('igap',2),e=>e.reason==='read_failed');await fs.mkdir(path.join(dir,'nasim'),{recursive:true});await fs.writeFile(path.join(dir,'nasim/1.json'),JSON.stringify({...original,provider:'nasim'}));await assert.rejects(good.load('nasim',1));
 await fs.writeFile(file,JSON.stringify({...original,tag:'0'.repeat(32)}));await assert.rejects(good.load('igap',1),e=>e.reason==='read_failed');good.lock();
}));
test('invalid paths, provider mismatch and oversized records cannot overwrite an existing session',()=>fixture(async dir=>{
 const v=new SessionVault(dir);await v.unlock(password);await v.save('igap',1,{provider:'igap',token:'preserved'});
 for(const [provider,slot]of [['../igap',1],['igap',0],['igap',3],['igap','1']])await assert.rejects(v.save(provider,slot,{provider}),e=>e.reason==='invalid_account');
 await assert.rejects(v.save('igap',1,{provider:'nasim',token:'wrong'}),e=>e.reason==='provider_mismatch');await assert.rejects(v.save('igap',1,{provider:'igap',token:'x'.repeat(140000)}),e=>e.reason==='record_too_large');assert.equal((await v.load('igap',1)).token,'preserved');await v.remove('igap',1);assert.equal(await v.has('igap',1),false);v.lock();
}));
test('locking during slow password derivation prevents a late unlock',()=>fixture(async dir=>{
 const v=new SessionVault(dir);const pending=v.unlock(password);v.lock();await assert.rejects(pending,e=>e.reason==='locked');assert.equal(v.unlocked,false);const resumed=new SessionVault(dir);await resumed.unlock(password);assert.equal(resumed.unlocked,true);resumed.lock();
}));
