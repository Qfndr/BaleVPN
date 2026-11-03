// Standalone laboratory vault. Never reads or migrates BaleVPN account folders.
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const {promisify}=require('node:util');const scrypt=promisify(crypto.scrypt);
const FORMAT='provider-lab-v1',PROVIDERS=new Set(['igap','eitaa','nasim','rubika']);
class VaultError extends Error{constructor(reason){super('Session vault '+reason);this.reason=reason;}}
function location(provider,slot){if(!PROVIDERS.has(provider)||!Number.isInteger(slot)||slot<1||slot>2)throw new VaultError('invalid_account');return provider+'/'+slot;}
function seal(key,data,aad){const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(Buffer.from(aad));const ciphertext=Buffer.concat([cipher.update(data),cipher.final()]);return {iv:iv.toString('hex'),tag:cipher.getAuthTag().toString('hex'),ciphertext:ciphertext.toString('base64')};}
function unseal(key,record,aad){if(!record||!/^[a-f0-9]{24}$/.test(record.iv)||!/^[a-f0-9]{32}$/.test(record.tag)||typeof record.ciphertext!=='string'||record.ciphertext.length>180000||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(record.ciphertext))throw new VaultError('invalid_file');const decipher=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(record.iv,'hex'));decipher.setAAD(Buffer.from(aad));decipher.setAuthTag(Buffer.from(record.tag,'hex'));return Buffer.concat([decipher.update(Buffer.from(record.ciphertext,'base64')),decipher.final()]);}
async function readJson(file){const bytes=await fs.readFile(file);if(bytes.length>200000)throw new VaultError('invalid_file');return JSON.parse(bytes.toString('utf8'));}
async function atomic(file,data){const temp=file+'.'+crypto.randomBytes(8).toString('hex')+'.tmp';await fs.mkdir(path.dirname(file),{recursive:true,mode:0o700});try{await fs.writeFile(temp,JSON.stringify(data),{mode:0o600,flag:'wx'});await fs.rename(temp,file);}finally{await fs.unlink(temp).catch(e=>{if(e.code!=='ENOENT')throw e;});}}
class SessionVault{
 #directory;#key;#unlocking=false;#epoch=0;
 constructor(directory){this.#directory=path.resolve(directory);}
 get unlocked(){return !!this.#key;}
 async unlock(password){
  if(this.#unlocking)throw new VaultError('busy');if(this.#key)throw new VaultError('already_unlocked');
  if(typeof password!=='string'||password.length<12||Buffer.byteLength(password)>1024)throw new VaultError('password_too_short');
  this.#unlocking=true;const epoch=this.#epoch;let key;
  try{
   const file=path.join(this.#directory,'vault.json');let manifest;try{manifest=await readJson(file);}catch(e){if(e.code!=='ENOENT')throw e;}
   if(manifest&&(manifest.format!==FORMAT||!/^[a-f0-9]{32}$/.test(manifest.salt)))throw new VaultError('invalid_file');
   const salt=manifest?Buffer.from(manifest.salt,'hex'):crypto.randomBytes(16);
   key=await scrypt(password,salt,32,{N:32768,r:8,p:1,maxmem:64*1024*1024});
   if(manifest){const check=unseal(key,manifest,FORMAT+'/manifest');try{if(check.toString()!=='provider-lab-vault')throw new VaultError('invalid_file');}finally{check.fill(0);}}
   else{
    const data={format:FORMAT,salt:salt.toString('hex'),...seal(key,Buffer.from('provider-lab-vault'),FORMAT+'/manifest')};
    await fs.mkdir(this.#directory,{recursive:true,mode:0o700});await fs.writeFile(file,JSON.stringify(data),{mode:0o600,flag:'wx'});
   }
   if(epoch!==this.#epoch)throw new VaultError('locked');this.#key=key;key=null;
  }catch(e){if(e instanceof VaultError)throw e;throw new VaultError(e.code==='EEXIST'?'concurrent_unlock':'unlock_failed');}
  finally{key?.fill(0);this.#unlocking=false;}
 }
 async save(provider,slot,record){const id=location(provider,slot);if(!this.#key)throw new VaultError('locked');if(record?.provider!==provider)throw new VaultError('provider_mismatch');const data=Buffer.from(JSON.stringify(record));if(data.length>128*1024)throw new VaultError('record_too_large');try{const envelope={format:FORMAT,provider,slot,...seal(this.#key,data,FORMAT+'/'+id)};await atomic(path.join(this.#directory,provider,slot+'.json'),envelope);}finally{data.fill(0);}}
 async load(provider,slot){const id=location(provider,slot);if(!this.#key)throw new VaultError('locked');try{const record=await readJson(path.join(this.#directory,provider,slot+'.json'));if(record.format!==FORMAT||record.provider!==provider||record.slot!==slot)throw new VaultError('provider_mismatch');const plain=unseal(this.#key,record,FORMAT+'/'+id);try{const data=JSON.parse(plain.toString('utf8'));if(data.provider!==provider)throw new VaultError('provider_mismatch');return data;}finally{plain.fill(0);}}catch(e){if(e.code==='ENOENT')return null;if(e instanceof VaultError)throw e;throw new VaultError('read_failed');}}
 async has(provider,slot){location(provider,slot);try{const stat=await fs.stat(path.join(this.#directory,provider,slot+'.json'));return stat.isFile();}catch(e){if(e.code==='ENOENT')return false;throw new VaultError('read_failed');}}
 async remove(provider,slot){location(provider,slot);if(!this.#key)throw new VaultError('locked');await fs.unlink(path.join(this.#directory,provider,slot+'.json')).catch(e=>{if(e.code!=='ENOENT')throw new VaultError('write_failed');});}
 async saveRecovery(provider,slot,record){
  const id=location(provider,slot);if(provider!=='eitaa'||record?.provider!==provider||record.format!=='eitaa-auth-recovery-v1')throw new VaultError('invalid_account');
  if(!this.#key)throw new VaultError('locked');const data=Buffer.from(JSON.stringify(record));
  try{if(data.length>128*1024)throw new VaultError('record_too_large');const envelope={format:FORMAT,provider,slot,...seal(this.#key,data,FORMAT+'/recovery/'+id)};await atomic(path.join(this.#directory,'recovery',provider,slot+'.json'),envelope);}finally{data.fill(0);}
 }
 async loadRecovery(provider,slot){const id=location(provider,slot);if(provider!=='eitaa')throw new VaultError('invalid_account');if(!this.#key)throw new VaultError('locked');try{const record=await readJson(path.join(this.#directory,'recovery',provider,slot+'.json'));if(record.format!==FORMAT||record.provider!==provider||record.slot!==slot)throw new VaultError('provider_mismatch');const plain=unseal(this.#key,record,FORMAT+'/recovery/'+id);try{const data=JSON.parse(plain.toString('utf8'));if(data.provider!==provider||data.format!=='eitaa-auth-recovery-v1')throw new VaultError('provider_mismatch');return data;}finally{plain.fill(0);}}catch(e){if(e.code==='ENOENT')return null;if(e instanceof VaultError)throw e;throw new VaultError('read_failed');}}
 async hasRecovery(provider,slot){location(provider,slot);if(provider!=='eitaa')throw new VaultError('invalid_account');try{const stat=await fs.stat(path.join(this.#directory,'recovery',provider,slot+'.json'));return stat.isFile();}catch(e){if(e.code==='ENOENT')return false;throw new VaultError('read_failed');}}
 async removeRecovery(provider,slot){location(provider,slot);if(provider!=='eitaa')throw new VaultError('invalid_account');if(!this.#key)throw new VaultError('locked');await fs.unlink(path.join(this.#directory,'recovery',provider,slot+'.json')).catch(e=>{if(e.code!=='ENOENT')throw new VaultError('write_failed');});}
 lock(){this.#epoch++;this.#key?.fill(0);this.#key=null;}
}
module.exports={SessionVault,VaultError};
