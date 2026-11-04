// Standalone laboratory vault. Never reads or migrates BaleVPN account folders.
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const {promisify,isDeepStrictEqual}=require('node:util');const scrypt=promisify(crypto.scrypt);
const FORMAT='provider-lab-v1',PROVIDERS=new Set(['igap','eitaa','nasim','rubika']);
const {validateCallRecovery,CallRecoveryError,MAX_CALL_RECOVERY_BYTES:CALL_RECOVERY_MAX}=require('../rubika/call-recovery.cjs');
const CALL_RECOVERY='rubika-request-call-recovery-v1';
const {validateIntent}=require('../nasim/cleanup-intent.cjs');
const NASIM_CLEANUP='nasim-cleanup-intent-v1';
const refreshRecovery=require('../eitaa/refresh-recovery.cjs');
const {validateOfficialIntent}=require('../nasim/official-call-gate.cjs');
const NASIM_OFFICIAL='nasim-official-call-journal-v1',NASIM_OFFICIAL_MAX=64*1024;
const FIELDS_CLEANUP=['format','provider','accountBinding','selfId','selfClientId','peerId','callUUID','capturedAt'];
class VaultError extends Error{constructor(reason){super('Session vault '+reason);this.reason=reason;}}
function location(provider,slot){if(!PROVIDERS.has(provider)||!Number.isInteger(slot)||slot<1||slot>2)throw new VaultError('invalid_account');return provider+'/'+slot;}
function callRecoveryLocation(provider,slot){const id=location(provider,slot);if(provider!=='rubika')throw new VaultError('invalid_account');return id;}
function callRecoveryData(input){let data;try{data=validateCallRecovery(input);}catch(e){throw new VaultError(e instanceof CallRecoveryError?e.reason:'invalid_call_recovery');}return Buffer.from(JSON.stringify(data));}
function officialIntent(value){try{return validateOfficialIntent(value);}catch{throw new VaultError('invalid_official_call_intent');}}
function officialJournal(value){
 if(!value||Object.keys(value).length!==2||!Object.hasOwn(value,'intent')||!Object.hasOwn(value,'response'))throw new VaultError('invalid_official_call_intent');
 const intent=officialIntent(value.intent),response=value.response;
 if(response!==null){
  if(intent.phase==='prepared'||!response||!isDeepStrictEqual(Object.keys(response).sort(),['frame','status'])||
   !Number.isInteger(response.status)||response.status<100||response.status>599||
   intent.phase==='bound'&&(response.status<200||response.status>=300)||
   typeof response.frame!=='string'||response.frame.length>4*Math.ceil(NASIM_OFFICIAL_MAX/3))throw new VaultError('invalid_official_call_response');
  const bytes=Buffer.from(response.frame,'base64');try{if(!bytes.length||bytes.length>NASIM_OFFICIAL_MAX||bytes.toString('base64')!==response.frame)throw new VaultError('invalid_official_call_response');}finally{bytes.fill(0);}
 }else if(intent.phase==='bound')throw new VaultError('invalid_official_call_response');
 return {intent,response};
}
function advanceOfficial(previous,next,response){
 if(!previous)return next.phase==='prepared';
 const {phase,callUUID,terminalEvents,...identity}=next,{phase:oldPhase,callUUID:oldUUID,terminalEvents:oldEvents,...oldIdentity}=previous;
 if(!isDeepStrictEqual(identity,oldIdentity))return false;
 if(oldPhase==='prepared')return phase==='requested';
 if(oldPhase==='requested')return phase==='bound'&&response!==null&&response.status>=200&&response.status<300&&terminalEvents.length===0;
 return phase==='bound'&&callUUID===oldUUID&&terminalEvents.length===oldEvents.length+1&&
  oldEvents.every(old=>terminalEvents.some(event=>isDeepStrictEqual(event,old)));
}

function seal(key,data,aad){const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(Buffer.from(aad));const ciphertext=Buffer.concat([cipher.update(data),cipher.final()]);return {iv:iv.toString('hex'),tag:cipher.getAuthTag().toString('hex'),ciphertext:ciphertext.toString('base64')};}
function unseal(key,record,aad){if(!record||!/^[a-f0-9]{24}$/.test(record.iv)||!/^[a-f0-9]{32}$/.test(record.tag)||typeof record.ciphertext!=='string'||record.ciphertext.length>180000||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(record.ciphertext))throw new VaultError('invalid_file');const decipher=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(record.iv,'hex'));decipher.setAAD(Buffer.from(aad));decipher.setAuthTag(Buffer.from(record.tag,'hex'));return Buffer.concat([decipher.update(Buffer.from(record.ciphertext,'base64')),decipher.final()]);}
async function readJson(file){const bytes=await fs.readFile(file);if(bytes.length>200000)throw new VaultError('invalid_file');return JSON.parse(bytes.toString('utf8'));}
async function atomic(file,data){const temp=file+'.'+crypto.randomBytes(8).toString('hex')+'.tmp';await fs.mkdir(path.dirname(file),{recursive:true,mode:0o700});try{await fs.writeFile(temp,JSON.stringify(data),{mode:0o600,flag:'wx'});await fs.rename(temp,file);}finally{await fs.unlink(temp).catch(e=>{if(e.code!=='ENOENT')throw e;});}}
async function syncOfficialDirectory(directory){
 if(process.platform!=='linux')return;
 const handle=await fs.open(directory,'r');try{await handle.sync();}finally{await handle.close();}
}
async function writeOfficialJournal(file,data){
 const temp=file+'.'+crypto.randomBytes(8).toString('hex')+'.tmp';let handle;
 try{
  handle=await fs.open(temp,'wx',0o600);await handle.writeFile(JSON.stringify(data));await handle.sync();
  await handle.close();handle=null;await fs.rename(temp,file);await syncOfficialDirectory(path.dirname(file));
 }finally{await handle?.close().catch(()=>{});await fs.unlink(temp).catch(e=>{if(e.code!=='ENOENT')throw e;});}
}
class SessionVault{
 #directory;#key;#unlocking=false;#epoch=0;#callRecoveryWrites=new Map();
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
 async openNasimOfficialCallJournal(){
  if(!this.#key)throw new VaultError('locked');const epoch=this.#epoch;
  const directory=path.join(this.#directory,'nasim-official-call'),file=path.join(directory,'pair.json'),ownerFile=path.join(directory,'owner.json');
  const owner={pid:process.pid,nonce:crypto.randomBytes(16).toString('hex')},aad=FORMAT+'/nasim-official-call/pair';
  await fs.mkdir(directory,{recursive:true,mode:0o700});
  await syncOfficialDirectory(this.#directory);
  try{await fs.writeFile(ownerFile,JSON.stringify(owner),{flag:'wx',mode:0o600});}catch(error){throw new VaultError(error.code==='EEXIST'?'official_call_owner_busy':'write_failed');}
  let closed=false;
  const close=async()=>{
   if(closed)return;closed=true;
   return this.#callRecoveryWork('nasim-official-call',async()=>{
    const storedOwner=await readJson(ownerFile);
    if(!isDeepStrictEqual(storedOwner,owner))throw new VaultError('official_call_owner_changed');
    await fs.unlink(ownerFile);
   });
  };
  const guard=()=>{if(closed||!this.#key||epoch!==this.#epoch)throw new VaultError('locked');};
  try{guard();}catch(error){await close();throw error;}
  const work=action=>this.#callRecoveryWork('nasim-official-call',async()=>{
   guard();let stored=null;
   try{
    const envelope=await readJson(file);guard();
    if(envelope.format!==FORMAT||envelope.purpose!==NASIM_OFFICIAL||envelope.provider!=='nasim')throw new VaultError('provider_mismatch');
    const plain=unseal(this.#key,envelope,aad);try{stored=officialJournal(JSON.parse(plain.toString('utf8')));}finally{plain.fill(0);}
   }catch(error){if(error.code!=='ENOENT')throw error instanceof VaultError?error:new VaultError('read_failed');}
   guard();
   const write=async next=>{
    guard();const data=Buffer.from(JSON.stringify(officialJournal(next)));let envelope;
    try{envelope={format:FORMAT,purpose:NASIM_OFFICIAL,provider:'nasim',...seal(this.#key,data,aad)};}finally{data.fill(0);}
    await writeOfficialJournal(file,envelope);guard();
   };
   return action(stored,write,guard);
  });
  return Object.freeze({
   load:()=>work(stored=>stored?.intent??null),
   save:(value,previous,check)=>work(async(stored,write)=>{
    check();const intent=officialIntent(value),old=previous===null?null:officialIntent(previous),response=stored?.response??null;
    if(!isDeepStrictEqual(old,stored?.intent??null)||!advanceOfficial(old,intent,response))throw new VaultError('official_call_intent_conflict');
    await write({intent,response});check();
   }),
   stageResponse:(operationId,bytes,status)=>{
    if(!Buffer.isBuffer(bytes)||!bytes.length||bytes.length>NASIM_OFFICIAL_MAX||!Number.isInteger(status)||status<100||status>599)throw new VaultError('invalid_official_call_response');
    const response={status,frame:bytes.toString('base64')};
    return work(async(stored,write)=>{
     if(stored?.intent.operationId!==operationId||stored.intent.phase!=='requested')throw new VaultError('official_call_intent_conflict');
     if(stored.response!==null){if(isDeepStrictEqual(stored.response,response))return;throw new VaultError('official_call_response_exists');}
     await write({...stored,response});
    });
   },
   loadResponse:operationId=>work(stored=>{
    if(stored?.intent.operationId!==operationId)throw new VaultError('official_call_intent_conflict');
    return stored.response===null?null:{status:stored.response.status,body:Buffer.from(stored.response.frame,'base64')};
   }),
   clear:(value,check)=>work(async(stored,_,checkVault)=>{
    check();const intent=officialIntent(value);
    if(!isDeepStrictEqual(stored?.intent,intent)||intent.phase!=='prepared'&&intent.terminalEvents.length!==2)throw new VaultError('official_call_intent_conflict');
    await fs.unlink(file);await syncOfficialDirectory(directory);checkVault();check();
   }),
   close
  });
 }
 async saveRecovery(provider,slot,record){
  const id=location(provider,slot);if(provider!=='eitaa'||record?.provider!==provider||record.format!=='eitaa-auth-recovery-v1')throw new VaultError('invalid_account');
  if(!this.#key)throw new VaultError('locked');const data=Buffer.from(JSON.stringify(record));
  try{if(data.length>128*1024)throw new VaultError('record_too_large');const envelope={format:FORMAT,provider,slot,...seal(this.#key,data,FORMAT+'/recovery/'+id)};await atomic(path.join(this.#directory,'recovery',provider,slot+'.json'),envelope);}finally{data.fill(0);}
 }
 async loadRecovery(provider,slot){const id=location(provider,slot);if(provider!=='eitaa')throw new VaultError('invalid_account');if(!this.#key)throw new VaultError('locked');try{const record=await readJson(path.join(this.#directory,'recovery',provider,slot+'.json'));if(record.format!==FORMAT||record.provider!==provider||record.slot!==slot)throw new VaultError('provider_mismatch');const plain=unseal(this.#key,record,FORMAT+'/recovery/'+id);try{const data=JSON.parse(plain.toString('utf8'));if(data.provider!==provider||data.format!=='eitaa-auth-recovery-v1')throw new VaultError('provider_mismatch');return data;}finally{plain.fill(0);}}catch(e){if(e.code==='ENOENT')return null;if(e instanceof VaultError)throw e;throw new VaultError('read_failed');}}
 async hasRecovery(provider,slot){location(provider,slot);if(provider!=='eitaa')throw new VaultError('invalid_account');try{const stat=await fs.stat(path.join(this.#directory,'recovery',provider,slot+'.json'));return stat.isFile();}catch(e){if(e.code==='ENOENT')return false;throw new VaultError('read_failed');}}
 async removeRecovery(provider,slot){location(provider,slot);if(provider!=='eitaa')throw new VaultError('invalid_account');if(!this.#key)throw new VaultError('locked');await fs.unlink(path.join(this.#directory,'recovery',provider,slot+'.json')).catch(e=>{if(e.code!=='ENOENT')throw new VaultError('write_failed');});}
 async saveRefreshRecovery(provider,slot,value){
  const id=location(provider,slot);if(provider!=='eitaa'||!refreshRecovery.valid(value))throw new VaultError('invalid_refresh_recovery');
  if(!this.#key)throw new VaultError('locked');const epoch=this.#epoch;
  const bytes=Buffer.from(JSON.stringify(value));let envelope;
  try{envelope={format:FORMAT,purpose:refreshRecovery.FORMAT,provider,slot,...seal(this.#key,bytes,FORMAT+'/refresh-recovery/'+id)};}finally{bytes.fill(0);}
  return this.#callRecoveryWork('refresh/'+id,async()=>{
   if(!this.#key||epoch!==this.#epoch)throw new VaultError('locked');
   const file=path.join(this.#directory,'refresh-recovery',provider,slot+'.json');
   try{const current=await readJson(file);if(!this.#key||epoch!==this.#epoch)throw new VaultError('locked');
    if(current.format!==FORMAT||current.purpose!==refreshRecovery.FORMAT||current.provider!==provider||current.slot!==slot)throw new VaultError('provider_mismatch');
    const plain=unseal(this.#key,current,FORMAT+'/refresh-recovery/'+id);
    try{const stored=JSON.parse(plain.toString('utf8'));if(refreshRecovery.same(stored,value))return;if(!refreshRecovery.canAdvance(stored,value))throw new VaultError('refresh_recovery_available');}finally{plain.fill(0);}
   }catch(error){if(error.code!=='ENOENT')throw error;}
   if(!this.#key||epoch!==this.#epoch)throw new VaultError('locked');
   await atomic(file,envelope);
  });
 }
 async loadRefreshRecovery(provider,slot){
  const id=location(provider,slot);if(provider!=='eitaa')throw new VaultError('invalid_account');if(!this.#key)throw new VaultError('locked');const epoch=this.#epoch;
  return this.#callRecoveryWork('refresh/'+id,async()=>{
   try{const value=await readJson(path.join(this.#directory,'refresh-recovery',provider,slot+'.json'));
    if(!this.#key||epoch!==this.#epoch)throw new VaultError('locked');
    if(value.format!==FORMAT||value.purpose!==refreshRecovery.FORMAT||value.provider!==provider||value.slot!==slot)throw new VaultError('provider_mismatch');
    const plain=unseal(this.#key,value,FORMAT+'/refresh-recovery/'+id);
    try{const result=JSON.parse(plain.toString('utf8'));if(!refreshRecovery.valid(result))throw new VaultError('invalid_refresh_recovery');return result;}finally{plain.fill(0);}
   }catch(error){if(error.code==='ENOENT')return null;if(error instanceof VaultError)throw error;throw new VaultError('read_failed');}
  });
 }
 async hasRefreshRecovery(provider,slot){const id=location(provider,slot);if(provider!=='eitaa')throw new VaultError('invalid_account');return this.#callRecoveryWork('refresh/'+id,async()=>{
  try{return (await fs.stat(path.join(this.#directory,'refresh-recovery',provider,slot+'.json'))).isFile();}catch(error){if(error.code==='ENOENT')return false;throw new VaultError('read_failed');}
 });}
 async removeRefreshRecovery(provider,slot,expected){
  const id=location(provider,slot);if(provider!=='eitaa'||!refreshRecovery.valid(expected))throw new VaultError('invalid_refresh_recovery');if(!this.#key)throw new VaultError('locked');const epoch=this.#epoch;
  return this.#callRecoveryWork('refresh/'+id,async()=>{
   if(!this.#key||epoch!==this.#epoch)throw new VaultError('locked');const file=path.join(this.#directory,'refresh-recovery',provider,slot+'.json');
   try{const value=await readJson(file);if(value.format!==FORMAT||value.purpose!==refreshRecovery.FORMAT||value.provider!==provider||value.slot!==slot)throw new VaultError('provider_mismatch');
    const plain=unseal(this.#key,value,FORMAT+'/refresh-recovery/'+id);try{if(!refreshRecovery.same(JSON.parse(plain.toString('utf8')),expected))throw new VaultError('account_binding_changed');}finally{plain.fill(0);}
    if(!this.#key||epoch!==this.#epoch)throw new VaultError('locked');await fs.unlink(file);
   }catch(error){if(error.code!=='ENOENT')throw error;}
  });
 }
 async #callRecoveryWork(id,work){const prior=this.#callRecoveryWrites.get(id)||Promise.resolve(),current=prior.catch(()=>{}).then(work);this.#callRecoveryWrites.set(id,current);try{return await current;}finally{if(this.#callRecoveryWrites.get(id)===current)this.#callRecoveryWrites.delete(id);}}
 async saveCallRecovery(provider,slot,input){
  const id=callRecoveryLocation(provider,slot);if(!this.#key)throw new VaultError('locked');
  const plain=callRecoveryData(input),epoch=this.#epoch;let envelope;
  try{envelope={format:FORMAT,purpose:CALL_RECOVERY,provider,slot,...seal(this.#key,plain,FORMAT+'/call-recovery/'+id+'/requestCall')};}finally{plain.fill(0);}
  return this.#callRecoveryWork(id,async()=>{
   if(!this.#key||epoch!==this.#epoch)throw new VaultError('locked');
   await atomic(path.join(this.#directory,'call-recovery',provider,slot+'.json'),envelope);
  });
 }
 async loadCallRecovery(provider,slot){
  const id=callRecoveryLocation(provider,slot);if(!this.#key)throw new VaultError('locked');const epoch=this.#epoch;
  return this.#callRecoveryWork(id,async()=>{
   if(!this.#key||epoch!==this.#epoch)throw new VaultError('locked');
   const file=path.join(this.#directory,'call-recovery',provider,slot+'.json');
   try{
    const record=await readJson(file);if(!this.#key||epoch!==this.#epoch)throw new VaultError('locked');
    if(record.format!==FORMAT||record.purpose!==CALL_RECOVERY||record.provider!==provider||record.slot!==slot)throw new VaultError('provider_mismatch');
    const plain=unseal(this.#key,record,FORMAT+'/call-recovery/'+id+'/requestCall');
    try{
     if(plain.length>CALL_RECOVERY_MAX)throw new VaultError('record_too_large');
     const data=JSON.parse(plain.toString('utf8'));let checked;
     try{checked=callRecoveryData(data);}catch(e){if(e instanceof VaultError&&e.reason==='call_recovery_expired'){await fs.unlink(file);return null;}throw e;}
     checked.fill(0);return data;
    }finally{plain.fill(0);}
   }catch(e){if(e.code==='ENOENT')return null;if(e instanceof VaultError)throw e;throw new VaultError('read_failed');}
  });
 }
 async hasCallRecovery(provider,slot){const id=callRecoveryLocation(provider,slot);return this.#callRecoveryWork(id,async()=>{try{return (await fs.stat(path.join(this.#directory,'call-recovery',provider,slot+'.json'))).isFile();}catch(e){if(e.code==='ENOENT')return false;throw new VaultError('read_failed');}});}
 async removeCallRecovery(provider,slot){const id=callRecoveryLocation(provider,slot);if(!this.#key)throw new VaultError('locked');const epoch=this.#epoch;return this.#callRecoveryWork(id,async()=>{if(!this.#key||epoch!==this.#epoch)throw new VaultError('locked');await fs.unlink(path.join(this.#directory,'call-recovery',provider,slot+'.json')).catch(e=>{if(e.code!=='ENOENT')throw new VaultError('write_failed');});});}
 async saveCleanupIntent(provider,slot,value){
  const id=location(provider,slot);if(provider!=='nasim')throw new VaultError('invalid_account');
  const checked=validateIntent(value);if(!this.#key)throw new VaultError('locked');const epoch=this.#epoch;
  return this.#callRecoveryWork('cleanup/'+id,async()=>{
   if(!this.#key||epoch!==this.#epoch)throw new VaultError('locked');
   const file=path.join(this.#directory,'cleanup-intents',provider,slot+'.json');
   try{const old=await readJson(file);if(old.format!==FORMAT||old.purpose!==NASIM_CLEANUP||old.provider!==provider||old.slot!==slot)throw new VaultError('provider_mismatch');const plain=unseal(this.#key,old,FORMAT+'/cleanup/'+id);try{
    const previous=validateIntent(JSON.parse(plain.toString('utf8')));
    if(previous.callUUID!==checked.callUUID||previous.accountBinding!==checked.accountBinding||previous.peerId!==checked.peerId)throw new VaultError('cleanup_pending');
   }finally{plain.fill(0);}}catch(e){if(e.code!=='ENOENT')throw e;}
   if(!this.#key||epoch!==this.#epoch)throw new VaultError('locked');
   const bytes=Buffer.from(JSON.stringify(checked));try{await atomic(file,{format:FORMAT,purpose:NASIM_CLEANUP,provider,slot,...seal(this.#key,bytes,FORMAT+'/cleanup/'+id)});if(epoch!==this.#epoch)throw new VaultError('locked');}finally{bytes.fill(0);}
  });
 }
 async loadCleanupIntent(provider,slot){
  const id=location(provider,slot);if(provider!=='nasim')throw new VaultError('invalid_account');if(!this.#key)throw new VaultError('locked');const epoch=this.#epoch;
  return this.#callRecoveryWork('cleanup/'+id,async()=>{
   try{const record=await readJson(path.join(this.#directory,'cleanup-intents',provider,slot+'.json'));
    if(!this.#key||epoch!==this.#epoch)throw new VaultError('locked');
    if(record.format!==FORMAT||record.purpose!==NASIM_CLEANUP||record.provider!==provider||record.slot!==slot)throw new VaultError('provider_mismatch');
    const bytes=unseal(this.#key,record,FORMAT+'/cleanup/'+id);try{return validateIntent(JSON.parse(bytes.toString('utf8')));}finally{bytes.fill(0);}
   }catch(e){if(e.code==='ENOENT')return null;if(e instanceof VaultError)throw e;throw new VaultError('read_failed');}
  });
 }
 async hasCleanupIntent(provider,slot){const id=location(provider,slot);if(provider!=='nasim')throw new VaultError('invalid_account');return this.#callRecoveryWork('cleanup/'+id,async()=>{try{return (await fs.stat(path.join(this.#directory,'cleanup-intents',provider,slot+'.json'))).isFile();}catch(e){if(e.code==='ENOENT')return false;throw new VaultError('read_failed');}});}
 async removeCleanupIntent(provider,slot,expected){
  const id=location(provider,slot);if(provider!=='nasim')throw new VaultError('invalid_account');const checked=validateIntent(expected);if(!this.#key)throw new VaultError('locked');const epoch=this.#epoch;
  return this.#callRecoveryWork('cleanup/'+id,async()=>{
   if(!this.#key||epoch!==this.#epoch)throw new VaultError('locked');const file=path.join(this.#directory,'cleanup-intents',provider,slot+'.json');
   try{const record=await readJson(file);if(record.format!==FORMAT||record.purpose!==NASIM_CLEANUP||record.provider!==provider||record.slot!==slot)throw new VaultError('provider_mismatch');const bytes=unseal(this.#key,record,FORMAT+'/cleanup/'+id);try{const old=validateIntent(JSON.parse(bytes.toString('utf8')));
    if(FIELDS_CLEANUP.some(k=>old[k]!==checked[k]))throw new VaultError('account_binding_changed');
   }finally{bytes.fill(0);}if(epoch!==this.#epoch)throw new VaultError('locked');await fs.unlink(file);}catch(e){if(e.code!=='ENOENT')throw e;}
  });
 }
 lock(){this.#epoch++;this.#key?.fill(0);this.#key=null;}
}
module.exports={SessionVault,VaultError};
