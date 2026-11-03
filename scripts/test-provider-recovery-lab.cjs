'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {startLab}=require('../experiments/providers/lab.cjs');
test('encrypted response recovery survives locking, blocks another OTP, isolates accounts and clears only after confirmation',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'provider-recovery-lab-')),calls=[];let lab;
 const frame=Buffer.from('fixture-private-authorization-response').toString('base64');
 class Account{
  constructor(slot,options){this.slot=slot;this.options=options;this.close();}
  get state(){return {stage:this.signed?'authenticated':this.stage,busy:false,signedIn:this.signed,hasSession:!!this.record,userId:this.signed?String(this.slot):null};}
  async start(){calls.push('start'+this.slot);this.stage='code';return {};}
  async verify(){await this.options.saveRecovery({provider:'eitaa',format:'eitaa-auth-recovery-v1',frame});this.stage='recovery_required';throw Object.assign(new Error('fixture parse error'),{reason:'trailing_data'});}
  async recoverAuthorization(record){calls.push('recover'+this.slot);assert.equal(record.frame,frame);this.record={provider:'eitaa',token:'fixture-recovered-private-token'};await this.options.saveSession(this.record);throw Object.assign(new Error('fixture identity confirmation failed'),{reason:'invalid_auth_response'});}
  async restore(record){this.record=record;this.signed=true;return {authenticated:true};}
  async resume(){calls.push('confirm'+this.slot);this.signed=true;return {authenticated:true};}
  close(){this.stage='idle';this.signed=false;this.record=null;}
 }
 try{
  lab=await startLab({directory:dir,port:0,eitaaSessionFactory:(slot,options)=>new Account(slot,options)});const key=new URL(lab.url).hash.slice(1);
  const request=(route,body)=>fetch(lab.origin+'/api/'+route,{method:body===undefined?'GET':'POST',headers:{Authorization:'Bearer '+key,...body===undefined?{}:{Origin:lab.origin,'Content-Type':'application/json'}},body:body===undefined?undefined:JSON.stringify(body)});
  await request('vault/unlock',{password:'fixture-recovery-passphrase'});await request('eitaa/1/start',{country:'IR',phone:'09120000001'});assert.equal((await request('eitaa/1/verify',{code:'123456'})).status,400);
  let state=await(await request('state')).json();assert.equal(state.providerAccounts.eitaa[0].recoveryStored,true);assert.equal(state.providerAccounts.eitaa[1].recoveryStored,false);assert.ok(!JSON.stringify(state).includes(frame));
  const disk=await fs.readFile(path.join(dir,'recovery','eitaa','1.json'),'utf8');assert.ok(!disk.includes(frame));const blocked=await request('eitaa/1/start',{country:'IR',phone:'09120000001'});assert.equal((await blocked.json()).reason,'auth_recovery_available');assert.deepEqual(calls,['start1']);
  await request('vault/lock',{});assert.equal((await request('eitaa/1/resume',{})).status,423);await request('vault/unlock',{password:'fixture-recovery-passphrase'});
  const unconfirmed=await request('eitaa/1/resume',{});assert.equal(unconfirmed.status,400);state=await(await request('state')).json();assert.equal(state.providerAccounts.eitaa[0].signedIn,false);assert.equal(state.providerAccounts.eitaa[0].stored,true);assert.equal(state.providerAccounts.eitaa[0].recoveryStored,true,'a saved token without verified identity must preserve recovery');
  const resumed=await request('eitaa/1/resume',{});assert.equal(resumed.status,200);state=await(await request('state')).json();assert.equal(state.providerAccounts.eitaa[0].signedIn,true);assert.equal(state.providerAccounts.eitaa[0].stored,true);assert.equal(state.providerAccounts.eitaa[0].recoveryStored,false);assert.deepEqual(calls,['start1','recover1','confirm1']);assert.ok(!JSON.stringify(state).includes('fixture-recovered-private-token'));
  assert.equal(await fs.stat(path.join(dir,'recovery','eitaa','1.json')).then(()=>true,()=>false),false);
 }finally{await lab?.close();const target=path.resolve(dir);if(!target.startsWith(path.resolve(os.tmpdir())+path.sep)||!path.basename(target).startsWith('provider-recovery-lab-'))throw Error('Unexpected cleanup target');await fs.rm(target,{recursive:true,force:true,maxRetries:5,retryDelay:100});}
});
