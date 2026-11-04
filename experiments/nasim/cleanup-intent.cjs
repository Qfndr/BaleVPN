// Minimal private call cleanup context. No SDP, relay credentials or auth token.
const crypto=require('node:crypto');
const FIELDS=['format','provider','accountBinding','selfId','selfClientId','peerId','callUUID','capturedAt'];
const fail=reason=>Object.assign(new Error('Nasim cleanup '+reason),{reason});
const id=v=>typeof v==='string'&&/^[1-9]\d{0,15}$/.test(v)&&BigInt(v)<=BigInt(Number.MAX_SAFE_INTEGER);
function validateIntent(value){
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==FIELDS.length||Object.keys(value).some(k=>!FIELDS.includes(k))||
  value.format!=='nasim-cleanup-intent-v1'||value.provider!=='nasim'||typeof value.accountBinding!=='string'||! /^[a-f0-9]{64}$/.test(value.accountBinding)||
  !id(value.selfId)||!id(value.peerId)||value.selfId===value.peerId||typeof value.selfClientId!=='string'||! /^[A-Za-z0-9_-]{1,128}$/.test(value.selfClientId)||
  typeof value.callUUID!=='string'||! /^[-A-Za-z0-9_:]{1,128}$/.test(value.callUUID)||!Number.isSafeInteger(value.capturedAt)||value.capturedAt<=0||value.capturedAt>Date.now()+60000)throw fail('invalid_cleanup_intent');
 return Object.fromEntries(FIELDS.map(k=>[k,value[k]]));
}
function binding(account){
 const s=account.state;if(s.provider!=='nasim'||!s.signedIn||!id(s.userId))throw fail('not_authenticated');
 const record=account.exportSession();
 if(record.provider!=='nasim'||record.userId!==s.userId||record.clientId!==s.clientId||typeof record.token!=='string'||!record.token)throw fail('account_binding_changed');
 return {selfId:s.userId,selfClientId:s.clientId,accountBinding:crypto.createHash('sha256').update(JSON.stringify([record.provider,record.userId,record.clientId,record.token])).digest('hex')};
}
class CleanupIntent {
 #account;#save;#load;#clear;#intent=null;#failed=false;#busy=false;#generation=0;
 constructor(account,{saveIntent,loadIntent,clearIntent}){
  if(![saveIntent,loadIntent,clearIntent].every(f=>typeof f==='function'))throw fail('invalid_cleanup_store');
  this.#account=account;this.#save=saveIntent;this.#load=loadIntent;this.#clear=clearIntent;
 }
 #guard(context,generation){
  if(generation!==this.#generation)throw fail('cleanup_cancelled');
  const now=binding(this.#account);
  if(['selfId','selfClientId','accountBinding'].some(k=>now[k]!==context[k]))throw fail('account_binding_changed');
 }
 async restore(){
  const context=binding(this.#account),generation=this.#generation;
  const value=await this.#load();this.#guard(context,generation);
  if(!value){this.#intent=null;return false;}
  const intent=validateIntent(value);
  if(['selfId','selfClientId','accountBinding'].some(k=>intent[k]!==context[k]))throw fail('account_binding_changed');
  this.#intent=intent;return true;
 }
 async ensureClear(){if(this.#intent||await this.restore())throw fail('cleanup_pending');}
 async capture({peerId,callUUID}){
  const context=binding(this.#account),generation=this.#generation;
  const existing=this.#intent||await this.#load();this.#guard(context,generation);
  if(existing){const old=validateIntent(existing);if(old.callUUID!==callUUID||old.peerId!==peerId||old.accountBinding!==context.accountBinding)throw fail('cleanup_pending');this.#intent=old;if(this.#failed)throw fail('cleanup_save_failed');return;}
  const intent=validateIntent({...context,format:'nasim-cleanup-intent-v1',provider:'nasim',peerId,callUUID,capturedAt:Date.now()});
  this.#intent=intent;
  try{await this.#save(intent,()=>this.#guard(context,generation));this.#guard(context,generation);
   const stored=validateIntent(await this.#load());this.#guard(context,generation);
   if(FIELDS.some(k=>stored[k]!==intent[k]))throw fail('cleanup_save_failed');this.#failed=false;}
  catch{this.#failed=true;throw fail('cleanup_save_failed');}
 }
 async #ack(intent,guard){await this.#clear(intent,guard);guard();this.#intent=null;this.#failed=false;}
 async peerEnded({peerId,callUUID}){
  const intent=this.#intent;if(!intent||intent.callUUID!==callUUID||intent.peerId!==peerId)return;
  const generation=this.#generation,guard=()=>this.#guard(intent,generation);guard();await this.#ack(intent,guard);
 }
 async cleanup(){
  if(this.#busy)throw fail('cleanup_busy');this.#busy=true;
  try{
   if(!this.#intent&&!await this.restore())return {cleanupPending:false,serviceAcknowledged:false,remoteEndedVerified:false};
   const intent=this.#intent,generation=this.#generation,guard=()=>this.#guard(intent,generation);guard();
   const rpc=this.#account.signalConnection;
   const check=()=>{guard();if(this.#account.signalConnection!==rpc)throw fail('account_binding_changed');};
   const result=await rpc.send({type:'bye',callUUID:intent.callUUID,callData:null},{peerId:intent.peerId});check();
   if(!this.#matchesAck(intent,result))throw fail('cleanup_unconfirmed');
   await this.#ack(intent,check);
   return {cleanupPending:false,serviceAcknowledged:true,remoteEndedVerified:false};
  }finally{this.#busy=false;}
 }
 #matchesAck(intent,result){const ack=result?.terminalAcknowledgement;return result?.acknowledged===true&&ack?.type==='bye'&&ack.callUUID===intent.callUUID&&ack.peerId===intent.peerId;}
 async terminalAck({peerId,callUUID},result){if(this.#intent&&this.#matchesAck(this.#intent,result))await this.peerEnded({peerId,callUUID});}
 forgetMemory(){this.#generation++;if(!this.#failed)this.#intent=null;}
 get state(){return {pending:!!this.#intent,saveFailed:this.#failed,busy:this.#busy};}
}
module.exports={CleanupIntent,validateIntent};
