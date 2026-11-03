// Read-only account-relative target discovery. No phone upload/contact import,
// shared access hashes, OTP or silent selection of a different account.
'use strict';
const {AccountClient}=require('./account-client.cjs'),{CallClient}=require('./call-client.cjs'),{CallError}=require('./call-session.cjs');
const fail=reason=>{throw new CallError(reason);};
function binding(account){
 const state=account.state;if(state?.provider!=='eitaa'||!state.signedIn||!state.selfConfirmed)fail('both_accounts_required');
 const record=account.exportSession();if(record?.provider!=='eitaa'||record.userId!==state.userId||typeof record.userId!=='string'||!/^[1-9]\d{0,18}$/.test(record.userId)||BigInt(record.userId)>=1n<<63n||typeof record.token!=='string'||!record.token||typeof record.imei!=='string'||!/^[a-z0-9]{15}__web$/.test(record.imei))fail('invalid_account_binding');return record;
}
const same=(a,b)=>a.token===b.token&&a.imei===b.imei&&a.userId===b.userId;
function user(value,id){return value?._==='user'&&value.id===BigInt(id)&&!value.deleted&&!value.min&&!value.bot&&typeof value.access_hash==='bigint'&&value.access_hash!==0n;}
function username(value){return typeof value==='string'&&/^[A-Za-z][A-Za-z0-9_]{2,31}$/.test(value)?value:null;}
class TargetResolver{
 #accounts;#auth;#calls;#clients=new Set();#epoch=0;#busy=false;
 constructor(accounts,{createAccountClient=o=>new AccountClient(o),createCallClient=o=>new CallClient(o)}={}){this.#accounts=accounts;this.#auth=createAccountClient;this.#calls=createCallClient;}
 close(){this.#epoch++;this.#busy=false;for(const client of this.#clients)client.close();this.#clients.clear();}
 async resolve(){
  if(this.#busy)fail('call_busy');const records=new Map([1,2].map(slot=>[slot,binding(this.#accounts.get(slot))]));this.#busy=true;const epoch=++this.#epoch;
  const guard=()=>{if(epoch!==this.#epoch)fail('call_cancelled');for(const [slot,record]of records)if(!same(record,binding(this.#accounts.get(slot))))fail('account_binding_changed');};
  const using=async(slot,factory,work)=>{
   guard();const record=records.get(slot),client=factory({provider:'eitaa',token:record.token,imei:record.imei,...record.profile?{profile:record.profile}:{}});this.#clients.add(client);
   try{const result=await work(client);guard();return result;}finally{client.close();this.#clients.delete(client);}
  };
  try{
   if(records.get(1).userId===records.get(2).userId)fail('distinct_accounts_required');
   const metadata=await Promise.all([1,2].map(slot=>using(slot,this.#auth,async client=>{
    const values=await client.request('users.getUsers');guard();const id=records.get(slot).userId;
    if(!Array.isArray(values)||values.length!==1||values[0]?._!=='user'||values[0].id!==BigInt(id)||values[0].self!==true||values[0].deleted)fail('target_self_mismatch');return {id,username:username(values[0].username)};
   })));
   const resolved=await Promise.all([1,2].map(slot=>using(slot,this.#calls,async client=>{
    const target=metadata[2-slot];let found;
    if(target.username){
     const result=await client.request('contacts.resolveUsername',{username:target.username});guard();
     if(result?._!=='contacts.resolvedPeer'||result.peer?._!=='peerUser'||result.peer.user_id!==BigInt(target.id)||!Array.isArray(result.users))fail('target_identity_mismatch');
     const values=result.users.filter(v=>user(v,target.id)&&username(v.username)?.toLowerCase()===target.username.toLowerCase());if(values.length!==1)fail('target_identity_mismatch');found=values[0];
    }else{
     const contacts=await client.request('contacts.getContacts');guard();if(contacts?._!=='contacts.contacts'||!Array.isArray(contacts.users)||!Array.isArray(contacts.contacts))fail('target_contacts_unavailable');
     const matches=contacts.users.filter(v=>user(v,target.id));if(contacts.contacts.some(c=>c?._==='contact'&&c.user_id===BigInt(target.id))){if(matches.length>1)fail('target_identity_mismatch');found=matches[0];}
     if(!found)fail('target_contact_required');
    }
    return [slot,{userId:target.id,accessHash:found.access_hash}];
   })));
   guard();return new Map(resolved);
  }catch(e){if(epoch!==this.#epoch)throw new CallError('call_cancelled');this.close();throw e instanceof CallError?e:new CallError('target_lookup_failed');}
  finally{if(epoch===this.#epoch)this.#busy=false;}
 }
}
module.exports={TargetResolver,binding};
