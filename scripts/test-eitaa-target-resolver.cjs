'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {TargetResolver}=require('../experiments/eitaa/target-resolver.cjs'),{account}=require('./eitaa-call-session-fixture.cjs');
function fixture({contacts=true,withUsername=true}={}){
 const accounts=new Map([[1,account(101)],[2,account(202)]]),calls=[],clients=[];let intercept;
 const factory=kind=>options=>{const self=Number(options.token.split('-').at(-1)),target=self===101?202:101,client={closed:false,close(){this.closed=true;},async request(method,input){calls.push({self,kind,method,input});if(intercept){const result=await intercept({self,method,input});if(result!==undefined)return result;}
  const user={_:'user',id:BigInt(target),access_hash:-BigInt(self)*10n,username:'Target'+target};
  if(method==='users.getUsers')return [{_:'user',self:true,id:BigInt(self),...withUsername?{username:'Target'+self}:{}}];
  if(method==='contacts.getContacts')return {_:'contacts.contacts',contacts:contacts?[{_:'contact',user_id:BigInt(target),mutual:true}]:[],users:contacts?[user]:[]};
  if(method==='contacts.resolveUsername')return {_:'contacts.resolvedPeer',peer:{_:'peerUser',user_id:BigInt(target)},users:[user],chats:[]};throw Error('unexpected fixture method');
 }};clients.push(client);return client;};
 const resolver=new TargetResolver(accounts,{createAccountClient:factory('auth'),createCallClient:factory('calls')});return {accounts,resolver,calls,clients,set intercept(value){intercept=value;}};
}
test('target hashes are read from each caller, never copied from the target self record or shared across accounts',async t=>{
 const f=fixture({withUsername:false});t.after(()=>f.resolver.close());const targets=await f.resolver.resolve();assert.deepEqual(targets.get(1),{userId:'202',accessHash:-1010n});assert.deepEqual(targets.get(2),{userId:'101',accessHash:-2020n});assert.equal(f.calls.length,4);assert.ok(f.clients.every(c=>c.closed));assert.ok(f.calls.every(c=>['users.getUsers','contacts.getContacts'].includes(c.method)));
});
test('verified public usernames resolve directly without reading the address book, with an exact user ID match',async t=>{
 const f=fixture({contacts:false});t.after(()=>f.resolver.close());const result=await f.resolver.resolve();assert.equal(result.get(1).accessHash,-1010n);assert.deepEqual(f.calls.filter(c=>c.method==='contacts.resolveUsername').map(c=>c.input.username).sort(),['Target101','Target202']);
});
test('missing public username never causes phone contact import, arbitrary searching or an automatic call',async()=>{
 const f=fixture({contacts:false,withUsername:false});await assert.rejects(f.resolver.resolve(),{reason:'target_contact_required'});assert.ok(f.clients.every(c=>c.closed));assert.ok(f.calls.every(c=>['users.getUsers','contacts.getContacts'].includes(c.method)));
});
test('a username reassigned to another identity and incomplete or duplicated contact records cannot select a different account',async()=>{
 const f=fixture({contacts:false});f.intercept=({method})=>method==='contacts.resolveUsername'?{_:'contacts.resolvedPeer',peer:{_:'peerUser',user_id:999n},users:[],chats:[]}:undefined;await assert.rejects(f.resolver.resolve(),{reason:'target_identity_mismatch'});
 const g=fixture({withUsername:false});g.intercept=({self,method})=>method==='contacts.getContacts'?{_:'contacts.contacts',contacts:[{_:'contact',user_id:BigInt(self===101?202:101)}],users:Array(2).fill({_:'user',id:BigInt(self===101?202:101),access_hash:1n})}:undefined;await assert.rejects(g.resolver.resolve(),{reason:'target_identity_mismatch'});
});
test('uncached not-modified replies and self/account mismatches fail without returning private target material',async()=>{
 const f=fixture({withUsername:false});f.intercept=({method})=>method==='contacts.getContacts'?{_:'contacts.contactsNotModified'}:undefined;await assert.rejects(f.resolver.resolve(),{reason:'target_contacts_unavailable'});
 const g=fixture();g.intercept=({method})=>method==='users.getUsers'?[{_:'user',self:true,id:999n}]:undefined;await assert.rejects(g.resolver.resolve(),{reason:'target_self_mismatch'});
});
test('cancellation closes in-flight clients and late contact replies cannot produce targets',async()=>{
 const f=fixture({withUsername:false}),releases=[];let signal;const entered=new Promise(r=>{signal=r;});f.intercept=({method})=>method==='contacts.getContacts'?new Promise(r=>{releases.push(()=>r({_:'contacts.contacts',contacts:[],users:[]}));if(releases.length===2)signal();}):undefined;
 const pending=f.resolver.resolve();await entered;f.resolver.close();for(const release of releases)release();await assert.rejects(pending,{reason:'call_cancelled'});assert.ok(f.clients.every(c=>c.closed));
});
test('account changes invalidate lookup and failed or unauthenticated attempts do not leave the resolver busy',async()=>{
 const f=fixture();f.accounts.get(1).stop();await assert.rejects(f.resolver.resolve(),{reason:'both_accounts_required'});assert.equal(f.calls.length,0);f.resolver.close();
 const g=fixture({withUsername:false});g.intercept=({self,method})=>{if(self===101&&method==='contacts.getContacts')g.accounts.get(1).record.token='fixture-new-101';};await assert.rejects(g.resolver.resolve(),{reason:'account_binding_changed'});g.intercept=null;const targets=await g.resolver.resolve();assert.equal(targets.size,2);g.resolver.close();
});
