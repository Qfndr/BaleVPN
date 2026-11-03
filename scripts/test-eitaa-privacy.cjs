'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {AccountClient}=require('../experiments/eitaa/account-client.cjs'),{AuthSession}=require('../experiments/eitaa/auth-session.cjs');
const wire=require('../experiments/eitaa/wire.cjs'),codec=require('../experiments/eitaa/privacy-wire.cjs');
const imei='0123456789abcde__web',phone={country:'IR',nationalNumber:'9120000001',internationalNumber:'+989120000001'};
const rules=mode=>({_:'account.privacyRules',rules:[{_:mode}],chats:[],users:[]});
function fixture({initial='privacyValueDisallowAll',confirm=true}={}){
 const calls=[];let mode=initial;
 const account=new AuthSession({createClient:()=>({setToken(){},close(){},async request(method,input){calls.push({method,input});
  if(method==='auth.sendCode')return {_:'auth.sentCode',phone_code_hash:'fixture-hash',type:{_:'auth.sentCodeTypeSms',length:6}};
  if(method==='auth.signIn')return {_:'auth.authorization',token:'fixture-private-token',user:{_:'user',id:41n,self:true,phone:'989120000001'}};
  if(method==='users.getUsers')return [{_:'user',id:41n,self:true,phone:'989120000001'}];
  if(method==='account.getPrivacy')return rules(mode);
  if(method==='account.setPrivacy'){if(confirm)mode='privacyValueAllowAll';return rules('privacyValueAllowAll');}
  throw Error('Unexpected fixture method');
 }})});
 return {account,calls,async login(){await account.start(phone);await account.verify('123456');}};
}
test('Eitaa privacy wire accepts only the two reviewed phone-call privacy methods',()=>{
 const encoded=codec.method('account.setPrivacy',{key:{_:'inputPrivacyKeyPhoneCall'},rules:[{_:'inputPrivacyValueAllowAll'}]});const reader=new wire.Reader(encoded);
 assert.equal(reader.int(),-906486552);assert.equal(reader.int(),-88417185);assert.equal(reader.int(),481674261);assert.equal(reader.int(),1);assert.equal(reader.int(),407582158);reader.end();
 assert.deepEqual(codec.response(codec.object(rules('privacyValueAllowAll')),'account.getPrivacy'),rules('privacyValueAllowAll'));
 assert.throws(()=>codec.method('phone.requestCall',{}));
});
test('account privacy RPCs need a session and force phone-call key without exposing arbitrary privacy writes',async()=>{
 let requests=0;const client=new AccountClient({imei,token:'fixture-private-token',fetchImpl:async(_url,options)=>{
  requests++;const r=new wire.Reader(options.body);r.int();r.string();r.string();const inner=new wire.Reader(r.bytes());const method=inner.int();assert.ok([-623130288,-906486552].includes(method));assert.equal(inner.int(),-88417185);if(method===-906486552){assert.equal(inner.int(),481674261);assert.equal(inner.int(),1);assert.equal(inner.int(),407582158);}inner.end();return new Response(codec.object(rules('privacyValueAllowAll')));
 }});
 try{await client.request('account.getPrivacy');await client.request('account.setPrivacy',{allowAll:true});for(const input of [{allowAll:false},{allowAll:true,key:'phoneP2P'},{key:'phoneCall'}])await assert.rejects(client.request('account.setPrivacy',input),/invalid_request/);assert.equal(requests,2);}finally{client.close();}
 const anonymous=new AccountClient({imei,fetchImpl:async()=>{throw Error('Unexpected anonymous request');}});await assert.rejects(anonymous.request('account.getPrivacy'),/not_authorized/);anonymous.close();
});
test('allowing all calls reads, writes only phone-call privacy and verifies with a fresh read',async()=>{
 const f=fixture();try{await f.login();const result=await f.account.allowAllCalls();assert.deepEqual(result,{changed:true,callPrivacy:{mode:'everyone',allowedEveryone:true}});assert.deepEqual(f.calls.slice(-3).map(c=>c.method),['account.getPrivacy','account.setPrivacy','account.getPrivacy']);assert.deepEqual(f.calls.at(-2).input,{allowAll:true});assert.deepEqual(f.account.state.callPrivacy,result.callPrivacy);assert.ok(!JSON.stringify(result).includes('fixture-private-token'));assert.equal(f.calls.filter(c=>c.method==='auth.sendCode').length,1);}finally{f.account.close();}
});
test('already-everyone is idempotent and does not write or create a new session',async()=>{
 const f=fixture({initial:'privacyValueAllowAll'});try{await f.login();assert.equal((await f.account.allowAllCalls()).changed,false);assert.equal(f.calls.some(c=>c.method==='account.setPrivacy'),false);}finally{f.account.close();}
});
test('a service echo alone cannot confirm the permission change and stopped accounts cannot mutate privacy',async()=>{
 const f=fixture({confirm:false});try{await assert.rejects(f.account.allowAllCalls(),/not_authenticated/);assert.equal(f.calls.length,0);await f.login();await assert.rejects(f.account.allowAllCalls(),/privacy_change_not_confirmed/);assert.equal(f.account.state.callPrivacy.allowedEveryone,false);f.account.stop();assert.equal(f.account.state.callPrivacy,null);await assert.rejects(f.account.getCallPrivacy(),/not_authenticated/);}finally{f.account.close();}
});
