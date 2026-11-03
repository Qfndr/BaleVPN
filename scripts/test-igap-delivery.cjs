'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {AuthSession,APP_ID}=require('../experiments/igap/auth-session.cjs');
const {RpcError}=require('../experiments/igap/rpc-connection.cjs'),{wire:w}=require('../experiments/igap/signaling.cjs');
const phone={country:'IR',nationalNumber:'9120000001',internationalNumber:'+989120000001'};
function fixture({method=0,id='41',password=false,delay=0}={}){
 const rpc={method,failStart:false,calls:[],status:{phase:'ready'},async request(action,body=Buffer.alloc(0)){
  this.calls.push({action,fields:w.parse(body)});let payload;
  if(action===100){if(this.failStart)throw new RpcError('rejected',100,1);payload=Buffer.concat([w.string(2,'fixture-private-username',128),w.field(3,BigInt(id),0),...this.method===undefined?[]:[w.field(5,this.method,0)],w.field(6,delay,0),w.field(9,5,0)]);}
  else if(action===101){if(password)throw new RpcError('rejected',184,0);payload=w.string(2,'fixture-private-token',128);}
  else if(action===131)payload=w.string(4,'fixture password hint',128);
  else if(action===127)payload=Buffer.alloc(0);
  else throw Error('Unexpected fixture action');
  return {action:action+30000,fields:w.parse(payload)};
 },async login(){this.calls.push({action:102});return {action:30102,fields:w.parse(w.field(14,BigInt(id),0))};},close(){this.status.phase='closed';}};
 const session=new AuthSession({connect:async()=>rpc});return {session,rpc};
}
test('iGap code state retains all four service delivery methods without changing the register request',async()=>{
 for(const method of [0,1,2,3]){const f=fixture({method});try{assert.equal(f.session.state.deliveryMethod,null);const response=await f.session.start(phone);assert.equal(response.method,method);assert.equal(f.session.state.deliveryMethod,method);const request=f.rpc.calls[0];assert.equal(request.action,100);assert.equal(w.one(request.fields,2,0),9120000001n);assert.equal(w.str(request.fields,3,2),'IR');assert.equal(w.one(request.fields,4,0),0n);assert.equal(w.one(request.fields,5,0),BigInt(APP_ID));for(const secret of ['fixture-private-username','fixture-private-token',phone.internationalNumber,'12345'])assert.ok(!JSON.stringify(f.session.state).includes(secret));}finally{f.session.close();}}
});
test('a proto3 omitted delivery method means SMS while unknown method values fail closed',async()=>{
 const f=fixture();f.rpc.method=undefined;try{assert.equal((await f.session.start(phone)).method,0);assert.equal(f.session.state.deliveryMethod,0);}finally{f.session.close();}
 const invalid=fixture({method:4});try{await assert.rejects(invalid.session.start(phone),/invalid_auth_response/);assert.equal(invalid.session.state.deliveryMethod,null);}finally{invalid.session.close();}
});
test('two pending accounts retain independent hints and a blocked resend preserves the current valid hint',async()=>{
 const a=fixture({method:1,delay:60}),b=fixture({method:3,id:'42'});try{await Promise.all([a.session.start(phone),b.session.start(phone)]);await assert.rejects(a.session.start(phone),/cooldown/);assert.equal(a.session.state.deliveryMethod,1);assert.equal(b.session.state.deliveryMethod,3);assert.equal(a.rpc.calls.length,1);}finally{a.session.close();b.session.close();}
});
test('new register attempts clear the old hint before the new request completes or fails',async()=>{
 const f=fixture({method:1});try{await f.session.start(phone);f.rpc.failStart=true;await assert.rejects(f.session.start(phone),/rejected/);assert.equal(f.session.state.deliveryMethod,null);assert.equal(f.rpc.calls.filter(v=>v.action===100).length,2);}finally{f.session.close();}
});
test('local input errors preserve a usable delivery hint; successful verify does not persist it in the session',async()=>{
 const f=fixture({method:2});try{await f.session.start(phone);await assert.rejects(f.session.verify('bad'),/invalid_code_format/);assert.equal(f.session.state.deliveryMethod,2);await f.session.verify('12345');assert.equal(f.session.state.deliveryMethod,null);assert.equal(f.session.state.signedIn,true);assert.equal(Object.hasOwn(f.session.exportSession(),'deliveryMethod'),false);}finally{f.session.close();}
});
test('password transition, stop, close and expired connections remove the delivery hint',async()=>{
 const twoStep=fixture({method:2,password:true});try{await twoStep.session.start(phone);await twoStep.session.verify('12345');assert.equal(twoStep.session.state.stage,'password');assert.equal(twoStep.session.state.deliveryMethod,null);}finally{twoStep.session.close();}
 for(const operation of ['stop','close','expire']){const f=fixture({method:3});try{await f.session.start(phone);if(operation==='expire'){f.rpc.close();await assert.rejects(f.session.verify('12345'),/login_connection_expired/);}else f.session[operation]();assert.equal(f.session.state.deliveryMethod,null);}finally{f.session.close();}}
 const observed=fixture({method:1});try{await observed.session.start(phone);observed.rpc.close();assert.equal(observed.session.state.deliveryMethod,null);}finally{observed.session.close();}
});
