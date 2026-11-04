'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {readMySessionStatus,decodeSessionStatus}=require('../experiments/rubika/session-status.cjs');
const {ApiError,HttpClient}=require('../experiments/rubika/http-client.cjs'),wire=require('../experiments/rubika/wire.cjs'),profiles=require('../experiments/rubika/client-profile.cjs');
async function credentials(mode=profiles.ANDROID){return {provider:'rubika',userId:'fixture_account_01',auth:'abcdefghijklmnopqrstuvwxyz012345',...await wire.createIdentity(),...mode===profiles.ANDROID?{profile:{protocolProfile:mode}}:{}};}
const servicePage=()=>({active_session:{key:'fixture-private-session-key',ip:'192.0.2.1',location:'fixture-private-location',device:'fixture-private-device',isCurrentSession:true},
 other_sessions:[{key:'fixture-private-other-key',ip:'192.0.2.2'}],can_remove_all:true,unrelated_chat:'fixture-private-chat'});

test('protected session projection returns only aggregate metadata and never evaluates private fields',()=>{
 const response=servicePage();let read=0;
 for(const field of ['key','ip','location','device'])Object.defineProperty(response.active_session,field,{enumerable:true,get(){read++;throw Error('private field must not be read');}});
 assert.deepEqual(decodeSessionStatus(response),{activeSessionPresent:true,otherSessionCount:1,currentFlag:true});assert.equal(read,0);
 assert.deepEqual(decodeSessionStatus({active_session:null,other_sessions:[]}),{activeSessionPresent:false,otherSessionCount:0});
 assert.deepEqual(decodeSessionStatus({other_sessions:[]}),{activeSessionPresent:false,otherSessionCount:0});
});

test('session projection rejects malformed aggregate fields, oversized lists and known-field accessors',()=>{
 for(const value of [null,[],{}, {active_session:[],other_sessions:[]},{active_session:{isCurrentSession:'yes'},other_sessions:[]},
  {other_sessions:Array(129).fill({})},{other_sessions:[null]},{other_sessions:new Array(1)}])assert.throws(()=>decodeSessionStatus(value),/invalid_session_status/);
 const response={other_sessions:[]};let executed=0;Object.defineProperty(response,'active_session',{get(){executed++;return {};}});
 assert.throws(()=>decodeSessionStatus(response),/invalid_session_status/);assert.equal(executed,0);
 assert.throws(()=>decodeSessionStatus(new Proxy({},{getPrototypeOf(){throw Error('proxy executed');}})),/invalid_session_status/);
});

test('one private session-status read keeps exact credentials/profile and closes without registration or persistence',async()=>{
 const record=await credentials(),before=JSON.stringify(record),seen=[];let closed=0;
 const result=await readMySessionStatus(record,{createClient:options=>({async discover(){seen.push({method:'discover',options});},async request(method,input,options){
  seen.push({method,input});assert.equal(options.credentials.auth,record.auth);assert.equal(options.credentials.privateKey,record.privateKey);return servicePage();
 },close(){closed++;}})});
 assert.deepEqual(result,{activeSessionPresent:true,otherSessionCount:1,currentFlag:true});assert.equal(closed,1);assert.equal(JSON.stringify(record),before);
 assert.deepEqual(seen.map(x=>x.method),['discover','getMySessions']);assert.deepEqual(seen[1].input,{});assert.equal(seen[0].options.updatesFactory,null);
 for(const secret of [record.auth,record.userId,record.privateKey,'fixture-private'])assert.ok(!JSON.stringify(result).includes(secret));
});

test('errors identify a fixed failed stage without leaking provider messages or attempting registration',async()=>{
 for(const failedStage of ['discover','getMySessions']){
  const record=await credentials(),seen=[];let closed=0;
  await assert.rejects(readMySessionStatus(record,{createClient:()=>({async discover(){seen.push('discover');if(failedStage==='discover')throw new ApiError('registration_required');},
   async request(method){seen.push(method);throw new ApiError('registration_required');},close(){closed++;}})}),e=>{
   assert.equal(e.reason,'registration_required');assert.equal(e.stage,failedStage);assert.ok(!e.message.includes(record.auth));return true;
  });assert.equal(closed,1);assert.deepEqual(seen,failedStage==='discover'?['discover']:['discover','getMySessions']);
 }
 const record=await credentials();await assert.rejects(readMySessionStatus(record,{createClient:()=>({async discover(){throw Error('fixture-private-error');},close(){}})}),e=>e.reason==='session_status_failed'&&!e.message.includes('fixture-private'));
});

test('an account change while I/O is pending invalidates the read and closes only its diagnostic client',async()=>{
 const record=await credentials();let release,closed=0;const pending=readMySessionStatus(record,{createClient:()=>({async discover(){},async request(){return new Promise(resolve=>{release=resolve;});},close(){closed++;}})});
 while(!release)await new Promise(resolve=>setImmediate(resolve));record.auth='012345abcdefghijklmnopqrstuvwxyz';release(servicePage());
 await assert.rejects(pending,/account_binding_changed/);assert.equal(closed,1);assert.equal(record.auth,'012345abcdefghijklmnopqrstuvwxyz');
});

test('a rejected read from a replaced account cannot publish that account’s status',async()=>{
 const record=await credentials();let reject,closed=0;
 const pending=readMySessionStatus(record,{createClient:()=>({async discover(){},async request(){return new Promise((_,fail)=>{reject=fail;});},close(){closed++;}})});
 while(!reject)await new Promise(resolve=>setImmediate(resolve));record.auth='012345abcdefghijklmnopqrstuvwxyz';
 reject(Object.assign(new ApiError('registration_required',undefined,'NOT_REGISTERED'),{diagnosticStatus:'ERROR_ACTION'}));
 await assert.rejects(pending,error=>error.reason==='account_binding_changed'&&error.serviceCode===undefined);assert.equal(closed,1);
});

test('private status probe retains the fixed Android error class without raw error details',async()=>{
 const record=await credentials();
 for(const [status,reason,expectedStatus]of [['ERROR_ACTION','registration_required','ERROR_ACTION'],
  ['ERROR_GENERIC','service_rejected','ERROR_GENERIC'],['UNRECOGNIZED_STATUS','service_rejected',undefined]]){
  let requests=0;
  await assert.rejects(readMySessionStatus(record,{createClient:options=>new HttpClient({...options,fetchImpl:async(_url,options)=>{
   requests++;if(JSON.parse(options.body).method==='getDCs')return Response.json({status:'OK',data:{default_api_urls:['https://messengerg2c1.iranlms.ir/']}});
   return Response.json({data_enc:wire.encrypt({status,status_det:'NOT_REGISTERED',message:'fixture-private-message',data:{auth:record.auth}},record.auth,profiles.ANDROID)});
  }})}),error=>{
   assert.equal(error.reason,reason);assert.equal(error.stage,'getMySessions');assert.equal(error.serviceCode,'NOT_REGISTERED');
   assert.equal(error.diagnosticStatus,expectedStatus);assert.ok(!JSON.stringify(error).includes(record.auth));
   assert.ok(!JSON.stringify(error).includes('fixture-private-message'));return true;
  });
  assert.equal(requests,2);
 }
});

test('real signed Android framing carries only getMySessions and returns sanitized metadata from an offline service',async()=>{
 const record=await credentials(),seen=[];
 const result=await readMySessionStatus(record,{createClient:options=>new HttpClient({...options,fetchImpl:async(url,options)=>{
  const body=JSON.parse(options.body);if(body.method==='getDCs'){seen.push('getDCs');return Response.json({status:'OK',data:{default_api_urls:['https://messengerg2c1.iranlms.ir/']}});}
  assert.equal(body.api_version,6);assert.equal(crypto.verify('RSA-SHA256',Buffer.from(body.data_enc),record.publicKey,Buffer.from(body.sign,'base64')),true);
  const decoded=wire.decrypt(body.data_enc,record.auth,profiles.ANDROID);seen.push(decoded.method);assert.equal(decoded.method,'getMySessions');assert.deepEqual(decoded.input,{});
  return Response.json({data_enc:wire.encrypt({status:'OK',data:servicePage()},record.auth,profiles.ANDROID)});
 }})});
 assert.deepEqual(seen,['getDCs','getMySessions']);assert.deepEqual(result,{activeSessionPresent:true,otherSessionCount:1,currentFlag:true});
});
