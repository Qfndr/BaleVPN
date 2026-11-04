'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {HttpClient,DISCOVERY}=require('../experiments/rubika/http-client.cjs'),wire=require('../experiments/rubika/wire.cjs'),profiles=require('../experiments/rubika/client-profile.cjs');
const oldRoute='https://messengerg2c1.iranlms.ir/',newRoute='https://messengerg3c2.iranlms.ir/';
const record=(extra={})=>({provider:'rubika',userId:'fixture_account_01',auth:'abcdefghijklmnopqrstuvwxyz012345',profile:{protocolProfile:profiles.ANDROID},...extra});
const routes=(urls=[oldRoute])=>Response.json({status:'OK',data:{default_api_urls:urls}});

test('explicit Android V4 DC reload sends raw auth only to fixed HTTPS discovery and reports no URLs or credentials',async()=>{
 const keys=await wire.createIdentity(),credentials=record({...keys,loginPhone:'fixture-private-phone'}),seen=[];
 const client=new HttpClient({protocolProfile:profiles.ANDROID,updatesFactory:null,fetchImpl:async(url,options)=>{
  const body=JSON.parse(options.body);seen.push({url,body});assert.equal(options.redirect,'error');
  if(body.method==='getDCs'){
   assert.equal(url,DISCOVERY);assert.equal(options.headers.origin,undefined);assert.deepEqual(Object.keys(body).sort(),body.auth?['api_version','auth','client','method']:['api_version','client','method']);
   if(seen.length===1){assert.equal(body.auth,undefined);assert.equal(body.api_version,'4');return routes();}
   assert.equal(body.api_version,4);assert.equal(body.auth,credentials.auth);assert.notEqual(body.auth,wire.transform(credentials.auth));
   for(const privateField of [credentials.privateKey,credentials.publicKey,credentials.loginPhone])assert.ok(!options.body.includes(privateField));
   assert.equal(body.client.platform,'Android');return routes([newRoute]);
  }
  assert.equal(url,newRoute);assert.equal(body.api_version,6);assert.equal(body.auth,wire.transform(credentials.auth));
  assert.equal(crypto.verify('RSA-SHA256',Buffer.from(body.data_enc),keys.publicKey,Buffer.from(body.sign,'base64')),true);
  assert.equal(wire.decrypt(body.data_enc,credentials.auth,profiles.ANDROID).method,'getUserInfo');
  return Response.json({data_enc:wire.encrypt({status:'OK',data:{user:{user_guid:credentials.userId}}},credentials.auth,profiles.ANDROID)});
 }});
 try{
  assert.deepEqual(await client.discover(),{apiServerSelected:true});
  const metadata=await client.discoverWithCredentials({credentials});
  assert.deepEqual(metadata,{apiServerSelected:true,candidateCount:1,comparedWithPrevious:true,apiListEqual:false,selectedServerChanged:true});
  assert.equal(seen.length,2,'DC reload never performs an implicit self read, registration or retry');
  for(const privateField of [credentials.auth,credentials.userId,oldRoute,newRoute])assert.ok(!JSON.stringify(metadata).includes(privateField));
  const self=await client.request('getUserInfo',{user_guid:credentials.userId},{credentials});assert.equal(self.user.user_guid,credentials.userId);assert.equal(seen.length,3);
 }finally{client.close();}
});

test('credentialed DC reload is unavailable for Web, foreign providers or invalid credentials before any request',async()=>{
 let count=0;const create=profile=>new HttpClient({protocolProfile:profile,fetchImpl:async()=>{count++;return routes();}});
 const web=create(profiles.WEB),android=create(profiles.ANDROID);
 try{
  await assert.rejects(web.discoverWithCredentials({credentials:record()}),/invalid_credentials/);
  for(const credentials of [undefined,record({provider:'bale'}),record({profile:{protocolProfile:profiles.WEB}}),record({userId:'bad'}),record({auth:'bad'})])
   await assert.rejects(android.discoverWithCredentials({credentials}),/invalid_credentials/);
  assert.equal(count,0);
 }finally{web.close();android.close();}
});

test('credentialed route cannot silently become anonymous or be reused by a different account/session',async()=>{
 let count=0;const credentials=record(),client=new HttpClient({protocolProfile:profiles.ANDROID,fetchImpl:async()=>{count++;return routes();}});
 try{
  const metadata=await client.discoverWithCredentials({credentials});assert.equal(metadata.comparedWithPrevious,false);assert.equal(metadata.apiListEqual,null);
  await assert.rejects(client.discover(),/invalid_credentials/);
  for(const changed of [record({userId:'fixture_account_02'}),record({auth:'012345abcdefghijklmnopqrstuvwxyz'}),record({profile:{protocolProfile:profiles.WEB}})]){
   await assert.rejects(client.discoverWithCredentials({credentials:changed}),/invalid_credentials/);
   await assert.rejects(client.request('getUserInfo',{user_guid:changed.userId},{credentials:changed}),/invalid_credentials/);
   await assert.rejects(client.startUpdates(changed),/invalid_credentials/);
  }
  await assert.rejects(client.request('sendCode',{phone_number:'989120000001',send_type:'SMS'}),/invalid_credentials/);
  assert.equal(count,1);
 }finally{client.close();}
});

test('changed credentials and closed clients cannot adopt a late DC reload response',async()=>{
 for(const close of [false,true]){
  let release,count=0;const credentials=record(),client=new HttpClient({protocolProfile:profiles.ANDROID,fetchImpl:async()=>{count++;return new Promise(resolve=>{release=resolve;});}});
  try{
   const pending=client.discoverWithCredentials({credentials});assert.equal(count,1);
   if(close)client.close();else credentials.auth='012345abcdefghijklmnopqrstuvwxyz';release(routes([newRoute]));
   await assert.rejects(pending,close?/closed/:/invalid_credentials/);assert.equal(count,1);
  }finally{client.close();}
 }
});

test('DC responses remain strictly provider-bound and service errors never trigger registration or retries',async()=>{
 for(const response of [()=>routes(['https://attacker.invalid/']),()=>routes(['http://messengerg2c1.iranlms.ir/']),
  ()=>Response.json({status:'ERROR_ACTION',status_det:'NOT_REGISTERED',message:'fixture-private-server-message'})]){
  let count=0;const client=new HttpClient({protocolProfile:profiles.ANDROID,fetchImpl:async()=>{count++;return response();}});
  try{await assert.rejects(client.discoverWithCredentials({credentials:record()}),error=>{
   assert.ok(['invalid_dc_server','registration_required'].includes(error.reason));assert.ok(!error.message.includes('fixture-private'));return true;
  });assert.equal(count,1);}finally{client.close();}
 }
});
