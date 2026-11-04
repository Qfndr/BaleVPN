'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {HttpClient,DISCOVERY}=require('../experiments/rubika/http-client.cjs'),wire=require('../experiments/rubika/wire.cjs'),profiles=require('../experiments/rubika/client-profile.cjs');
const routes=[1,2,3,4].map(index=>'https://session-fixture-'+index+'.iranlms.ir/');
const auth='abcdefghijklmnopqrstuvwxyz012345',selfId='fixture_self_01';
const reason=value=>error=>error.reason===value;
const encoded=(value,mode=profiles.WEB)=>Response.json({data_enc:wire.encrypt(value,auth,mode)});
async function fixture(mode=profiles.WEB,hook=()=>undefined){
 const identity=await wire.createIdentity(),credentials={provider:'rubika',userId:selfId,auth,...identity,...mode===profiles.ANDROID?{profile:{protocolProfile:mode}}:{}};
 const seen=[];
 const client=new HttpClient({protocolProfile:mode,fetchImpl:async(url,options)=>{
  const body=JSON.parse(options.body);if(url===DISCOVERY){seen.push({url,method:'getDCs',body});return Response.json({status:'OK',data:{default_api_urls:routes}});}
  assert.equal(body.auth,wire.transform(auth));assert.equal(body.tmp_session,undefined);
  assert.equal(body.api_version,mode===profiles.ANDROID?6:'6');
  assert.equal(crypto.verify('RSA-SHA256',Buffer.from(body.data_enc),identity.publicKey,Buffer.from(body.sign,'base64')),true);
  const payload=wire.decrypt(body.data_enc,auth,mode);assert.deepEqual(payload.client,profiles.client(mode,'fa'));assert.equal(payload.is_background,mode===profiles.ANDROID?false:undefined);
  seen.push({url,method:payload.method,input:payload.input,signal:options.signal});const custom=await hook(url,payload,options,credentials);if(custom!==undefined)return custom;
  if(payload.method==='getUserInfo')return encoded({status:'OK',data:{user:{user_guid:selfId}}},mode);
  return encoded({status:'OK',data:{active_session:{isCurrentSession:true,session_key:'private-session-key',ip:'private-ip',device:'private-device'},other_sessions:[{session_key:'private-other-key',device:'private-other-device'}]}},mode);
 }});
 return {client,credentials,seen};
}

test('explicit session probe visits only the first three discovered DCs and preserves the active route, account and profile',async()=>{
 for(const mode of [profiles.WEB,profiles.ANDROID]){
  const f=await fixture(mode,(url,payload)=>{
   if(payload.method!=='getMySessions')return;
   if(url===routes[0])return encoded({status:'ERROR_GENERIC',status_det:'NOT_REGISTERED',message:'private-server-message'},mode);
   if(url===routes[2])return encoded({status:'ERROR_ACTION',status_det:'INVALID_AUTH',message:'private-server-message'},mode);
  });
  try{
   await f.client.discover();const before=JSON.stringify(f.credentials),result=await f.client.probeDiscoveredSessions({credentials:f.credentials});
   assert.deepEqual(result,{discoveredCount:4,attemptedCount:3,stoppedOnRateLimit:false,budgetExhausted:false,results:[
    {index:0,ok:false,reason:'registration_required',serviceCode:'NOT_REGISTERED'},
    {index:1,ok:true,activeSessionPresent:true,otherSessionCount:1,currentFlag:true},
    {index:2,ok:false,reason:'not_authorized',serviceCode:'INVALID_AUTH'}]});
   assert.deepEqual(f.seen.slice(1).map(item=>item.url),routes.slice(0,3));assert.deepEqual(f.seen.slice(1).map(item=>item.method),['getMySessions','getMySessions','getMySessions']);assert.ok(f.seen.slice(1).every(item=>Object.keys(item.input).length===0));
   const safe=JSON.stringify(result);for(const secret of [...routes,auth,f.credentials.privateKey,f.credentials.publicKey,'private-session-key','private-ip','private-device','private-server-message'])assert.ok(!safe.includes(secret));
   assert.equal(JSON.stringify(f.credentials),before);await f.client.request('getUserInfo',{user_guid:selfId},{credentials:f.credentials});assert.equal(f.seen.at(-1).url,routes[0]);
  }finally{f.client.close();}
 }
});

test('probe stops immediately on HTTP or service rate limits without touching other DCs',async()=>{
 for(const http of [true,false]){
  const f=await fixture(profiles.WEB,()=>http?new Response('',{status:429}):encoded({status:'ERROR_GENERIC',status_det:'TOO_REQUESTS'}));
  try{await f.client.discover();const result=await f.client.probeDiscoveredSessions({credentials:f.credentials});assert.equal(result.attemptedCount,1);assert.equal(result.stoppedOnRateLimit,true);assert.equal(result.results[0].reason,'rate_limited');assert.equal(f.seen.length,2);}finally{f.client.close();}
 }
});

test('probing requires discovery and fixed options, empty getMySessions input, valid keys and matching retained profile',async()=>{
 const f=await fixture();try{
  await assert.rejects(f.client.probeDiscoveredSessions({credentials:f.credentials}),reason('discovery_required'));await f.client.discover();
  for(const options of [{credentials:f.credentials,url:'https://attacker.invalid/'},{credentials:f.credentials,method:'logout'},{credentials:f.credentials,timeout:5001},{credentials:f.credentials,timeout:0},null])await assert.rejects(f.client.probeDiscoveredSessions(options),reason('invalid_request'));
  await assert.rejects(f.client.probeDiscoveredSessions({credentials:{...f.credentials,profile:{protocolProfile:profiles.ANDROID}}}),reason('invalid_credentials'));
  await assert.rejects(f.client.probeDiscoveredSessions({credentials:{...f.credentials,privateKey:'invalid-private-key'}}),reason('invalid_credentials'));
  let executed=0;const serializer={};Object.defineProperty(serializer,'toJSON',{value(){executed++;return {session_key:'private-key'};}});
  for(const input of [{session_key:'private-session-key'},{limit:1},{user_guid:selfId},new Date(),serializer,new Proxy({},{ownKeys(){executed++;return [];}})])await assert.rejects(f.client.request('getMySessions',input,{credentials:f.credentials}),reason('invalid_request'));
  await assert.rejects(f.client.request('getMySessions',{}),reason('invalid_credentials'));assert.equal(executed,0);
  assert.equal(f.seen.length,1);
 }finally{f.client.close();}
});

test('duplicate discovered DCs are never retried and invalid discovery URLs cannot enter the probe cache',async()=>{
 const identity=await wire.createIdentity(),credentials={provider:'rubika',userId:selfId,auth,...identity};let count=0;
 const client=new HttpClient({fetchImpl:async(url)=>{if(url===DISCOVERY)return Response.json({status:'OK',data:{default_api_urls:[routes[0],routes[0],routes[1],routes[2]]}});count++;return encoded({status:'OK',data:{active_session:null,other_sessions:[]}});}});
 try{await client.discover();const result=await client.probeDiscoveredSessions({credentials});assert.deepEqual(result.results.map(item=>item.index),[0,2]);assert.equal(result.attemptedCount,2);assert.equal(count,2);}finally{client.close();}
 const invalid=new HttpClient({fetchImpl:async()=>Response.json({status:'OK',data:{default_api_urls:['https://attacker.invalid/']}})});
 try{await assert.rejects(invalid.discover(),reason('invalid_dc_server'));await assert.rejects(invalid.probeDiscoveredSessions({credentials}),reason('discovery_required'));}finally{invalid.close();}
});

test('probe blocks concurrent actions and rejects account or profile mutation before accepting a DC result',async()=>{
 for(const mutate of [record=>{record.auth='012345abcdefghijklmnopqrstuvwxyz';},record=>{record.profile={protocolProfile:profiles.ANDROID};}]){
  let release;const blocked=new Promise(resolve=>{release=resolve;});const f=await fixture(profiles.WEB,async()=>{await blocked;return encoded({status:'OK',data:{active_session:null,other_sessions:[]}});});
  try{
   await f.client.discover();const pending=f.client.probeDiscoveredSessions({credentials:f.credentials});
   for(const call of [()=>f.client.discover(),()=>f.client.discoverWithCredentials({credentials:f.credentials}),()=>f.client.startUpdates(f.credentials),()=>f.client.request('getMySessions',{}, {credentials:f.credentials}),()=>f.client.probeDiscoveredSessions({credentials:f.credentials})])await assert.rejects(call(),reason('account_busy'));
   mutate(f.credentials);release();await assert.rejects(pending,reason('invalid_credentials'));assert.equal(f.seen.length,2);
  }finally{release();f.client.close();}
 }
});

test('bounded per-DC timeouts and malformed session replies expose only fixed diagnostics',async()=>{
 const f=await fixture(profiles.WEB,async(url,payload,options)=>new Promise((resolve,reject)=>{options.signal.addEventListener('abort',()=>reject(Error('private transport detail')),{once:true});}));
 try{await f.client.discover();const result=await f.client.probeDiscoveredSessions({credentials:f.credentials,timeout:5});assert.equal(result.attemptedCount,3);assert.ok(result.results.every(item=>item.reason==='timeout'));assert.ok(f.seen.slice(1).every(item=>item.signal.aborted));}finally{f.client.close();}
 const malformed=await fixture(profiles.WEB,()=>encoded({status:'OK',data:{active_session:{session_key:'private-key'},other_sessions:'private-malformed-list'}}));
 try{await malformed.client.discover();const result=await malformed.client.probeDiscoveredSessions({credentials:malformed.credentials});assert.equal(result.attemptedCount,3);assert.ok(result.results.every(item=>item.reason==='invalid_session_status'));assert.ok(!JSON.stringify(result).includes('private'));}finally{malformed.client.close();}
});

test('credentialed discovery binding survives the read-only probe and close cancels a late result without another DC',async()=>{
 const f=await fixture(profiles.ANDROID);try{
  await f.client.discoverWithCredentials({credentials:f.credentials});const before=f.seen.length;
  await assert.rejects(f.client.probeDiscoveredSessions({credentials:{...f.credentials,userId:'fixture_foreign_02'}}),reason('invalid_credentials'));assert.equal(f.seen.length,before);
  const result=await f.client.probeDiscoveredSessions({credentials:f.credentials});assert.equal(result.attemptedCount,3);
  await assert.rejects(f.client.discover(),reason('invalid_credentials'));
  await f.client.request('getUserInfo',{user_guid:selfId},{credentials:f.credentials});assert.equal(f.seen.at(-1).url,routes[0]);
 }finally{f.client.close();}
 let release;const blocked=new Promise(resolve=>{release=resolve;});const late=await fixture(profiles.WEB,async()=>{await blocked;return encoded({status:'OK',data:{active_session:null,other_sessions:[]}});});
 try{await late.client.discover();const pending=late.client.probeDiscoveredSessions({credentials:late.credentials});late.client.close();release();await assert.rejects(pending,reason('closed'));assert.equal(late.seen.length,2);}finally{release();late.client.close();}
});

test('a transport ignoring abort cannot hold the probe open or cause concurrent DC requests',async()=>{
 const f=await fixture(profiles.WEB,()=>new Promise(()=>{}));try{
  await f.client.discover();const result=await f.client.probeDiscoveredSessions({credentials:f.credentials,timeout:5});
  assert.equal(result.attemptedCount,1);assert.deepEqual(result.results,[{index:0,ok:false,reason:'timeout'}]);assert.equal(f.seen.length,2);assert.equal(f.seen[1].signal.aborted,true);
 }finally{f.client.close();}
});
