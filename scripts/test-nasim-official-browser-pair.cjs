// Synthetic service responses exercise the pinned vendor call in two browsers.
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {chromium}=require(process.env.BALEVPN_PLAYWRIGHT_MODULE||'playwright');
const {SessionVault}=require('../experiments/providers/session-vault.cjs');
const {ENDPOINT}=require('../experiments/nasim/official-call-transport.cjs');
const {OfficialMediaGuard}=require('../experiments/nasim/official-media-guard.cjs');
const {runOfficialReference}=require('../experiments/nasim/official-reference-runner.cjs');
const wire=require('../experiments/nasim/wire.cjs');
(async()=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'nasim-official-browser-fixture-'));
 const vault=new SessionVault(directory),calls=[],readRequests=[],streams=new Map(),cursors=[0,0];
 try{
  await vault.unlock('synthetic-official-browser-vault-password');
  const accounts=new Map([1,2].map(slot=>[slot,{
   state:{provider:'nasim',signedIn:true,userId:String(40+slot),clientId:'client-'+slot},
   exportSession(){return {provider:'nasim',userId:this.state.userId,clientId:this.state.clientId,
    token:'synthetic-official-browser-token-'+slot,deviceId:'web.synthetic-browser-'+slot,loginPhone:'+98912000000'+slot};}
  }]));
  for(const slot of [1,2])await vault.save('nasim',slot,accounts.get(slot).exportSession());
  // This synthetic-only policy permits the fixture's discard-port loopback
  // STUN/TURN URLs. The production policy rejects all private relay URLs.
  const candidatePolicy=new OfficialMediaGuard({approvedServers:['stun:1.1.1.1:3478','turn:1.1.1.1:3478']});
  const mediaGuard={resolverRules:'',capture:(...args)=>candidatePolicy.capture(...args),
   checkServers(servers){assert.deepEqual(servers.map(s=>s.urls),['stun:127.0.0.1:9','turn:127.0.0.1:9']);},
   async checkSignal(slot,signal){if(signal.type==='config')this.checkServers(signal.iceServers);else await candidatePolicy.checkSignal(slot,signal);}
  };
  const callUUID='synthetic-official-browser-call',participants=[{userID:41,nickname:'Fixture caller'},{userID:42,nickname:'Fixture callee'}];
  const streamOrigin='https://stream.fixture.gaplication.com';
  function queue(slot,signal,sender){
   const message={topic:`u/${40+slot}/${40+sender}`,type:'msgGroupCall',data:signal,
    from:{id:40+sender},senderClientID:'client-'+sender,time:Date.now()};
   const data=wire.encryptBytes(Buffer.from(JSON.stringify({messages:[message]})),accounts.get(slot).exportSession().token).toString('base64');
   streams.get(slot).enqueue(Buffer.from(`id: ${++cursors[slot-1]}\nevent: message\ndata: ${data}\n\n`));
  }
  let idleChecks=0;
  const result=await runOfficialReference({vault,accounts,mediaGuard,chromium,executablePath:process.env.BALEVPN_BROWSER_EXECUTABLE,
   directory:process.env.BALEVPN_NASIM_OFFICIAL_DIRECTORY,mediaTimeoutMs:10000,checkIdle:async()=>{idleChecks++;return true;},
   fetchImpl:async(url,options)=>{
    assert.equal(options.redirect,'error');
    if(url!==ENDPOINT){
     readRequests.push(url);
     if(url==='https://core.gap.im/utils/getTime.json')return Response.json({status:'success',data:{time:Math.floor(Date.now()/1000)}});
     if(url==='https://api.gaplication.com/groupList?page=reset')return Response.json({status:'success',data:{groups:[]}});
     if(url==='https://core.gaplication.com/message/get/config'){
      return new Response(wire.encrypt({status:'success',data:{SSEServerAddress:streamOrigin}},options.headers.token));
     }
     if(url==='https://core.gaplication.com/mxb/user/status'){
      return new Response(wire.encrypt({status:'success',data:{active:true,userID:40+Number(options.headers.clientid.at(-1))}},options.headers.token));
     }
     assert.equal(url,streamOrigin+'/message/get');
     const slot=Number(options.headers.clientid.at(-1));
     return new Response(new ReadableStream({start(controller){streams.set(slot,controller);}}),{headers:{'content-type':'text/event-stream'}});
    }
    assert.equal(url,ENDPOINT);const sender=Number(options.headers['x-clientid'].at(-1)),token=accounts.get(sender).exportSession().token;
    const plain=wire.decryptBytes(options.body,token);let signal;
    try{signal=JSON.parse(plain.toString('utf8')).data;}finally{plain.fill(0);}
    calls.push(signal.type);let data={};
    if(signal.type==='callRequest'){
     data={callUUID,callData:{method:'audio',status:'not_answered',duration:0,participants}};
     const config={type:'config',callUUID,callData:{...data.callData,invitedParticipantUserID:42,
      stunServer:{url:'127.0.0.1:9'},turnServer:{url:'127.0.0.1:9',username:'fixture',password:'fixture'}}};
     queue(1,config,1);queue(2,config,1);
    }else queue(3-sender,signal,sender);
    return new Response(wire.encryptBytes(Buffer.from(JSON.stringify({status:'success',data})),token));
   }});
  assert.equal(result.ok,true,JSON.stringify({result,calls,readRequests:readRequests.length}));
  assert.equal(result.callRequestBound,true);assert.equal(result.cleanupPending,false);assert.equal(idleChecks,2);assert.equal(readRequests.length,10);
  assert.deepEqual(result.protectedSessions,[{authenticated:true,selfConfirmed:true},{authenticated:true,selfConfirmed:true}]);
  assert.equal(result.serverClockVerified,true);assert.equal(result.savedSessionsUnchanged,true);assert.equal(result.browserIdentitiesUnchanged,true);
  assert.equal(await vault.hasCleanupIntent('nasim',1),false);assert.equal(await vault.hasCleanupIntent('nasim',2),false);
  assert.equal(calls.filter(type=>type==='callRequest').length,1);assert.equal(calls.filter(type=>type==='bye').length,1);
  console.log(JSON.stringify({ok:true,officialBrowserAudio:true,syntheticService:true,realProviderRequests:0,
   encryptedCleanupConfirmed:true,actualSseParser:true,protectedSessions:result.protectedSessions,
   serverClockVerified:result.serverClockVerified,savedSessionsUnchanged:result.savedSessionsUnchanged,
   browserIdentitiesUnchanged:result.browserIdentitiesUnchanged,stats:result.stats,instrumentation:result.instrumentation}));
 }finally{
  vault.lock();
  const target=await fs.realpath(directory),temp=await fs.realpath(os.tmpdir());
  if(path.dirname(target)===temp)await fs.rm(target,{recursive:true,force:true,maxRetries:3,retryDelay:50});
 }
})().catch(error=>{console.error('Official browser pair fixture failed',error.name,error.reason||error.message);process.exitCode=1;});
