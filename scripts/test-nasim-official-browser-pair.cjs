// Synthetic service responses exercise the pinned vendor call in two browsers.
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {setTimeout:delay}=require('node:timers/promises');
const {chromium}=require(process.env.BALEVPN_PLAYWRIGHT_MODULE||'playwright');
const {SessionVault}=require('../experiments/providers/session-vault.cjs');
const {CleanupIntent}=require('../experiments/nasim/cleanup-intent.cjs');
const {OfficialCallGate}=require('../experiments/nasim/official-call-gate.cjs');
const {OfficialCallTransport,ENDPOINT}=require('../experiments/nasim/official-call-transport.cjs');
const {OfficialMediaGuard}=require('../experiments/nasim/official-media-guard.cjs');
const {openOfficialBrowserPair}=require('../experiments/nasim/official-browser-pair.cjs');
const wire=require('../experiments/nasim/wire.cjs');
(async()=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'nasim-official-browser-fixture-'));
 const vault=new SessionVault(directory);let journal,transport,pair;
 const calls=[],errors=[];
 try{
  await vault.unlock('synthetic-official-browser-vault-password');journal=await vault.openNasimOfficialCallJournal();
  const accounts=new Map([1,2].map(slot=>[slot,{
   state:{provider:'nasim',signedIn:true,userId:String(40+slot),clientId:'client-'+slot},
   exportSession(){return {...this.state,token:'synthetic-official-browser-token-'+slot,deviceId:'web.synthetic-browser-'+slot};}
  }]));
  const cleanups=new Map([1,2].map(slot=>[slot,new CleanupIntent(accounts.get(slot),{
   saveIntent:value=>vault.saveCleanupIntent('nasim',slot,value),loadIntent:()=>vault.loadCleanupIntent('nasim',slot),
   clearIntent:value=>vault.removeCleanupIntent('nasim',slot,value)
  })]));
  const gate=new OfficialCallGate(accounts,cleanups,journal);
  // This synthetic-only policy permits the fixture's discard-port loopback
  // STUN/TURN URLs. The production policy rejects all private relay URLs.
  const candidatePolicy=new OfficialMediaGuard({approvedServers:['stun:1.1.1.1:3478','turn:1.1.1.1:3478']});
  const mediaGuard={resolverRules:'',capture:(...args)=>candidatePolicy.capture(...args),
   checkServers(servers){assert.deepEqual(servers.map(s=>s.urls),['stun:127.0.0.1:9','turn:127.0.0.1:9']);},
   async checkSignal(slot,signal){if(signal.type==='config')this.checkServers(signal.iceServers);else await candidatePolicy.checkSignal(slot,signal);}
  };
  const callUUID='synthetic-official-browser-call',participants=[{userID:41,nickname:'Fixture caller'},{userID:42,nickname:'Fixture callee'}];
  function queue(slot,signal,sender){
   const message={topic:`u/${40+slot}/${40+sender}`,type:'msgGroupCall',data:signal,
    from:{id:40+sender},senderClientID:'client-'+sender,time:Date.now()};
   setImmediate(()=>transport.incoming(slot,message).catch(error=>errors.push(error.reason||error.name)));
  }
  transport=new OfficialCallTransport({accounts,gate,journal,mediaGuard,deliver:(slot,message)=>pair.deliver(slot,message),
   fetchImpl:async(url,options)=>{
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
  pair=await openOfficialBrowserPair({chromium,executablePath:process.env.BALEVPN_BROWSER_EXECUTABLE,
   directory:process.env.BALEVPN_NASIM_OFFICIAL_DIRECTORY,accounts,transport,mediaGuard});
  await gate.begin();await pair.start(1);await transport.releaseEvents();
  let accepted=false;
  for(let i=0;i<40&&!accepted;i++){accepted=await pair.accept(2);if(!accepted)await delay(50);}
  assert.equal(accepted,true,'Fixture callee did not obtain a peer connection');
  let stats;
  for(let i=0;i<100;i++){
   stats=await Promise.all([pair.stats(1),pair.stats(2)]);
   if(stats.every(slot=>slot.some(pc=>pc.state==='connected'&&pc.audioSent>0&&pc.audioReceived>0)))break;
   await delay(100);
  }
  assert.ok(stats.every(slot=>slot.some(pc=>pc.state==='connected'&&pc.audioSent>0&&pc.audioReceived>0)),
   JSON.stringify({stats,calls,errors,diagnostics:pair.diagnostics()}));
  await pair.end(1);for(let i=0;i<40&&gate.state.pending;i++)await delay(50);
  assert.equal(gate.state.pending,false);assert.equal(await journal.load(),null);assert.deepEqual(errors,[]);
  assert.equal(calls.filter(type=>type==='callRequest').length,1);assert.equal(calls.filter(type=>type==='bye').length,1);
  console.log(JSON.stringify({ok:true,officialBrowserAudio:true,syntheticService:true,realProviderRequests:0,
   encryptedCleanupConfirmed:true,stats,instrumentation:pair.diagnostics()}));
 }finally{
  transport?.close();await pair?.close();await journal?.close();vault.lock();
  const target=await fs.realpath(directory),temp=await fs.realpath(os.tmpdir());
  if(path.dirname(target)===temp)await fs.rm(target,{recursive:true,force:true,maxRetries:3,retryDelay:50});
 }
})().catch(error=>{console.error('Official browser pair fixture failed',error.name,error.reason||error.message);process.exitCode=1;});
