// Explicit private runner. No default account source, fetch, or Lab preflight.
'use strict';
const {setTimeout:delay}=require('node:timers/promises');
const crypto=require('node:crypto');
const path=require('node:path');
const {AuthSession}=require('./auth-session.cjs');
const {HttpClient}=require('./http-client.cjs');
const {CleanupIntent}=require('./cleanup-intent.cjs');
const {OfficialCallGate}=require('./official-call-gate.cjs');
const {OfficialCallTransport}=require('./official-call-transport.cjs');
const {openOfficialBrowserPair}=require('./official-browser-pair.cjs');
const {SignalingConnection,serverBase}=require('./signaling-connection.cjs');
const CLOCK='https://core.gap.im/utils/getTime.json',CURSOR='https://api.gaplication.com/groupList?page=reset';
const CONFIG='https://core.gaplication.com/message/get/config';
const STATUS='https://core.gaplication.com/mxb/user/status';
const fail=reason=>Object.assign(new Error('Official Nasim reference '+reason),{reason});
const SAFE=new Set(['not_authorized','invalid_event_stream','invalid_stream_server','stream_connect_timeout','stream_connect_failed',
 'cleanup_pending','cleanup_unconfirmed','official_call_owner_busy','account_binding_changed','reference_timeout','stream_reset',
 'media_timeout','accept_timeout','lab_not_idle','tls_verification_disabled','server_clock_unavailable','login_account_mismatch']);
function safe(error){return SAFE.has(error?.reason)?error.reason:'reference_failed';}
async function limited(action,ms){let timer;
 try{return await Promise.race([Promise.resolve().then(action),new Promise((_,reject)=>{timer=setTimeout(()=>reject(fail('reference_timeout')),ms);})]);}
 finally{clearTimeout(timer);}
}
function signalFetch(record,fetchImpl){
 let configRead=false,streamOpened=false;
 return async(url,options)=>{
  if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw fail('tls_verification_disabled');
  if(options.redirect!=='error')throw fail('request_denied');
  const headers=new Headers(options.headers),method=options.method;
  const identity=headers.get('token')===record.token&&headers.get('clientid')===record.clientId&&headers.get('duid')===record.deviceId;
  if(url===CLOCK&&method==='GET'&&!headers.has('token')&&!headers.has('x-token'))return fetchImpl(url,options);
  if(url===CURSOR&&method==='GET'&&headers.get('x-token')===record.token)return fetchImpl(url,options);
  if(url===STATUS&&method==='POST'&&identity)return fetchImpl(url,options);
  if(url===CONFIG&&method==='POST'&&identity&&options.body===undefined&&!configRead){
   const response=await fetchImpl(url,options);configRead=response.status===200;return response;
  }
  if(typeof url==='string'&&url.endsWith('/message/get')&&configRead&&!streamOpened&&method==='GET'&&identity&&
   /^\d{1,20}$/.test(headers.get('lastEventTime'))){
   const base=serverBase(url.slice(0,-'/message/get'.length));if(url!==base+'/message/get')throw fail('request_denied');
   streamOpened=true;return fetchImpl(url,options);
  }
  throw fail('request_denied');
 };
}
async function verifySession(record,fetchImpl){
 const verifier=new AuthSession({deviceId:record.deviceId,createClient:options=>new HttpClient({...options,fetchImpl:signalFetch(record,fetchImpl)})});
 try{return await verifier.restore(record);}finally{verifier.close();}
}
async function runOfficialReference({vault,accounts,chromium,executablePath,directory,mediaGuard,fetchImpl,checkIdle,
 callerSlot=1,mediaTimeoutMs=20000}={}){
 if(!vault?.unlocked||!accounts?.get(1)||!accounts.get(2)||!chromium?.launch||typeof directory!=='string'||!path.isAbsolute(directory)||
  !mediaGuard?.checkSignal||!mediaGuard?.checkServers||!mediaGuard?.capture||typeof fetchImpl!=='function'||typeof checkIdle!=='function'||
  ![1,2].includes(callerSlot)||!Number.isInteger(mediaTimeoutMs)||mediaTimeoutMs<1000||mediaTimeoutMs>30000)throw fail('invalid_options');
 if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw fail('tls_verification_disabled');
 if(await checkIdle()!==true)throw fail('lab_not_idle');
 const journal=await vault.openNasimOfficialCallJournal(),controller=new AbortController(),streams=[];
 const cleanups=new Map([1,2].map(slot=>[slot,new CleanupIntent(accounts.get(slot),{
  saveIntent:value=>vault.saveCleanupIntent('nasim',slot,value),loadIntent:()=>vault.loadCleanupIntent('nasim',slot),
  clearIntent:value=>vault.removeCleanupIntent('nasim',slot,value)
 })]));
 const gate=new OfficialCallGate(accounts,cleanups,journal);
 let pair,streamError=null,error=null,stats=null,started=false,requested=false,localCleanupFallback=false;
 let originalFingerprints=null,savedSessionsUnchanged=false,browserIdentitiesUnchanged=false,serverClockVerified=false;
 const protectedSessions=[];
 async function readStored(){
  return Promise.all([1,2].map(async slot=>{
   const stored=await vault.load('nasim',slot),active=accounts.get(slot).exportSession();
   if(!stored||['provider','userId','clientId','deviceId','token'].some(key=>stored[key]!==active[key]))throw fail('account_binding_changed');
   return stored;
  }));
 }
 const fingerprints=records=>records.map(record=>crypto.createHash('sha256').update(JSON.stringify(record)).digest('hex'));
 const assertStored=async()=>{
  const current=fingerprints(await readStored());
  if(current.some((value,index)=>value!==originalFingerprints[index]))throw fail('account_binding_changed');
 };
 const transport=new OfficialCallTransport({accounts,gate,journal,mediaGuard,fetchImpl,deliver:(slot,message)=>pair.deliver(slot,message)});
 const streamsReady=()=>{
  if(streamError)throw fail(streamError);
  if(streams.length!==2||streams.some(stream=>stream.state.phase!=='connected'))throw fail('invalid_event_stream');
  if(streams.some(stream=>!stream.state.serverClockVerified))throw fail('server_clock_unavailable');
  serverClockVerified=true;
 };
 try{
  const stored=await readStored();originalFingerprints=fingerprints(stored);
  if(await gate.restore()){
   // Recover evidence locally. An existing journal can never start a fresh call.
   const intent=await journal.load();if(intent.phase==='requested')await transport.recoverResponse(intent.callerSlot).catch(()=>false);
   return {ok:false,reason:'cleanup_pending',cleanupPending:true,phase:gate.state.phase,uuidKnown:gate.state.uuidKnown};
  }
  for(const cleanup of cleanups.values())await cleanup.ensureClear();
  protectedSessions.push(...await Promise.all(stored.map(record=>verifySession(record,fetchImpl))));
  pair=await openOfficialBrowserPair({chromium,executablePath,directory,accounts,transport,mediaGuard});
  await Promise.all([1,2].map(async slot=>{
   const record=accounts.get(slot).exportSession();
   const stream=await SignalingConnection.open(record,{fetchImpl:signalFetch(record,fetchImpl),signal:controller.signal,
    onEvent:event=>{if(event.type==='streamReset')streamError='stream_reset';},
    onCallMessage:message=>transport.incoming(slot,message).catch(reason=>{
     if(['call_uuid_mismatch','wrong_client','wrong_peer','candidate_denied','invalid_candidate'].includes(reason.reason))return;
     throw reason;
    })});
   streams.push(stream);
  }));
  streamsReady();if(await checkIdle()!==true)throw fail('lab_not_idle');await assertStored();
  await gate.begin(callerSlot);started=true;await limited(()=>pair.start(callerSlot),12000);requested=gate.state.uuidKnown;
  await transport.releaseEvents();
  const acceptDeadline=performance.now()+4000;
  while(true){
   streamsReady();if(await limited(()=>pair.accept(3-callerSlot),3000))break;
   if(performance.now()>=acceptDeadline)throw fail('accept_timeout');await delay(50);
  }
  const mediaDeadline=performance.now()+mediaTimeoutMs;
  do{
   streamsReady();stats=await limited(()=>Promise.all([pair.stats(1),pair.stats(2)]),3000);
   if(stats.every(slot=>slot.some(pc=>pc.state==='connected'&&pc.audioSent>0&&pc.audioReceived>0)))break;
   await delay(100);
  }while(performance.now()<mediaDeadline);
  if(!stats?.every(slot=>slot.some(pc=>pc.state==='connected'&&pc.audioSent>0&&pc.audioReceived>0)))throw fail('media_timeout');
 }catch(problem){error=safe(problem);}
 finally{
  try{
   if(started&&gate.state.phase==='prepared')await gate.abandonPrepared();
   else if(started&&gate.state.uuidKnown&&pair){
    requested=true;
    const ended=await limited(()=>pair.end(callerSlot),6000);
    if(!ended){localCleanupFallback=true;await transport.endKnownCall(callerSlot);}
    const endDeadline=performance.now()+5000;while(gate.state.pending&&performance.now()<endDeadline)await delay(50);
   }
  }catch(problem){error??=safe(problem);}
  if(pair)try{await limited(()=>pair.verifyBindings(),3000);browserIdentitiesUnchanged=true;}catch(problem){error??=safe(problem);}
  if(originalFingerprints)try{await assertStored();savedSessionsUnchanged=true;}catch(problem){error??=safe(problem);}
  controller.abort();for(const stream of streams)stream.close();transport.close();await pair?.close();await journal.close();
 }
 if(gate.state.pending)error??='cleanup_unconfirmed';
 return {ok:error===null,reason:error,callRequestBound:requested,cleanupPending:gate.state.pending,
  localCleanupFallback,stats,protectedSessions,serverClockVerified,savedSessionsUnchanged,browserIdentitiesUnchanged,
  instrumentation:pair?.diagnostics()??null};
}
module.exports={runOfficialReference};
