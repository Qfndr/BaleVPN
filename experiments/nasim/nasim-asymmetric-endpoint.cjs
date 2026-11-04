'use strict';
// Private, one-call Nasim endpoint. Both ends must be controlled by the same
// operator. Secrets enter through local stdin, never args, env, logs or stdout.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const fail=reason=>Object.assign(new Error(reason),{safeReason:reason});
const allowed=new Set(['invalid_input','input_timeout','invalid_invocation','helper_hash_mismatch',
 'vault_unavailable','cleanup_pending','session_binding_changed','clock_unverified','invalid_command','call_already_attempted']);
const defaultCallSeconds=90,callDurations=[90,300,900],prepBudgetMs=600000;
const proof='client-relay/server-public';
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).every(key=>keys.includes(key));
const emit=value=>process.stdout.write(JSON.stringify(value)+'\n');

async function* inputLines(input){
 let buffer=Buffer.alloc(0);
 try{
  for await(const chunk of input){
   let start=0;
   for(let at=0;at<chunk.length;at++)if(chunk[at]===10){
    if(buffer.length+at-start>65536)throw fail('invalid_input');
    const line=Buffer.concat([buffer,chunk.subarray(start,at)]);buffer.fill(0);buffer=Buffer.alloc(0);start=at+1;
    let value;try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(line));}catch{throw fail('invalid_input');}finally{line.fill(0);}
    yield value;
   }
   if(buffer.length+chunk.length-start>65536)throw fail('invalid_input');
   const next=Buffer.concat([buffer,chunk.subarray(start)]);buffer.fill(0);buffer=next;
  }
  if(buffer.length)throw fail('invalid_input');
 }finally{buffer.fill(0);}
}
function boundedReader(input,budgetMs){
 const lines=inputLines(input),deadline=Date.now()+budgetMs;
 return async(limit=deadline)=>{
  if(Date.now()>=Math.min(deadline,limit))throw fail('input_timeout');
  let timer;try{
   const result=await Promise.race([lines.next(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(fail('input_timeout')),Math.max(0,Math.min(deadline,limit)-Date.now()));})]);
   return result.done?null:result.value;
  }finally{clearTimeout(timer);}
 };
}
function validateStart(value){
 if(!exact(value,['command','role','vaultDirectory','vaultPassword','slot','peerUserId','socksPort','callLimitSeconds'])||value.command!=='start'||
  !['client','server'].includes(value.role)||![1,2].includes(value.slot)||typeof value.vaultDirectory!=='string'||!path.isAbsolute(value.vaultDirectory)||
  typeof value.vaultPassword!=='string'||!value.vaultPassword||value.vaultPassword.length>1024||typeof value.peerUserId!=='string'||
  !/^[1-9]\d{0,15}$/.test(value.peerUserId)||BigInt(value.peerUserId)>BigInt(Number.MAX_SAFE_INTEGER))throw fail('invalid_input');
 const port=value.role==='server'?0:value.socksPort??1098;
 if(!Number.isInteger(port)||port<0||port>65535||value.role==='client'&&port<1024)throw fail('invalid_input');
 const callLimitSeconds=value.callLimitSeconds===undefined?defaultCallSeconds:value.callLimitSeconds;
 if(!callDurations.includes(callLimitSeconds))throw fail('invalid_input');
 return {...value,socksPort:port,callLimitSeconds};
}
const counter=value=>Number.isSafeInteger(value)&&value>=0;
function safeMetrics(call,role){
 const media=call.media;
 if(call.phase!=='connected'||media?.mediaConnected!==true||media.routeProof!==proof||
    media.peerAuthenticated!==true||(role==='client'&&media.proxyReady!==true)||
    !counter(media.receivedBytes)||!counter(media.sentBytes))return undefined;
 const q=media.quic;
 const quic=role==='client'&&q&&Number.isFinite(q.rttMs)&&q.rttMs>=0&&q.rttMs<=120000&&
    counter(q.sentPackets)&&counter(q.lostPackets)&&q.lostPackets<=q.sentPackets
    ?{rttMs:q.rttMs,sentPackets:q.sentPackets,lostPackets:q.lostPackets}:null;
 return {receivedBytes:media.receivedBytes,sentBytes:media.sentBytes,quic};
}
function safeTermination(call){
 if(!['ended','uncertain','failed'].includes(call.phase))return null;
 const signal=call.terminal?.signal;
 if(['bye','reject','busy','other_device','media_failure','stream_reset'].includes(signal))return signal;
 return ['call_connection_changed','event_stream_not_connected','cleanup_save_failed','call_timeout','transport_closed'].includes(call.reason)?call.reason:null;
}
function safeState(controller,role){
 const call=controller.state,media=call.media;
 return {event:'state',phase:call.phase,busy:call.busy===true,localAccepted:call.localAccepted===true,remoteAccepted:call.remoteAccepted===true,
  configured:call.signaling?.configured===true,negotiated:call.signaling?.negotiated===true,
  routeProof:[proof,'unverified'].includes(media?.routeProof)?media.routeProof:null,
  peerAuthenticated:media?.peerAuthenticated===true,proxyReady:media?.proxyReady===true,
  cleanupPending:call.cleanup?.pending===true,metrics:safeMetrics(call,role),termination:safeTermination(call)};
}

const cleanupReasons=new Set([
 'vault_unavailable','unlock_failed','read_failed','invalid_file','invalid_cleanup_intent',
 'session_binding_changed','account_binding_changed','invalid_saved_session','login_account_mismatch',
 'not_authorized','not_authenticated','event_stream_not_connected','stream_connect_timeout',
 'stream_connect_failed','stream_ended','invalid_event_stream','invalid_stream_cursor',
 'cleanup_pending','cleanup_unconfirmed','cleanup_cancelled','call_rejected','invalid_call_response',
 'call_transport_failed','network_error','timeout'
]);
async function runCleanup(raw,dependencies){
 let password=raw.vaultPassword;raw.vaultPassword='';
 if(!exact(raw,['command','vaultDirectory','vaultPassword','slot'])||![1,2].includes(raw.slot)||
    typeof raw.vaultDirectory!=='string'||!path.isAbsolute(raw.vaultDirectory)||
    typeof password!=='string'||!password||password.length>1024)throw fail('invalid_input');
 let vault,session,timer,expired=false,completed=false,acknowledged=false,reason='cleanup_failed',phase='vault';
 try{
  vault=dependencies.vault(raw.vaultDirectory);
  try{await vault.unlock(password);}finally{password='';}
  phase='read';
  if(!await vault.hasCleanupIntent('nasim',raw.slot)){
   completed=true;
  }else{
   const record=await vault.load('nasim',raw.slot);
   if(!record||record.provider!=='nasim')throw fail('session_binding_changed');
   phase='restore';
   session=dependencies.session();
   // Reserve time for the receipt and vault lock before the parent IPC timeout.
   timer=setTimeout(()=>{expired=true;try{session.close();}catch{}},15000);
   await session.restore(record);
   if(expired||session.state.userId!==record.userId||session.state.clientId!==record.clientId)throw fail('session_binding_changed');
   const cleanup=dependencies.cleanup(session,vault,raw.slot);
   if(!await cleanup.restore()||expired)throw fail('cleanup_pending');
   phase='stream';
   const stream=await session.connectSignals();
   if(expired||stream?.eventsConnected!==true)throw fail('event_stream_not_connected');
   phase='send';
   const result=await cleanup.cleanup();
   phase='receipt';
   acknowledged=result.serviceAcknowledged===true;
   completed=acknowledged&&!await vault.hasCleanupIntent('nasim',raw.slot);
   if(!completed)reason=acknowledged?'cleanup_pending':'cleanup_unconfirmed';
  }
 }catch(error){
  const code=error?.safeReason??error?.reason;
  if(cleanupReasons.has(code))reason=code;
 }finally{
  clearTimeout(timer);
  try{session?.close();}finally{vault?.lock();}
 }
 return {event:'closed',endCompleted:completed,cleanupAcknowledged:acknowledged,cleanupPending:!completed,
  ...completed?{}:{reason:expired?'timeout':reason,phase}};
}

async function runEndpoint(read,write,dependencies,now=Date.now){
 const prepDeadline=now()+prepBudgetMs;
 let callDeadline=Infinity,durationElapsed=false;
 const raw=await read(prepDeadline);
 if(raw?.command==='cleanup'){write(await runCleanup(raw,dependencies));return;}
 const start=validateStart(raw);raw.vaultPassword='';
 let session,controller,vault,cleanup,ended=false,attempted=false;
 try{
  vault=dependencies.vault(start.vaultDirectory);
  try{await vault.unlock(start.vaultPassword);}finally{start.vaultPassword='';}
  if(await vault.hasCleanupIntent('nasim',start.slot))throw fail('cleanup_pending');
  const record=await vault.load('nasim',start.slot);
  if(!record||record.provider!=='nasim'||record.userId===start.peerUserId)throw fail('session_binding_changed');
  session=dependencies.session();await session.restore(record);
  if(session.state.userId!==record.userId||session.state.clientId!==record.clientId)throw fail('session_binding_changed');
  cleanup=dependencies.cleanup(session,vault,start.slot);
  controller=dependencies.controller(session,cleanup);
  await session.connectSignals({onEvent:event=>controller.handleEvent(event)});
  if(session.state.events?.serverClockVerified!==true)throw fail('clock_unverified');
  controller.setAllowedPeers([start.peerUserId]);
  const prepared=await controller.prepare({role:start.role,socksPort:start.socksPort,throughput:false});
  write({event:'prepared',role:start.role,publicCertificate:prepared.publicCertificate,callLimitSeconds:start.callLimitSeconds});
  for(;;){
   const deadline=attempted?callDeadline:prepDeadline;
   let command;
   try{command=await read(deadline);}
   catch(error){
    if(!attempted||error.safeReason!=='input_timeout')throw error;
    if(now()>=deadline)durationElapsed=['dialing','outgoing','incoming','negotiating','connected'].includes(controller.state.phase);
    break;
   }
   if(command===null)break;
   if(attempted&&now()>=deadline){
    durationElapsed=['dialing','outgoing','incoming','negotiating','connected'].includes(controller.state.phase);
    break;
   }
   if(!exact(command,['command','publicCertificate']))throw fail('invalid_command');
   switch(command.command){
    case 'trust':
     if(typeof command.publicCertificate!=='string')throw fail('invalid_command');
     controller.trustCertificate(command.publicCertificate);break;
    case 'dial':
     if(start.role!=='client'||command.publicCertificate!==undefined)throw fail('invalid_command');
     if(attempted)throw fail('call_already_attempted');attempted=true;callDeadline=now()+start.callLimitSeconds*1000;
     await controller.dial(start.peerUserId);break;
    case 'accept':
     if(start.role!=='server'||command.publicCertificate!==undefined)throw fail('invalid_command');
     if(attempted)throw fail('call_already_attempted');attempted=true;callDeadline=now()+start.callLimitSeconds*1000;
     await controller.accept();break;
    case 'state':if(command.publicCertificate!==undefined)throw fail('invalid_command');break;
    case 'end':if(command.publicCertificate!==undefined)throw fail('invalid_command');ended=true;break;
    default:throw fail('invalid_command');
   }
   if(ended)break;
   write(safeState(controller,start.role));
  }
 }finally{
  const call=controller?.state;
  const peerEnded=attempted&&call?.phase==='ended'&&call.terminal?.signal==='bye'&&call.terminal.actor==='peer';
  const termination=durationElapsed?'call_duration_elapsed':peerEnded?'bye':null;
  start.vaultPassword='';let endCompleted=false,cleanupAcknowledged=false,pending=true;
  if(controller){try{await controller.end();endCompleted=true;}catch{}
   // A matching durable intent is the only fallback; no retry after an
   // uncertain end and no generic hangup against another call.
   if(endCompleted&&vault)try{if(await vault.hasCleanupIntent('nasim',start.slot)){
    cleanupAcknowledged=(await controller.cleanupPending()).serviceAcknowledged===true;
   }}catch{}
  }
  if(vault)try{pending=await vault.hasCleanupIntent('nasim',start.slot);}catch{}
  try{controller?.reset();}catch{}try{session?.close();}catch{}try{vault?.lock();}catch{}
  write({event:'closed',endCompleted,cleanupAcknowledged,cleanupPending:pending,...termination?{termination}:{}});
  if(pending||controller&&!endCompleted)process.exitCode=1;
 }
}

function runtimeDependencies(){
 const repo=process.env.BALEVPN_NASIM_REPO,executable=process.env.BALEVPN_NASIM_BRIDGE,expected=process.env.BALEVPN_EXPECTED_NASIM_HELPER_SHA256;
 if(!repo||!path.isAbsolute(repo)||!executable||!path.isAbsolute(executable)||! /^[a-f0-9]{64}$/.test(expected||''))throw fail('invalid_invocation');
 if(crypto.createHash('sha256').update(fs.readFileSync(executable)).digest('hex')!==expected)throw fail('helper_hash_mismatch');
 const {SessionVault}=require(path.join(repo,'experiments/providers/session-vault.cjs'));
 const {AuthSession}=require(path.join(repo,'experiments/nasim/auth-session.cjs'));
 const {CleanupIntent}=require(path.join(repo,'experiments/nasim/cleanup-intent.cjs'));
 const {CallSession}=require(path.join(repo,'experiments/nasim/call-session.cjs'));
 const {createBridge}=require(path.join(repo,'experiments/providers/relay-media-bridge.cjs'));
 const {NativeMediaBridge}=createBridge('nasim',{nasimAsymmetric:true});
 return {
  vault:directory=>{if(!fs.existsSync(path.join(directory,'vault.json')))throw fail('vault_unavailable');return new SessionVault(directory);},
  session:()=>new AuthSession(),
  controller:(account,cleanup)=>new CallSession(account,{executable,open:NativeMediaBridge.open,cleanup}),
  cleanup:(account,vault,slot)=>new CleanupIntent(account,{
   loadIntent:()=>vault.loadCleanupIntent('nasim',slot),
   saveIntent:async(record,guard)=>{guard();await vault.saveCleanupIntent('nasim',slot,record);guard();},
   clearIntent:async(record,guard)=>{guard();await vault.removeCleanupIntent('nasim',slot,record);guard();},
  }),
 };
}

async function main(){
 if(process.argv.length===3&&process.argv[2]==='--capabilities'){emit({callDurations,cleanupOnly:true});return;}
 if(process.argv.includes('--self-test'))return selfTest();
 if(process.argv.length!==3||process.argv[2]!=='--run-once')throw fail('invalid_invocation');
 const dependencies=runtimeDependencies();
 const stop=()=>process.stdin.destroy();process.once('SIGINT',stop);process.once('SIGTERM',stop);
 try{await runEndpoint(boundedReader(process.stdin,prepBudgetMs+Math.max(...callDurations)*1000),emit,dependencies);}
 finally{process.removeListener('SIGINT',stop);process.removeListener('SIGTERM',stop);process.stdin.destroy();}
}

async function selfTest(){
 const assert=require('node:assert/strict'),{Readable}=require('node:stream');
 const root=path.resolve('fixture-vault'),outputs=[],ops=[];
 const start={command:'start',role:'client',vaultDirectory:root,vaultPassword:'fixture-pass',slot:1,peerUserId:'42'};
 const read=boundedReader(Readable.from([Buffer.from('{"command":"state"}\n')]),1000);assert.deepEqual(await read(),{command:'state'});assert.equal(await read(),null);
 assert.throws(()=>validateStart({...start,serverEndpoint:'invalid'}));
 const commands=[start,{command:'trust',publicCertificate:'bb'.repeat(80)},{command:'dial'},{command:'state'},{command:'end'}];
 const record={provider:'nasim',userId:'41',clientId:'fixture-client'},session={state:{...record,events:{serverClockVerified:true}},restore:async()=>{},connectSignals:async()=>{},close:()=>ops.push('session-close')};
 const vault={unlock:async()=>{},hasCleanupIntent:async()=>false,load:async()=>record,lock:()=>ops.push('vault-lock')};
 const controller={state:{phase:'ready',callUUID:'fixture-private-id'},setAllowedPeers:()=>{},prepare:async()=>({publicCertificate:'aa'.repeat(80)}),
  trustCertificate:()=>ops.push('trust'),dial:async()=>ops.push('dial'),end:async()=>ops.push('end'),reset:()=>ops.push('reset')};
 const deps={vault:()=>vault,session:()=>session,cleanup:()=>({}),controller:()=>controller};
 await runEndpoint(async()=>commands.shift()??null,v=>outputs.push(v),deps);
 assert.deepEqual(ops,['trust','dial','end','reset','session-close','vault-lock']);
 assert.ok(!JSON.stringify(outputs).includes('fixture-pass'));assert.ok(!JSON.stringify(outputs).includes('fixture-private-id'));
 assert.equal(outputs.at(-1).cleanupPending,false);
 const blocked=[{...start,vaultPassword:'fixture-pass'},{command:'dial'},{command:'dial'}];
 await assert.rejects(runEndpoint(async()=>blocked.shift()??null,()=>{},deps),e=>e.safeReason==='call_already_attempted');
 for(const [option,seconds] of [[undefined,90],[300,300],[900,900]]){
  const input=[{...start,vaultPassword:'fixture-pass',...option===undefined?{}:{callLimitSeconds:option}},
   {command:'dial'},{command:'state'}],deadlines=[],records=[];
  let now=1000;const before=ops.length;controller.state.phase='connected';
  await runEndpoint(async limit=>{
   deadlines.push(limit);
   if(input.length)return input.shift();
   now=limit;
   throw fail('input_timeout');
  },record=>records.push(record),deps,()=>now);
  assert.deepEqual(deadlines,[601000,601000,1000+seconds*1000,1000+seconds*1000]);
  assert.equal(records[0].callLimitSeconds,seconds);
  assert.deepEqual(ops.slice(before),['dial','end','reset','session-close','vault-lock']);
  assert.deepEqual(records.at(-1),{event:'closed',endCompleted:true,cleanupAcknowledged:false,cleanupPending:false,termination:'call_duration_elapsed'});
 }
 for(const [phase,actor,closedInput,termination] of [
  ['ended',undefined,false,undefined],['ended','peer',false,'bye'],
  ['ended','local',false,undefined],['uncertain','peer',false,undefined],
  ['connected',undefined,true,undefined],
 ]){
  controller.state.phase=phase;
  controller.state.terminal=actor?{signal:'bye',actor}:null;
  const input=[{...start,vaultPassword:'fixture-pass'},{command:'dial'}],records=[];
  let now=1000;
  await runEndpoint(async limit=>{
   if(input.length)return input.shift();
   now=limit;
   if(closedInput)return null;
   throw fail('input_timeout');
  },record=>records.push(record),deps,()=>now);
  assert.equal(records.at(-1).termination,termination);
 }
 for(const invalid of [null,0,299,901,'300'])assert.throws(()=>validateStart({...start,vaultPassword:'fixture-pass',callLimitSeconds:invalid}));
 const cleanupModule=path.join(__dirname,'cleanup-intent.cjs');
 const {CleanupIntent}=require(fs.existsSync(cleanupModule)?cleanupModule:path.join(__dirname,'source/experiments/nasim/cleanup-intent.cjs'));
 const cleanupRecord={...record,signedIn:true,token:'fixture-private-auth-token'};
 const cleanupCommand={command:'cleanup',vaultDirectory:root,vaultPassword:'fixture-pass',slot:1};
 let saved=null,confirmed=true,connections=0,locks=0,closes=0,restoreFault=null;
 const sent=[];
 const rpc={async send(signal,{peerId}){
  sent.push({signal,peerId});
  return {acknowledged:true,terminalAcknowledgement:{type:'bye',callUUID:confirmed?signal.callUUID:'other-call',peerId}};
 }};
 const cleanupSession={state:cleanupRecord,signalConnection:rpc,exportSession:()=>cleanupRecord,restore:async()=>{if(restoreFault)throw restoreFault;},
  connectSignals:async()=>{connections++;return {eventsConnected:true};},close:()=>{closes++;}};
 const storage={loadIntent:async()=>saved,saveIntent:async(value,guard)=>{guard();saved=value;},
  clearIntent:async(_,guard)=>{guard();saved=null;}};
 const cleanupDeps={vault:()=>({unlock:async()=>{},hasCleanupIntent:async()=>Boolean(saved),load:async()=>cleanupRecord,lock:()=>{locks++;}}),
  session:()=>cleanupSession,cleanup:session=>new CleanupIntent(session,storage),
  controller:()=>{throw Error('cleanup_must_not_open_media');}};
 const cleanupRun=async(extra={})=>{
  const input={...cleanupCommand,...extra},results=[];
  let reads=0;
  await runEndpoint(async()=>{assert.equal(++reads,1);return input;},value=>results.push(value),cleanupDeps);
  assert.equal(input.vaultPassword,'');
  assert.equal(results.length,1);
  assert.ok(!JSON.stringify(results).includes('fixture-private'));
  return results[0];
 };
 assert.deepEqual(await cleanupRun(),{event:'closed',endCompleted:true,cleanupAcknowledged:false,cleanupPending:false});
 assert.equal(connections,0);
 const seed=new CleanupIntent(cleanupSession,storage);
 await seed.capture({peerId:'42',callUUID:'fixture-private-call'});
 const original=saved;
 cleanupRecord.token='fixture-different-token';
 assert.deepEqual(await cleanupRun(),{event:'closed',endCompleted:false,cleanupAcknowledged:false,cleanupPending:true,reason:'account_binding_changed',phase:'restore'});
 assert.deepEqual(saved,original);assert.equal(connections,0);assert.equal(sent.length,0);
 cleanupRecord.token='fixture-private-auth-token';
 restoreFault=Object.assign(Error('fixture-private-error'),{reason:'fixture-private-code'});
 assert.deepEqual(await cleanupRun(),{event:'closed',endCompleted:false,cleanupAcknowledged:false,cleanupPending:true,reason:'cleanup_failed',phase:'restore'});
 assert.deepEqual(saved,original);assert.equal(connections,0);assert.equal(sent.length,0);
 restoreFault=null;confirmed=false;
 assert.deepEqual(await cleanupRun(),{event:'closed',endCompleted:false,cleanupAcknowledged:false,cleanupPending:true,reason:'cleanup_unconfirmed',phase:'send'});
 assert.deepEqual(saved,original);
 confirmed=true;
 assert.deepEqual(await cleanupRun(),{event:'closed',endCompleted:true,cleanupAcknowledged:true,cleanupPending:false});
 assert.equal(saved,null);assert.equal(connections,2);assert.equal(closes,4);assert.equal(locks,5);
 assert.deepEqual(sent,Array(2).fill({signal:{type:'bye',callUUID:'fixture-private-call',callData:null},peerId:'42'}));
 await assert.rejects(cleanupRun({peerUserId:'42'}),error=>error.safeReason==='invalid_input');
 const connected={phase:'connected',media:{mediaConnected:true,routeProof:proof,peerAuthenticated:true,proxyReady:true,
  receivedBytes:1024,sentBytes:512,quic:{rttMs:25,sentPackets:10,lostPackets:1,private:'fixture-secret'}}};
 const totals={receivedBytes:1024,sentBytes:512};
 assert.deepEqual(safeMetrics(connected,'client'),{...totals,quic:{rttMs:25,sentPackets:10,lostPackets:1}});
 assert.deepEqual(safeMetrics(connected,'server'),{...totals,quic:null});
 connected.media.quic.lostPackets=11;
 assert.deepEqual(safeMetrics(connected,'client'),{...totals,quic:null});
 connected.media.routeProof='unverified';
 assert.equal(safeMetrics(connected,'client'),undefined);
 assert.equal(safeTermination({phase:'uncertain',reason:'call_timeout'}),'call_timeout');
 assert.equal(safeTermination({phase:'uncertain',reason:'event_stream_not_connected'}),'event_stream_not_connected');
 assert.equal(safeTermination({phase:'connected',reason:'event_stream_not_connected'}),null);
 assert.equal(safeTermination({phase:'uncertain',reason:'call_stream_reset',terminal:{signal:'stream_reset'}}),'stream_reset');
 assert.equal(safeTermination({phase:'ended',terminal:{signal:'busy',peerId:'fixture-private-id'}}),'busy');
 assert.equal(safeTermination({phase:'ended',reason:'fixture-private-id'}),null);
 emit({event:'selfTest',passed:true,networkRequests:0,liveCalls:0});
}

const safeError=error=>allowed.has(error.safeReason)?error.safeReason:'endpoint_failed';
if(require.main===module)main().catch(error=>{emit({event:'error',reason:safeError(error)});process.exitCode=1;});
module.exports={runEndpoint,runtimeDependencies,safeError};
