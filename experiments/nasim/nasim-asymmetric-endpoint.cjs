'use strict';
// Private, one-call Nasim endpoint. Both ends must be controlled by the same
// operator. Secrets enter through local stdin, never args, env, logs or stdout.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const fail=reason=>Object.assign(new Error(reason),{safeReason:reason});
const allowed=new Set(['invalid_input','input_timeout','invalid_invocation','helper_hash_mismatch',
 'vault_unavailable','cleanup_pending','session_binding_changed','clock_unverified','invalid_command','call_already_attempted']);
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
  let timer;try{
   const result=await Promise.race([lines.next(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(fail('input_timeout')),Math.max(0,Math.min(deadline,limit)-Date.now()));})]);
   return result.done?null:result.value;
  }finally{clearTimeout(timer);}
 };
}
function validateStart(value){
 if(!exact(value,['command','role','vaultDirectory','vaultPassword','slot','peerUserId','socksPort'])||value.command!=='start'||
  !['client','server'].includes(value.role)||![1,2].includes(value.slot)||typeof value.vaultDirectory!=='string'||!path.isAbsolute(value.vaultDirectory)||
  typeof value.vaultPassword!=='string'||!value.vaultPassword||value.vaultPassword.length>1024||typeof value.peerUserId!=='string'||
  !/^[1-9]\d{0,15}$/.test(value.peerUserId)||BigInt(value.peerUserId)>BigInt(Number.MAX_SAFE_INTEGER))throw fail('invalid_input');
 const port=value.role==='server'?0:value.socksPort??1098;
 if(!Number.isInteger(port)||port<0||port>65535||value.role==='client'&&port<1024)throw fail('invalid_input');
 return {...value,socksPort:port};
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
 if(['bye','reject','busy','other_device','media_failure'].includes(signal))return signal;
 return ['call_connection_changed','cleanup_save_failed','call_timeout','transport_closed'].includes(call.reason)?call.reason:null;
}
function safeState(controller,role){
 const call=controller.state,media=call.media;
 return {event:'state',phase:call.phase,busy:call.busy===true,localAccepted:call.localAccepted===true,remoteAccepted:call.remoteAccepted===true,
  configured:call.signaling?.configured===true,negotiated:call.signaling?.negotiated===true,
  routeProof:[proof,'unverified'].includes(media?.routeProof)?media.routeProof:null,
  peerAuthenticated:media?.peerAuthenticated===true,proxyReady:media?.proxyReady===true,
  cleanupPending:call.cleanup?.pending===true,metrics:safeMetrics(call,role),termination:safeTermination(call)};
}

async function runEndpoint(read,write,dependencies){
 const prepDeadline=Date.now()+600000;
 let callDeadline=Infinity;
 const raw=await read(prepDeadline),start=validateStart(raw);raw.vaultPassword='';
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
  write({event:'prepared',role:start.role,publicCertificate:prepared.publicCertificate});
  for(;;){
   const command=await read(attempted?callDeadline:prepDeadline);if(command===null)break;
   if(!exact(command,['command','publicCertificate']))throw fail('invalid_command');
   switch(command.command){
    case 'trust':
     if(typeof command.publicCertificate!=='string')throw fail('invalid_command');
     controller.trustCertificate(command.publicCertificate);break;
    case 'dial':
     if(start.role!=='client'||command.publicCertificate!==undefined)throw fail('invalid_command');
     if(attempted)throw fail('call_already_attempted');attempted=true;callDeadline=Date.now()+90000;
     await controller.dial(start.peerUserId);break;
    case 'accept':
     if(start.role!=='server'||command.publicCertificate!==undefined)throw fail('invalid_command');
     if(attempted)throw fail('call_already_attempted');attempted=true;callDeadline=Date.now()+90000;
     await controller.accept();break;
    case 'state':if(command.publicCertificate!==undefined)throw fail('invalid_command');break;
    case 'end':if(command.publicCertificate!==undefined)throw fail('invalid_command');ended=true;break;
    default:throw fail('invalid_command');
   }
   if(ended)break;
   write(safeState(controller,start.role));
  }
 }finally{
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
  write({event:'closed',endCompleted,cleanupAcknowledged,cleanupPending:pending});
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
 if(process.argv.includes('--self-test'))return selfTest();
 if(process.argv.length!==3||process.argv[2]!=='--run-once')throw fail('invalid_invocation');
 const dependencies=runtimeDependencies();
 const stop=()=>process.stdin.destroy();process.once('SIGINT',stop);process.once('SIGTERM',stop);
 try{await runEndpoint(boundedReader(process.stdin,690000),emit,dependencies);}
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
 assert.equal(safeTermination({phase:'ended',terminal:{signal:'busy',peerId:'fixture-private-id'}}),'busy');
 assert.equal(safeTermination({phase:'ended',reason:'fixture-private-id'}),null);
 emit({event:'selfTest',passed:true,networkRequests:0,liveCalls:0});
}

const safeError=error=>allowed.has(error.safeReason)?error.safeReason:'endpoint_failed';
if(require.main===module)main().catch(error=>{emit({event:'error',reason:safeError(error)});process.exitCode=1;});
module.exports={runEndpoint,runtimeDependencies,safeError};
