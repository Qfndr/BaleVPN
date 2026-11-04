'use strict';
const readline=require('node:readline/promises');
const {runEndpoint,runtimeDependencies,safeError}=require('./nasim-asymmetric-endpoint.cjs');
const fail=reason=>Object.assign(new Error(reason),{safeReason:reason});

function hiddenPassword(input,output,signals=process){
 if(!input.isTTY||typeof input.setRawMode!=='function')throw fail('invalid_input');
 return new Promise((resolve,reject)=>{
  const raw=input.isRaw,bytes=Buffer.alloc(4096);let used=0,done=false;
  const finish=(error,value)=>{
   if(done)return;done=true;clearTimeout(timer);input.removeListener('data',onData);input.removeListener('end',onEnd);
   signals.removeListener('SIGINT',onEnd);signals.removeListener('SIGTERM',onEnd);
   try{input.setRawMode(!!raw);}catch{}input.pause();bytes.fill(0);output.write('\n');
   if(error)reject(error);else resolve(value);
  };
  const onEnd=()=>finish(fail('invalid_input'));
  const onData=chunk=>{
   for(const byte of chunk){
    if(byte===3||byte===4){finish(fail('invalid_input'));return;}
    if(byte===13||byte===10){
     try{const value=new TextDecoder('utf-8',{fatal:true}).decode(bytes.subarray(0,used));finish(value?null:fail('invalid_input'),value);}
     catch{finish(fail('invalid_input'));}return;
    }
    if(byte===8||byte===127){if(used){const previous=used;used--;while(used>0&&(bytes[used]&0xc0)===0x80)used--;bytes.fill(0,used,previous);}continue;}
    if(byte<32)continue;
    if(used===bytes.length){finish(fail('invalid_input'));return;}bytes[used++]=byte;
   }
  };
  const timer=setTimeout(()=>finish(fail('input_timeout')),600000);
  output.write('Vault password (hidden): ');
  try{input.setRawMode(true);input.on('data',onData);input.once('end',onEnd);signals.once('SIGINT',onEnd);signals.once('SIGTERM',onEnd);input.resume();}
  catch{finish(fail('invalid_input'));}
 });
}
function command(line){
 if(line.length>16432)return null;
 const [name,certificate,...extra]=line.trim().split(/\s+/);
 if(name==='trust'&&!extra.length&&typeof certificate==='string'&&/^[a-f0-9]{128,16384}$/.test(certificate)&&certificate.length%2===0)
  return {command:'trust',publicCertificate:certificate};
 if(['dial','accept','state','end'].includes(name)&&certificate===undefined)return {command:name};
 return null;
}
function show(value){
 if(value.event==='prepared'){
  process.stdout.write('Public pairing certificate\n'+value.publicCertificate+'\n');
  process.stdout.write('Exchange certificates, then use trust <certificate>. Client uses dial, server uses state then accept.\n');
 }else if(value.event==='state'){
  process.stdout.write(`State ${value.phase} | route ${value.routeProof||'waiting'} | peer authenticated ${value.peerAuthenticated?'yes':'no'} | proxy ${value.proxyReady?'ready':'waiting'}\n`);
 }else if(value.event==='closed'){
  process.stdout.write(`Closed | end completed ${value.endCompleted?'yes':'no'} | cleanup pending ${value.cleanupPending?'yes':'no'}\n`);
 }
}

async function main(){
 if(process.argv[2]==='--self-test')return selfTest();
 const [role,vaultDirectory,slotText]=process.argv.slice(2);
 if(process.argv.length!==5||!['client','server'].includes(role)||!['1','2'].includes(slotText)||
    Number(process.versions.node.split('.')[0])<22)throw fail('invalid_invocation');
 const dependencies=runtimeDependencies();
 let password=await hiddenPassword(process.stdin,process.stderr);
 const terminal=readline.createInterface({input:process.stdin,output:process.stderr,terminal:true,historySize:0});
 const closed=new Promise(resolve=>terminal.once('close',()=>resolve(null)));
 const stop=()=>terminal.close();terminal.on('SIGINT',stop);process.once('SIGTERM',stop);
 const ask=async(message,deadline)=>{
  const signal=AbortSignal.timeout(Math.max(1,deadline-Date.now()));
  try{return await Promise.race([closed,terminal.question(message,{signal})]);}
  catch(error){if(signal.aborted)throw fail('input_timeout');throw error;}
 };
 try{
  const peerUserId=await ask('Other Nasim account ID: ',Date.now()+600000);
  if(peerUserId===null)throw fail('invalid_input');
  let start={command:'start',role,vaultDirectory,vaultPassword:password,slot:Number(slotText),peerUserId:peerUserId.trim()};
  password='';
  await runEndpoint(async deadline=>{
   if(start){const value=start;start=null;return value;}
   for(;;){
    const line=await ask('Nasim> ',deadline);if(line===null)return null;
    const request=command(line);if(request)return request;
    process.stderr.write('Commands: trust <certificate>, dial, accept, state, end\n');
   }
  },show,dependencies);
 }finally{password='';terminal.close();process.removeListener('SIGTERM',stop);}
}

async function selfTest(){
 const assert=require('node:assert/strict'),{EventEmitter}=require('node:events');
 const input=new EventEmitter();input.isTTY=true;input.isRaw=false;
 input.setRawMode=value=>{input.isRaw=value;};input.pause=()=>{};input.resume=()=>queueMicrotask(()=>input.emit('data',Buffer.from('fixture-secret\r')));
 let output='';assert.equal(await hiddenPassword(input,{write:chunk=>{output+=chunk;}}),'fixture-secret');
 assert.equal(input.isRaw,false);assert.ok(!output.includes('fixture-secret'));
 for(const signal of ['SIGINT','SIGTERM']){
  const bus=new EventEmitter();input.resume=()=>queueMicrotask(()=>bus.emit(signal));
  await assert.rejects(hiddenPassword(input,{write:()=>{}},bus));assert.equal(input.isRaw,false);assert.equal(bus.listenerCount(signal),0);
 }
 assert.equal(command('trust '+'aa'.repeat(80)).command,'trust');assert.equal(command('trust no'),null);
 assert.deepEqual(command('accept'),{command:'accept'});assert.equal(command('dial other'),null);
 process.stdout.write('{"event":"selfTest","passed":true,"networkRequests":0,"liveCalls":0}\n');
}

main().catch(error=>{process.stderr.write('Nasim endpoint stopped ('+safeError(error)+')\n');process.exitCode=1;});
