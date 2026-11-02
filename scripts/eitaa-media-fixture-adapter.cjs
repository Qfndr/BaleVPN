// Private fixture subprocess: native SDP -> encrypted Eitaa-shaped messages ->
// native SDP. No provider APIs, credentials, network sockets or public state.
'use strict';
const {pair}=require('./eitaa-call-session-fixture.cjs');
const {fromDescription,toDescription}=require('../experiments/eitaa/media-description.cjs');
const MAX=192*1024;
function output(value){return new Promise((resolve,reject)=>process.stdout.write(JSON.stringify(value)+'\n',e=>e?reject(Error('output_closed')):resolve()));}
(async()=>{
 if(process.argv.length!==2)throw Error('arguments_not_allowed');
 const cleanup=[];let buffer=Buffer.alloc(0),count=0;
 try{
  const controllers=await pair({after:fn=>cleanup.push(fn)});await controllers.negotiate();
  if(!controllers.a.state.keyNegotiated||!controllers.b.state.keyNegotiated)throw Error('fixture_failed');await output({event:'ready',fixture:true});
  for await(const chunk of process.stdin){
   if(buffer.length+chunk.length>MAX)throw Error('invalid_input');buffer=Buffer.concat([buffer,chunk]);
   while(buffer.includes(10)){
    const at=buffer.indexOf(10),line=buffer.subarray(0,at),rest=Buffer.from(buffer.subarray(at+1));let command;try{command=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(line));}finally{buffer.fill(0);buffer=rest;}
    const expected=count===0?'offer':'answer';if(count>=2||!command||Object.keys(command).some(k=>!['command','description'].includes(k))||command.command!==expected||command.description?.type!==expected)throw Error('invalid_command');
    const converted=fromDescription(command.description),sender=count===0?controllers.a:controllers.b,receiver=count===0?controllers.b:controllers.a,signals=count===0?controllers.bSignals:controllers.aSignals;
    await sender.sendSignal(converted.initialSetup);for(const message of converted.candidateMessages)await sender.sendSignal(message);await receiver.pollOnce();
    const [initial,...candidates]=signals.splice(0);if(candidates.length!==converted.candidateMessages.length)throw Error('fixture_failed');
    const description=toDescription(initial,candidates,{type:expected});await output({event:'description',description,signalPackets:1+candidates.length});count++;
   }
   if(count===2)break;
  }
  if(count!==2)throw Error('incomplete_fixture');
 }finally{buffer.fill(0);for(const close of cleanup)close();}
})().catch(async e=>{await output({event:'error',reason:['invalid_input','invalid_command','incomplete_fixture'].includes(e.message)?e.message:e.reason||'fixture_failed'}).catch(()=>{});process.exitCode=1;});
