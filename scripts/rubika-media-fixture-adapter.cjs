// Private offline SDP -> explicit 6.0.0 encrypted packets -> SDP fixture.
// No provider/account APIs or sockets. Used by the real local Rust media test.
'use strict';
const crypto=require('node:crypto'),{LegacySignalCipher}=require('../experiments/rubika/legacy-signal-cipher.cjs');
const {fromDescription,toDescription,validateSignal}=require('../experiments/rubika/media-description.cjs');
const key=crypto.randomBytes(256),profile={key,libraryVersion:'6.0.0',protocolLayer:92},a=new LegacySignalCipher({...profile,isOutgoing:true}),b=new LegacySignalCipher({...profile,isOutgoing:false});key.fill(0);
let buffer=Buffer.alloc(0),count=0;
const output=value=>new Promise((resolve,reject)=>process.stdout.write(JSON.stringify(value)+'\n',e=>e?reject(Error('output_closed')):resolve()));
function exchange(value,sender,receiver){
 validateSignal(value);const raw=Buffer.from(JSON.stringify(value)),packet=sender.encryptRaw(raw);let decoded;
 try{decoded=receiver.decryptRaw(packet);const value=JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(decoded));validateSignal(value);return value;}
 finally{raw.fill(0);packet.fill(0);decoded?.fill(0);}
}
(async()=>{
 if(process.argv.length!==2)throw Error('arguments_not_allowed');await output({event:'ready',fixture:true});
 for await(const chunk of process.stdin){
  if(buffer.length+chunk.length>192*1024)throw Error('invalid_input');buffer=Buffer.concat([buffer,chunk]);
  while(buffer.includes(10)){
   const at=buffer.indexOf(10),rest=Buffer.from(buffer.subarray(at+1));let command;
   try{command=JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(buffer.subarray(0,at)));}finally{buffer.fill(0);buffer=rest;}
   const expected=count===0?'offer':'answer';if(count>=2||!command||Object.keys(command).some(k=>!['command','description'].includes(k))||command.command!==expected||command.description?.type!==expected)throw Error('invalid_command');
   const converted=fromDescription(command.description),sender=count===0?a:b,receiver=count===0?b:a;
   const initial=exchange(converted.initialSetup,sender,receiver),candidates=converted.candidateMessages.map(v=>exchange(v,sender,receiver));
   await output({event:'description',description:toDescription(initial,candidates,{type:expected}),signalPackets:1+candidates.length});count++;
  }
  if(count===2)break;
 }
 if(count!==2)throw Error('incomplete_fixture');
})().catch(async()=>{await output({event:'error',reason:'fixture_failed'}).catch(()=>{});process.exitCode=1;}).finally(()=>{buffer.fill(0);a.close();b.close();});
