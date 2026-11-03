// Real local media/helpers with synthetic accepted-call context and private
// legacy signaling only. No provider APIs, auth sessions or external server.
'use strict';
const crypto=require('node:crypto'),{CallMedia}=require('../experiments/rubika/call-media.cjs'),{LegacySignalCipher}=require('../experiments/rubika/legacy-signal-cipher.cjs');
const {validateSignal}=require('../experiments/rubika/media-description.cjs');
const profile={libraryVersion:'6.0.0',protocolLayer:92},key=crypto.randomBytes(256),leftCipher=new LegacySignalCipher({...profile,key,isOutgoing:true}),rightCipher=new LegacySignalCipher({...profile,key,isOutgoing:false});key.fill(0);
const queue=[];let a,b,connected=false,buffer=Buffer.alloc(0),count=0;
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const output=value=>new Promise((resolve,reject)=>process.stdout.write(JSON.stringify(value)+'\n',e=>e?reject(Error('output_closed')):resolve()));
async function close(){a?.close();b?.close();leftCipher.close();rightCipher.close();for(const item of queue)item.packet.fill(0);queue.length=0;}
function context(direction,selfId,peerId,port,sender,side){return {callId:'fixture_call_01',direction,selfId,peerId,
 connections:[{type:'WebRTC',ip:'127.0.0.1',port,turn_username:'fixture',turn_password:'local-fixture-password'}],
 send:async signal=>{validateSignal(signal);const bytes=Buffer.from(JSON.stringify(signal));try{queue.push({side,packet:sender.encryptRaw(bytes)});}finally{bytes.fill(0);}}};}
async function connect(port){
 if(connected||!Number.isInteger(port)||port<1024||port>65535)throw Error('invalid_command');connected=true;
 a=new CallMedia({...profile,executable:process.env.BALEVPN_RUBIKA_BRIDGE,role:'client',socksPort:0});b=new CallMedia({...profile,executable:process.env.BALEVPN_RUBIKA_BRIDGE,role:'server',socksPort:0});
 const [ac,bc]=await Promise.all([a.prepare(),b.prepare()]);a.trustCertificate(bc.publicCertificate);b.trustCertificate(ac.publicCertificate);
 const left=context('outgoing','fixture_self_01','fixture_peer_02',port,leftCipher,'right'),right=context('incoming','fixture_peer_02','fixture_self_01',port,rightCipher,'left');
 await b.onSecure(right);await a.onSecure(left);
 while(queue.length){if(++count>32)throw Error('fixture_limit');const item=queue.shift();let raw;
  try{raw=(item.side==='left'?leftCipher:rightCipher).decryptRaw(item.packet);const message=JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(raw));validateSignal(message);
   await(item.side==='left'?a:b).onSignal(message,item.side==='left'?left:right);
  }finally{raw?.fill(0);item.packet.fill(0);}
 }
 const deadline=Date.now()+12000;while((!a.state.ready||!b.state.ready)&&Date.now()<deadline){if([a.state.phase,b.state.phase].includes('failed'))throw Error('native_media_failed');await sleep(30);}
 if(!a.state.ready||!b.state.ready)throw Error('media_not_ready');await output({event:'connected',client:a.state,server:b.state});
}
(async()=>{
 if(process.argv.length!==2)throw Error('arguments_not_allowed');await output({event:'ready',fixture:true});
 for await(const chunk of process.stdin){
  if(buffer.length+chunk.length>192*1024)throw Error('invalid_command');buffer=Buffer.concat([buffer,chunk]);
  while(buffer.includes(10)){
   const at=buffer.indexOf(10),rest=Buffer.from(buffer.subarray(at+1));let value;try{value=JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(buffer.subarray(0,at)));}finally{buffer.fill(0);buffer=rest;}
   if(value?.command==='stop'&&Object.keys(value).length===1){await close();await output({event:'stopped'});return;}
   if(value?.command!=='connect'||Object.keys(value).some(k=>!['command','turnPort'].includes(k)))throw Error('invalid_command');await connect(value.turnPort);
  }
 }
})().catch(async()=>{await output({event:'error',reason:'fixture_failed',client:a?.state||null,server:b?.state||null}).catch(()=>{});process.exitCode=1;}).finally(async()=>{buffer.fill(0);await close();});
