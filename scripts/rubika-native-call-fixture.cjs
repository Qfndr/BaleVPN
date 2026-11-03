// Real normal helpers/media and account-bound call lifecycle. Only accounts,
// provider discovery/RPC and call notifications use the offline broker fixture.
'use strict';
const {AccountMedia}=require('../experiments/rubika/account-media.cjs'),{pair}=require('./rubika-account-media-fixture.cjs');
const profile={libraryVersion:'6.0.0',protocolLayer:92};
let a,b,controllers,connected=false,buffer=Buffer.alloc(0);
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const output=value=>new Promise((resolve,reject)=>process.stdout.write(JSON.stringify(value)+'\n',e=>e?reject(Error('output_closed')):resolve()));
async function close(){a?.close();b?.close();controllers?.close();}
async function connect(port){
 if(connected||!Number.isInteger(port)||port<1024||port>65535)throw Error('invalid_command');connected=true;
 controllers=await pair({connections:[{type:'WebRTC',ip:'127.0.0.1',port,turn_username:'fixture',turn_password:'local-fixture-password'}]});
 a=new AccountMedia(controllers.a,{...profile,executable:process.env.BALEVPN_RUBIKA_BRIDGE,role:'client',socksPort:0});
 b=new AccountMedia(controllers.b,{...profile,executable:process.env.BALEVPN_RUBIKA_BRIDGE,role:'server',socksPort:0});
 const [ac,bc]=await Promise.all([a.prepare(),b.prepare()]);a.trustCertificate(bc.publicCertificate);b.trustCertificate(ac.publicCertificate);
 await controllers.negotiate();await b.attachAccepted();await a.attachAccepted();
 const deadline=Date.now()+12000;
 while(Date.now()<deadline){
  await b.pollOnce();await a.pollOnce();if(a.state.ready&&b.state.ready)break;
  if([a.state.phase,b.state.phase].includes('failed'))throw Error('native_media_failed');await sleep(30);
 }
 if(!a.state.ready||!b.state.ready||controllers.started.some(n=>n!==1))throw Error('media_not_ready');
 await output({event:'connected',client:a.state,server:b.state});
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
