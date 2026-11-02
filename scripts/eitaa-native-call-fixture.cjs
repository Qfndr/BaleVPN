// Opt-in private local integration driver. Real normal helper executables and
// real media; synthetic accounts/RPC only. No provider socket or OTP is used.
'use strict';
const {CallMedia}=require('../experiments/eitaa/call-media.cjs'),{NativeMediaBridge}=require('../experiments/eitaa/native-media-bridge.cjs');
const {pair}=require('./eitaa-call-session-fixture.cjs');
const helpers=[],cleanup=[];let a,b,connected=false,buffer=Buffer.alloc(0);
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function output(v){return new Promise((resolve,reject)=>process.stdout.write(JSON.stringify(v)+'\n',e=>e?reject(Error('output_failed')):resolve()));}
async function close(){for(const fn of cleanup)fn();a?.close();b?.close();for(const helper of helpers)helper.close();const deadline=Date.now()+5000;while(helpers.some(h=>!['closed','failed'].includes(h.state.phase))&&Date.now()<deadline)await sleep(20);if(helpers.some(h=>!['closed','failed'].includes(h.state.phase)))throw Error('helper_stop_failed');}
async function connect(port){
 if(connected||!Number.isInteger(port)||port<1024||port>65535)throw Error('invalid_command');connected=true;
 const open=async path=>{const bridge=await NativeMediaBridge.open(path);helpers.push(bridge);return bridge;};
 a=new CallMedia({executable:process.env.BALEVPN_EITAA_BRIDGE,role:'client',socksPort:0,open});b=new CallMedia({executable:process.env.BALEVPN_EITAA_BRIDGE,role:'server',socksPort:0,open});
 const [ac,bc]=await Promise.all([a.prepare(),b.prepare()]);if(ac.publicCertificate===bc.publicCertificate)throw Error('identity_reused');a.trustCertificate(bc.publicCertificate);b.trustCertificate(ac.publicCertificate);
 const controllers=await pair({after:fn=>cleanup.push(fn)},{connections:[{_:'phoneConnectionWebrtc',turn:true,id:1n,ip:'127.0.0.1',ipv6:'',port,username:'fixture',password:'local-fixture-password'}],onASecure:c=>a.onSecure(c),onBSecure:c=>b.onSecure(c),onASignal:(v,c)=>a.onSignal(v,c),onBSignal:(v,c)=>b.onSignal(v,c),onAEnd:()=>a.close(),onBEnd:()=>b.close()});
 await controllers.negotiate();await controllers.a.pollOnce();const deadline=Date.now()+12000;
 while((!a.state.ready||!b.state.ready)&&Date.now()<deadline){if([a.state.phase,b.state.phase].includes('failed'))throw Error('native_media_failed');await sleep(30);}
 if(!a.state.ready||!b.state.ready)throw Error('media_not_ready');await output({event:'connected',client:a.state,server:b.state});
}
(async()=>{
 if(process.argv.length!==2)throw Error('arguments_not_allowed');await output({event:'ready',fixture:true});
 for await(const chunk of process.stdin){
  if(buffer.length+chunk.length>192*1024)throw Error('invalid_command');buffer=Buffer.concat([buffer,chunk]);
  while(buffer.includes(10)){
   const at=buffer.indexOf(10),rest=Buffer.from(buffer.subarray(at+1));let value;try{value=JSON.parse(buffer.subarray(0,at).toString('utf8'));}finally{buffer.fill(0);buffer=rest;}
   if(value?.command==='stop'&&Object.keys(value).length===1){await close();await output({event:'stopped'});return;}
   if(value?.command!=='connect'||Object.keys(value).some(k=>!['command','turnPort'].includes(k)))throw Error('invalid_command');await connect(value.turnPort);
  }
 }
})().catch(async e=>{
 const diagnostic={event:'error',reason:'fixture_failed',componentReason:typeof e?.reason==='string'&&/^[a-z_]{1,64}$/.test(e.reason)?e.reason:null,client:a?.state||null,server:b?.state||null};
 if(process.env.BALEVPN_EITAA_FIXTURE_DIAGNOSTICS)require('node:fs').writeFileSync(process.env.BALEVPN_EITAA_FIXTURE_DIAGNOSTICS,JSON.stringify(diagnostic));
 await output(diagnostic).catch(()=>{});process.exitCode=1;
}).finally(async()=>{buffer.fill(0);await close().catch(()=>{});});
