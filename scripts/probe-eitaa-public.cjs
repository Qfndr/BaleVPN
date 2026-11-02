// Explicit anonymous HTTPS ping only; never sends a code, login or call request.
'use strict';
const {HttpClient}=require('../experiments/eitaa/http-client.cjs');
(async()=>{
 if(process.argv.slice(2).some(a=>a!=='--connect'))throw Error('Only --connect is supported');
 if(!process.argv.includes('--connect')){console.log(JSON.stringify({provider:'eitaa',connected:false,method:'ping',otpSubmitted:false}));return;}
 let requests=0;const client=new HttpClient({fetchImpl:async(url,options)=>{requests++;return fetch(url,options);}});
 try{const result=await client.ping();console.log(JSON.stringify({provider:'eitaa',anonymousPing:result.pong,elapsedMs:result.elapsedMs,requests,otpSubmitted:false,loginTested:false,liveCallTested:false,billingVerified:false}));}
 catch(e){console.log(JSON.stringify({provider:'eitaa',anonymousPing:false,requests,reason:e.reason||'probe_failed',statusCode:e.statusCode,otpSubmitted:false,loginTested:false}));process.exitCode=1;}
 finally{client.close();}
})().catch(()=>{console.error('Invalid probe arguments');process.exitCode=2;});
