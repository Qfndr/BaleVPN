// Opt-in anonymous read-only discovery. Never calls sendCode/signIn/registerDevice.
const {HttpClient}=require('../experiments/rubika/http-client.cjs');
(async()=>{
 if(process.argv.slice(2).some(a=>a!=='--connect'))throw Error('Only --connect is supported');
 if(!process.argv.includes('--connect')){console.log(JSON.stringify({provider:'rubika',connected:false,method:'getDCs',otpSubmitted:false}));return;}
 let requests=0;const client=new HttpClient({fetchImpl:async(url,options)=>{requests++;return fetch(url,options);}});
 try{const result=await client.discover();console.log(JSON.stringify({provider:'rubika',anonymousDiscovery:result.apiServerSelected,requests,otpSubmitted:false,loginTested:false,liveCallTested:false,billingVerified:false}));}
 catch(e){console.log(JSON.stringify({provider:'rubika',anonymousDiscovery:false,requests,reason:e.reason||'probe_failed',statusCode:e.statusCode,otpSubmitted:false,loginTested:false}));process.exitCode=1;}
 finally{client.close();}
})().catch(()=>{console.error('Invalid probe arguments');process.exitCode=2;});
