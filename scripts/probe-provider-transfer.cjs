'use strict';
// Explicit live integrity probe. No account credentials, SDP or private state.
const {spawn}=require('node:child_process'),crypto=require('node:crypto');
const MARKER='\nBALEVPN_PROBE_META=';
const FONT_URL='https://raw.githubusercontent.com/Qfndr/BaleVPN/082dda1c65e28c18038881646f201af47a81228a/bale-vpn-rust/bale-vpn/assets/fonts/InterVariable.woff2';
const FONT_HASH='693b77d4f32ee9b8bfc995589b5fad5e99adf2832738661f5402f9978429a8e3';
const UPLOAD=Buffer.from('BaleVPN-iGap-transfer-integrity-v1\n'.repeat(2048));
const hash=buffer=>crypto.createHash('sha256').update(buffer).digest('hex');
function fail(reason){throw Object.assign(new Error(reason),{reason});}
function decodeOutput(output,port){
 const at=output.lastIndexOf(Buffer.from(MARKER));if(at<0)fail('missing_transfer_metadata');
 const meta=output.subarray(at+Buffer.byteLength(MARKER)).toString('ascii').trim().split(':');
 if(meta.length!==6||!meta.every((v,i)=>i===1?/^[\d.]+$/.test(v):/^\d+(?:\.\d+)?$/.test(v)))fail('invalid_transfer_metadata');
 const [status,remote,remotePort,uploaded,downloaded,elapsed]=meta;
 if(status!=='200')fail('http_failed');if(remote!=='127.0.0.1'||Number(remotePort)!==port)fail('proxy_not_used');
 const body=output.subarray(0,at);if(Number(downloaded)!==body.length)fail('truncated_transfer');
 return {body,uploaded:Number(uploaded),downloaded:body.length,elapsedSeconds:Number(elapsed)};
}
async function request(port,url,upload){
 const args=['--disable','--proxy','socks5h://127.0.0.1:'+port,'--noproxy','','--max-time','30','--connect-timeout','10','--fail','--silent','--show-error'];
 if(upload)args.push('--header','Content-Type: text/plain','--data-binary','@-');
 args.push('--write-out',MARKER+'%{http_code}:%{remote_ip}:%{remote_port}:%{size_upload}:%{size_download}:%{time_total}\n',url);
 return new Promise((resolve,reject)=>{
  const env={...process.env};delete env.SSLKEYLOGFILE;
  const child=spawn(process.platform==='win32'?'curl.exe':'curl',args,{windowsHide:true,shell:false,env,stdio:['pipe','pipe','pipe']});
  const chunks=[];let size=0,done=false;const finish=(error,result)=>{if(done)return;done=true;clearTimeout(timer);if(error){child.kill();reject(error);}else resolve(result);};
  const timer=setTimeout(()=>finish(new Error('transfer_timeout')),35000);
  child.stdout.on('data',chunk=>{size+=chunk.length;if(size>1024*1024)return finish(new Error('response_too_large'));chunks.push(chunk);});
  child.stderr.on('data',()=>{}); // curl diagnostics can contain remote details.
  child.on('error',()=>finish(new Error('curl_unavailable')));child.stdin.on('error',()=>{});
  child.on('close',code=>{if(code!==0)return finish(new Error('curl_failed'));try{finish(null,decodeOutput(Buffer.concat(chunks),port));}catch(e){finish(e);}});
  child.stdin.end(upload||undefined);
 });
}
async function probe({provider,port}){
 if(!['bale','igap','eitaa','nasim','rubika'].includes(provider)||!Number.isInteger(port)||port<1024||port>65535)fail('invalid_probe_options');
 const download=await request(port,FONT_URL);if(download.downloaded!==352240||hash(download.body)!==FONT_HASH)fail('download_integrity_failed');
 const upload=await request(port,'https://httpbin.org/post',UPLOAD);let echo;try{echo=JSON.parse(upload.body.toString('utf8'));}catch{fail('invalid_echo_response');}
 if(upload.uploaded!==UPLOAD.length||typeof echo.data!=='string'||hash(Buffer.from(echo.data))!==hash(UPLOAD))fail('upload_integrity_failed');
 return {provider,proxy:'127.0.0.1:'+port,payloadIntegrityVerified:true,download:{bytes:download.downloaded,sha256:FONT_HASH,elapsedSeconds:download.elapsedSeconds},upload:{bytes:upload.uploaded,sha256:hash(UPLOAD),echoMatches:true,elapsedSeconds:upload.elapsedSeconds},providerPathVerified:false,operatorBillingVerified:false,internationalOutageVerified:false};
}
if(require.main===module){(async()=>{const args=process.argv.slice(2);let provider,port,connect=false;for(let i=0;i<args.length;i++){if(args[i]==='--provider')provider=args[++i];else if(args[i]==='--port')port=Number(args[++i]);else if(args[i]==='--connect')connect=true;else fail('invalid_probe_options');}if(!['bale','igap','eitaa','nasim','rubika'].includes(provider)||!Number.isInteger(port)||port<1024||port>65535)fail('invalid_probe_options');if(!connect){console.log(JSON.stringify({networkEnabled:false,provider,port,requires:'--connect',downloadBytes:352240,uploadBytes:UPLOAD.length}));return;}console.log(JSON.stringify(await probe({provider,port})));})().catch(e=>{console.error(JSON.stringify({ok:false,reason:e.reason||(['transfer_timeout','response_too_large','curl_unavailable','curl_failed'].includes(e.message)?e.message:'probe_failed')}));process.exitCode=1;});}
module.exports={decodeOutput,probe};
