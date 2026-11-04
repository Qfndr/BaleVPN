// Private child-process control. SDP replies are delivered only to the awaited
// signaling operation; state never contains SDP, TURN credentials or raw errors.
const path=require('node:path'),{spawn}=require('node:child_process');
const {iceDiagnostics}=require('./ice-diagnostics.cjs');
function createBridge(provider){
if(!['nasim','eitaa','rubika'].includes(provider))throw Error('Unsupported media provider');
const MAX=192*1024;
const REASONS=new Set(['arguments_not_allowed','unsafe_environment','identity_failed','bridge_panic','config_timeout',
 'input_closed','invalid_command','invalid_config','invalid_role','invalid_pairing','invalid_port','invalid_profile','invalid_relay',
 'invalid_description','media_setup_failed','negotiation_failed','gather_timeout','no_relay','transport_closed',
 'event_stream_unavailable','output_closed','invalid_control_command','connect_timeout','server_setup_failed',
 'proxy_bind_failed','transport_failed','transport_disconnected','ice_failed','dtls_failed','relay_route_failed']);
function fail(reason){return Object.assign(new Error('Native media '+reason),{reason});}
function keys(v,allowed){return v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).every(k=>allowed.includes(k));}
function cert(v){return typeof v==='string'&&v.length>=128&&v.length<=16384&&v.length%2===0&&/^[a-f0-9]+$/.test(v);}
function id(v){return provider==='rubika'?typeof v==='string'&&/^[A-Za-z0-9_-]{8,128}$/.test(v):typeof v==='string'&&/^[1-9]\d{0,18}$/.test(v)&&BigInt(v)<=(provider==='eitaa'?(1n<<63n)-1n:BigInt(Number.MAX_SAFE_INTEGER));}
function uuid(v){return typeof v==='string'&&/^[-A-Za-z0-9_:]{1,128}$/.test(v);}
function description(v,type){
 if(!keys(v,['type','sdp'])||v.type!==type||typeof v.sdp!=='string'||Buffer.byteLength(v.sdp)>65535||v.sdp.includes('\0'))throw fail('invalid_description');
 const lines=v.sdp.split(/\r?\n/);if(!v.sdp.startsWith('v=0')||lines.filter(l=>l.startsWith('m=')).length!==1||
  !lines.some(l=>/^m=audio .* UDP\/TLS\/RTP\/SAVPF /.test(l))||
  !lines.some(l=>/^a=fingerprint:sha-256 (?:[a-fA-F0-9]{2}:){31}[a-fA-F0-9]{2}$/.test(l))||
  lines.some(l=>l.startsWith('a=crypto:')||l.startsWith('a=candidate:')&&l.trim().split(/\s+/)[7]!=='relay'))throw fail('invalid_description');
 return {type:v.type,sdp:v.sdp};
}
function relay(value){
 if(!keys(value,['urls','username','credential'])||typeof value.username!=='string'||!value.username||Buffer.byteLength(value.username)>1024||
  typeof value.credential!=='string'||!value.credential||Buffer.byteLength(value.credential)>1024)throw fail('invalid_relay');
 const urls=typeof value.urls==='string'?[value.urls]:value.urls;
 if(!Array.isArray(urls)||!urls.length||urls.length>4||urls.some(u=>typeof u!=='string'||u.length>512||
  !/^turn:(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)(?::[0-9]{1,5})?(?:\?transport=udp)?$/.test(u)))throw fail('invalid_relay');
 return {urls:[...urls],username:value.username,credential:value.credential};
}
class NativeMediaBridge {
 #child;#buffer=Buffer.alloc(0);#phase='starting';#role;#context;#certificate;#pending;#prepare;#timer;#killTimer;#reason=null;#latest={};#stderr=false;
 static async open(executable,{spawnImpl=spawn,prepareTimeout=10000}={}){
  if(typeof executable!=='string'||!path.isAbsolute(executable)||!Number.isInteger(prepareTimeout)||prepareTimeout<100||prepareTimeout>30000)throw fail('invalid_executable');
  if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw fail('unsafe_environment');
  const bridge=new NativeMediaBridge();
  return new Promise((resolve,reject)=>{
   bridge.#prepare={resolve:()=>resolve(bridge),reject};bridge.#timer=setTimeout(()=>bridge.#failed('prepare_timeout'),prepareTimeout);
   const env={...process.env};for(const key of ['SSLKEYLOGFILE','RUST_LOG','RUST_BACKTRACE'])delete env[key];
   try{bridge.#child=spawnImpl(executable,[],{shell:false,windowsHide:true,stdio:['pipe','pipe','pipe'],env});
    bridge.#child.stdout.on('data',chunk=>bridge.#read(chunk));
    bridge.#child.stderr.on('data',()=>{bridge.#stderr=true;});
    bridge.#child.on('error',()=>bridge.#failed('process_failed'));bridge.#child.stdin.on('error',()=>bridge.#failed('input_closed'));
    bridge.#child.on('exit',()=>{clearTimeout(bridge.#killTimer);if(bridge.#phase==='closing')bridge.#phase='closed';
     else if(!['failed','closed'].includes(bridge.#phase))bridge.#failed('process_exited');});
   }catch{bridge.#failed('process_failed');}
  });
 }
 #failed(reason){
  if(['failed','closed'].includes(this.#phase))return;this.#phase='failed';this.#reason=reason;this.#latest=this.#latest.ice?{ice:this.#latest.ice}:{};
  clearTimeout(this.#timer);clearTimeout(this.#killTimer);this.#prepare?.reject(fail(reason));this.#prepare=null;
  if(this.#pending){clearTimeout(this.#pending.timer);this.#pending.reject(fail(reason));this.#pending=null;}
  this.#buffer.fill(0);this.#buffer=Buffer.alloc(0);this.#child?.stdin.destroy();this.#child?.kill();
 }
 #read(chunk){
  if(['failed','closed'].includes(this.#phase))return;
  try{
   // Bound each line, while accepting several complete replies in one read.
   let start=0;for(let at=0;at<chunk.length;at++)if(chunk[at]===10){
    if(this.#buffer.length+at-start>MAX)throw Error();
    const bytes=Buffer.concat([this.#buffer,chunk.subarray(start,at)]);this.#buffer.fill(0);this.#buffer=Buffer.alloc(0);start=at+1;
    try{this.#event(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)));}finally{bytes.fill(0);}
    if(['failed','closed'].includes(this.#phase))return;
   }
   if(this.#buffer.length+chunk.length-start>MAX)throw Error();
   const next=Buffer.concat([this.#buffer,chunk.subarray(start)]);this.#buffer.fill(0);this.#buffer=next;
  }catch{this.#failed('invalid_native_output');}
 }
 #event(v){
  if(v?.event==='iceDiagnostics'){
   if(!['configured','connecting','connected'].includes(this.#phase)||!keys(v,['event','ice']))throw Error();
   this.#latest.ice=iceDiagnostics(v.ice);return;
  }
  if(v?.event==='prepared'){
   if(this.#phase!=='starting'||!keys(v,['event','protocol','provider','publicCertificate'])||v.protocol!==2||v.provider!==provider||!cert(v.publicCertificate))throw Error();
   this.#certificate=v.publicCertificate;this.#phase='prepared';clearTimeout(this.#timer);this.#prepare.resolve();this.#prepare=null;return;
  }
  if(v?.event==='error'){if(!keys(v,['event','reason'])||!REASONS.has(v.reason))throw Error();this.#failed(v.reason);return;}
  if(v?.event==='stopped'){if(this.#phase!=='closing'||!keys(v,['event']))throw Error();this.#phase='closed';return;}
  if(this.#phase==='closing')return;
  if(['configured','description','negotiated','candidateAdded'].includes(v?.event)){
   const pending=this.#pending;if(!pending||v.event!==pending.expected)throw Error();
   let result;
   if(v.event==='configured'){if(!keys(v,['event','provider'])||v.provider!==provider)throw Error();this.#phase='configured';}
   else if(v.event==='description'){if(!keys(v,['event','description']))throw Error();result=description(v.description,pending.type);this.#phase='connecting';}
   else if(!keys(v,['event']))throw Error();
   this.#pending=null;clearTimeout(pending.timer);pending.resolve(result);return;
  }
  if(!['connecting','connected'].includes(this.#phase))throw Error();
  const common=['event','mediaConnected','relayPair','peerAuthenticated','proxyReady','providerPathVerified','billingVerified'];
  if(![v.mediaConnected,v.peerAuthenticated,v.proxyReady].every(x=>typeof x==='boolean')||v.relayPair!==true||v.providerPathVerified!==false||v.billingVerified!==false||
   v.proxyReady&&(!v.mediaConnected||!v.peerAuthenticated))throw Error();
  if(v.event==='connected'){
   if(this.#phase!=='connecting'||!keys(v,[...common,'provider','socksAddress'])||v.provider!==provider||!v.mediaConnected||
    (this.#role==='server'?v.socksAddress!==null:typeof v.socksAddress!=='string'||!/^127\.0\.0\.1:[1-9]\d{0,4}$/.test(v.socksAddress)||Number(v.socksAddress.split(':')[1])>65535))throw Error();
   this.#phase='connected';this.#latest.socksAddress=v.socksAddress;
  }else if(v.event==='metrics'){
   if(this.#phase!=='connected'||!keys(v,[...common,'receivedBytes','sentBytes','quic'])||!['receivedBytes','sentBytes'].every(k=>Number.isSafeInteger(v[k])&&v[k]>=0))throw Error();
   const q=v.quic;if(q!==null&&(!keys(q,['rttMs','lostPackets','sentPackets','congestionWindow','sendWindowBytes','profile'])||
    !['throughput','balanced'].includes(q.profile)||!['rttMs','lostPackets','sentPackets','congestionWindow','sendWindowBytes'].every(k=>Number.isFinite(q[k])&&q[k]>=0)))throw Error();
   this.#latest.receivedBytes=v.receivedBytes;this.#latest.sentBytes=v.sentBytes;this.#latest.quic=q?{...q}:null;
  }else throw Error();
  for(const k of ['mediaConnected','peerAuthenticated','proxyReady','relayPair'])this.#latest[k]=v[k];
 }
 #request(command,expected,type){
  if(this.#pending)throw fail('operation_busy');
  if(['failed','closing','closed'].includes(this.#phase))throw fail('closed');
  const encoded=Buffer.from(JSON.stringify(command)+'\n');if(encoded.length>MAX){encoded.fill(0);throw fail('invalid_command');}
  return new Promise((resolve,reject)=>{
   this.#pending={expected,type,resolve,reject,timer:setTimeout(()=>this.#failed('operation_timeout'),20000)};
   try{this.#child.stdin.write(encoded,error=>{encoded.fill(0);if(error)this.#failed('input_closed');});}
   catch{encoded.fill(0);this.#failed('input_closed');}
  });
 }
 get publicCertificate(){if(this.#phase!=='prepared')throw fail('not_prepared');return this.#certificate;}
 async configure(call,{role,trustedCertificates,socksPort=1089,throughput=false}={}){
  if(this.#phase!=='prepared')throw fail('not_prepared');
  if(!keys(call,['provider','callUUID','selfId','peerId','iceServers'])||call.provider!==provider||!uuid(call.callUUID)||!id(call.selfId)||!id(call.peerId)||call.selfId===call.peerId||
   !Array.isArray(call.iceServers)||!call.iceServers.length||call.iceServers.length>4)throw fail('invalid_call');
  // STUN from the provider config is not forwarded to this relay-only driver.
  const servers=call.iceServers.filter(s=>typeof s?.urls==='string'&&s.urls.startsWith('stun:')?false:true).map(relay);
  if(!servers.length)throw fail('invalid_relay');
  if(!['client','server'].includes(role)||typeof throughput!=='boolean'||!Number.isInteger(socksPort)||socksPort<0||socksPort>65535||socksPort>0&&socksPort<1024||
   !Array.isArray(trustedCertificates)||!trustedCertificates.length||trustedCertificates.length>8||new Set(trustedCertificates).size!==trustedCertificates.length||
   trustedCertificates.some(c=>!cert(c)||c===this.#certificate))throw fail('invalid_pairing');
  this.#role=role;this.#context={selfId:call.selfId,peerId:call.peerId,callUUID:call.callUUID};this.#phase='configuring';
  await this.#request({command:'configure',provider,role,trustedCertificates,socksPort,throughput,iceServers:servers},'configured');
 }
 async offer(){if(this.#phase!=='configured')throw fail('not_configured');this.#phase='connecting';return this.#request({command:'offer'},'description','offer');}
 async answer(offer){if(this.#phase!=='configured')throw fail('not_configured');const sdp=description(offer,'offer');this.#phase='connecting';return this.#request({command:'answer',description:sdp},'description','answer');}
 async setAnswer(answer){if(this.#phase!=='connecting')throw fail('not_connecting');return this.#request({command:'setAnswer',description:description(answer,'answer')},'negotiated');}
 async addCandidate(candidate){
  if(!['connecting','connected'].includes(this.#phase))throw fail('not_connecting');
  if(!keys(candidate,['candidate','sdpMid','sdpMLineIndex','usernameFragment'])||typeof candidate.candidate!=='string'||candidate.candidate.length>4096||/[\r\n]/.test(candidate.candidate)||
   candidate.candidate.trim().split(/\s+/)[7]!=='relay'||typeof candidate.sdpMid!=='string'||candidate.sdpMid.length>128||
   !Number.isInteger(candidate.sdpMLineIndex)||candidate.sdpMLineIndex<0||candidate.sdpMLineIndex>32||
   candidate.usernameFragment!==undefined&&candidate.usernameFragment!==null&&(typeof candidate.usernameFragment!=='string'||candidate.usernameFragment.length>256))throw fail('invalid_description');
  return this.#request({command:'candidate',candidate},'candidateAdded');
 }
 close(){
  if(['failed','closed','closing'].includes(this.#phase))return;this.#phase='closing';this.#latest={};clearTimeout(this.#timer);
  this.#prepare?.reject(fail('closed'));this.#prepare=null;if(this.#pending){clearTimeout(this.#pending.timer);this.#pending.reject(fail('closed'));this.#pending=null;}
  this.#buffer.fill(0);this.#buffer=Buffer.alloc(0);
  try{this.#child.stdin.end('{"command":"stop"}\n');}catch{this.#child.kill();}
  this.#killTimer=setTimeout(()=>this.#child.kill(),2500);this.#killTimer.unref();
 }
 get state(){return {provider,phase:this.#phase,role:this.#role||null,context:this.#context?{...this.#context}:null,...this.#latest,
  ...(this.#latest.ice?{ice:{...this.#latest.ice}}:{}),
  quic:this.#latest.quic?{...this.#latest.quic}:null,reason:this.#reason,stderrPresent:this.#stderr,
  providerPathVerified:false,billingVerified:false,internationalOutageVerified:false};}
}
return {NativeMediaBridge};
}
module.exports={createBridge};
