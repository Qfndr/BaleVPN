// Fixed Rubika service methods, no retries or redirects, no public raw errors.
// Discovery is anonymous by default. An explicit Android V4 reload may send
// account auth only to the fixed official HTTPS DC service; never RSA keys.
const wire=require('./wire.cjs');
const profiles=require('./client-profile.cjs');
const calls=require('./call-codec.cjs');
const privacy=require('./privacy-wire.cjs');
const crypto=require('node:crypto'),{performance}=require('node:perf_hooks'),{types}=require('node:util');
const {decodeSessionStatus}=require('./session-status-codec.cjs');
const {SocketUpdates,socketEndpoint}=require('./socket-updates.cjs');
const DISCOVERY='https://getdcmess.iranlms.ir/';
const DEFAULT='https://messengerg2c1.iranlms.ir/';
const METHODS=new Set(['sendCode','signIn','registerDevice','getUserInfo','logout','getPrivacySetting','setSetting','getCalls','getMySessions',...calls.PROTECTED_METHODS]);
const UNAUTH=new Set(['sendCode','signIn']);
const CODES=new Set(['INVALID_AUTH','INVALID_INPUT','NOT_REGISTERED','TOO_REQUESTS','ACCESS_DENIED']);
class ApiError extends Error{constructor(reason,status,serviceCode){super('Rubika API '+reason);this.reason=reason;if(status!==undefined)this.statusCode=status;if(CODES.has(serviceCode))this.serviceCode=serviceCode;}}
function endpoint(value){
 let url;try{url=new URL(value);}catch{throw new ApiError('invalid_dc_server');}
 if(typeof value!=='string'||value.length>512||url.protocol!=='https:'||url.username||url.password||url.port||url.pathname!=='/'||url.search||url.hash||
  !(url.hostname==='iranlms.ir'||url.hostname.endsWith('.iranlms.ir')))throw new ApiError('invalid_dc_server');return url.origin+'/';
}
function object(value){return value&&typeof value==='object'&&!Array.isArray(value);}
function exact(value,fields){return object(value)&&Object.keys(value).every(k=>fields.includes(k));}
function text(value,max){return typeof value==='string'&&value.length>0&&Buffer.byteLength(value)<=max&&!/[\0\r\n]/.test(value);}
function input(method,value,profile){
 if(method==='getCalls'){if(!exact(value,['filter_type','sort'])||Object.keys(value).length!==2||value.filter_type!=='All'||value.sort!=='FromMax')throw new ApiError('invalid_request');return value;}
 if(method==='getMySessions'){if(!object(value)||types.isProxy(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value))||Reflect.ownKeys(value).length)throw new ApiError('invalid_request');return value;}
 if(method==='getPrivacySetting'){if(!exact(value,[])||Object.keys(value).length)throw new ApiError('invalid_request');return value;}
 if(method==='setSetting'){if(!privacy.validSettingInput(value))throw new ApiError('invalid_request');return value;}
 if(calls.PROTECTED_METHODS.includes(method)){try{return calls.validateInput(method,value);}catch{throw new ApiError('invalid_request');}}
 const phone=v=>typeof v==='string'&&/^[1-9]\d{6,14}$/.test(v);
 if(method==='sendCode'){
  if(!exact(value,['phone_number','send_type','pass_key'])||!phone(value.phone_number)||value.send_type!=='SMS'||value.pass_key!==undefined&&!text(value.pass_key,256))throw new ApiError('invalid_request');
 }else if(method==='signIn'){
  if(!exact(value,['phone_number','phone_code_hash','phone_code','public_key'])||!phone(value.phone_number)||!text(value.phone_code_hash,2048)||
   typeof value.phone_code!=='string'||!/^\d{4,10}$/.test(value.phone_code)||!(profile===profiles.ANDROID?
    typeof value.public_key==='string'&&value.public_key.length<=8192&&/^(?:[A-Za-z0-9+/=]{76}\n)*[A-Za-z0-9+/=]{1,76}\n$/.test(value.public_key):text(value.public_key,8192)))throw new ApiError('invalid_request');
 }else if(method==='registerDevice'){
  const android=profile===profiles.ANDROID;
  if(!exact(value,['token_type','token','app_version','lang_code','system_version','device_model','device_hash',...android?['is_multi_account']:[]])||value.token_type!==(android?'Firebase':'Web')||value.token!==''||
   android&&(value.app_version!=='MA_4.1.1'||typeof value.is_multi_account!=='boolean')||
   !['fa','en'].includes(value.lang_code)||!['app_version','system_version','device_model','device_hash'].every(k=>text(value[k],256)))throw new ApiError('invalid_request');
 }else if(method==='getUserInfo'){
  // The web API treats GUIDs as opaque. A future restore must pin the exact
  // returned self ID, rather than inventing a prefix or fixed-length rule.
  if(!exact(value,['user_guid'])||typeof value.user_guid!=='string'||! /^[A-Za-z0-9_-]{8,128}$/.test(value.user_guid))throw new ApiError('invalid_request');
 }else if(method==='logout'&&(!exact(value,[])||Object.keys(value).length))throw new ApiError('invalid_request');
 return value;
}
function serviceResult(value,allowEmpty=false){
 if(!object(value))throw new ApiError('invalid_response');
 if(value.status!=='OK'){
  const code=CODES.has(value.status_det)?value.status_det:undefined;
  // Official Web distinguishes a revoked session from an operation denied to
  // an otherwise usable session, even though both carry INVALID_AUTH.
  const error=new ApiError(code==='INVALID_AUTH'?(value.status==='ERROR_GENERIC'?'access_denied':'not_authorized'):code==='TOO_REQUESTS'?'rate_limited':code==='NOT_REGISTERED'?'registration_required':'service_rejected',undefined,code);
  // Only short alphabetic status symbols; never return service data or messages.
  for(const [key,valueKey]of [['diagnosticStatus','status'],['diagnosticDetail','status_det']])if(typeof value[valueKey]==='string'&&/^[A-Z][A-Z_]{0,39}$/.test(value[valueKey]))error[key]=value[valueKey];
  throw error;
 }
 if(allowEmpty&&(value.data===null||value.data===undefined))return {};
 if(!object(value.data))throw new ApiError('invalid_response');return value.data;
}
async function bounded(response){
 const length=response.headers.get('content-length');const max=512*1024;
 if(length&&(!/^\d+$/.test(length)||Number(length)>max))throw new ApiError('response_too_large');
 const reader=response.body?.getReader();if(!reader)throw new ApiError('invalid_response');const chunks=[];let size=0;
 try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>max)throw new ApiError('response_too_large');chunks.push(Buffer.from(value));}}
 catch(e){await reader.cancel().catch(()=>{});throw e;}finally{reader.releaseLock();}
 try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,size)));}catch{throw new ApiError('invalid_response');}
}
class HttpClient {
 #fetch;#session;#server=DEFAULT;#pending;#closed=false;#lang;#profile;#socketServer='wss://jsocket5.iranlms.ir:80/';#updates;#updatesFactory;#updatesAbort;#updateBinding;
 #discoveryServers=null;#dcBinding=null;#probingSessions=false;
 constructor({fetchImpl=globalThis.fetch,temporarySession=wire.temporarySession(),language='fa',updatesFactory=SocketUpdates.open,protocolProfile='web'}={}){
  const key=wire.serviceKey(temporarySession);key.fill(0);if(!['fa','en'].includes(language))throw new ApiError('invalid_request');
  try{this.#profile=profiles.mode(protocolProfile);}catch{throw new ApiError('invalid_request');}
  if(updatesFactory!==null&&typeof updatesFactory!=='function')throw new ApiError('invalid_request');this.#updatesFactory=updatesFactory;this.#fetch=fetchImpl;this.#session=temporarySession;this.#lang=language;
 }
 get temporarySession(){return this.#session;}
 #client(){return profiles.client(this.#profile,this.#lang);}
 async #post(url,body,{timeout=10000,json=false}={}){
  if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw new ApiError('tls_verification_disabled');
  if(this.#closed)throw new ApiError('closed');if(this.#pending)throw new ApiError('account_busy');
  if(!Number.isInteger(timeout)||timeout<1||timeout>30000)throw new ApiError('invalid_request');
  const controller=new AbortController();this.#pending=controller;const timer=setTimeout(()=>controller.abort(),timeout);
  try{
   const response=await this.#fetch(url,{method:'POST',headers:{'content-type':json?'application/json':'text/plain',...this.#profile===profiles.WEB?{origin:'https://web.rubika.ir',referer:'https://web.rubika.ir/'}:{}},
    body:JSON.stringify(body),redirect:'error',cache:'no-store',signal:controller.signal});
   if(controller.signal.aborted||this.#closed)throw new ApiError(this.#closed?'closed':'timeout');
   if(response.status<200||response.status>=300)await response.body?.cancel().catch(()=>{});
   if(response.status===401||response.status===403)throw new ApiError('not_authorized',response.status);
   if(response.status===429)throw new ApiError('rate_limited',429);
   if(response.status<200||response.status>=300)throw new ApiError('http_error',response.status);
   const value=await bounded(response);if(controller.signal.aborted||this.#closed)throw new ApiError(this.#closed?'closed':'timeout');return value;
  }catch(e){if(e instanceof ApiError)throw e;throw new ApiError(this.#closed?'closed':controller.signal.aborted?'timeout':'network_error');}
  finally{clearTimeout(timer);if(this.#pending===controller)this.#pending=null;}
 }
 #discoveryRoutes(response){
  const result=serviceResult(response);
  if(!Array.isArray(result.default_api_urls)||!result.default_api_urls.length||result.default_api_urls.length>16)throw new ApiError('invalid_dc_response');
  const servers=result.default_api_urls.map(endpoint);let socketServer;
  if(result.default_sockets!==undefined){if(!Array.isArray(result.default_sockets)||!result.default_sockets.length||result.default_sockets.length>16)throw new ApiError('invalid_dc_response');try{socketServer=result.default_sockets.map(socketEndpoint)[0];}catch{throw new ApiError('invalid_dc_response');}}
  return {servers,socketServer};
 }
 #applyDiscovery({servers,socketServer}){if(this.#closed)throw new ApiError('closed');if(this.#probingSessions)throw new ApiError('account_busy');this.#server=servers[0];this.#discoveryServers=[...servers];if(socketServer)this.#socketServer=socketServer;}
 async discover({timeout}={}){
  if(this.#probingSessions)throw new ApiError('account_busy');
  if(this.#dcBinding)throw new ApiError('invalid_credentials');
  const response=await this.#post(DISCOVERY,{api_version:'4',method:'getDCs',client:this.#client()},{timeout,json:true});
  this.#applyDiscovery(this.#discoveryRoutes(response));return {apiServerSelected:true};
 }
 // Explicit, read-only Android compatibility probe/reload. No retries,
 // device registration, profile changes or additional account API calls.
 async discoverWithCredentials({credentials,timeout}={}){
  if(this.#probingSessions)throw new ApiError('account_busy');
  if(this.#closed)throw new ApiError('closed');
  if(this.#profile!==profiles.ANDROID||credentials?.provider!=='rubika'||
   typeof credentials.userId!=='string'||!/^[A-Za-z0-9_-]{8,128}$/.test(credentials.userId)||
   typeof credentials.auth!=='string'||!/^[A-Za-z0-9]{32}$/.test(credentials.auth))throw new ApiError('invalid_credentials');
  try{if(profiles.fromRecord(credentials)!==profiles.ANDROID)throw Error();}catch{throw new ApiError('invalid_credentials');}
  if(this.#updates||this.#updatesAbort)throw new ApiError('account_busy');
  const binding={userId:credentials.userId,auth:credentials.auth};
  const same=()=>credentials.provider==='rubika'&&credentials.userId===binding.userId&&credentials.auth===binding.auth&&profiles.fromRecord(credentials)===profiles.ANDROID;
  if(this.#dcBinding&&['userId','auth'].some(key=>this.#dcBinding[key]!==binding[key]))throw new ApiError('invalid_credentials');
  const before=this.#discoveryServers&&[...this.#discoveryServers];
  // Android sendV4/getJsonObject uses the raw auth, not V6 encodeChars.
  const response=await this.#post(DISCOVERY,{api_version:4,method:'getDCs',client:this.#client(),auth:binding.auth},{timeout,json:true});
  try{if(!same())throw Error();}catch{throw new ApiError('invalid_credentials');}
  const routes=this.#discoveryRoutes(response);
  const result={apiServerSelected:true,candidateCount:routes.servers.length,comparedWithPrevious:before!==null,
   apiListEqual:before===null?null:before.length===routes.servers.length&&before.every((url,i)=>url===routes.servers[i]),
   selectedServerChanged:before===null?null:before[0]!==routes.servers[0]};
  this.#applyDiscovery(routes);this.#dcBinding=binding;return result;
 }
 async startUpdates(credentials){
  if(this.#probingSessions)throw new ApiError('account_busy');
  if(this.#closed)throw new ApiError('closed');if(this.#updates||this.#updatesAbort||this.#pending)throw new ApiError('account_busy');if(!this.#updatesFactory)return;
  try{if(credentials?.provider!=='rubika'||profiles.fromRecord(credentials)!==this.#profile)throw Error();}catch{throw new ApiError('invalid_credentials');}
  if(this.#dcBinding&&['userId','auth'].some(key=>credentials[key]!==this.#dcBinding[key]))throw new ApiError('invalid_credentials');
  const binding={provider:credentials?.provider,userId:credentials?.userId,auth:credentials?.auth,...this.#profile===profiles.ANDROID?{profile:{protocolProfile:this.#profile}}:{}};this.#updatesAbort=new AbortController();try{const channel=await this.#updatesFactory(binding,{url:this.#socketServer,signal:this.#updatesAbort.signal});if(this.#closed){channel.close();throw new ApiError('closed');}this.#updates=channel;this.#updateBinding=binding;}catch(e){this.#updatesAbort=null;throw e;}
 }
 async request(method,value={}, {credentials,timeout}={}){
  if(this.#probingSessions)throw new ApiError('account_busy');
  return this.#requestTo(this.#server,method,value,{credentials,timeout});
 }
 async #requestTo(server,method,value,{credentials,timeout}={}){
  if(this.#closed)throw new ApiError('closed');if(this.#pending)throw new ApiError('account_busy');
  if(!METHODS.has(method))throw new ApiError('invalid_request');input(method,value,this.#profile);
  const unauth=UNAUTH.has(method);
  if(unauth&&credentials!==undefined||!unauth&&(!credentials||credentials.provider!=='rubika'))throw new ApiError('invalid_credentials');
  if(!unauth){try{if(profiles.fromRecord(credentials)!==this.#profile)throw Error();}catch{throw new ApiError('invalid_credentials');}}
  if(this.#dcBinding&&(unauth||['userId','auth'].some(key=>credentials[key]!==this.#dcBinding[key])))throw new ApiError('invalid_credentials');
  if(method==='getUpdate'&&this.#updates){if(['provider','userId','auth'].some(k=>credentials[k]!==this.#updateBinding[k]))throw new ApiError('invalid_credentials');return this.#updates.read();}
  const session=unauth?this.#session:credentials.auth;
  let data;try{data=wire.encrypt({method,input:value,client:this.#client(),...this.#profile===profiles.ANDROID?{is_background:false}:{}},session,this.#profile);}catch{throw new ApiError('invalid_credentials');}
  const body={api_version:this.#profile===profiles.ANDROID?6:'6',data_enc:data};
  if(unauth)body.tmp_session=session;
  else{try{body.auth=wire.transform(credentials.auth);body.sign=wire.signature(data,credentials.privateKey,this.#profile);}catch{throw new ApiError('invalid_credentials');}}
  const response=await this.#post(server,body,{timeout});
  if(!(this.#profile===profiles.ANDROID?typeof response?.data_enc==='string'&&response.data_enc.length>0&&response.data_enc.length<=512*1024:text(response?.data_enc,512*1024))){
   if(response?.status&&response.status!=='OK')serviceResult(response);
   throw new ApiError('invalid_encrypted_response');
  }
  let decoded;try{decoded=wire.decrypt(response.data_enc,session,this.#profile);}catch{throw new ApiError('invalid_encrypted_response');}
  return serviceResult(decoded,['registerDevice','logout','setSetting'].includes(method));
 }
 // Explicit bounded read-only comparison. It never selects a new active route,
 // repeats a DC, registers a device, or sends a caller-supplied URL or method.
 async probeDiscoveredSessions(options={}){
  if(!exact(options,['credentials','timeout']))throw new ApiError('invalid_request');
  const {credentials,timeout=5000}=options;
  if(this.#closed)throw new ApiError('closed');
  if(this.#probingSessions||this.#pending||this.#updates||this.#updatesAbort)throw new ApiError('account_busy');
  if(!Number.isInteger(timeout)||timeout<1||timeout>5000)throw new ApiError('invalid_request');
  if(!this.#discoveryServers?.length)throw new ApiError('discovery_required');
  let record,profileText,fingerprint;
  const identity=value=>{
   if(value?.provider!=='rubika'||typeof value.userId!=='string'||!/^[A-Za-z0-9_-]{8,128}$/.test(value.userId)||
    typeof value.auth!=='string'||!/^[A-Za-z0-9]{32}$/.test(value.auth)||typeof value.privateKey!=='string'||value.privateKey.length>16384||
    typeof value.publicKey!=='string'||value.publicKey.length>8192||profiles.fromRecord(value)!==this.#profile)throw Error();
   return crypto.createHash('sha256').update(JSON.stringify([value.provider,value.userId,value.auth,value.privateKey,value.publicKey,value.profile??null])).digest('hex');
  };
  try{
   fingerprint=identity(credentials);profileText=JSON.stringify(credentials.profile??null);
   const privateKey=crypto.createPrivateKey(credentials.privateKey),publicKey=crypto.createPublicKey(credentials.publicKey);
   if(privateKey.asymmetricKeyType!=='rsa'||publicKey.asymmetricKeyType!=='rsa'||privateKey.asymmetricKeyDetails.modulusLength<2048||publicKey.asymmetricKeyDetails.modulusLength<2048||
    !crypto.createPublicKey(privateKey).export({type:'spki',format:'der'}).equals(publicKey.export({type:'spki',format:'der'})))throw Error();
   record={provider:'rubika',userId:credentials.userId,auth:credentials.auth,privateKey:credentials.privateKey,publicKey:credentials.publicKey,
    ...credentials.profile===undefined?{}:{profile:JSON.parse(profileText)}};
  }catch{throw new ApiError('invalid_credentials');}
  if(this.#dcBinding&&['userId','auth'].some(key=>record[key]!==this.#dcBinding[key]))throw new ApiError('invalid_credentials');
  const server=this.#server,routes=[...this.#discoveryServers],dcBinding=this.#dcBinding&&{...this.#dcBinding};
  const guard=()=>{
   if(this.#closed)throw new ApiError('closed');
   try{if(identity(credentials)!==fingerprint||this.#server!==server||!this.#discoveryServers||
    this.#discoveryServers.length!==routes.length||!routes.every((url,i)=>url===this.#discoveryServers[i])||
    JSON.stringify(this.#dcBinding)!==JSON.stringify(dcBinding))throw Error();}catch{throw new ApiError('invalid_credentials');}
  };
  const results=[],seen=new Set(),deadline=performance.now()+15000;let stoppedOnRateLimit=false,budgetExhausted=false;
  const safe=new Set(['not_authorized','access_denied','registration_required','rate_limited','timeout','network_error','http_error','invalid_response',
   'invalid_encrypted_response','response_too_large','tls_verification_disabled']);
  this.#probingSessions=true;
  try{
   for(let index=0;index<Math.min(3,routes.length);index++){
    guard();if(seen.has(routes[index]))continue;seen.add(routes[index]);
    const remaining=Math.floor(deadline-performance.now());if(remaining<1){budgetExhausted=true;break;}
    let item,timer;
    try{
     const requestTimeout=Math.min(timeout,remaining),operation=this.#requestTo(routes[index],'getMySessions',{}, {credentials:record,timeout:requestTimeout});
     const reply=await Promise.race([operation,new Promise((resolve,reject)=>{timer=setTimeout(()=>{this.#pending?.abort();reject(new ApiError('timeout'));},requestTimeout);})]);guard();
     item={index,ok:true,...decodeSessionStatus(reply)};
    }catch(error){
     guard();if(error instanceof ApiError&&['invalid_credentials','account_busy','closed'].includes(error.reason))throw error;
     const reason=error instanceof ApiError&&safe.has(error.reason)?error.reason:'invalid_session_status';
     item={index,ok:false,reason,...error instanceof ApiError&&CODES.has(error.serviceCode)?{serviceCode:error.serviceCode}:{}};
     if(reason==='rate_limited')stoppedOnRateLimit=true;
    }finally{clearTimeout(timer);}
    // An abort-ignoring transport must not hold this explicit diagnostic open
    // or receive a second simultaneous request. The caller can close it.
    results.push(item);if(stoppedOnRateLimit||this.#pending)break;
   }
   guard();return {discoveredCount:routes.length,attemptedCount:results.length,stoppedOnRateLimit,budgetExhausted,results};
  }finally{this.#probingSessions=false;record.auth='';record.privateKey='';record.publicKey='';}
 }
 close(){this.#closed=true;this.#pending?.abort();this.#updatesAbort?.abort();this.#updatesAbort=null;this.#updates?.close();this.#updates=null;this.#updateBinding=null;this.#session=null;this.#dcBinding=null;this.#discoveryServers=null;}
}
module.exports={HttpClient,ApiError,endpoint,DISCOVERY};
