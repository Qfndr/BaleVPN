// Fixed Rubika service methods, no retries or redirects, no public raw errors.
// Discovery is anonymous; account auth/private keys never go to the DC service.
const wire=require('./wire.cjs');
const calls=require('./call-codec.cjs');
const DISCOVERY='https://getdcmess.iranlms.ir/';
const DEFAULT='https://messengerg2c1.iranlms.ir/';
const METHODS=new Set(['sendCode','signIn','registerDevice','getUserInfo','logout',...calls.PROTECTED_METHODS]);
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
function input(method,value){
 if(calls.PROTECTED_METHODS.includes(method)){try{return calls.validateInput(method,value);}catch{throw new ApiError('invalid_request');}}
 const phone=v=>typeof v==='string'&&/^[1-9]\d{6,14}$/.test(v);
 if(method==='sendCode'){
  if(!exact(value,['phone_number','send_type','pass_key'])||!phone(value.phone_number)||value.send_type!=='SMS'||value.pass_key!==undefined&&!text(value.pass_key,256))throw new ApiError('invalid_request');
 }else if(method==='signIn'){
  if(!exact(value,['phone_number','phone_code_hash','phone_code','public_key'])||!phone(value.phone_number)||!text(value.phone_code_hash,2048)||
   typeof value.phone_code!=='string'||!/^\d{4,10}$/.test(value.phone_code)||!text(value.public_key,8192))throw new ApiError('invalid_request');
 }else if(method==='registerDevice'){
  if(!exact(value,['token_type','token','app_version','lang_code','system_version','device_model','device_hash'])||value.token_type!=='Web'||value.token!==''||
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
  const error=new ApiError(code==='INVALID_AUTH'?'not_authorized':code==='TOO_REQUESTS'?'rate_limited':code==='NOT_REGISTERED'?'registration_required':'service_rejected',undefined,code);
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
 #fetch;#session;#server=DEFAULT;#pending;#closed=false;#lang;
 constructor({fetchImpl=globalThis.fetch,temporarySession=wire.temporarySession(),language='fa'}={}){
  const key=wire.serviceKey(temporarySession);key.fill(0);if(!['fa','en'].includes(language))throw new ApiError('invalid_request');
  this.#fetch=fetchImpl;this.#session=temporarySession;this.#lang=language;
 }
 get temporarySession(){return this.#session;}
 #client(){return {app_name:'Main',app_version:'4.4.34',platform:'Web',package:'web.rubika.ir',lang_code:this.#lang};}
 async #post(url,body,{timeout=10000,json=false}={}){
  if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw new ApiError('tls_verification_disabled');
  if(this.#closed)throw new ApiError('closed');if(this.#pending)throw new ApiError('account_busy');
  if(!Number.isInteger(timeout)||timeout<1||timeout>30000)throw new ApiError('invalid_request');
  const controller=new AbortController();this.#pending=controller;const timer=setTimeout(()=>controller.abort(),timeout);
  try{
   const response=await this.#fetch(url,{method:'POST',headers:{'content-type':json?'application/json':'text/plain',origin:'https://web.rubika.ir',referer:'https://web.rubika.ir/'},
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
 async discover({timeout}={}){
  const response=await this.#post(DISCOVERY,{api_version:'4',method:'getDCs',client:this.#client()},{timeout,json:true});
  const result=serviceResult(response);
  if(!Array.isArray(result.default_api_urls)||!result.default_api_urls.length||result.default_api_urls.length>16)throw new ApiError('invalid_dc_response');
  const servers=result.default_api_urls.map(endpoint);if(this.#closed)throw new ApiError('closed');this.#server=servers[0];return {apiServerSelected:true};
 }
 async request(method,value={}, {credentials,timeout}={}){
  if(this.#closed)throw new ApiError('closed');if(this.#pending)throw new ApiError('account_busy');
  if(!METHODS.has(method))throw new ApiError('invalid_request');input(method,value);
  const unauth=UNAUTH.has(method);
  if(unauth&&credentials!==undefined||!unauth&&(!credentials||credentials.provider!=='rubika'))throw new ApiError('invalid_credentials');
  const session=unauth?this.#session:credentials.auth;
  let data;try{data=wire.encrypt({method,input:value,client:this.#client()},session);}catch{throw new ApiError('invalid_credentials');}
  const body={api_version:'6',data_enc:data};
  if(unauth)body.tmp_session=session;
  else{try{body.auth=wire.transform(credentials.auth);body.sign=wire.signature(data,credentials.privateKey);}catch{throw new ApiError('invalid_credentials');}}
  const response=await this.#post(this.#server,body,{timeout});
  if(!text(response?.data_enc,512*1024)){
   if(response?.status&&response.status!=='OK')serviceResult(response);
   throw new ApiError('invalid_encrypted_response');
  }
  let decoded;try{decoded=wire.decrypt(response.data_enc,session);}catch{throw new ApiError('invalid_encrypted_response');}
  return serviceResult(decoded,['registerDevice','logout'].includes(method));
 }
 close(){this.#closed=true;this.#pending?.abort();this.#session=null;}
}
module.exports={HttpClient,ApiError,endpoint,DISCOVERY};
