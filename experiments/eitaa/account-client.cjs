// Private account RPCs. No auto-login, refresh/retry loop, OTP or registration.
// The research lab must never serialize these response objects into public state.
'use strict';
const os=require('node:os'),crypto=require('node:crypto'),wire=require('./wire.cjs'),codec=require('./auth-wire.cjs');
const {Transport,ApiError}=require('./http-client.cjs');
const AUTH=new Set(['users.getUsers','auth.logOut','eitaaRefreshToken']);
const CODES=new Set(['PHONE_NUMBER_INVALID','PHONE_CODE_INVALID','PHONE_CODE_EXPIRED','PHONE_CODE_EMPTY','PHONE_NUMBER_BANNED','SESSION_PASSWORD_NEEDED','PASSWORD_HASH_INVALID','INVALID_LOGIN','AUTH_KEY_UNREGISTERED','SESSION_REVOKED','INVALID_CONSTRUCTOR']);
const FIELDS={
 'auth.sendCode':['phone_number'],
 'auth.signIn':['phone_number','phone_code_hash','phone_code'],
 'auth.checkPassword2':['password_hash','phone_number','phone_code'],
 'account.getPassword':[],'account.getPasswordLayer68':[],'users.getUsers':[],'auth.logOut':[],'eitaaRefreshToken':[]
};
function text(v,max){return typeof v==='string'&&!!v&&Buffer.byteLength(v)<=max&&!/[\0\r\n]/.test(v);}
function token(v){return v===''||text(v,4096);}
function deviceProfile(){return {deviceModel:'BaleVPN Provider Lab (desktop)',systemVersion:(os.platform()+' '+os.release()+' '+os.arch()).slice(0,128)};}
function validProfile(p){return p&&p.deviceModel==='BaleVPN Provider Lab (desktop)'&&text(p.systemVersion,128)&&!/[\x00-\x1f\x7f]/.test(p.systemVersion);}
function requestInput(name,input,language,profile){
 const fields=Object.hasOwn(FIELDS,name)&&FIELDS[name];if(!fields||!input||typeof input!=='object'||Array.isArray(input)||![Object.prototype,null].includes(Object.getPrototypeOf(input))||Object.keys(input).some(k=>!fields.includes(k)))throw new ApiError('invalid_request');
 const phone=v=>typeof v==='string'&&/^\+[1-9]\d{6,14}$/.test(v),code=v=>typeof v==='string'&&/^\d{4,10}$/.test(v);
 if(name==='auth.sendCode'){if(!phone(input.phone_number))throw new ApiError('invalid_phone');return {...input,api_id:2496,api_hash:'8da85b0d5bfe62527e5b244c209159c3',settings:{_:'codeSettings'}};}
 if(name==='auth.signIn'){if(!phone(input.phone_number)||!code(input.phone_code)||!text(input.phone_code_hash,4096))throw new ApiError('invalid_request');}
 if(name==='auth.checkPassword2'){if(!(input.password_hash instanceof Uint8Array)||input.password_hash.length!==32||!phone(input.phone_number)||!code(input.phone_code))throw new ApiError('invalid_request');}
 if(name==='users.getUsers')return {id:[{_:'inputUserSelf'}]};
 if(name==='eitaaRefreshToken')return {app_info:{_:'eitaaAppInfo',build_version:2496,device_model:profile.deviceModel,system_version:profile.systemVersion,app_version:'5.2 K',lang_code:language,sign:''}};
 return input;
}
function serviceError(value){
 const e=new ApiError('service_rejected',value.code);if(CODES.has(value.text))e.serviceCode=value.text;
 const wait=typeof value.text==='string'&&value.text.match(/^FLOOD_WAIT_(\d{1,5})$/);if(wait){e.reason='rate_limited';e.waitSeconds=Math.min(86400,Number(wait[1]));}
 return e;
}
function passwordHash(password,salt){
 if(typeof password!=='string'||!password||Buffer.byteLength(password)>1024||!(salt instanceof Uint8Array)||salt.length<8||salt.length>4096)throw new ApiError('invalid_password_format');
 const bytes=Buffer.from(password,'utf8');if(new TextDecoder('utf-8',{fatal:true}).decode(bytes)!==password){bytes.fill(0);throw new ApiError('invalid_password_format');}
 try{return crypto.createHash('sha256').update(salt).update(bytes).update(salt).digest();}finally{bytes.fill(0);}
}
class AccountClient{
 #transport;#imei;#token;#language;#profile;
 constructor({imei,token:sessionToken='',language='fa',provider='eitaa',profile=deviceProfile(),...options}={}){
  if(provider!=='eitaa'||typeof imei!=='string'||!/^[a-z0-9]{15}__web$/.test(imei)||!token(sessionToken)||!['fa','en'].includes(language)||!validProfile(profile))throw new ApiError('invalid_credentials');
  this.#transport=new Transport(options);this.#imei=imei;this.#token=sessionToken;this.#language=language;this.#profile={deviceModel:profile.deviceModel,systemVersion:profile.systemVersion};
 }
 setToken(value){this.#transport.assertOpen();if(!text(value,4096))throw new ApiError('invalid_credentials');this.#token=value;}
 async request(name,input={},options={}){
  this.#transport.assertOpen();const value=requestInput(name,input,this.#language,this.#profile);if(AUTH.has(name)&&!this.#token)throw new ApiError('not_authorized');if(name==='auth.sendCode'&&this.#token)throw new ApiError('already_signed_in');
  const body=wire.envelope(codec.method(name,value),{imei:this.#imei,token:this.#token});
  let result=codec.response(await this.#transport.post(body,options),name);this.#transport.assertOpen();if(result?._==='rpc_result')result=result.result;
  if(result?._==='error'||result?._==='eitta_error')throw serviceError(result);
  if(['eitaa_updates_expire_token','eitaa_token_updating'].includes(result?._))throw new ApiError('session_refresh_required');
  // Preserve the acknowledgement honestly, never invent a service-issued hash.
  if(result?._==='pong'){if(name==='auth.sendCode')return {acknowledged:true,codeIssued:false};throw new ApiError('unexpected_acknowledgement');}
  return result;
 }
 close(){this.#transport.close();this.#token='';this.#imei='';}
}
module.exports={AccountClient,passwordHash,deviceProfile,validProfile};
