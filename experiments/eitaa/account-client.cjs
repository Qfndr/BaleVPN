// Private account RPCs. No auto-login, refresh/retry loop, OTP or registration.
// The research lab must never serialize these response objects into public state.
'use strict';
const os=require('node:os'),crypto=require('node:crypto'),wire=require('./wire.cjs'),codec=require('./auth-wire.cjs');
const {Transport,ApiError}=require('./http-client.cjs');
const privacyCodec=require('./privacy-wire.cjs');
const profiles=require('./client-profile.cjs'),{apkEnvelope}=require('./android-envelope.cjs');
const AUTH_RECOVERY_FRAME=Symbol('Eitaa private authorization recovery frame');
const SOCKET_RECOVERY_FRAME=Symbol('Eitaa private socket-credential recovery frame');
const AUTH=new Set(['users.getUsers','auth.logOut','eitaaRefreshToken','eitaaGetSocketToken','account.getPrivacy','account.setPrivacy']);
const CODES=new Set(['PHONE_NUMBER_INVALID','PHONE_CODE_INVALID','PHONE_CODE_EXPIRED','PHONE_CODE_EMPTY','PHONE_NUMBER_BANNED','SESSION_PASSWORD_NEEDED','PASSWORD_HASH_INVALID','INVALID_LOGIN','AUTH_KEY_UNREGISTERED','SESSION_REVOKED','INVALID_CONSTRUCTOR']);
const FIELDS={
 'auth.sendCode':['phone_number'],
 'auth.signIn':['phone_number','phone_code_hash','phone_code'],
 'auth.checkPassword2':['password_hash','phone_number','phone_code'],
 'account.getPassword':[],'account.getPasswordLayer68':[],'users.getUsers':[],'auth.logOut':[],'eitaaRefreshToken':[],'eitaaGetSocketToken':[],
 'account.getPrivacy':[],'account.setPrivacy':['allowAll']
};
function text(v,max){return typeof v==='string'&&!!v&&Buffer.byteLength(v)<=max&&!/[\0\r\n]/.test(v);}
function token(v){return v===''||text(v,4096);}
function deviceProfile(protocolProfile='web'){return {deviceModel:'Desktop '+crypto.randomBytes(6).toString('hex'),systemVersion:(os.platform()+' '+os.release()+' '+os.arch()).slice(0,128),...profiles.mode(protocolProfile)===profiles.ANDROID?{protocolProfile}:{}};}
function validProfile(p){try{profiles.fromProfile(p);return p&&(p.deviceModel==='BaleVPN Provider Lab (desktop)'||/^Desktop [a-f0-9]{12}$/.test(p.deviceModel))&&text(p.systemVersion,128)&&!/[\x00-\x1f\x7f]/.test(p.systemVersion);}catch{return false;}}
function requestInput(name,input,language,profile,imei){
 const fields=Object.hasOwn(FIELDS,name)&&FIELDS[name];if(!fields||!input||typeof input!=='object'||Array.isArray(input)||![Object.prototype,null].includes(Object.getPrototypeOf(input))||Object.keys(input).some(k=>!fields.includes(k)))throw new ApiError('invalid_request');
 const phone=v=>typeof v==='string'&&/^\+[1-9]\d{6,14}$/.test(v),code=v=>typeof v==='string'&&/^\d{4,10}$/.test(v);
 if(name==='auth.sendCode'){if(!phone(input.phone_number))throw new ApiError('invalid_phone');return {...input,api_id:profiles.fromProfile(profile)===profiles.ANDROID?profiles.ANDROID_API_ID:2496,api_hash:profiles.fromProfile(profile)===profiles.ANDROID?profiles.ANDROID_API_HASH:'8da85b0d5bfe62527e5b244c209159c3',settings:{_:'codeSettings'}};}
 if(name==='auth.signIn'){if(!phone(input.phone_number)||!code(input.phone_code)||!text(input.phone_code_hash,4096))throw new ApiError('invalid_request');}
 if(name==='auth.checkPassword2'){if(!(input.password_hash instanceof Uint8Array)||input.password_hash.length!==32||!phone(input.phone_number)||!code(input.phone_code))throw new ApiError('invalid_request');}
 if(name==='users.getUsers')return {id:[{_:'inputUserSelf'}]};
 if(name==='account.getPrivacy')return {key:{_:'inputPrivacyKeyPhoneCall'}};
 if(name==='account.setPrivacy'){if(Object.keys(input).length!==1||input.allowAll!==true)throw new ApiError('invalid_request');return {key:{_:'inputPrivacyKeyPhoneCall'},rules:[{_:'inputPrivacyValueAllowAll'}]};}
 if(name==='eitaaRefreshToken'){if(profiles.fromProfile(profile)===profiles.ANDROID)throw new ApiError('profile_refresh_unavailable');const model=profile.deviceModel==='BaleVPN Provider Lab (desktop)'?'Desktop '+crypto.createHash('sha256').update(imei).digest('hex').slice(0,12):profile.deviceModel;return {app_info:{_:'eitaaAppInfo',build_version:2496,device_model:model,system_version:profile.systemVersion,app_version:'5.2 K',lang_code:language,sign:''}};}
 if(name==='eitaaGetSocketToken'&&profiles.fromProfile(profile)!==profiles.ANDROID)throw new ApiError('profile_refresh_unavailable');
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
 #transport;#imei;#token;#language;#profile;#captureAuthRecovery;#captureSocketRecovery;#mode;#codec;
 constructor({imei,token:sessionToken='',language='fa',provider='eitaa',profile=deviceProfile(),captureAuthRecovery=false,captureSocketRecovery=false,...options}={}){
  let mode;try{mode=profiles.fromProfile(profile);}catch{throw new ApiError('invalid_credentials');}
  if(provider!=='eitaa'||!profiles.validImei(imei,mode)||!token(sessionToken)||!['fa','en'].includes(language)||!validProfile(profile))throw new ApiError('invalid_credentials');
  if(typeof captureAuthRecovery!=='boolean')throw new ApiError('invalid_credentials');this.#captureAuthRecovery=captureAuthRecovery;
  if(typeof captureSocketRecovery!=='boolean')throw new ApiError('invalid_credentials');this.#captureSocketRecovery=captureSocketRecovery;
  this.#mode=mode;this.#codec=codec.forProfile(mode);this.#transport=new Transport({...options,protocolProfile:mode});this.#imei=imei;this.#token=sessionToken;this.#language=language;this.#profile={deviceModel:profile.deviceModel,systemVersion:profile.systemVersion,...Object.hasOwn(profile,'protocolProfile')?{protocolProfile:profile.protocolProfile}:{}};
 }
 setToken(value){this.#transport.assertOpen();if(!text(value,4096))throw new ApiError('invalid_credentials');this.#token=value;}
 async request(name,input={},options={}){
  this.#transport.assertOpen();const value=requestInput(name,input,this.#language,this.#profile,this.#imei);if(AUTH.has(name)&&!this.#token)throw new ApiError('not_authorized');if(name==='auth.sendCode'&&this.#token)throw new ApiError('already_signed_in');
  const selected=name==='account.getPrivacy'||name==='account.setPrivacy'?privacyCodec:this.#codec;
  const packed=selected.method(name,value),body=this.#mode===profiles.ANDROID?apkEnvelope(packed,{record:{provider:'eitaa',imei:this.#imei,token:this.#token,profile:this.#profile},language:this.#language}):wire.envelope(packed,{imei:this.#imei,token:this.#token});
  const frame=await this.#transport.post(body,options),socketFrame=this.#captureSocketRecovery&&name==='eitaaGetSocketToken'?Buffer.from(frame):null;let result;
  try{result=selected.response(frame,name);}catch(error){
   if(this.#captureAuthRecovery&&['auth.signIn','auth.checkPassword2'].includes(name)&&error instanceof wire.WireError&&['unknown_flags','trailing_data'].includes(error.reason))Object.defineProperty(error,AUTH_RECOVERY_FRAME,{value:Buffer.from(frame),enumerable:false});
   if(socketFrame)Object.defineProperty(error,SOCKET_RECOVERY_FRAME,{value:socketFrame,enumerable:false});
   throw error;
  }finally{frame.fill(0);}
  try{this.#transport.assertOpen();if(result?._==='rpc_result')result=result.result;
  if(result?._==='error'||result?._==='eitta_error')throw serviceError(result);
  if(['eitaa_updates_expire_token','eitaa_token_updating'].includes(result?._))throw new ApiError('session_refresh_required');
  // Preserve the acknowledgement honestly, never invent a service-issued hash.
  if(result?._==='pong'){if(name==='auth.sendCode')return {acknowledged:true,codeIssued:false};throw new ApiError('unexpected_acknowledgement');}
  // Ownership of this private buffer passes to the explicit caller, including
  // a syntactically valid reply that may fail credential semantic validation.
  if(socketFrame)Object.defineProperty(result,SOCKET_RECOVERY_FRAME,{value:socketFrame,enumerable:false});
  return result;
  }catch(error){if(socketFrame)Object.defineProperty(error,SOCKET_RECOVERY_FRAME,{value:socketFrame,enumerable:false});throw error;}
 }
 close(){this.#transport.close();this.#token='';this.#imei='';}
}
module.exports={AccountClient,passwordHash,deviceProfile,validProfile,serviceError,AUTH_RECOVERY_FRAME,SOCKET_RECOVERY_FRAME};
