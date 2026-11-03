// Independent Rubika account lifecycle. Native service credentials are saved
// before device registration; restore never signs in or registers implicitly.
const crypto=require('node:crypto'),os=require('node:os');
const wire=require('./wire.cjs'),{HttpClient,ApiError}=require('./http-client.cjs');
const profiles=require('./client-profile.cjs');
const {countries}=require('../providers/phone.cjs');
const guid=v=>typeof v==='string'&&/^[A-Za-z0-9_-]{8,128}$/.test(v);
const clean=(v,max=256)=>typeof v==='string'?v.replace(/[\x00-\x1f\x7f]/g,' ').slice(0,max):'';
const digits=v=>v.replace(/[۰-۹]/g,c=>String(c.charCodeAt(0)-1776)).replace(/[٠-٩]/g,c=>String(c.charCodeAt(0)-1632));
class AuthSession {
 #create;#createIdentity;#save;#client;#discovered=false;#identity;#record;#pending;#phone='';#hint='';#count=0;#delivery=null;
 #stage='idle';#busy=false;#epoch=0;#retryAt=0;#error=null;#signed=false;#selfConfirmed=false;#language;#profile;
 constructor({createClient=options=>new HttpClient(options),createIdentity=wire.createIdentity,saveSession=async()=>{},language='fa'}={}){
  if(!['fa','en'].includes(language)||typeof saveSession!=='function')throw new ApiError('invalid_request');
  this.#create=createClient;this.#createIdentity=createIdentity;this.#save=saveSession;this.#language=language;
 }
 async #run(action){
  if(this.#busy)throw new ApiError('account_busy');this.#busy=true;this.#error=null;const epoch=this.#epoch;
  const guard=()=>{if(epoch!==this.#epoch)throw new ApiError('closed');};
  try{const result=await action(guard);guard();return result;}
  catch(e){const safe=e instanceof ApiError?e:new ApiError('invalid_auth_response');if(epoch===this.#epoch){
   this.#error={reason:safe.reason,...safe.statusCode?{statusCode:safe.statusCode}:{},...safe.serviceCode?{serviceCode:safe.serviceCode}:{}};
   if(safe.reason==='rate_limited')this.#retryAt=Math.max(this.#retryAt,Date.now()+60000);
   if(safe.reason==='not_authorized'){this.#signed=false;this.#selfConfirmed=false;}
  }throw safe;}finally{if(epoch===this.#epoch)this.#busy=false;}
 }
 async #transport(guard){
  if(!this.#client){this.#client=this.#create({language:this.#language,protocolProfile:profiles.fromRecord(this.#record||{profile:this.#profile})});this.#discovered=false;}
  const client=this.#client;if(!this.#discovered){await client.discover();guard();this.#discovered=true;}return client;
 }
 async #request(method,input,guard,authenticated=false){
  const client=await this.#transport(guard);guard();let result;
  try{result=await client.request(method,input,authenticated?{credentials:this.#record}:{});}catch(e){guard();throw e;}
  guard();return result;
 }
 async #persist(guard){
  guard();try{await this.#save(this.exportSession());}catch{throw new ApiError('session_save_failed');}guard();
 }
 #result(response){
  if(!response||typeof response!=='object')throw new ApiError('invalid_auth_response');
  switch(response.status){
   case 'OK':
    if(typeof response.phone_code_hash!=='string'||!response.phone_code_hash||response.phone_code_hash.length>2048||
     !Number.isInteger(response.code_digits_count)||response.code_digits_count<4||response.code_digits_count>10||
     !['SMS','Internal','CallCode'].includes(response.send_type))throw new ApiError('invalid_auth_response');
    this.#pending.hash=response.phone_code_hash;this.#count=response.code_digits_count;this.#delivery=response.send_type;this.#stage='code';this.#hint='';this.#retryAt=Math.max(this.#retryAt,Date.now()+60000);
    return {codeRequested:true,delivery:this.#delivery,digits:this.#count};
   case 'SendPassKey':this.#stage='password';this.#hint=clean(response.hint_pass_key);this.#pending.hash=null;return {twoFactorRequired:true};
   case 'InvalidPassKey':this.#stage='password';throw new ApiError('invalid_password');
   default:throw new ApiError('invalid_auth_response');
  }
 }
 async start({country,nationalNumber,internationalNumber},options={}){
  return this.#run(async guard=>{
   if(this.#record)throw new ApiError('already_signed_in');if(Date.now()<this.#retryAt)throw new ApiError('cooldown');
   let protocolProfile;try{if(!options||typeof options!=='object'||Array.isArray(options)||Object.keys(options).some(k=>k!=='protocolProfile'))throw Error();protocolProfile=profiles.mode(options.protocolProfile);}catch{throw new ApiError('invalid_client_profile');}
   const c=countries.find(c=>c.iso===country);
   if(!c||typeof nationalNumber!=='string'||!/^\d{5,15}$/.test(nationalNumber)||internationalNumber!=='+'+c.code+nationalNumber||
    !/^\+[1-9]\d{6,14}$/.test(internationalNumber)||country==='IR'&&!/^9\d{9}$/.test(nationalNumber))throw new ApiError('invalid_phone');
   this.#pending={phone:internationalNumber.slice(1),hash:null};this.#phone=internationalNumber;this.#identity=null;this.#hint='';this.#count=0;this.#delivery=null;
   this.#client?.close();this.#client=null;this.#discovered=false;
   this.#profile={protocolProfile,deviceHash:crypto.randomBytes(16).toString('hex'),deviceModel:'BaleVPN Provider Lab (desktop)',systemVersion:clean(os.platform()+' '+os.release()+' '+os.arch(),128)};
   await this.#transport(guard);guard();this.#retryAt=Date.now()+60000;
   return this.#result(await this.#request('sendCode',{phone_number:this.#pending.phone,send_type:'SMS'},guard));
  });
 }
 async password(value){
  return this.#run(async guard=>{
   if(this.#stage!=='password'||!this.#pending)throw new ApiError('no_pending_password');
   if(typeof value!=='string'||!value||value.length>64)throw new ApiError('invalid_password_format');
   const response=await this.#request('sendCode',{phone_number:this.#pending.phone,send_type:'SMS',pass_key:digits(value)},guard);
   return this.#result(response);
  });
 }
 async verify(code){
  return this.#run(async guard=>{
   if(this.#stage!=='code'||!this.#pending?.hash)throw new ApiError('no_pending_code');
   if(typeof code!=='string'||!/^\d{4,10}$/.test(code)||code.length!==this.#count)throw new ApiError('invalid_code_format');
   if(!this.#identity){const identity=await this.#createIdentity();guard();this.#identity=identity;}
   const response=await this.#request('signIn',{phone_number:this.#pending.phone,phone_code_hash:this.#pending.hash,phone_code:code,public_key:wire.publicKeyField(this.#identity.publicKey,profiles.mode(this.#profile.protocolProfile))},guard);
   if(response?.status!=='OK'){
    if(['CodeIsExpired','CodeIsUsed'].includes(response?.status)){this.#pending.hash=null;this.#stage='expired';throw new ApiError(response.status==='CodeIsExpired'?'code_expired':'code_used');}
    throw new ApiError(response?.status==='CodeIsInvalid'?'invalid_code':'invalid_auth_response');
   }
   if(!guid(response.user?.user_guid))throw new ApiError('invalid_auth_response');
   let auth;try{auth=wire.decryptAuth(response.auth,this.#identity.privateKey,profiles.mode(this.#profile.protocolProfile));}catch{throw new ApiError('invalid_auth_response');}
   this.#record={provider:'rubika',userId:response.user.user_guid,auth,privateKey:this.#identity.privateKey,publicKey:this.#identity.publicKey,
    loginPhone:this.#phone,profile:{...this.#profile},registration:'required'};
   this.#identity=null;this.#pending=null;this.#stage='device_required';
   // The server has already created an auth: do not lose it if the next
   // network request fails or the account is subsequently stopped.
   await this.#persist(guard);await this.#register(guard);return this.#confirm(guard);
  });
 }
 async #register(guard){
  if(!this.#record)throw new ApiError('no_saved_session');
  this.#signed=false;this.#selfConfirmed=false;this.#record.registration='uncertain';this.#stage='registration_uncertain';await this.#persist(guard);
  const p=this.#record.profile;
  try{await this.#request('registerDevice',profiles.registration(profiles.fromRecord(this.#record),p,this.#language),guard,true);}
  catch(e){if(e instanceof ApiError&&e.reason==='registration_required'){this.#record.registration='required';this.#stage='device_required';await this.#persist(guard);}throw e;}
  this.#record.registration='confirmed';this.#stage='restoring';await this.#persist(guard);
 }
 async #confirm(guard){
  let result;try{result=await this.#request('getUserInfo',{user_guid:this.#record.userId},guard,true);}
  catch(e){if(e instanceof ApiError&&e.reason==='registration_required'){this.#record.registration='required';this.#stage='device_required';await this.#persist(guard);}throw e;}
  if(result?.user?.user_guid!==this.#record.userId)throw new ApiError('login_account_mismatch');
  this.#signed=true;this.#selfConfirmed=true;this.#stage='authenticated';return {authenticated:true,selfConfirmed:true};
 }
 async register(){return this.#run(async guard=>{if(!this.#record||this.#record.registration!=='required')throw new ApiError('registration_not_requested');await this.#register(guard);return this.#confirm(guard);});}
 async restore(record){
  return this.#run(async guard=>{
   if(this.#record)throw new ApiError('already_signed_in');
   if(record?.provider!=='rubika'||!guid(record.userId)||typeof record.loginPhone!=='string'||!/^\+[1-9]\d{6,14}$/.test(record.loginPhone)||
    !['required','uncertain','confirmed'].includes(record.registration)||!record.profile||! /^[a-f0-9]{32}$/.test(record.profile.deviceHash)||
    typeof record.profile.deviceModel!=='string'||!record.profile.deviceModel||record.profile.deviceModel.length>128||
    typeof record.profile.systemVersion!=='string'||!record.profile.systemVersion||record.profile.systemVersion.length>128)throw new ApiError('invalid_saved_session');
   try{const mode=profiles.fromRecord(record);const key=wire.serviceKey(record.auth);key.fill(0);wire.publicKeyField(record.publicKey,mode);wire.signature(wire.encrypt({},record.auth),record.privateKey);
    const derived=crypto.createPublicKey(record.privateKey).export({type:'spki',format:'der'}),given=crypto.createPublicKey(record.publicKey).export({type:'spki',format:'der'});
    if(!derived.equals(given))throw Error();
   }catch{throw new ApiError('invalid_saved_session');}
   this.#client?.close();this.#client=null;this.#discovered=false;
   this.#record={provider:'rubika',userId:record.userId,auth:record.auth,privateKey:record.privateKey,publicKey:record.publicKey,
    loginPhone:record.loginPhone,registration:record.registration,profile:{deviceHash:record.profile.deviceHash,deviceModel:record.profile.deviceModel,systemVersion:record.profile.systemVersion,...Object.hasOwn(record.profile,'protocolProfile')?{protocolProfile:record.profile.protocolProfile}:{}}};
   this.#phone=record.loginPhone;this.#stage='restoring';return this.#confirm(guard);
  });
 }
 async resume(){return this.#run(async guard=>{if(!this.#record)throw new ApiError('no_saved_session');this.#signed=false;this.#selfConfirmed=false;this.#stage='restoring';await this.#persist(guard);return this.#confirm(guard);});}
 async logout(){return this.#run(async guard=>{if(!this.#record)throw new ApiError('no_saved_session');await this.#request('logout',{},guard,true);this.#clear();return {loggedOut:true};});}
 exportSession(){if(!this.#record)throw new ApiError('session_not_ready');return {...this.#record,profile:{...this.#record.profile}};}
 #clear(){this.#client?.close();this.#client=null;this.#discovered=false;this.#record=null;this.#identity=null;this.#pending=null;this.#phone='';this.#hint='';this.#count=0;this.#delivery=null;this.#signed=false;this.#selfConfirmed=false;this.#profile=null;this.#error=null;this.#stage='idle';}
 stop(){this.#epoch++;this.#busy=false;this.#client?.close();this.#client=null;this.#discovered=false;this.#signed=false;this.#selfConfirmed=false;this.#stage=this.#record?'stopped':'idle';this.#pending=null;this.#identity=null;this.#error=null;}
 close(){this.#epoch++;this.#busy=false;this.#clear();}
 get state(){return {provider:'rubika',stage:this.#stage,busy:this.#busy,connected:this.#signed,signedIn:this.#signed,hasSession:!!this.#record,
  userId:this.#record?.userId||null,maskedPhone:this.#phone?'•••• '+this.#phone.slice(-4):'',retryAfter:Math.max(0,Math.ceil((this.#retryAt-Date.now())/1000)),
  hint:this.#hint,error:this.#error,codeDigits:this.#count,delivery:this.#delivery,selfConfirmed:this.#selfConfirmed,
  registration:this.#record?.registration||null,deviceModel:this.#record?.profile.deviceModel||null,systemVersion:this.#record?.profile.systemVersion||null,
  protocolProfile:profiles.fromRecord(this.#record||{profile:this.#profile}),
  providerVerified:false,callReady:false};}
}
module.exports={AuthSession};
