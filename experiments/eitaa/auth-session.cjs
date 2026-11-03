// Account-local Eitaa lifecycle. Protected self confirmation and sealed saving
// precede public authentication. No auto OTP, registration, refresh or retries.
'use strict';
const crypto=require('node:crypto'),wire=require('./wire.cjs');
const {AccountClient,passwordHash,deviceProfile,validProfile}=require('./account-client.cjs');
const {ApiError}=require('./http-client.cjs'),{countries}=require('../providers/phone.cjs');
const clean=(v,n=128)=>typeof v==='string'?v.replace(/[\x00-\x1f\x7f]/g,' ').slice(0,n):'';
const text=(v,max)=>typeof v==='string'&&!!v&&Buffer.byteLength(v)<=max&&!/[\0\r\n]/.test(v);
const userId=v=>typeof v==='bigint'&&v>0n&&v<2n**63n;
const revoked=new Set(['INVALID_LOGIN','AUTH_KEY_UNREGISTERED','SESSION_REVOKED']);
// Matches the official worker's local message-ID format, used only for the
// explicit received-code compatibility path after pong. It is NOT a server hash.
function requestIds({clock=Date.now,random=()=>crypto.randomInt(65536)}={}){
 let last=0n;return ()=>{const now=clock(),r=random();if(!Number.isSafeInteger(now)||now<0||!Number.isInteger(r)||r<0||r>65535)throw new ApiError('invalid_request');
  let id=(BigInt(Math.floor(now/1000))<<32n)|BigInt(((now%1000)<<21|r<<3|4)>>>0);if(id<=last)id=last+4n;last=id;return String(id);};
}
class AuthSession{
 #create;#save;#language;#ids;#client;#record;#pending;#salt;#profile;#imei;#phone='';#hint='';#count=0;#delivery=null;#hashSource=null;
 #stage='idle';#busy=false;#epoch=0;#retryAt=0;#error=null;#signed=false;#writes=Promise.resolve();
 constructor({createClient=options=>new AccountClient(options),saveSession=async()=>{},language='fa',createRequestId=requestIds()}={}){
  if(!['fa','en'].includes(language)||typeof createClient!=='function'||typeof saveSession!=='function'||typeof createRequestId!=='function')throw new ApiError('invalid_request');
  this.#create=createClient;this.#save=saveSession;this.#language=language;this.#ids=createRequestId;
 }
 async #run(action){
  if(this.#busy)throw new ApiError('account_busy');this.#busy=true;this.#error=null;const epoch=this.#epoch,guard=()=>{if(epoch!==this.#epoch)throw new ApiError('closed');};
  try{const result=await action(guard);guard();return result;}
  catch(e){const safe=e instanceof ApiError?e:e instanceof wire.WireError?new ApiError(e.reason):new ApiError('invalid_auth_response');if(epoch===this.#epoch){
   if(this.#stage==='requesting')this.#stage='uncertain';
   this.#error={reason:safe.reason,...safe.statusCode!==undefined?{statusCode:safe.statusCode}:{},...safe.serviceCode?{serviceCode:safe.serviceCode}:{}};
   if(safe.reason==='rate_limited')this.#retryAt=Math.max(this.#retryAt,Date.now()+Math.max(1,Math.min(86400,safe.waitSeconds||60))*1000);
   if(revoked.has(safe.serviceCode)||safe.reason==='not_authorized'){this.#signed=false;this.#stage=this.#record?'expired':this.#stage;}
   if(safe.reason==='session_refresh_required'){this.#signed=false;this.#stage='refresh_required';}
  }throw safe;}finally{if(epoch===this.#epoch)this.#busy=false;}
 }
 #transport(){if(!this.#client)this.#client=this.#create({provider:'eitaa',imei:this.#imei,token:this.#record?.token||'',profile:this.#profile,language:this.#language});return this.#client;}
 async #request(method,input,guard){const client=this.#transport();guard();let result;try{result=await client.request(method,input);}catch(e){guard();throw e;}guard();return result;}
 async #persist(guard){
  guard();const record=this.exportSession(),task=this.#writes.then(async()=>{guard();try{await this.#save(record);}catch{guard();throw new ApiError('session_save_failed');}guard();});this.#writes=task.catch(()=>{});await task;
 }
 #clearPending(){this.#salt?.fill(0);this.#salt=null;this.#pending=null;this.#hint='';}
 #validateUser(user,{self=false}={}){if(user?._!=='user'||!userId(user.id)||user.deleted||self&&user.self!==true||user.phone!==undefined&&user.phone!==this.#phone.slice(1))throw new ApiError('invalid_auth_response');return user;}
 async #accept(response,guard){
  if(response?._==='auth.authorizationSignUpRequired')throw new ApiError('existing_account_required');
  if(response?._!=='auth.authorization'||!text(response.token,4096))throw new ApiError('invalid_auth_response');const user=this.#validateUser(response.user);
  this.#record={provider:'eitaa',format:1,token:response.token,imei:this.#imei,userId:String(user.id),loginPhone:this.#phone,
   profile:{...this.#profile},deviceMetadataSent:false,name:clean([user.first_name,user.last_name].filter(Boolean).join(' '))};
  this.#signed=false;this.#stage='restoring';this.#clearPending();this.#client.setToken(response.token);await this.#persist(guard);return this.#confirm(guard);
 }
 async #confirm(guard){
  const users=await this.#request('users.getUsers',{},guard);if(!Array.isArray(users)||users.length!==1)throw new ApiError('invalid_auth_response');const user=this.#validateUser(users[0],{self:true});
  if(String(user.id)!==this.#record.userId)throw new ApiError('login_account_mismatch');this.#signed=true;this.#stage='authenticated';return {authenticated:true,selfConfirmed:true};
 }
 async start({country,nationalNumber,internationalNumber}){
  return this.#run(async guard=>{
   if(this.#record)throw new ApiError('already_signed_in');if(Date.now()<this.#retryAt)throw new ApiError('cooldown');const c=countries.find(c=>c.iso===country);
   if(!c||typeof nationalNumber!=='string'||!/^\d{5,14}$/.test(nationalNumber)||internationalNumber!=='+'+c.code+nationalNumber||!/^\+[1-9]\d{6,14}$/.test(internationalNumber)||country==='IR'&&!/^9\d{9}$/.test(nationalNumber))throw new ApiError('invalid_phone');
   this.#client?.close();this.#client=null;this.#clearPending();this.#imei=wire.deviceId();this.#profile=deviceProfile();this.#phone=internationalNumber;this.#signed=false;this.#hashSource=null;this.#delivery=null;this.#count=0;this.#stage='requesting';
   const correlation=this.#ids();if(!/^[1-9]\d{0,19}$/.test(correlation))throw new ApiError('invalid_request');this.#pending={phone:this.#phone,hash:null,correlation};this.#retryAt=Date.now()+60000;
   let response;try{response=await this.#request('auth.sendCode',{phone_number:this.#phone},guard);}catch(e){guard();
    // A definite number rejection cannot have produced a usable code. Keep
    // cooldown protection, but reserve "uncertain" for unconfirmed outcomes.
    if(e instanceof ApiError&&e.reason==='service_rejected'&&['PHONE_NUMBER_INVALID','PHONE_NUMBER_BANNED'].includes(e.serviceCode)){this.#clearPending();this.#stage='idle';}
    else this.#stage='uncertain';throw e;}
   if(response?.acknowledged===true&&response.codeIssued===false){this.#stage='code';this.#count=6;this.#delivery='Unconfirmed';this.#hashSource='localCompatibility';return {acknowledged:true,codeRequested:false,deliveryUnconfirmed:true};}
   const channels={'auth.sentCodeTypeSms':'SMS','auth.sentCodeTypeApp':'Internal','auth.sentCodeTypeCall':'CallCode'};
   if(response?._!=='auth.sentCode'||!text(response.phone_code_hash,4096)||!channels[response.type?._]||!Number.isInteger(response.type.length)||response.type.length<4||response.type.length>10)throw new ApiError('invalid_auth_response');
   this.#pending.hash=response.phone_code_hash;this.#hashSource='service';this.#count=response.type.length;this.#delivery=channels[response.type._];this.#stage='code';
   if(Number.isInteger(response.timeout)&&response.timeout>=0&&response.timeout<=86400)this.#retryAt=Math.max(this.#retryAt,Date.now()+response.timeout*1000);
   return {codeRequested:true,delivery:this.#delivery,digits:this.#count};
  });
 }
 async verify(code){
  return this.#run(async guard=>{
   if(this.#stage!=='code'||!this.#pending)throw new ApiError('no_pending_code');if(typeof code!=='string'||!/^\d{4,10}$/.test(code)||code.length!==this.#count)throw new ApiError('invalid_code_format');
   // Only an explicit user-supplied received code enters this compatibility
   // branch. Its locally generated correlation is never called a service hash.
   const hash=this.#pending.hash||this.#pending.correlation;let response;
   try{response=await this.#request('auth.signIn',{phone_number:this.#pending.phone,phone_code_hash:hash,phone_code:code},guard);}
   catch(e){guard();if(e.serviceCode==='PHONE_CODE_EXPIRED'){this.#stage='expired';this.#clearPending();}
    if(e.serviceCode==='SESSION_PASSWORD_NEEDED'){this.#pending.code=code;this.#stage='password';await this.#passwordState(guard);return {twoFactorRequired:true};}throw e;}
   return this.#accept(response,guard);
  });
 }
 async #passwordState(guard){
  const state=await this.#request('account.getPassword',{},guard);if(state?._!=='account.password2')throw new ApiError('unsupported_password_algorithm');
  if(!(state.current_salt instanceof Uint8Array)||state.current_salt.length<8||state.current_salt.length>4096)throw new ApiError('invalid_auth_response');
  this.#salt?.fill(0);this.#salt=Buffer.from(state.current_salt);this.#hint=clean(state.hint);
 }
 async password(value){
  return this.#run(async guard=>{if(this.#stage!=='password'||!this.#pending?.code)throw new ApiError('no_pending_password');if(!this.#salt)await this.#passwordState(guard);
   const hash=passwordHash(value,this.#salt);let response;try{response=await this.#request('auth.checkPassword2',{password_hash:hash,phone_number:this.#pending.phone,phone_code:this.#pending.code},guard);}finally{hash.fill(0);}return this.#accept(response,guard);
  });
 }
 async restore(record){
  return this.#run(async guard=>{
   if(this.#record)throw new ApiError('already_signed_in');if(record?.provider!=='eitaa'||record.format!==1||!text(record.token,4096)||typeof record.imei!=='string'||!/^[a-z0-9]{15}__web$/.test(record.imei)||
    typeof record.userId!=='string'||!/^\d{1,19}$/.test(record.userId)||!userId(BigInt(record.userId))||typeof record.loginPhone!=='string'||!/^\+[1-9]\d{6,14}$/.test(record.loginPhone)||!validProfile(record.profile)||typeof record.deviceMetadataSent!=='boolean')throw new ApiError('invalid_saved_session');
   this.#client?.close();this.#client=null;this.#clearPending();this.#record={provider:'eitaa',format:1,token:record.token,imei:record.imei,userId:record.userId,loginPhone:record.loginPhone,profile:{deviceModel:record.profile.deviceModel,systemVersion:record.profile.systemVersion},deviceMetadataSent:record.deviceMetadataSent,name:clean(record.name)};
   this.#imei=record.imei;this.#profile={...this.#record.profile};this.#phone=record.loginPhone;this.#signed=false;this.#stage='restoring';return this.#confirm(guard);
  });
 }
 async resume(){return this.#run(async guard=>{if(!this.#record)throw new ApiError('no_saved_session');this.#signed=false;this.#stage='restoring';await this.#persist(guard);return this.#confirm(guard);});}
 async refresh(){return this.#run(async guard=>{
  if(!this.#record)throw new ApiError('no_saved_session');const response=await this.#request('eitaaRefreshToken',{},guard);if(response?._!=='eitaa_updates_token'||!text(response.token,4096))throw new ApiError('invalid_auth_response');
  this.#record.token=response.token;this.#record.deviceMetadataSent=true;this.#signed=false;this.#stage='restoring';this.#transport().setToken(response.token);await this.#persist(guard);return this.#confirm(guard);
 });}
 async logout(){return this.#run(async guard=>{if(!this.#record)throw new ApiError('no_saved_session');if(await this.#request('auth.logOut',{},guard)!==true)throw new ApiError('logout_not_confirmed');this.#clear();return {loggedOut:true};});}
 exportSession(){if(!this.#record)throw new ApiError('session_not_ready');return {...this.#record,profile:{...this.#record.profile}};}
 #clear(){this.#client?.close();this.#client=null;this.#clearPending();this.#record=null;this.#imei=null;this.#profile=null;this.#phone='';this.#stage='idle';this.#signed=false;this.#error=null;this.#delivery=null;this.#hashSource=null;this.#count=0;}
 stop(){this.#epoch++;this.#busy=false;this.#client?.close();this.#client=null;this.#clearPending();this.#signed=false;this.#stage=this.#record?'stopped':'idle';this.#error=null;}
 close(){this.#epoch++;this.#busy=false;this.#clear();}
 get state(){return {provider:'eitaa',stage:this.#stage,busy:this.#busy,connected:this.#signed,signedIn:this.#signed,hasSession:!!this.#record,userId:this.#record?.userId||null,
  maskedPhone:this.#phone?'•••• '+this.#phone.slice(-4):'',retryAfter:Math.max(0,Math.ceil((this.#retryAt-Date.now())/1000)),hint:this.#hint,error:this.#error,codeDigits:this.#count,delivery:this.#delivery,codeHashSource:this.#hashSource,
  selfConfirmed:this.#signed,deviceModel:this.#profile?.deviceModel||null,systemVersion:this.#profile?.systemVersion||null,deviceMetadataSent:this.#record?.deviceMetadataSent||false,providerVerified:false,callReady:false};}
}
module.exports={AuthSession,requestIds};
