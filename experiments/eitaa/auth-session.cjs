// Account-local Eitaa lifecycle. Protected self confirmation and sealed saving
// precede public authentication. No auto OTP, registration, refresh or retries.
'use strict';
const crypto=require('node:crypto'),wire=require('./wire.cjs');
const {AccountClient,passwordHash,deviceProfile,validProfile,AUTH_RECOVERY_FRAME,SOCKET_RECOVERY_FRAME}=require('./account-client.cjs');
const codec=require('./auth-wire.cjs');
const profiles=require('./client-profile.cjs');
const socketCredential=require('./socket-credential.cjs');
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
 #create;#save;#saveRecovery;#saveSocketRecovery;#language;#ids;#client;#record;#pending;#salt;#profile;#imei;#phone='';#hint='';#count=0;#delivery=null;#hashSource=null;
 #stage='idle';#busy=false;#epoch=0;#retryAt=0;#error=null;#signed=false;#writes=Promise.resolve();#callPrivacy=null;#recoveryAvailable=false;
 constructor({createClient=options=>new AccountClient(options),saveSession=async()=>{},saveRecovery=null,saveSocketRecovery=null,language='fa',createRequestId=requestIds()}={}){
  if(!['fa','en'].includes(language)||typeof createClient!=='function'||typeof saveSession!=='function'||typeof createRequestId!=='function')throw new ApiError('invalid_request');
  if(saveRecovery!==null&&typeof saveRecovery!=='function')throw new ApiError('invalid_request');this.#saveRecovery=saveRecovery;
  if(saveSocketRecovery!==null&&typeof saveSocketRecovery!=='function')throw new ApiError('invalid_request');this.#saveSocketRecovery=saveSocketRecovery;
  this.#create=createClient;this.#save=saveSession;this.#language=language;this.#ids=createRequestId;
 }
 async #run(action){
  if(this.#busy)throw new ApiError('account_busy');this.#busy=true;this.#error=null;const epoch=this.#epoch,guard=()=>{if(epoch!==this.#epoch)throw new ApiError('closed');};
  try{const result=await action(guard);guard();return result;}
  catch(e){const safe=e instanceof ApiError?e:e instanceof wire.WireError?new ApiError(e.reason):new ApiError('invalid_auth_response');if(epoch===this.#epoch){
   if(this.#stage==='requesting')this.#stage='uncertain';
   this.#error={reason:safe.reason,...safe.statusCode!==undefined?{statusCode:safe.statusCode}:{},...safe.serviceCode?{serviceCode:safe.serviceCode}:{}};
   // Retain only numeric schema metadata, never the private response body.
   if(e instanceof wire.WireError&&e.reason==='unknown_flags'&&e.schemaDiagnostic){
    const d=e.schemaDiagnostic,keys=['constructorId','flags','knownMask'];
    if(keys.every(k=>Number.isInteger(d[k])&&d[k]>=0&&d[k]<=0xffffffff))this.#error.schemaDiagnostic=Object.fromEntries(keys.map(k=>[k,d[k]]));
   }
   if(e instanceof wire.WireError&&e.reason==='trailing_data'&&e.trailingDiagnostic){
    const d=e.trailingDiagnostic,ids=['constructorId','lastConstructorId'],sizes=['consumed','total','remaining'];
    if(ids.every(k=>Number.isInteger(d[k])&&d[k]>=0&&d[k]<=0xffffffff)&&sizes.every(k=>Number.isInteger(d[k])&&d[k]>=0&&d[k]<=wire.MAX)&&d.remaining>0&&d.consumed+d.remaining===d.total)this.#error.trailingDiagnostic=Object.fromEntries([...ids,...sizes].map(k=>[k,d[k]]));
   }
   if(safe.reason==='rate_limited')this.#retryAt=Math.max(this.#retryAt,Date.now()+Math.max(1,Math.min(86400,safe.waitSeconds||60))*1000);
   if(revoked.has(safe.serviceCode)||safe.reason==='not_authorized'){this.#signed=false;this.#stage=this.#record?'expired':this.#stage;}
   if(safe.reason==='session_refresh_required'){this.#signed=false;this.#stage='refresh_required';}
  }throw safe;}finally{if(epoch===this.#epoch)this.#busy=false;}
 }
 #transport(){if(!this.#client)this.#client=this.#create({provider:'eitaa',imei:this.#imei,token:this.#record?.token||'',profile:this.#profile,language:this.#language,captureAuthRecovery:!!this.#saveRecovery,captureSocketRecovery:!!this.#saveSocketRecovery});return this.#client;}
 async #archiveSocketFrame(frame,guard){
  guard();if(!this.#saveSocketRecovery||!(frame instanceof Buffer)||frame.length<1||frame.length>wire.MAX)throw new ApiError('invalid_auth_response');
  this.#signed=false;this.#stage='socket_recovery_required';const recovery={provider:'eitaa',format:'eitaa-socket-credential-recovery-v1',method:'eitaaGetSocketToken',createdAt:Date.now(),userId:this.#record.userId,imei:this.#imei,profile:{...this.#profile},httpTokenSha256:crypto.createHash('sha256').update(this.#record.token).digest('hex'),frame:frame.toString('base64')};
  const task=this.#writes.then(async()=>{guard();try{await this.#saveSocketRecovery(recovery);}catch{guard();throw new ApiError('recovery_save_failed');}guard();});this.#writes=task.catch(()=>{});await task;
 }
 async #request(method,input,guard){const client=this.#transport();guard();let result;try{result=await client.request(method,input,method==='auth.sendCode'?{timeout:30000}:undefined);}catch(e){
  const socketFrame=e?.[SOCKET_RECOVERY_FRAME];if(socketFrame instanceof Buffer){try{
   guard();if(method==='eitaaGetSocketToken')await this.#archiveSocketFrame(socketFrame,guard);
  }finally{socketFrame.fill(0);}}
  const frame=e?.[AUTH_RECOVERY_FRAME];try{guard();if(this.#saveRecovery&&frame instanceof Buffer&&frame.length>0&&frame.length<=wire.MAX&&e instanceof wire.WireError&&['unknown_flags','trailing_data'].includes(e.reason)&&['auth.signIn','auth.checkPassword2'].includes(method)){
   const recovery={provider:'eitaa',format:'eitaa-auth-recovery-v1',imei:this.#imei,loginPhone:this.#phone,profile:{...this.#profile},frame:frame.toString('base64'),method,createdAt:Date.now()};
   // The service may already have created a session. Never reuse the submitted
   // code after this undecodable reply, even if encrypted persistence fails.
   this.#clearPending();this.#stage='uncertain';
   const task=this.#writes.then(async()=>{guard();try{await this.#saveRecovery(recovery);}catch{guard();throw new ApiError('recovery_save_failed');}guard();});this.#writes=task.catch(()=>{});await task;guard();this.#clearPending();this.#recoveryAvailable=true;this.#stage='recovery_required';
  }}finally{if(frame instanceof Buffer)frame.fill(0);}throw e;
 }try{guard();return result;}catch(error){const frame=result?.[SOCKET_RECOVERY_FRAME];if(frame instanceof Buffer)frame.fill(0);throw error;}}
 async #persist(guard){
  guard();const record=this.exportSession(),task=this.#writes.then(async()=>{guard();try{await this.#save(record);}catch{guard();throw new ApiError('session_save_failed');}guard();});this.#writes=task.catch(()=>{});await task;
 }
 #clearPending(){this.#salt?.fill(0);this.#salt=null;this.#pending=null;this.#hint='';}
 #validateUser(user,{self=false}={}){if(user?._!=='user'||!userId(user.id)||user.deleted||self&&user.self!==true||user.phone!==undefined&&user.phone!==this.#phone.slice(1))throw new ApiError('invalid_auth_response');return user;}
 async #accept(response,guard){
  if(response?._==='auth.authorizationSignUpRequired')throw new ApiError('existing_account_required');
  if(response?._!=='auth.authorization'||!text(response.token,4096))throw new ApiError('invalid_auth_response');const user=this.#validateUser(response.user);
  const appendix=response[codec.AUTHORIZATION_APPENDIX];if(appendix!==undefined&&!codec.validAuthorizationAppendix(appendix))throw new ApiError('invalid_auth_response');
  this.#record={provider:'eitaa',format:1,token:response.token,imei:this.#imei,userId:String(user.id),loginPhone:this.#phone,
   profile:{...this.#profile},deviceMetadataSent:false,name:clean([user.first_name,user.last_name].filter(Boolean).join(' '))};
  if(appendix!==undefined)this.#record.authorizationAppendix={...appendix};
  this.#signed=false;this.#stage='restoring';this.#clearPending();this.#client.setToken(response.token);await this.#persist(guard);return this.#confirm(guard);
 }
 async #confirm(guard){
  this.#callPrivacy=null;
  const users=await this.#request('users.getUsers',{},guard);if(!Array.isArray(users)||users.length!==1)throw new ApiError('invalid_auth_response');const user=this.#validateUser(users[0],{self:true});
  if(String(user.id)!==this.#record.userId)throw new ApiError('login_account_mismatch');this.#signed=true;this.#recoveryAvailable=false;this.#stage='authenticated';return {authenticated:true,selfConfirmed:true};
 }
 async #readCallPrivacy(guard){
  if(!this.#record||!this.#signed)throw new ApiError('not_authenticated');
  const reply=await this.#request('account.getPrivacy',{},guard);
  const types=new Set(['privacyValueAllowAll','privacyValueAllowContacts','privacyValueAllowUsers','privacyValueDisallowContacts','privacyValueDisallowAll','privacyValueDisallowUsers','privacyValueAllowChatParticipants','privacyValueDisallowChatParticipants']);
  if(reply?._!=='account.privacyRules'||!Array.isArray(reply.rules)||reply.rules.length>256||reply.rules.some(rule=>!rule||!types.has(rule._)))throw new ApiError('invalid_privacy_response');
  const single=reply.rules.length===1?reply.rules[0]._:null;
  const mode=single==='privacyValueAllowAll'?'everyone':single==='privacyValueAllowContacts'?'contacts':single==='privacyValueDisallowAll'?'nobody':'custom';
  this.#callPrivacy={mode,allowedEveryone:mode==='everyone'};return {...this.#callPrivacy};
 }
 getCallPrivacy(){return this.#run(async guard=>({callPrivacy:await this.#readCallPrivacy(guard)}));}
 allowAllCalls(){return this.#run(async guard=>{
  const current=await this.#readCallPrivacy(guard);if(current.allowedEveryone)return {changed:false,callPrivacy:current};
  this.#callPrivacy=null;await this.#request('account.setPrivacy',{allowAll:true},guard);
  const verified=await this.#readCallPrivacy(guard);if(!verified.allowedEveryone)throw new ApiError('privacy_change_not_confirmed');
  return {changed:true,callPrivacy:verified};
 });}
 async start({country,nationalNumber,internationalNumber},options={}){
  return this.#run(async guard=>{
   if(this.#record)throw new ApiError('already_signed_in');if(this.#recoveryAvailable)throw new ApiError('recovery_required');if(Date.now()<this.#retryAt)throw new ApiError('cooldown');const c=countries.find(c=>c.iso===country);
   let mode;try{if(!options||typeof options!=='object'||Array.isArray(options)||Object.keys(options).some(k=>k!=='protocolProfile'))throw Error();mode=profiles.mode(options.protocolProfile);}catch{throw new ApiError('invalid_client_profile');}
   if(!c||typeof nationalNumber!=='string'||!/^\d{5,14}$/.test(nationalNumber)||internationalNumber!=='+'+c.code+nationalNumber||!/^\+[1-9]\d{6,14}$/.test(internationalNumber)||country==='IR'&&!/^9\d{9}$/.test(nationalNumber))throw new ApiError('invalid_phone');
   this.#client?.close();this.#client=null;this.#clearPending();this.#imei=profiles.createImei(mode);this.#profile=deviceProfile(mode);this.#phone=internationalNumber;this.#signed=false;this.#hashSource=null;this.#delivery=null;this.#count=0;this.#stage='requesting';
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
 async recoverAuthorization(record){
  return this.#run(async guard=>{
   if(this.#record)throw new ApiError('already_signed_in');
   const keys=['provider','format','imei','loginPhone','profile','frame','method','createdAt'],now=Date.now();
   if(!record||typeof record!=='object'||Array.isArray(record)||Object.keys(record).length!==keys.length||Object.keys(record).some(k=>!keys.includes(k))||record.provider!=='eitaa'||record.format!=='eitaa-auth-recovery-v1'||
    !validProfile(record.profile)||!profiles.validImei(record.imei,profiles.fromProfile(record.profile))||typeof record.loginPhone!=='string'||!/^\+[1-9]\d{6,14}$/.test(record.loginPhone)||
    !['auth.signIn','auth.checkPassword2'].includes(record.method)||!Number.isSafeInteger(record.createdAt)||record.createdAt<now-86400000||record.createdAt>now+30000||
    typeof record.frame!=='string'||!record.frame||record.frame.length>4*Math.ceil(wire.MAX/3)||record.frame.length%4||!/^[A-Za-z0-9+/]+={0,2}$/.test(record.frame))throw new ApiError('invalid_recovery_record');
   const frame=Buffer.from(record.frame,'base64');
   try{
    if(!frame.length||frame.length>wire.MAX||frame.toString('base64')!==record.frame)throw new ApiError('invalid_recovery_record');
    let response=codec.forProfile(profiles.fromProfile(record.profile)).response(frame,record.method);if(response?._==='rpc_result')response=response.result;guard();
    this.#client?.close();this.#client=null;this.#clearPending();this.#imei=record.imei;this.#phone=record.loginPhone;this.#profile={...record.profile};this.#signed=false;this.#recoveryAvailable=true;this.#stage='recovery_required';
    this.#transport();return await this.#accept(response,guard);
   }finally{frame.fill(0);}
  });
 }
 async restore(record){
  return this.#run(async guard=>{
   if(this.#record)throw new ApiError('already_signed_in');if(record?.provider!=='eitaa'||record.format!==1||!text(record.token,4096)||!validProfile(record.profile)||!profiles.validImei(record.imei,profiles.fromProfile(record.profile))||
    typeof record.userId!=='string'||!/^\d{1,19}$/.test(record.userId)||!userId(BigInt(record.userId))||typeof record.loginPhone!=='string'||!/^\+[1-9]\d{6,14}$/.test(record.loginPhone)||!validProfile(record.profile)||typeof record.deviceMetadataSent!=='boolean'||Object.hasOwn(record,'authorizationAppendix')&&!codec.validAuthorizationAppendix(record.authorizationAppendix)||Object.hasOwn(record,'nativeSocketCredential')&&!socketCredential.valid(record.nativeSocketCredential,record))throw new ApiError('invalid_saved_session');
   this.#client?.close();this.#client=null;this.#clearPending();this.#record={provider:'eitaa',format:1,token:record.token,imei:record.imei,userId:record.userId,loginPhone:record.loginPhone,profile:{deviceModel:record.profile.deviceModel,systemVersion:record.profile.systemVersion,...Object.hasOwn(record.profile,'protocolProfile')?{protocolProfile:record.profile.protocolProfile}:{}},deviceMetadataSent:record.deviceMetadataSent,name:clean(record.name)};
   if(Object.hasOwn(record,'authorizationAppendix'))this.#record.authorizationAppendix={...record.authorizationAppendix};
   if(Object.hasOwn(record,'nativeSocketCredential'))this.#record.nativeSocketCredential={...record.nativeSocketCredential};
   this.#imei=record.imei;this.#profile={...this.#record.profile};this.#phone=record.loginPhone;this.#signed=false;this.#stage='restoring';return this.#confirm(guard);
  });
 }
 async resume(){return this.#run(async guard=>{if(!this.#record)throw new ApiError('no_saved_session');this.#signed=false;this.#stage='restoring';await this.#persist(guard);return this.#confirm(guard);});}
 // Explicit private research operation, not automatic and not an HTTP/UI route.
 // The service may rotate the HTTP token too, so seal both before self read.
 async obtainSocketCredential(){return this.#run(async guard=>{
  if(!this.#record||!this.#signed)throw new ApiError('not_authenticated');if(profiles.fromRecord(this.#record)!==profiles.ANDROID)throw new ApiError('profile_refresh_unavailable');
  if(!this.#saveSocketRecovery)throw new ApiError('recovery_storage_required');
  const response=await this.#request('eitaaGetSocketToken',{},guard),frame=response?.[SOCKET_RECOVERY_FRAME];try{
  let record,credential;if(response?._==='eitaa_updates_token'&&text(response.token,4096)){record={...this.#record,token:response.token};credential=socketCredential.fromResponse(response,record);}
  if(!credential){await this.#archiveSocketFrame(frame,guard);throw new ApiError('invalid_auth_response');}
  record.nativeSocketCredential=credential;this.#record=record;this.#signed=false;this.#stage='restoring';this.#transport().setToken(response.token);await this.#persist(guard);return this.#confirm(guard);
  }finally{if(frame instanceof Buffer)frame.fill(0);}
 });}
 async refresh(){return this.#run(async guard=>{
  if(!this.#record)throw new ApiError('no_saved_session');const response=await this.#request('eitaaRefreshToken',{},guard);if(response?._!=='eitaa_updates_token'||!text(response.token,4096))throw new ApiError('invalid_auth_response');
  this.#record.token=response.token;this.#record.deviceMetadataSent=true;this.#signed=false;this.#stage='restoring';this.#transport().setToken(response.token);await this.#persist(guard);return this.#confirm(guard);
 });}
 async logout(){return this.#run(async guard=>{if(!this.#record)throw new ApiError('no_saved_session');if(await this.#request('auth.logOut',{},guard)!==true)throw new ApiError('logout_not_confirmed');this.#clear();return {loggedOut:true};});}
 exportSession(){if(!this.#record)throw new ApiError('session_not_ready');return {...this.#record,profile:{...this.#record.profile},...this.#record.authorizationAppendix?{authorizationAppendix:{...this.#record.authorizationAppendix}}:{},...this.#record.nativeSocketCredential?{nativeSocketCredential:{...this.#record.nativeSocketCredential}}:{}};}
 #clear(){this.#client?.close();this.#client=null;this.#clearPending();this.#record=null;this.#imei=null;this.#profile=null;this.#phone='';this.#stage='idle';this.#signed=false;this.#error=null;this.#delivery=null;this.#hashSource=null;this.#count=0;this.#callPrivacy=null;this.#recoveryAvailable=false;}
 stop(){this.#epoch++;this.#busy=false;this.#client?.close();this.#client=null;this.#clearPending();this.#signed=false;this.#stage=this.#record?'stopped':this.#recoveryAvailable?'recovery_required':'idle';this.#error=null;this.#callPrivacy=null;}
 close(){this.#epoch++;this.#busy=false;this.#clear();}
 get state(){return {provider:'eitaa',stage:this.#stage,busy:this.#busy,connected:this.#signed,signedIn:this.#signed,hasSession:!!this.#record,hasRecovery:this.#recoveryAvailable,userId:this.#record?.userId||null,
  maskedPhone:this.#phone?'•••• '+this.#phone.slice(-4):'',retryAfter:Math.max(0,Math.ceil((this.#retryAt-Date.now())/1000)),hint:this.#hint,error:this.#error,codeDigits:this.#count,delivery:this.#delivery,codeHashSource:this.#hashSource,
  selfConfirmed:this.#signed,callPrivacy:this.#signed&&this.#callPrivacy?{...this.#callPrivacy}:null,deviceModel:this.#profile?.deviceModel||null,systemVersion:this.#profile?.systemVersion||null,protocolProfile:profiles.fromProfile(this.#profile),deviceMetadataSent:this.#record?.deviceMetadataSent||false,providerVerified:false,callReady:false};}
}
module.exports={AuthSession,requestIds};
