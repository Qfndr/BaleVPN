// Experimental, one connection and login transaction per account. No raw secrets
// in public state; a caller may persist exportSession() only in an encrypted vault.
const crypto=require('node:crypto');
const {wire:w}=require('./signaling.cjs');
const {Connection,RpcError}=require('./rpc-connection.cjs');
const APP_ID=67291; // Independent ID per archived iGap+ guidance; live delivery is unverified.
const REGISTRATION_PROFILES=Object.freeze({independent:APP_ID,'web-v3-compat':1});
function registrationProfile(p){
 if(p?.registrationProfile==='web-v3-compat'&&p.appId===1)return 'web-v3-compat';
 if(p&&[undefined,'independent'].includes(p.registrationProfile)&&Number.isInteger(p.appId)&&p.appId>=1000&&p.appId<=100000)return 'independent';
 throw new RpcError('invalid_profile');
}
function createProfile({registrationProfile:mode='independent'}={}){if(!Object.hasOwn(REGISTRATION_PROFILES,mode))throw new RpcError('invalid_profile');return {registrationProfile:mode,appId:REGISTRATION_PROFILES[mode],appBuild:1,appVersion:'0.1.0',appName:'BaleVPN Provider Lab',platform:({win32:4,linux:5,darwin:3})[process.platform]||0,platformVersion:process.platform,device:1,deviceName:'BaleVPN Lab '+crypto.randomUUID().slice(0,8),language:1};}
function profileFields(p,verify){
 registrationProfile(p);if(!Number.isInteger(p.platform)||p.platform<0||p.platform>6||p.device!==1||p.language!==1)throw new RpcError('invalid_profile');
 const offset=verify?2:0;
 return Buffer.concat([w.string(3+offset,p.appName,64),w.field(4+offset,p.appId,0),w.field(5+offset,w.uint(p.appBuild,0xffffffffn),0),w.string(6+offset,p.appVersion,64),w.field(7+offset,p.platform,0),w.string(8+offset,p.platformVersion,64),w.field(9+offset,p.device,0),w.string(10+offset,p.deviceName,64),w.field(11+offset,p.language,0)]);
}
class AuthSession{
 #connect;#rpc;#loggedRpc;#needsProfile=false;#profile;#stage='idle';#busy=false;#pending;#deliveryMethod=null;#token;#userId;#phone='';#retryAt=0;#error=null;#hint='';#onPush;#epoch=0;
 constructor({connect=Connection.open,profile=createProfile(),onPush=()=>{}}={}){profileFields(profile,false);this.#connect=connect;this.#profile=profile;this.#onPush=onPush;}
 async #run(action){if(this.#busy)throw new RpcError('account_busy');this.#busy=true;this.#error=null;const epoch=this.#epoch;try{const result=await action();if(epoch!==this.#epoch){this.close();throw new RpcError('closed');}return result;}catch(e){const error=e instanceof RpcError?e:new RpcError('invalid_auth_response');if(error.waitSeconds)this.#retryAt=Date.now()+error.waitSeconds*1000;this.#error={reason:error.reason,...error.major===undefined?{}:{major:error.major,minor:error.minor},...error.waitSeconds?{waitSeconds:error.waitSeconds}:{}};throw error;}finally{this.#busy=false;}}
 async #connection(){if(this.#rpc?.status.phase==='ready')return this.#rpc;this.#rpc?.close();this.#loggedRpc=null;const epoch=this.#epoch,rpc=await this.#connect({onPush:this.#onPush});if(epoch!==this.#epoch){rpc.close();throw new RpcError('closed');}this.#rpc=rpc;return rpc;}
 async start({country,nationalNumber,internationalNumber},{registrationProfile:mode}={}){return this.#run(async()=>{
  if(this.#token)throw new RpcError('already_signed_in');if(Date.now()<this.#retryAt)throw new RpcError('cooldown',undefined,undefined,Math.ceil((this.#retryAt-Date.now())/1000));
  if(!/^[A-Z]{2}$/.test(country)||!/^\d{5,15}$/.test(nationalNumber)||BigInt(nationalNumber)===0n||!/^\+[1-9]\d{5,14}$/.test(internationalNumber))throw new RpcError('invalid_phone');
  // An explicit diagnostic choice, never a fallback or an OTP resend loop.
  // Keep the lab's honest name/version/device metadata in both profiles.
  if(mode!==undefined)this.#profile=createProfile({registrationProfile:mode});
  this.#deliveryMethod=null;const rpc=await this.#connection();this.#pending=null;
  const response=await rpc.request(100,Buffer.concat([w.field(2,BigInt(nationalNumber),0),w.string(3,country,2),w.field(4,0,0),w.field(5,this.#profile.appId,0)]));
  const f=response.fields,userId=w.one(f,3,0,0n).toString(),username=w.str(f,2,256),method=w.number(f,5,3n),digits=w.number(f,9)||5,delay=Math.min(w.number(f,6),3600);
  if(userId==='0'||!username||digits<3||digits>9)throw new RpcError('invalid_auth_response');
  this.#pending={userId,username,digits};this.#deliveryMethod=method;this.#userId=userId;this.#phone=internationalNumber;this.#retryAt=Date.now()+delay*1000;this.#stage='code';return {method,digits,retryAfter:delay};
 });}
 async verify(code){return this.#run(async()=>{
  if(this.#stage!=='code'||!this.#pending)throw new RpcError('no_pending_code');if(this.#rpc?.status.phase!=='ready'){this.#deliveryMethod=null;throw new RpcError('login_connection_expired');}
  if(typeof code!=='string'||!new RegExp('^\\d{'+this.#pending.digits+'}$').test(code))throw new RpcError('invalid_code_format');
  let response;try{response=await this.#rpc.request(101,Buffer.concat([w.field(2,Number(code),0),w.string(3,this.#pending.username,256),w.string(4,'',0),profileFields(this.#profile,true)]));}
  catch(e){if(e.major===184){this.#deliveryMethod=null;this.#stage='password';const details=await this.#rpc.request(131);this.#hint=w.str(details.fields,4,256);return {twoFactorRequired:true};}throw e;}
  return this.#verified(response.fields);
 });}
 async password(value){return this.#run(async()=>{
  if(this.#stage!=='password'||this.#rpc?.status.phase!=='ready')throw new RpcError('no_pending_password');
  if(typeof value!=='string'||!value||Buffer.byteLength(value)>1024)throw new RpcError('invalid_password_format');
  const response=await this.#rpc.request(132,w.string(2,value,1024));return this.#verified(response.fields);
 });}
 async #verified(fields){const token=w.str(fields,2,16384);if(!token)throw new RpcError('invalid_auth_response');this.#token=token;this.#pending=null;this.#deliveryMethod=null;this.#hint='';
  this.#needsProfile=!!w.number(fields,3,1n);return this.#login();
 }
 async #login(){this.#stage='authenticating';const response=await this.#rpc.login(Buffer.concat([w.string(2,this.#token,16384),profileFields(this.#profile,false)]));const uid=w.one(response.fields,14,0,0n).toString();
  if(w.number(response.fields,2,1n))throw new RpcError('client_version_rejected');
  if(uid==='0'||uid!==this.#userId)throw new RpcError('login_account_mismatch');this.#loggedRpc=this.#rpc;this.#stage=this.#needsProfile?'profile_required':'authenticated';return {authenticated:true,...this.#needsProfile?{profileRequired:true}:{}};
 }
 async restore(record){return this.#run(async()=>{
  if(this.#token)throw new RpcError('already_signed_in');if(record?.provider!=='igap'||!/^\d{1,20}$/.test(record.userId)||record.userId==='0'||typeof record.token!=='string'||!record.token||Buffer.byteLength(record.token)>16384)throw new RpcError('invalid_saved_session');
  profileFields(record.profile,false);this.#deliveryMethod=null;this.#profile=record.profile;this.#userId=record.userId;this.#token=record.token;this.#phone=record.loginPhone||'';this.#needsProfile=record.needsProfile===true;this.#stage='restoring';await this.#connection();return this.#login();
 });}
 async resume(){return this.#run(async()=>{if(!this.#token||!this.#userId)throw new RpcError('no_saved_session');await this.#connection();return this.#login();});}
 async completeProfile(name){return this.#run(async()=>{if(this.#stage!=='profile_required'||this.#rpc?.status.phase!=='ready')throw new RpcError('no_pending_profile');if(typeof name!=='string'||!name.trim()||Buffer.byteLength(name)>128)throw new RpcError('invalid_profile_name');await this.#rpc.request(105,w.string(2,name.trim(),128));this.#needsProfile=false;this.#stage='authenticated';return {authenticated:true};});}
 async logout(){return this.#run(async()=>{if(!this.#token)throw new RpcError('not_authenticated');await this.#connection();if(this.#loggedRpc!==this.#rpc)await this.#login();await this.#rpc.request(127);this.#rpc.close();this.#token=null;this.#pending=null;this.#deliveryMethod=null;this.#phone='';this.#userId=null;this.#stage='idle';this.#loggedRpc=null;return {loggedOut:true};});}
 exportSession(){if(!this.#token||!['authenticated','profile_required'].includes(this.#stage))throw new RpcError('session_not_ready');return {provider:'igap',userId:this.#userId,token:this.#token,profile:{...this.#profile},loginPhone:this.#phone,needsProfile:this.#needsProfile};}
 get connection(){if(this.#stage!=='authenticated'||this.#loggedRpc!==this.#rpc||this.#rpc?.status.phase!=='ready')throw new RpcError('not_authenticated');return this.#rpc;}
 stop(){if(this.#busy)throw new RpcError('account_busy');this.#deliveryMethod=null;this.#rpc?.close();this.#loggedRpc=null;}
 close(){this.#epoch++;this.#rpc?.close();this.#loggedRpc=null;this.#token=null;this.#pending=null;this.#deliveryMethod=null;this.#phone='';this.#userId=null;this.#stage='idle';this.#hint='';this.#needsProfile=false;}
 get state(){if(this.#stage==='code'&&this.#rpc?.status.phase!=='ready')this.#deliveryMethod=null;return {stage:this.#stage,busy:this.#busy,connected:this.#rpc?.status.phase==='ready',signedIn:this.#stage==='authenticated'&&this.#loggedRpc===this.#rpc&&this.#rpc?.status.phase==='ready',hasSession:!!this.#token,userId:this.#userId||null,maskedPhone:this.#phone?'•••• '+this.#phone.slice(-4):'',retryAfter:Math.max(0,Math.ceil((this.#retryAt-Date.now())/1000)),hint:this.#hint,deliveryMethod:this.#stage==='code'?this.#deliveryMethod:null,registrationProfile:registrationProfile(this.#profile),error:this.#error,providerVerified:false};}
}
module.exports={AuthSession,createProfile,profileFields,APP_ID,REGISTRATION_PROFILES};
