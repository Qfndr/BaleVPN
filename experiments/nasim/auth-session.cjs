const {HttpClient, ApiError, duid} = require('./http-client.cjs');
const {countries} = require('../providers/phone.cjs');
function id(value) {
  if (typeof value === 'number' && (!Number.isSafeInteger(value) || value < 1)) throw new ApiError('invalid_auth_response');
  if (typeof value === 'bigint' && value < 1n) throw new ApiError('invalid_auth_response');
  if (!['string','number','bigint'].includes(typeof value)) throw new ApiError('invalid_auth_response');
  const result=String(value);if(!/^[A-Za-z0-9_-]{1,128}$/.test(result)||result==='0')throw new ApiError('invalid_auth_response');return result;
}
function secret(value) { return typeof value==='string' && /^[\x21-\x7e]{16,16384}$/.test(value); }
class AuthSession {
  #create;
  #client;
  #deviceId;
  #stage='idle';
  #busy=false;
  #epoch=0;
  #record;
  #pending;
  #verified;
  #phone='';
  #hint='';
  #retryAt=0;
  #error=null;
  #signedIn=false;
  #selfConfirmed=false;

  constructor({deviceId=duid(), createClient=options=>new HttpClient(options)}={}) {
    this.#deviceId=deviceId;this.#create=createClient;
    // Validate the device profile without opening a connection.
    new HttpClient({deviceId}).close();
  }
  #transport() {
    if(!this.#client)this.#client=this.#create({deviceId:this.#deviceId});return this.#client;
  }
  async #run(operation) {
    if(this.#busy)throw new ApiError('account_busy');this.#busy=true;this.#error=null;const epoch=this.#epoch;
    const guard=()=>{if(epoch!==this.#epoch)throw new ApiError('closed');};
    try{const result=await operation(guard);guard();return result;}
    catch(error){const safe=error instanceof ApiError?error:new ApiError('invalid_auth_response');
      if(epoch===this.#epoch){this.#error={reason:safe.reason,...safe.statusCode?{statusCode:safe.statusCode}:{},...safe.serviceType?{serviceType:safe.serviceType}:{}};
        if(safe.waitSeconds)this.#retryAt=Math.max(this.#retryAt,Date.now()+safe.waitSeconds*1000);}
      throw safe;
    }finally{this.#busy=false;}
  }
  async start({country,nationalNumber,internationalNumber}) {
    return this.#run(async guard=>{
      if(this.#record)throw new ApiError('already_signed_in');
      if(Date.now()<this.#retryAt)throw new ApiError('cooldown',undefined,undefined,Math.ceil((this.#retryAt-Date.now())/1000));
      const selected=countries.find(item=>item.iso===country);
      if(!selected||typeof nationalNumber!=='string'||!/^\d{5,15}$/.test(nationalNumber)||
          internationalNumber!=='+'+selected.code+nationalNumber||!/^\+[1-9]\d{5,14}$/.test(internationalNumber))throw new ApiError('invalid_phone');
      const phone={countryCode:'+'+selected.code,mobile:nationalNumber,subsystem:'client'};
      // A lost reply does not prove the service did not send a code. Preserve
      // the official UI's 90-second resend interval even after that failure.
      this.#retryAt=Date.now()+90000;
      await this.#transport().request('/otp/sendByMobile',phone);guard();
      this.#pending=phone;this.#phone=internationalNumber;this.#verified=null;this.#hint='';
      this.#stage='code';this.#retryAt=Date.now()+90000;return {codeRequested:true,retryAfter:90};
    });
  }
  async verify(code) {
    return this.#run(async guard=>{
      if(this.#stage!=='code'||!this.#pending)throw new ApiError('no_pending_code');
      if(typeof code!=='string'||!/^\d{3,10}$/.test(code))throw new ApiError('invalid_code_format');
      const response=await this.#transport().request('/user/login',{otp:code,...this.#pending});guard();
      return this.#result(response,guard);
    });
  }
  async #result(response,guard,depth=0,deviceReply=false) {
    guard();if(!response||typeof response!=='object'||Array.isArray(response)||depth>3)throw new ApiError('invalid_auth_response');
    const next=response.nextState||(deviceReply?'active':undefined);
    if(response.verifiedToken!==undefined){if(!secret(response.verifiedToken))throw new ApiError('invalid_auth_response');this.#verified=response.verifiedToken;}
    switch(next){
      case 'active':{
        if(!secret(response.token))throw new ApiError('invalid_auth_response');
        const userId=id(response.userID),clientId=id(response.clientID);
        this.#record={provider:'nasim',userId,clientId,token:response.token,deviceId:this.#deviceId,loginPhone:this.#phone};
        this.#pending=null;this.#verified=null;this.#hint='';this.#signedIn=true;this.#selfConfirmed=true;this.#stage='authenticated';return {authenticated:true};
      }
      case 'newDevice':{
        // A registration reply must not recursively register more sessions.
        if(!this.#verified||deviceReply||depth!==0)throw new ApiError('invalid_auth_response');
        this.#stage='authenticating';
        const result=await this.#transport().request('/device/register',{os:'web',company:'web'},{verifiedToken:this.#verified});guard();
        return this.#result(result,guard,depth+1,true);
      }
      case 'newUser':
        if(!this.#verified)throw new ApiError('invalid_auth_response');this.#stage='profile_required';return {profileRequired:true};
      case 'checkTwoFA':
        if(!this.#verified||response.twoFAPasswordHint!==undefined&&typeof response.twoFAPasswordHint!=='string')throw new ApiError('invalid_auth_response');
        this.#hint=(response.twoFAPasswordHint||'').slice(0,256);this.#stage='password';return {twoFactorRequired:true};
      default:throw new ApiError('invalid_auth_response');
    }
  }
  async password(password) {
    return this.#run(async guard=>{
      if(this.#stage!=='password'||!this.#verified)throw new ApiError('no_pending_password');
      if(typeof password!=='string'||!password||Buffer.byteLength(password)>1024)throw new ApiError('invalid_password_format');
      const response=await this.#transport().request('/twoFA/checkInLogin',{password},{verifiedToken:this.#verified});guard();return this.#result(response,guard);
    });
  }
  async completeProfile(name) {
    return this.#run(async guard=>{
      if(this.#stage!=='profile_required'||!this.#verified)throw new ApiError('no_pending_profile');
      if(typeof name!=='string'||!name.trim()||Buffer.byteLength(name)>128)throw new ApiError('invalid_profile_name');
      const response=await this.#transport().request('/user/register',{firstname:name.trim()},{verifiedToken:this.#verified});guard();return this.#result(response,guard);
    });
  }
  async #resume(guard) {
    const response=await this.#transport().request('/mxb/user/status',{}, {token:this.#record.token,clientId:this.#record.clientId});guard();
    if(!response||typeof response.active!=='boolean')throw new ApiError('invalid_auth_response');
    if(response.userID!==undefined&&id(response.userID)!==this.#record.userId)throw new ApiError('login_account_mismatch');
    // This protected API confirms token acceptance. Its active flag is the
    // cross-messenger feature status, not account validity or user identity.
    this.#selfConfirmed=response.userID!==undefined;this.#signedIn=true;this.#stage='authenticated';return {authenticated:true,selfConfirmed:this.#selfConfirmed};
  }
  async restore(record) {
    return this.#run(async guard=>{
      if(this.#record)throw new ApiError('already_signed_in');
      if(record?.provider!=='nasim'||!secret(record.token)||!/^web\.[a-z0-9.-]{12,80}$/.test(record.deviceId)||
          typeof record.loginPhone!=='string'||!/^\+[1-9]\d{5,14}$/.test(record.loginPhone))throw new ApiError('invalid_saved_session');
      const userId=id(record.userId),clientId=id(record.clientId);
      this.#client?.close();this.#client=null;this.#deviceId=record.deviceId;
      this.#record={provider:'nasim',userId,clientId,token:record.token,deviceId:record.deviceId,loginPhone:record.loginPhone};
      this.#phone=record.loginPhone;this.#signedIn=false;this.#selfConfirmed=false;this.#stage='restoring';return this.#resume(guard);
    });
  }
  async resume() { return this.#run(async guard=>{if(!this.#record)throw new ApiError('no_saved_session');this.#signedIn=false;this.#selfConfirmed=false;this.#stage='restoring';return this.#resume(guard);}); }
  async logout() {
    return this.#run(async guard=>{
      if(!this.#record)throw new ApiError('not_authenticated');
      await this.#transport().logout({token:this.#record.token});guard();this.#clear();return {loggedOut:true};
    });
  }
  exportSession() { if(!this.#record||!this.#signedIn)throw new ApiError('session_not_ready');return {...this.#record}; }
  #clear() { this.#client?.close();this.#client=null;this.#record=null;this.#pending=null;this.#verified=null;this.#phone='';this.#hint='';this.#signedIn=false;this.#selfConfirmed=false;this.#stage='idle'; }
  stop() { if(this.#busy)throw new ApiError('account_busy');this.#client?.close();this.#client=null;this.#signedIn=false;this.#selfConfirmed=false; }
  close() { this.#epoch++;this.#clear(); }
  get state() { return {provider:'nasim',stage:this.#stage,busy:this.#busy,connected:this.#signedIn,
    signedIn:this.#signedIn,hasSession:!!this.#record,userId:this.#record?.userId||null,
    clientId:this.#record?.clientId||null,maskedPhone:this.#phone?'•••• '+this.#phone.slice(-4):'',
    retryAfter:Math.max(0,Math.ceil((this.#retryAt-Date.now())/1000)),hint:this.#hint,error:this.#error,
    selfConfirmed:this.#selfConfirmed,providerVerified:false,callReady:false}; }
}
module.exports = {AuthSession};
