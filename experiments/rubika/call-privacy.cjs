// Narrow call-privacy operation: preserve phone/profile/last-seen and non-call
// exceptions. A separate readback, never a setter ACK, proves the result.
'use strict';
const {HttpClient,ApiError}=require('./http-client.cjs');
const profiles=require('./client-profile.cjs');
const privacy=require('./privacy-wire.cjs');
const PERMISSIONS=new Set(['Everybody','MyContacts','Nobody']);
function project(value){
 const setting=value?.privacy_setting;if(!setting||typeof setting!=='object'||Array.isArray(setting))throw new ApiError('invalid_privacy_response');
 if(setting.can_called_by===undefined)return {supported:false,permission:null,callExclusionCount:null,allowedForEveryone:false};
 if(!PERMISSIONS.has(setting.can_called_by))throw new ApiError('invalid_privacy_response');
 const entries=setting.exceptions??[];if(!Array.isArray(entries)||entries.length>128)throw new ApiError('invalid_privacy_response');let excluded=0;
 for(const entry of entries){if(!entry||typeof entry!=='object'||Array.isArray(entry)||typeof entry.setting_type!=='string')throw new ApiError('invalid_privacy_response');if(entry.setting_type!=='CanCalled')continue;const users=entry.exclude_users??[];if(!Array.isArray(users)||users.length>512)throw new ApiError('invalid_privacy_response');excluded+=users.length;}
 return {supported:true,permission:setting.can_called_by,callExclusionCount:excluded,allowedForEveryone:setting.can_called_by==='Everybody'&&excluded===0};
}
class CallPrivacy{
 #account;#create;#busy=false;#client;#epoch=0;
 constructor(account,{createClient=options=>new HttpClient(options)}={}){if(!account||typeof createClient!=='function')throw new ApiError('invalid_request');this.#account=account;this.#create=createClient;}
 #record(){const state=this.#account.state;let record;if(state?.provider!=='rubika'||state.signedIn!==true||state.selfConfirmed!==true)throw new ApiError('not_authenticated');try{record=this.#account.exportSession();}catch{throw new ApiError('not_authenticated');}if(record?.provider!=='rubika'||record.userId!==state.userId||['userId','auth','privateKey','publicKey'].some(k=>typeof record[k]!=='string'||!record[k]))throw new ApiError('invalid_account_binding');return record;}
 async #run(allow){
  if(this.#busy)throw new ApiError('account_busy');this.#busy=true;let client;const epoch=this.#epoch;
  try{const record=this.#record();let protocolProfile;try{protocolProfile=profiles.fromRecord(record);}catch{throw new ApiError('invalid_account_binding');}const guard=()=>{if(epoch!==this.#epoch)throw new ApiError('closed');const current=this.#record();let mode;try{mode=profiles.fromRecord(current);}catch{throw new ApiError('account_binding_changed');}if(['userId','auth','privateKey','publicKey'].some(k=>record[k]!==current[k])||mode!==protocolProfile)throw new ApiError('account_binding_changed');};
   client=this.#client=this.#create({language:'fa',protocolProfile});await client.discover();guard();const beforeReply=await client.request('getPrivacySetting',{}, {credentials:record}),before=project(beforeReply);guard();if(!allow)return before;if(!before.supported)throw new ApiError('call_privacy_unavailable');
   if(before.allowedForEveryone)return {...before,changed:false,verified:true,needsExceptionUpdate:false};
   const input={settings:{can_called_by:'Everybody'},update_parameters:['can_called_by']};
   if(before.callExclusionCount>0){try{input.settings.exceptions=privacy.otherExceptions(beforeReply.privacy_setting);input.update_parameters.push('exceptions');}catch{throw new ApiError('invalid_privacy_response');}}
   await client.request('setSetting',input,{credentials:record});guard();
   const afterReply=await client.request('getPrivacySetting',{}, {credentials:record}),after=project(afterReply);guard();let preserved=true;if(input.settings.exceptions)try{preserved=privacy.sameOthers(beforeReply.privacy_setting,afterReply.privacy_setting);}catch{preserved=false;}
   return {...after,changed:true,verified:after.allowedForEveryone&&preserved,needsExceptionUpdate:after.callExclusionCount>0,...preserved?{}:{otherSettingsPreserved:false}};
  }finally{client?.close();if(this.#client===client)this.#client=null;this.#busy=false;}
 }
 read(){return this.#run(false);}
 allowEveryone(){return this.#run(true);}
 close(){this.#epoch++;this.#client?.close();this.#client=null;}
}
module.exports={CallPrivacy,project};
