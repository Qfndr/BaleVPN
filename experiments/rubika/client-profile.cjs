// Explicit protocol compatibility, never an implicit change to a saved session.
'use strict';
const WEB='web',ANDROID='android-4.1.1-compat';
function mode(value=WEB){if(![WEB,ANDROID].includes(value))throw new Error('invalid_client_profile');return value;}
function fromRecord(record){return mode(record?.profile?.protocolProfile);}
function client(profile,language){return mode(profile)===ANDROID?
 {app_name:'Main',app_version:'4.1.1',platform:'Android',package:'app.rbmain.a',lang_code:language}:
 {app_name:'Main',app_version:'4.4.34',platform:'Web',package:'web.rubika.ir',lang_code:language};}
function registration(profile,device,language){return {token_type:mode(profile)===ANDROID?'Firebase':'Web',token:'',
 app_version:profile===ANDROID?'MA_4.1.1':'WB_4.4.34',lang_code:language,system_version:device.systemVersion,
 device_model:device.deviceModel,device_hash:device.deviceHash,...profile===ANDROID?{is_multi_account:false}:{}};}
module.exports={WEB,ANDROID,mode,fromRecord,client,registration};
