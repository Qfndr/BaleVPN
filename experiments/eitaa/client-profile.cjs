// Protocol compatibility is account-local and selected only before a new login.
'use strict';
const crypto=require('node:crypto');
const WEB='web',ANDROID='android-7.1.8-compat';
const ANDROID_ENDPOINT='https://armita.eitaa.com/eitaa/index.php',ANDROID_API_ID=1782360,ANDROID_API_HASH='0d870902a3e09e7cdc57e5d7bd68da6b';
function mode(value=WEB){if(![WEB,ANDROID].includes(value))throw new Error('invalid_client_profile');return value;}
function fromProfile(profile){return mode(profile?.protocolProfile);}
function fromRecord(record){return fromProfile(record?.profile);}
function validImei(value,profile=WEB){return typeof value==='string'&&(mode(profile)===WEB?/^[a-z0-9]{15}__web$/:/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/).test(value);}
function createImei(profile=WEB){return mode(profile)===ANDROID?crypto.randomUUID():crypto.randomBytes(8).toString('hex').slice(0,15)+'__web';}
module.exports={WEB,ANDROID,mode,fromProfile,fromRecord,validImei,createImei,ANDROID_ENDPOINT,ANDROID_API_ID,ANDROID_API_HASH};
