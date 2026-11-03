'use strict';
const TYPES=new Set(['ShowPhone','ShowPhoto','CanJoinChat','CanCalled','ShowLastOnline','ShowBirthDate']);
const plain=v=>v&&typeof v==='object'&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v));
function exceptions(value){
 if(!Array.isArray(value)||value.length>128)throw Error('Invalid call privacy exceptions');
 return value.map(entry=>{if(!plain(entry)||Object.keys(entry).some(k=>!['setting_type','exclude_users','include_users'].includes(k))||!TYPES.has(entry.setting_type))throw Error('Invalid call privacy exceptions');const result={setting_type:entry.setting_type};for(const key of ['exclude_users','include_users'])if(Object.hasOwn(entry,key)){const users=entry[key];if(users!==null&&(!Array.isArray(users)||users.length>512||users.some(id=>typeof id!=='string'||!/^[A-Za-z0-9_-]{8,128}$/.test(id))))throw Error('Invalid call privacy exceptions');result[key]=users===null?null:[...users];}return result;});
}
function validSettingInput(value){
 if(!plain(value)||Object.keys(value).length!==2||Object.keys(value).some(k=>!['settings','update_parameters'].includes(k))||!plain(value.settings)||value.settings.can_called_by!=='Everybody')return false;
 const keys=Object.keys(value.settings);if(keys.some(k=>!['can_called_by','exceptions'].includes(k))||!Array.isArray(value.update_parameters)||value.update_parameters.length!==keys.length||new Set(value.update_parameters).size!==keys.length||value.update_parameters.some(k=>!keys.includes(k)))return false;
 if(Object.hasOwn(value.settings,'exceptions'))try{if(exceptions(value.settings.exceptions).some(entry=>entry.setting_type==='CanCalled'))return false;}catch{return false;}
 return true;
}
function otherExceptions(setting){return exceptions(setting.exceptions??[]).filter(entry=>entry.setting_type!=='CanCalled');}
function sameOthers(a,b){const encode=value=>otherExceptions(value).map(entry=>JSON.stringify(entry)).sort();return JSON.stringify(encode(a))===JSON.stringify(encode(b));}
module.exports={exceptions,validSettingInput,otherExceptions,sameOthers};
