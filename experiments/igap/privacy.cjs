// Current web-v3 call-only privacy RPCs; no login, OTP or implicit retry.
'use strict';
const {wire:w}=require('./signaling.cjs');
class PrivacyError extends Error{constructor(reason,reply){super('iGap privacy '+reason);this.reason=reason;if(reason==='invalid_privacy_response'&&reply!==undefined)this.privacyDiagnostic=privacyDiagnostic(reply);}}
const fail=reason=>{throw new PrivacyError(reason);};
const TYPES=Object.freeze({voice:4,video:5}),GET=143,SET=144;
// Shape-only diagnostics: never include response bodies, strings or identifiers.
function privacyDiagnostic(reply){
 const result={action:Number.isInteger(reply?.action)&&reply.action>=0&&reply.action<=65535?reply.action:null,fields:[],rules:[],emptyRules:null};
 if(!(reply?.fields instanceof Map)){result.malformed=true;return result;}
 const fields=reply.fields;result.emptyRules=!(fields.get(4)?.length);if(fields.size>16)result.truncated=true;
 for(const [number,items]of [...fields].slice(0,16)){
  if(!Number.isInteger(number)||number<1||number>536870911||!Array.isArray(items)){result.malformed=true;continue;}
  const entry={number,count:Math.min(items.length,65535),items:[]};if(items.length>16)result.truncated=true;
  for(const item of items.slice(0,16)){
   if(![0,1,2,5].includes(item?.wire)){result.malformed=true;continue;}
   const info={wire:item.wire};if([30143,30144].includes(result.action)&&[2,3].includes(number)&&item.wire===0&&typeof item.value==='bigint'&&item.value>=0n&&item.value<=8n)info.enum=Number(item.value);if(item.wire===2){if(!Buffer.isBuffer(item.value)&&!(item.value instanceof Uint8Array)){result.malformed=true;continue;}info.length=item.value.byteLength;}
   entry.items.push(info);
   if(number===4&&item.wire===2&&item.value.byteLength<=1024){try{const nested=w.parse(item.value),rule={};for(const [field,name]of [[1,'level'],[2,'type']]){const values=nested.get(field);if(!values)continue;if(values.length!==1||values[0].wire!==0||typeof values[0].value!=='bigint'||values[0].value<0n||values[0].value>8n){rule.malformed=true;continue;}rule[name]=Number(values[0].value);}result.rules.push(rule);}catch{result.rules.push({malformed:true});}}
  }result.fields.push(entry);
 }return result;
}
function rule(fields,type){
 // The pinned original API returns one rule in top-level type2/level3.
 // Current web descriptors instead define repeated nested rules4; live service
 // still returns the original shape. Neither permits treating an empty reply
 // as an allowed call rule, nor mixing the two representations.
 if(fields.has(2)||fields.has(3)){
  if(fields.has(4))fail('invalid_privacy_response');
  try{if(w.number(fields,2,8n)!==type)fail('invalid_privacy_response');return w.number(fields,3,2n);}catch{fail('invalid_privacy_response');}
 }
 const items=fields.get(4)||[];if(items.length>16)fail('invalid_privacy_response');const rules=new Map();
 try{for(const item of items){if(item.wire!==2)fail('invalid_privacy_response');const f=w.parse(item.value),t=w.number(f,2,8n),level=w.number(f,1,2n);if(rules.has(t))fail('invalid_privacy_response');rules.set(t,level);}}catch{fail('invalid_privacy_response');}
 if(!rules.has(type))fail('invalid_privacy_response');return rules.get(type);
}
class CallPrivacy{
 #account;#rpc;#self;#busy=false;#closed=false;#epoch=0;
 constructor(account){this.#account=account;}
 #guard(epoch){if(this.#closed||epoch!==this.#epoch)fail('closed');const state=this.#account?.state;let rpc;try{rpc=this.#account.connection;}catch{fail('not_authenticated');}
  if(state?.signedIn!==true||typeof state.userId!=='string'||! /^[1-9]\d{0,19}$/.test(state.userId)||BigInt(state.userId)>0xffffffffffffffffn||typeof rpc?.request!=='function')fail('not_authenticated');
  if(this.#rpc&&(rpc!==this.#rpc||state.userId!==this.#self))fail('privacy_connection_changed');this.#rpc=rpc;this.#self=state.userId;
 }
 async #get(type,guard){guard();const reply=await this.#rpc.request(GET,w.field(2,type,0));guard();try{if(reply?.action!==GET+30000||!(reply.fields instanceof Map))fail('invalid_privacy_response');return rule(reply.fields,type);}catch(error){if(error instanceof PrivacyError&&error.reason==='invalid_privacy_response')throw new PrivacyError(error.reason,reply);throw error;}}
 async #read(guard){return {voice:await this.#get(TYPES.voice,guard),video:await this.#get(TYPES.video,guard)};}
 async #run(work){if(this.#busy)fail('account_busy');const epoch=this.#epoch;this.#busy=true;const guard=()=>this.#guard(epoch);try{guard();return await work(guard);}finally{this.#busy=false;}}
 read(){return this.#run(async guard=>{const levels=await this.#read(guard);return {provider:'igap',voice:levels.voice,video:levels.video,allowed:levels.voice===0&&levels.video===0,verified:true};});}
 ensureEveryone(){return this.#run(async guard=>{const before=await this.#read(guard),changed=[];
  for(const [name,type]of Object.entries(TYPES)){if(before[name]===0)continue;guard();const reply=await this.#rpc.request(SET,Buffer.concat([w.field(2,type,0),w.field(3,0,0)]));guard();
   try{if(reply?.action!==SET+30000||!(reply.fields instanceof Map)||w.number(reply.fields,2,8n)!==type||w.number(reply.fields,3,2n)!==0)fail('invalid_privacy_response');}catch{throw new PrivacyError('invalid_privacy_response',reply);}changed.push(name);
  }
  const after=await this.#read(guard);if(after.voice!==0||after.video!==0)fail('privacy_not_applied');return {provider:'igap',voice:0,video:0,allowed:true,verified:true,changed};
 });}
 close(){this.#closed=true;this.#epoch++;this.#rpc=null;this.#self=null;}
}
module.exports={CallPrivacy,PrivacyError,privacyDiagnostic,TYPES,GET,SET};
