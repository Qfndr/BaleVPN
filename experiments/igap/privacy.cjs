// Current web-v3 call-only privacy RPCs; no login, OTP or implicit retry.
'use strict';
const {wire:w}=require('./signaling.cjs');
class PrivacyError extends Error{constructor(reason){super('iGap privacy '+reason);this.reason=reason;}}
const fail=reason=>{throw new PrivacyError(reason);};
const TYPES=Object.freeze({voice:4,video:5}),GET=143,SET=144;
function rule(fields,type){
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
 async #get(type,guard){guard();const reply=await this.#rpc.request(GET,w.field(2,type,0));guard();if(reply?.action!==GET+30000||!(reply.fields instanceof Map))fail('invalid_privacy_response');return rule(reply.fields,type);}
 async #read(guard){return {voice:await this.#get(TYPES.voice,guard),video:await this.#get(TYPES.video,guard)};}
 async #run(work){if(this.#busy)fail('account_busy');const epoch=this.#epoch;this.#busy=true;const guard=()=>this.#guard(epoch);try{guard();return await work(guard);}finally{this.#busy=false;}}
 read(){return this.#run(async guard=>{const levels=await this.#read(guard);return {provider:'igap',voice:levels.voice,video:levels.video,allowed:levels.voice===0&&levels.video===0,verified:true};});}
 ensureEveryone(){return this.#run(async guard=>{const before=await this.#read(guard),changed=[];
  for(const [name,type]of Object.entries(TYPES)){if(before[name]===0)continue;guard();const reply=await this.#rpc.request(SET,Buffer.concat([w.field(2,type,0),w.field(3,0,0)]));guard();
   try{if(reply?.action!==SET+30000||!(reply.fields instanceof Map)||w.number(reply.fields,2,8n)!==type||w.number(reply.fields,3,2n)!==0)fail('invalid_privacy_response');}catch{fail('invalid_privacy_response');}changed.push(name);
  }
  const after=await this.#read(guard);if(after.voice!==0||after.video!==0)fail('privacy_not_applied');return {provider:'igap',voice:0,video:0,allowed:true,verified:true,changed};
 });}
 close(){this.#closed=true;this.#epoch++;this.#rpc=null;this.#self=null;}
}
module.exports={CallPrivacy,PrivacyError,TYPES,GET,SET};
