'use strict';
const {CallPrivacy:IgapPrivacy}=require('../igap/privacy.cjs');
const {CallPrivacy:RubikaPrivacy}=require('../rubika/call-privacy.cjs');
const supported=provider=>['igap','rubika','eitaa'].includes(provider);
function fail(reason){throw Object.assign(new Error('Call privacy '+reason),{reason});}
async function operate(provider,account,{allow=false,signal}={}){
 if(!supported(provider))return {supported:false,verified:false,allowedForEveryone:false,mode:'unknown',changed:false};
 if(signal?.aborted)fail('closed');const identity=account?.state;if(!identity?.signedIn||!identity.userId)fail('not_authenticated');let result,helper;const abort=()=>helper?.close?.();signal?.addEventListener('abort',abort,{once:true});
 try{
  if(provider==='eitaa'){if(typeof account.getCallPrivacy!=='function'||typeof account.allowAllCalls!=='function')fail('call_privacy_unavailable');const reply=await account[allow?'allowAllCalls':'getCallPrivacy']();result={supported:true,mode:reply.callPrivacy?.mode,allowedForEveryone:reply.callPrivacy?.allowedEveryone,verified:true,changed:!!reply.changed};}
  else if(provider==='igap'){helper=new IgapPrivacy(account);const reply=await helper[allow?'ensureEveryone':'read']();result={supported:true,mode:reply.allowed?'everyone':'custom',allowedForEveryone:reply.allowed,verified:reply.verified,changed:!!reply.changed?.length,voice:reply.voice,video:reply.video};}
  else{helper=new RubikaPrivacy(account);const reply=await helper[allow?'allowEveryone':'read']();result={supported:reply.supported,mode:({Everybody:'everyone',MyContacts:'contacts',Nobody:'nobody'})[reply.permission]||'unknown',allowedForEveryone:reply.allowedForEveryone,verified:allow?reply.verified===true:reply.supported===true,changed:reply.changed===true,callExclusionCount:reply.callExclusionCount};}
  const current=account.state;if(signal?.aborted||!current.signedIn||current.userId!==identity.userId)fail('account_binding_changed');
  if(!['everyone','contacts','nobody','custom','unknown'].includes(result.mode)||typeof result.allowedForEveryone!=='boolean'||typeof result.verified!=='boolean')fail('invalid_privacy_response');return result;
 }finally{signal?.removeEventListener('abort',abort);helper?.close?.();}
}
module.exports={supported,operate};
