// Only aggregate metadata from the protected getMySessions model. Never read
// session keys, device names, IPs or locations merely to report their presence.
'use strict';
const {types}=require('node:util');
class SessionStatusError extends Error{constructor(reason='invalid_session_status',stage){super('Rubika session status '+reason);this.reason=reason;if(stage)this.stage=stage;}}
const fail=()=>{throw new SessionStatusError();};
const plain=value=>value&&typeof value==='object'&&!types.isProxy(value)&&!Array.isArray(value)&&[Object.prototype,null].includes(Object.getPrototypeOf(value));
function own(value,key){const descriptor=Object.getOwnPropertyDescriptor(value,key);if(!descriptor)return undefined;if(!Object.hasOwn(descriptor,'value'))fail();return descriptor.value;}
function decodeSessionStatus(value){
 if(!plain(value))fail();
 const active=own(value,'active_session'),others=own(value,'other_sessions');
 if(active!==null&&active!==undefined&&!plain(active)||!Array.isArray(others)||types.isProxy(others)||others.length>128)fail();
 for(let i=0;i<others.length;i++)if(!plain(own(others,String(i))))fail();
 const result={activeSessionPresent:active!==null&&active!==undefined,otherSessionCount:others.length};
 if(result.activeSessionPresent){const current=own(active,'isCurrentSession');if(current!==undefined&&current!==null){if(typeof current!=='boolean')fail();result.currentFlag=current;}}
 return result;
}
module.exports={decodeSessionStatus,SessionStatusError};
