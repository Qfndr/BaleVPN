'use strict';
const net=require('node:net');
const MODE='nasim-client-relay-server-public';
const PROOF='client-relay/server-public';
const DIAGNOSTIC_REASONS=new Set(['noSelectedPair','noNomination','multipleNominations','nominationNotSucceeded',
 'missingCandidateStats','statsLimit','addressFamilyMismatch','localCandidateRejected','remoteCandidateRejected','verified']);
const DIAGNOSTIC_KINDS=new Set([null,'host','srflx','prflx','relay','unknown']);
function routeDiagnostic(value){
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==4||
  !Object.keys(value).every(key=>['reason','localKind','remoteKind','currentGeneration'].includes(key))||
  !DIAGNOSTIC_REASONS.has(value.reason)||!DIAGNOSTIC_KINDS.has(value.localKind)||!DIAGNOSTIC_KINDS.has(value.remoteKind)||
  typeof value.currentGeneration!=='boolean')return null;
 return {reason:value.reason,localKind:value.localKind,remoteKind:value.remoteKind,currentGeneration:value.currentGeneration};
}
function ip(value){
 if(value.includes('%'))return null;
 const family=net.isIP(value);if(!family)return null;
 if(family===4){const [a,b,c]=value.split('.').map(Number);
  if(a===0||a===10||a===127||a>=224||a===100&&b>=64&&b<=127||a===169&&b===254||a===172&&b>=16&&b<=31||
   a===192&&(b===168||b===0&&c===0||b===0&&c===2||b===88&&c===99)||a===198&&(b===18||b===19||b===51&&c===100)||a===203&&b===0&&c===113)return null;
  return value;
 }
 const canonical=new URL('http://['+value+']/').hostname.slice(1,-1);
 const parts=canonical.split(':');const first=parseInt(parts[0],16),second=parseInt(parts[1]||'0',16);
 if(!Number.isInteger(first)||first<0x2000||first>0x3fff||first===0x2001&&(second<0x200||second===0xdb8)||first===0x2002||first===0x3fff&&second<0x1000)return null;
 return canonical;
}
function allows(value,role,local=false){
   if(!['client','server'].includes(role)||typeof value!=='string'||value.length>4096||/[\r\n\0]/.test(value))return false;
   const p=value.trim().split(/\s+/);if(p.length!==8||!/^candidate:[A-Za-z0-9+/]{1,64}$/.test(p[0])||!['1','2'].includes(p[1])||p[2].toLowerCase()!=='udp'||
    !/^\d{1,10}$/.test(p[3])||Number(p[3])>0xffffffff||p[6]!=='typ'||!/^\d{1,5}$/.test(p[5])||Number(p[5])<1||Number(p[5])>65535)return false;
   if(!ip(p[4]))return false;
   return (role==='server')===local?Number(p[5])>=1024&&['host','srflx'].includes(p[7]):p[7]==='relay';
}
module.exports={allows,MODE,PROOF,routeDiagnostic};
