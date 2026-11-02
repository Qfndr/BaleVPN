// Executes only pinned pure SDP parser/projector helpers; no UI/runtime/media.
'use strict';
const fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {toDescription,fromDescription}=require('../experiments/eitaa/media-description.cjs');
const source=fs.readFileSync(process.env.BALEVPN_EITAA_CALL_UI||'','utf8');assert.equal(crypto.createHash('sha256').update(source).digest('hex'),'877c5cf4317887f7144a682b18a6c01fe443206d1e12e0fb81a13df740049c40');
function slice(start,end,max){const a=source.indexOf(start),b=source.indexOf(end,a);assert.ok(a>=0&&b>a&&b-a<max);return source.slice(a,b);}
const context=vm.createContext({Js:(instance,map,value)=>{assert.equal(map.has(instance),false);map.set(instance,value);},_s:(instance,map,value)=>{assert.equal(map.has(instance),true);map.set(instance,value);return value;},Ms:(instance,map)=>{assert.equal(map.has(instance),true);return map.get(instance);}});
vm.runInContext(slice('var pu,uu;class KG','function XG(',10000)+slice('function zS(','function qC(',100)+slice('function JG(','function ZG(',2000)+slice('function mk(','class EQ ',2500)+';globalThis.officialParse=nf;globalThis.officialProject=mk;',context,{timeout:1000});
const candidates=[{'@type':'Candidates',candidates:[{sdpString:'candidate:1 1 udp 123 203.0.113.1 3478 typ relay raddr 0.0.0.0 rport 0',sdpMid:'0',sdpMLineIndex:0}]}];
let checked=0;
for(const type of ['offer','answer'])for(const source of [12345678,0x7fffffff,0x80000000,0xffffffff]){
 const initial={'@type':'InitialSetup',fingerprints:[{hash:'sha-256',fingerprint:Array(32).fill('A5').join(':'),setup:type==='offer'?'actpass':'active'}],ufrag:'fixture-ufrag',pwd:'fixture-private-ice-password',audio:{ssrc:String(source|0),rtpExtensions:[{id:1,uri:'urn:ietf:params:rtp-hdrext:sdes:mid'}],payloadTypes:[{id:111,name:'opus',clockrate:48000,channels:2,parameters:{minptime:'10',useinbandfec:'1'},feedbackTypes:[{type:'transport-cc',subtype:''}]}]}};
 const description=toDescription(initial,candidates,{type}),parsed=context.officialParse(description.sdp),projected=JSON.parse(JSON.stringify(context.officialProject(parsed)));
 assert.deepEqual(projected,initial);assert.deepEqual(fromDescription(description).initialSetup,initial);checked++;
}
console.log('PASS '+checked+' official Eitaa SDP parser/InitialSetup projections: offer/answer, ICE, DTLS, Opus, RTP extensions and signed SSRC boundary values; pinned pure helpers only, no UI startup/network/account/call');
