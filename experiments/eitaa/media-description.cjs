// Private conversion for two native single-audio tunnel endpoints. No browser
// video/SCTP projection, direct ICE fallback, account lookup or media readiness.
'use strict';
const crypto=require('node:crypto'),net=require('node:net');
const {validateSignal}=require('./call-signaling.cjs');
const MAX_SDP=65535,MAX_CANDIDATES=64;
class DescriptionError extends Error{constructor(reason){super('Eitaa media '+reason);this.reason=reason;}}
const fail=reason=>{throw new DescriptionError(reason);};
const token=(v,max=128)=>typeof v==='string'&&v.length>0&&v.length<=max&&/^[A-Za-z0-9_.+/-]+$/.test(v);
const uint=(v,max)=>/^\d+$/.test(String(v))&&Number.isSafeInteger(Number(v))&&Number(v)>=0&&Number(v)<=max;
function candidate(value,ufrag){
 if(typeof value!=='string'||value.length>2048||/[\x00-\x1f\x7f]/.test(value)||!value.startsWith('candidate:'))fail('invalid_candidate');if(value.trim()!==value)fail('candidate_whitespace');
 const p=value.split(' ');if(p.some(v=>!v))fail('candidate_whitespace');if(p.length<8||!token(p[0].slice(10),64))fail('invalid_candidate');if(!['1','2'].includes(p[1]))fail('unsupported_candidate_component');if(p[2].toLowerCase()!=='udp')fail('unsupported_candidate_transport');if(!uint(p[3],0xffffffff))fail('invalid_candidate_priority');if(!net.isIP(p[4]))fail('invalid_candidate_address');if(!uint(p[5],65535)||Number(p[5])===0)fail('invalid_candidate_port');if(p[6]!=='typ')fail('invalid_candidate');
 if(p[7]!=='relay')fail('non_relay_candidate');if((p.length-8)%2)fail('invalid_candidate');const seen=new Set();
 for(let i=8;i<p.length;i+=2){const name=p[i],value=p[i+1];if(seen.has(name))fail('invalid_candidate');seen.add(name);
  if(['raddr'].includes(name)){if(!net.isIP(value))fail('invalid_candidate');}
  else if(name==='rport'){if(!uint(value,65535))fail('invalid_candidate');}
  else if(name==='ufrag'){if(value!==ufrag)fail('candidate_context_mismatch');}
  else if(['generation','network-id','network-cost'].includes(name)){if(!uint(value,0xffffffff))fail('invalid_candidate');}
  else fail('unsupported_candidate_attribute');
 }
 return {value,component:Number(p[1])};
}
function checkedSignal(v){try{return validateSignal(v);}catch{fail('invalid_media_signal');}}
function media(value){
 if(!value||!Array.isArray(value.payloadTypes)||!Array.isArray(value.rtpExtensions))fail('invalid_audio');
 const codecs=value.payloadTypes.filter(c=>c&&typeof c.name==='string'&&c.name.toLowerCase()==='opus');if(codecs.length!==1)fail('opus_required');const c=codecs[0];
 if(!Number.isInteger(c.id)||c.id<96||c.id>127||c.clockrate!==48000||c.channels!==2)fail('invalid_audio');
 const parameters={};if(c.parameters!==undefined){if(!c.parameters||typeof c.parameters!=='object'||Array.isArray(c.parameters)||Object.keys(c.parameters).length>32)fail('invalid_audio');for(const [k,v]of Object.entries(c.parameters)){if(!token(k,64)||typeof v!=='string'||v.length>256||! /^[A-Za-z0-9_.+/-]*$/.test(v))fail('invalid_audio');parameters[k]=v;}}
 const feedback=[];if(c.feedbackTypes!==undefined){if(!Array.isArray(c.feedbackTypes)||c.feedbackTypes.length>16)fail('invalid_audio');for(const f of c.feedbackTypes){if(!f||!token(f.type,64)||typeof f.subtype!=='string'||f.subtype!==''&&!token(f.subtype,64))fail('invalid_audio');feedback.push({type:f.type,subtype:f.subtype});}}
 const extensions=[],ids=new Set(),uris=new Set();for(const e of value.rtpExtensions){if(!e||!Number.isInteger(e.id)||e.id<1||e.id>255||ids.has(e.id)||typeof e.uri!=='string'||e.uri.length>512||! /^(?:urn:|https?:\/\/)[\x21-\x7e]+$/.test(e.uri)||uris.has(e.uri))fail('invalid_audio');ids.add(e.id);uris.add(e.uri);extensions.push({id:e.id,uri:e.uri});}
 return {ssrc:String(Number(value.ssrc)|0),rtpExtensions:extensions,payloadTypes:[{id:c.id,name:'opus',clockrate:48000,channels:2,...Object.keys(parameters).length?{parameters}:{},...feedback.length?{feedbackTypes:feedback}:{}}]};
}
function shape(initial,type){
 if(!['offer','answer'].includes(type))fail('invalid_description_type');checkedSignal(initial);if(initial['@type']!=='InitialSetup'||initial.video||initial.screencast)fail('unsupported_media');
 const fingerprints=initial.fingerprints;if(fingerprints.length!==1||type==='offer'&&fingerprints[0].setup!=='actpass'||type==='answer'&&!['active','passive'].includes(fingerprints[0].setup))fail('invalid_dtls_role');
 return media(initial.audio);
}
function unique(lines,prefix,required=true){const values=[...new Set(lines.filter(l=>l.startsWith(prefix)).map(l=>l.slice(prefix.length)))];if(values.length>1||required&&values.length!==1)fail('ambiguous_description');return values[0];}
function fromDescription(description){
 if(!description||!['offer','answer'].includes(description.type)||typeof description.sdp!=='string'||Buffer.byteLength(description.sdp)>MAX_SDP||/[\0]/.test(description.sdp)||/\r(?!\n)/.test(description.sdp))fail('invalid_description');
 const lines=description.sdp.split(/\r?\n/).filter(Boolean);if(lines[0]!=='v=0'||lines.some(l=>l.startsWith('a=crypto:'))||lines.filter(l=>l.startsWith('m=')).length!==1)fail('unsupported_media');
 const m=lines.find(l=>l.startsWith('m=')).split(' ');if(m[0]!=='m=audio'||!uint(m[1],65535)||Number(m[1])===0||m[2]!=='UDP/TLS/RTP/SAVPF'||m.length<4||m.slice(3).some(pt=>!uint(pt,127)))fail('invalid_audio');
 if(unique(lines,'a=mid:')!=='0'||!lines.includes('a=sendrecv')||!lines.includes('a=rtcp-mux'))fail('unsupported_media');
 const bundle=unique(lines,'a=group:BUNDLE ',false);if(bundle!==undefined&&bundle!=='0')fail('unsupported_media');
 const fingerprint=unique(lines,'a=fingerprint:').split(' '),ufrag=unique(lines,'a=ice-ufrag:'),pwd=unique(lines,'a=ice-pwd:'),setup=unique(lines,'a=setup:');if(fingerprint.length!==2)fail('invalid_description');
 const sources=[...new Set(lines.filter(l=>l.startsWith('a=ssrc:')).map(l=>l.slice(7).split(' ')[0]))];if(sources.length!==1)fail('unsupported_media');if(!uint(sources[0],0xffffffff)||Number(sources[0])===0)fail('invalid_audio');
 const payloadTypes=[];
 for(const pt of m.slice(3)){const rtp=unique(lines,'a=rtpmap:'+pt+' ',false);if(!rtp)continue;const [name,clockrate,channels]=rtp.split('/');if(name.toLowerCase()!=='opus')continue;
  const parameters={},fmtp=unique(lines,'a=fmtp:'+pt+' ',false);if(fmtp!==undefined)for(const raw of fmtp.split(';')){const p=raw.trim().split('=');if(p.length!==2||!token(p[0],64)||['__proto__','prototype','constructor','toJSON'].includes(p[0])||Object.hasOwn(parameters,p[0]))fail('invalid_audio');parameters[p[0]]=p[1];}
  const feedbackTypes=lines.filter(l=>l.startsWith('a=rtcp-fb:'+pt+' ')).map(l=>{const p=l.slice(('a=rtcp-fb:'+pt+' ').length).split(' ');if(p.length>2)fail('invalid_audio');return {type:p[0],subtype:p[1]||''};});
  payloadTypes.push({id:Number(pt),name,clockrate:Number(clockrate),channels:Number(channels||1),parameters,feedbackTypes});
 }
 const rtpExtensions=lines.filter(l=>l.startsWith('a=extmap:')).map(l=>{const p=l.slice(9).split(' ');if(p.length!==2||!uint(p[0],255))fail('unsupported_audio_extension');return {id:Number(p[0]),uri:p[1]};});
 const initial={'@type':'InitialSetup',fingerprints:[{hash:fingerprint[0],fingerprint:fingerprint[1],setup}],ufrag,pwd,audio:{ssrc:sources[0],rtpExtensions,payloadTypes}};
 initial.audio=shape(initial,description.type);const values=[...new Set(lines.filter(l=>l.startsWith('a=candidate:')).map(l=>candidate(l.slice(2),ufrag)).filter(c=>c.component===1).map(c=>c.value))];if(!values.length||values.length>MAX_CANDIDATES)fail('no_relay_candidate');
 const candidateMessages=[];for(let i=0;i<values.length;i+=16)candidateMessages.push({'@type':'Candidates',candidates:values.slice(i,i+16).map(sdpString=>({sdpString,sdpMLineIndex:0,sdpMid:'0'}))});
 return {initialSetup:initial,candidateMessages};
}
function toDescription(initial,candidateMessages,{type}={}){
 const audio=shape(initial,type);if(!Array.isArray(candidateMessages)||candidateMessages.length>64)fail('invalid_candidate');const candidates=[];
 for(const message of candidateMessages){checkedSignal(message);if(message['@type']!=='Candidates')fail('invalid_candidate');for(const c of message.candidates){if(c.sdpMLineIndex!==undefined&&c.sdpMLineIndex!==0||c.sdpMid!==undefined&&c.sdpMid!=='0')fail('candidate_context_mismatch');const parsed=candidate(c.sdpString,initial.ufrag);if(parsed.component===2)continue;const value=parsed.value;if(!candidates.includes(value))candidates.push(value);if(candidates.length>MAX_CANDIDATES)fail('invalid_candidate');}}
 if(!candidates.length)fail('no_relay_candidate');const f=initial.fingerprints[0],codec=audio.payloadTypes[0],sessionId=crypto.randomBytes(8).readBigUInt64BE()>>1n;
 const ssrc=String(Number(audio.ssrc)>>>0);const lines=['v=0',`o=- ${sessionId} 2 IN IP4 127.0.0.1`,'s=-','t=0 0','a=group:BUNDLE 0','a=msid-semantic: WMS tunnel',`a=fingerprint:${f.hash} ${f.fingerprint}`,`m=audio 9 UDP/TLS/RTP/SAVPF ${codec.id}`,'c=IN IP4 0.0.0.0',`a=ice-ufrag:${initial.ufrag}`,`a=ice-pwd:${initial.pwd}`,`a=setup:${f.setup}`,'a=ice-options:trickle','a=mid:0','a=sendrecv','a=rtcp-mux','a=rtcp-rsize'];
 for(const e of audio.rtpExtensions)lines.push(`a=extmap:${e.id} ${e.uri}`);lines.push(`a=rtpmap:${codec.id} opus/48000/2`);
 if(codec.parameters)lines.push(`a=fmtp:${codec.id} `+Object.entries(codec.parameters).map(([k,v])=>k+'='+v).join(';'));
 for(const f of codec.feedbackTypes||[])lines.push(`a=rtcp-fb:${codec.id} ${f.type}${f.subtype?' '+f.subtype:''}`);
 lines.push(`a=msid:tunnel audio${ssrc}`,`a=ssrc:${ssrc} cname:tunnel`,`a=ssrc:${ssrc} msid:tunnel audio${ssrc}`,...candidates.map(c=>'a='+c),'a=end-of-candidates');
 const sdp=lines.join('\r\n')+'\r\n';if(Buffer.byteLength(sdp)>MAX_SDP)fail('description_too_large');return {type,sdp};
}
module.exports={fromDescription,toDescription,DescriptionError};
