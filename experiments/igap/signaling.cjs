// Experimental plaintext codec, BEFORE iGap connection encryption.
// No sockets, authentication, OTP, storage or production imports.
// Schema references and pinned revisions: docs/igap-research-fa.md.
'use strict';
const MAX_FRAME=50*1024,MAX_SDP=40*1024,MAX_CANDIDATE=4096;
const utf8=new TextDecoder('utf-8',{fatal:true});
function fail(){throw new Error('Invalid iGap signaling frame');}
function uint(value,max=0xffffffffffffffffn){if(typeof value==='number'&&!Number.isSafeInteger(value))fail();if(!['number','bigint'].includes(typeof value))fail();const n=BigInt(value);if(n<0n||n>max)fail();return n;}
function varint(value){let n=uint(value);const bytes=[];do{let b=Number(n&127n);n>>=7n;if(n)b|=128;bytes.push(b);}while(n);return Buffer.from(bytes);}
function text(value,max){if(typeof value!=='string')fail();const b=Buffer.from(value,'utf8');if(b.length>max||utf8.decode(b)!==value)fail();return b;}
function field(id,value,wire=2){return Buffer.concat([varint(id*8+wire),wire===2?varint(value.length):Buffer.alloc(0),wire===2?value:varint(value)]);}
function string(id,value,max){return field(id,text(value,max));}
function frame(action,payload){const b=Buffer.alloc(2);b.writeUInt16LE(action);const result=Buffer.concat([b,payload]);if(result.length>MAX_FRAME)fail();return result;}
function encodeRequest(action,{id,token},args={}){
 if(![900,901,902,903,904,905].includes(action))fail();
 const fields=[field(1,Buffer.concat([string(1,id,128),string(2,token,4096)]))];
 if(!id||!token)fail();
 if(action===901){if(uint(args.peerId)===0n)fail();fields.push(field(2,args.peerId,0),field(3,uint(args.type??0,3n),0),string(4,args.sdp,MAX_SDP));}
 if(action===903)fields.push(string(2,args.sdp,MAX_SDP));
 if(action===904)fields.push(string(2,args.candidate,MAX_CANDIDATE),string(3,args.mid,128),field(4,uint(args.lineIndex,0xffffffffn),0));
 return frame(action,Buffer.concat(fields));
}
function readVarint(buffer,cursor){let n=0n;for(let i=0;i<10;i++){if(cursor.at>=buffer.length)fail();const b=buffer[cursor.at++];if(i===9&&b>1)fail();n|=BigInt(b&127)<<(7n*BigInt(i));if(!(b&128))return n;}fail();}
function parse(buffer){const c={at:0},out=new Map();let count=0;while(c.at<buffer.length){if(++count>2048)fail();const tag=readVarint(buffer,c),id=Number(tag>>3n),wire=Number(tag&7n);if(id<1||id>0x1fffffff)fail();let value;
 if(wire===0)value=readVarint(buffer,c);
 else if(wire===2){const size=Number(readVarint(buffer,c));if(size>buffer.length-c.at)fail();value=buffer.subarray(c.at,c.at+size);c.at+=size;}
 else if(wire===1||wire===5){const size=wire===1?8:4;if(c.at+size>buffer.length)fail();c.at+=size;continue;}
 else fail();
 if(!out.has(id))out.set(id,[]);out.get(id).push({wire,value});}return out;}
function one(fields,id,wire,fallback){const values=fields.get(id);if(!values)return fallback;if(values.length!==1||values[0].wire!==wire)fail();return values[0].value;}
function str(fields,id,max){const bytes=one(fields,id,2,Buffer.alloc(0));if(bytes.length>max)fail();try{return utf8.decode(bytes);}catch{fail();}}
function number(fields,id,max=0xffffffffn){const n=one(fields,id,0,0n);if(n>max)fail();return Number(n);}
function decodeResponse(bytes){if(!(bytes instanceof Uint8Array)||bytes.length<2||bytes.length>MAX_FRAME)fail();const b=Buffer.from(bytes),action=b.readUInt16LE();if(action<30900||action>30905)fail();const fields=parse(b.subarray(2));const response=parse(one(fields,1,2,Buffer.alloc(0)));const result={action,id:str(response,1,128),timestamp:number(response,2)};
 if(action===30900){const servers=fields.get(2)||[];if(servers.length>32)fail();result.iceServers=servers.map(f=>{if(f.wire!==2)fail();const s=parse(f.value),url=str(s,1,2048);if(!/^(stun|stuns|turn|turns):[^\s]+$/i.test(url))fail();return {urls:url,username:str(s,3,1024),credential:str(s,2,2048)};});for(const [key,id]of [['voice',3],['video',4],['screen',5],['secretChat',6]])result[key]=!!number(fields,id,1n);}
 if(action===30901){result.peerId=one(fields,2,0,0n).toString();result.type=number(fields,3,3n);result.sdp=str(fields,4,MAX_SDP);}
 if(action===30903)result.sdp=str(fields,2,MAX_SDP);
 if(action===30904){result.candidate=str(fields,2,MAX_CANDIDATE);result.mid=str(fields,3,128);result.lineIndex=number(fields,4);}
 if(action===30905)result.reason=number(fields,2,7n);
 return result;
}
// Safe report: never include SDP, ICE addresses/credentials, peer IDs or tokens.
function capabilities(config){return {voice:!!config.voice,video:!!config.video,stun:config.iceServers.some(s=>/^stuns?:/i.test(s.urls)),turn:config.iceServers.some(s=>/^turns?:/i.test(s.urls)),providerVerified:false};}
function inspectGreeting(bytes){if(!(bytes instanceof Uint8Array)||bytes.length<2||bytes.length>MAX_FRAME)fail();const b=Buffer.from(bytes);if(b.readUInt16LE()!==30001)fail();const fields=parse(b.subarray(2)),key=str(fields,2,8192);return {action:30001,publicKeyPresent:key.includes('BEGIN PUBLIC KEY'),symmetricKeyLength:number(fields,3),heartbeatSeconds:number(fields,4),providerVerified:false};}
// Internal helpers for the isolated v3 connection experiment; not a production API.
module.exports={encodeRequest,decodeResponse,capabilities,inspectGreeting,MAX_FRAME,wire:{uint,varint,field,string,frame,parse,one,str,number}};
