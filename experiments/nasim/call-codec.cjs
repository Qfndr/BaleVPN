// Factual current msgGroupCall wire shapes. No socket, media, auto-answer or
// service credential logging. Unknown/group/video calls are not admitted.
const net=require('node:net');
function invalid(){throw new Error('Invalid Nasim call signal');}
function userId(value){
 if(typeof value==='number'){if(!Number.isSafeInteger(value)||value<1)invalid();return String(value);}
 if(typeof value!=='string'||! /^[1-9]\d{0,15}$/.test(value)||BigInt(value)>BigInt(Number.MAX_SAFE_INTEGER))invalid();return value;
}
function clientId(value){if(typeof value!=='string'||! /^[A-Za-z0-9_-]{1,128}$/.test(value))invalid();return value;}
function uuid(value){if(typeof value!=='string'||! /^[-A-Za-z0-9_:]{1,128}$/.test(value))invalid();return value;}
function object(value){if(!value||typeof value!=='object'||Array.isArray(value))invalid();return value;}
function text(value,max){if(typeof value!=='string'||!value||Buffer.byteLength(value)>max||value.includes('\0'))invalid();return value;}
function sdp(value,type){
 object(value);if(value.type!==type)invalid();const content=text(value.sdp,65535);
 if(!content.startsWith('v=0')||!/^m=audio .*UDP\/TLS\/RTP\/SAVPF/m.test(content)||
  !/^a=fingerprint:sha-256 (?:[A-Fa-f0-9]{2}:){31}[A-Fa-f0-9]{2}\r?$/m.test(content)||/^a=crypto:/m.test(content))invalid();
 return {type,sdp:content};
}
function endpoint(value){
 text(value,256);
 // The web client prepends stun:/turn: itself. Credentials are separate.
 const match=value.match(/^(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)(?::([0-9]{1,5}))?(?:\?transport=(udp|tcp))?$/);
 if(!match||match[2]&&(Number(match[2])<1||Number(match[2])>65535))invalid();
 const host=match[1];if(host.startsWith('[')&&net.isIP(host.slice(1,-1))!==6)invalid();return value;
}
function participants(value,self){
 if(!Array.isArray(value)||value.length!==2)invalid();
 const ids=value.map(item=>userId(object(item).userID));
 if(new Set(ids).size!==2||!ids.includes(self))invalid();return ids;
}
function ice(value){
 object(value);const candidate=text(value.sdpCandidate,4096),mid=text(value.sdpMid,128);
 if(!candidate.startsWith('candidate:')||/[\r\n]/.test(candidate+mid)||
  !Number.isInteger(value.sdpMLineIndex)||value.sdpMLineIndex<0||value.sdpMLineIndex>32)invalid();
 return {sdpCandidate:candidate,sdpMid:mid,sdpMLineIndex:value.sdpMLineIndex,
  clientID:value.clientID===null?null:clientId(value.clientID)};
}
function outgoing(signal,self,peer){
 self=userId(self);peer=userId(peer);if(self===peer)invalid();object(signal);
 const type=signal.type;let data;
 if(type==='callRequest'){
  if(signal.callUUID!==undefined||object(signal.callData).method!=='audio')invalid();data={type,callData:{method:'audio'}};
 }else{
  const callUUID=uuid(signal.callUUID);let callData;
  if(type==='offer'||type==='answer'){
   callData=sdp(signal.callData,type);
   if(type==='answer'){
    callData.clientID=clientId(signal.callData.clientID);const participant=object(signal.callData.participantData);
    if(typeof participant.isCameraEnabled!=='boolean'||typeof participant.isMicrophoneMuted!=='boolean')invalid();
    callData.participantData={isCameraEnabled:participant.isCameraEnabled,isMicrophoneMuted:participant.isMicrophoneMuted};
   }
  }else if(type==='ice')callData=ice(signal.callData);
  else if(type==='accept')callData={};
  else if(['bye','reject','busy'].includes(type))callData=null;
  else invalid();
  data={type,callUUID,callData};
 }
 return {topic:'u/'+peer+'/'+self,body:{type:'msgGroupCall',data}};
}
function incoming(message,self){
 self=userId(self);object(message);if(message.type!=='msgGroupCall')invalid();
 const data=object(message.data),type=data.type,callUUID=uuid(data.callUUID);
 const result={provider:'nasim',type,callUUID};
 if(type==='config'||type==='callLog'){
  const call=object(data.callData);if(call.method!=='audio')invalid();
  const ids=participants(call.participants,self);result.participantIds=ids;result.peerId=ids.find(id=>id!==self);result.method='audio';
  if(type==='config'){
   const invited=userId(call.invitedParticipantUserID);if(!ids.includes(invited))invalid();
   const stun=object(call.stunServer),turn=object(call.turnServer);
   result.senderClientId=clientId(message.senderClientID);
   if(typeof message.time!=='number'||!Number.isFinite(message.time)||message.time<0)invalid();
   result.time=message.time;result.invitedUserId=invited;
   result.iceServers=[{urls:'stun:'+endpoint(stun.url)},
    {urls:'turn:'+endpoint(turn.url),username:text(turn.username,1024),credential:text(turn.password,1024)}];
  }else{
   if(!['notAnswered','not_answered','accepted','finished','rejected','busied'].includes(call.status))invalid();
   result.status=call.status;
  }
 }else{
  result.senderId=userId(message.from?.id);result.senderClientId=clientId(message.senderClientID);
  if(type==='offer'||type==='answer'){
   result.description=sdp(data.callData,type);
   if(type==='answer')result.targetClientId=clientId(data.callData.clientID);
  }else if(type==='ice')result.candidate=ice(data.callData);
  else if(!['accept','reject','bye','busy'].includes(type))invalid();
 }
 return result;
}
// callRequest returns callData/callUUID independently of an event type. The
// official client binds that UUID before processing its later config event.
function requestCallUUID(response,self,peer){
 self=userId(self);peer=userId(peer);
 if(response?.data?.callUUID===undefined)return null;
 const data=object(response.data),call=object(data.callData);
 if(call.method!=='audio'||self===peer)invalid();
 const ids=participants(call.participants,self);
 if(!ids.includes(peer))invalid();
 return uuid(data.callUUID);
}
module.exports={outgoing,incoming,userId,clientId,requestCallUUID};
