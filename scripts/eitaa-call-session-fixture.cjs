// Offline service fixture. It transports actual call keys/signaling but never
// sends provider requests or pretends to carry media through Eitaa.
'use strict';
const crypto=require('node:crypto'),codec=require('../experiments/eitaa/call-wire.cjs');
const {protocol}=require('../experiments/eitaa/call-client.cjs'),{CallSession}=require('../experiments/eitaa/call-session.cjs');
const f=require('./eitaa-call-fixtures.cjs');
const clone=v=>codec.decode(codec.object(v));
function account(id){let signed=true;const record={provider:'eitaa',userId:String(id),imei:(id===101?'0123456789abcde':'fedcba987654321')+'__web',token:'fixture-token-'+id};return {record,get state(){return {provider:'eitaa',signedIn:signed,selfConfirmed:signed,userId:record.userId};},exportSession(){return {...record};},stop(){signed=false;}};}
function service({connections=[f.connection],ids=[101,202],identifyToken=token=>Number(token.split('-').at(-1))}={}){
 const queues=new Map(ids.map(id=>[id,[]])),cursors=new Map(ids.map(id=>[id,10])),calls=[],clients=[];let call,nextCallId=f.peer.id;
 function active(forId){return {_:'phoneCall',...call.base,g_a_or_b:forId===call.base.admin_id?call.gb:call.ga,key_fingerprint:call.fingerprint,connections,start_date:f.state.date};}
 const api={queues,calls,clients,override:null,clone,get call(){return call;},
  createClient(options){const self=identifyToken(options.token);const client={closed:false,close(){this.closed=true;},async request(method,input){if(this.closed)throw Object.assign(Error('fixture closed'),{reason:'closed'});calls.push({self,method});if(api.override){const value=await api.override({self,method,input,client});if(value!==undefined)return value;}
   if(method==='updates.getState')return {...f.state,pts:cursors.get(self),seq:cursors.get(self)};
   if(method==='messages.getDhConfig')return {_:'messages.dhConfig',g:2,p:crypto.getDiffieHellman('modp14').getPrime(),version:1,random:crypto.randomBytes(256)};
   if(method==='phone.requestCall'){
    const other=Number(input.user_id.user_id);call={base:{id:nextCallId++,access_hash:f.peer.access_hash,date:f.state.date,admin_id:BigInt(self),participant_id:BigInt(other),protocol:protocol()},hash:Buffer.from(input.g_a_hash)};
    queues.get(other).push({_:'updatePhoneCall',phone_call:{_:'phoneCallRequested',...call.base,g_a_hash:call.hash}});return f.wrap({_:'phoneCallWaiting',...call.base});
   }
   if(method==='phone.receivedCall')return true;
   if(method==='phone.acceptCall'){call.gb=Buffer.from(input.g_b);queues.get(Number(call.base.admin_id)).push({_:'updatePhoneCall',phone_call:{_:'phoneCallAccepted',...call.base,g_b:call.gb}});return f.wrap({_:'phoneCallWaiting',...call.base});}
   if(method==='phone.confirmCall'){call.ga=Buffer.from(input.g_a);call.fingerprint=input.key_fingerprint;queues.get(Number(call.base.participant_id)).push({_:'updatePhoneCall',phone_call:active(Number(call.base.participant_id))});return f.wrap(active(self));}
   if(method==='phone.sendSignalingData'){const other=Number(BigInt(self)===call.base.admin_id?call.base.participant_id:call.base.admin_id);queues.get(other).push({_:'updatePhoneCallSignalingData',phone_call_id:call.base.id,data:Buffer.from(input.data)});return true;}
   if(method==='updates.getDifference'){const updates=queues.get(self).splice(0);if(!updates.length)return {_:'updates.differenceEmpty',date:f.state.date,seq:cursors.get(self)};cursors.set(self,cursors.get(self)+updates.length);return {_:'updates.difference',new_messages:[],new_encrypted_messages:[],other_updates:updates.map(clone),chats:[],users:[],state:{...f.state,pts:cursors.get(self),seq:cursors.get(self)}};}
   if(method==='phone.discardCall'){const update={_:'updatePhoneCall',phone_call:{_:'phoneCallDiscarded',id:call.base.id,reason:{_:input.reason},duration:input.duration}};queues.get(Number(BigInt(self)===call.base.admin_id?call.base.participant_id:call.base.admin_id)).push(update);return f.updates([update]);}
   throw Error('unexpected fixture method');
  }};clients.push(client);return client;}
 };return api;
}
async function pair(t,options={}){
 const api=service(options),aAccount=account(101),bAccount=account(202),aSignals=[],bSignals=[],aSecure=[],bSecure=[];
 const a=new CallSession(aAccount,{allowedPeers:['202'],createClient:o=>api.createClient(o),onSecure:async v=>{aSecure.push(v);await options.onASecure?.(v);},onSignal:async(v,context)=>{aSignals.push(v);await options.onASignal?.(v,context);},onEnd:()=>options.onAEnd?.()});
 const b=new CallSession(bAccount,{allowedPeers:['101'],createClient:o=>api.createClient(o),onSecure:async v=>{bSecure.push(v);await options.onBSecure?.(v);},onSignal:async(v,context)=>{bSignals.push(v);await options.onBSignal?.(v,context);},onEnd:()=>options.onBEnd?.()});
 t.after(()=>{a.close();b.close();});await a.start();await b.start();
 return {api,a,b,aAccount,bAccount,aSignals,bSignals,aSecure,bSecure,async negotiate(){await a.dial({userId:'202',accessHash:-22n});await b.pollOnce();await b.accept();await a.pollOnce();await b.pollOnce();}};
}
const signal={'@type':'Candidates',candidates:[{sdpString:'candidate:fixture 1 udp 1 192.0.2.1 40000 typ relay',sdpMLineIndex:0,sdpMid:'0'}]};
module.exports={account,service,pair,signal};
