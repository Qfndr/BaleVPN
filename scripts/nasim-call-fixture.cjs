const assert=require('node:assert/strict');
const codec=require('../experiments/nasim/call-codec.cjs');
const {CallSession}=require('../experiments/nasim/call-session.cjs');
const sdp=type=>({type,sdp:'v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=fingerprint:sha-256 '+Array(32).fill('AA').join(':')+'\r\na=ice-pwd:fixture-private-ice\r\n'});
function fixture({autoConfig=true,open,sendHook}={}){
 const accounts=new Map(),controllers=new Map(),natives=[],sent=[];let sequence=0;
 const raw=(sender,type,callUUID,callData)=>({type:'msgGroupCall',from:{id:Number(sender)},senderClientID:'client-'+sender,time:Date.now(),data:{type,callUUID,callData}});
 const deliver=(to,message)=>controllers.get(to).handleEvent(codec.incoming(message,to));
 function config(to,caller='41',callUUID='fixture-call-1'){
  return {type:'msgGroupCall',senderClientID:'client-'+caller,time:Date.now(),data:{type:'config',callUUID,callData:{method:'audio',
   participants:[{userID:41},{userID:42}],invitedParticipantUserID:caller==='41'?42:41,
   stunServer:{url:'relay.fixture.gap.im:3478'},turnServer:{url:'relay.fixture.gap.im:3478',username:'fixture-private-user',password:'fixture-private-password'}}}};
 }
 for(const id of ['41','42']){
  const account={state:{provider:'nasim',signedIn:true,userId:id,clientId:'client-'+id},disconnects:0,
   disconnectSignals(){this.disconnects++;this.signalConnection=null;}};
  account.signalConnection={send:async(signal,{peerId})=>{
   const request=codec.outgoing(signal,id,peerId);sent.push({sender:id,peerId,signal:structuredClone(signal)});
   if(sendHook){const result=await sendHook({sender:id,peerId,signal,account});if(result!==undefined)return result;}
   if(signal.type==='callRequest'){if(autoConfig){deliver(id,config(id,id));deliver(peerId,config(peerId,id));}}
   else deliver(peerId,raw(id,signal.type,signal.callUUID,request.body.data.callData));
   return {acknowledged:true,reply:null};
  }};accounts.set(id,account);
  const controller=new CallSession(account,{executable:'fixture-bridge',open:open||(async()=>{
   const certificate=(++sequence).toString(16).padStart(2,'0').repeat(80);
   const bridge={publicCertificate:certificate,ops:[],latest:{phase:'prepared'},get state(){return {...this.latest};},
    async configure(call,options){this.ops.push({op:'configure',call,options});this.call=call;this.options=options;this.latest.phase='configured';},
    async offer(){this.ops.push({op:'offer'});this.latest.phase='connecting';return sdp('offer');},
    async answer(offer){assert.equal(offer.type,'offer');this.ops.push({op:'answer'});this.latest.phase='connecting';return sdp('answer');},
    async setAnswer(answer){assert.equal(answer.type,'answer');this.ops.push({op:'setAnswer'});
     const other=natives.find(n=>n.publicCertificate===this.options.trustedCertificates[0]);
     if(!other||other.options.trustedCertificates[0]!==certificate)throw Object.assign(Error('fixture wrong pin'),{reason:'invalid_pairing'});
     for(const peer of [this,other])peer.latest={phase:'connected',mediaConnected:true,peerAuthenticated:true,proxyReady:peer.options.role==='client',relayPair:true};
    },async addCandidate(candidate){this.ops.push({op:'candidate',candidate});},
    close(){this.ops.push({op:'close'});this.latest={phase:'closed'};}};
   natives.push(bridge);return bridge;
  })});controllers.set(id,controller);
 }
 async function prepare(){
  const a=controllers.get('41'),b=controllers.get('42');a.setAllowedPeers(['42']);b.setAllowedPeers(['41']);
  const [one,two]=await Promise.all([a.prepare({role:'client'}),b.prepare({role:'server'})]);
  a.trustCertificate(two.publicCertificate);b.trustCertificate(one.publicCertificate);return {a,b};
 }
 function close(){for(const c of controllers.values())c.reset();}
 return {accounts,controllers,natives,sent,deliver,raw,config,prepare,close};
}
async function waitFor(predicate){const deadline=Date.now()+2000;while(!predicate()){if(Date.now()>deadline)throw Error('Controller fixture timed out');await new Promise(r=>setTimeout(r,5));}}
module.exports={fixture,sdp,waitFor};
