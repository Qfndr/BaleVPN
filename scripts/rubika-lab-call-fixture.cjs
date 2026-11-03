'use strict';
const assert=require('node:assert/strict'),{pair}=require('./rubika-account-media-fixture.cjs');
function description(type){return {type,sdp:['v=0','o=- 1 2 IN IP4 127.0.0.1','s=-','t=0 0','a=group:BUNDLE 0','a=fingerprint:sha-256 '+Array(32).fill('A5').join(':'),`a=setup:${type==='offer'?'actpass':'active'}`,
 'm=audio 9 UDP/TLS/RTP/SAVPF 111','c=IN IP4 0.0.0.0','a=ice-ufrag:fixture-ufrag','a=ice-pwd:fixture-private-ice-password','a=mid:0','a=sendrecv','a=rtcp-mux','a=rtpmap:111 opus/48000/2','a=ssrc:1234 cname:fixture','a=candidate:1 1 udp 1 192.0.2.1 40000 typ relay',''].join('\r\n')};}
async function fixture(options={}){
 const broker=await pair(options),natives=[];
 const open=async()=>{
  const certificate=(natives.length+1).toString(16).padStart(2,'0').repeat(80),state={phase:'prepared',mediaConnected:false,relayPair:false,peerAuthenticated:false,proxyReady:false,receivedBytes:2048,sentBytes:1024,
   quic:{rttMs:12,lostPackets:0,sentPackets:32,congestionWindow:65536,sendWindowBytes:262144,profile:'throughput'}},native={state,certificate,closed:0,options:null,call:null};
  native.bridge={publicCertificate:certificate,get state(){return {...state};},async configure(call,config){assert.equal(call.provider,'rubika');native.call=call;native.options=config;state.phase='configured';},
   async offer(){state.phase='connecting';return description('offer');},async answer(){state.phase='connecting';return description('answer');},async setAnswer(){
    for(const target of natives.filter(n=>n.closed===0&&n.options)){Object.assign(target.state,{phase:'connected',mediaConnected:true,relayPair:true,peerAuthenticated:true,proxyReady:target.options.role==='client',socksAddress:target.options.role==='client'?'127.0.0.1:'+target.options.socksPort:null});}
   },async addCandidate(){},close(){native.closed++;state.phase='closed';}};natives.push(native);return native.bridge;
 };
 const accounts=new Map(broker.accounts.map((account,i)=>{
  Object.assign(broker.accountStates[i],{stage:'authenticated',busy:false,hasSession:true,connected:true,maskedPhone:'•••• 000'+(i+1),providerVerified:false});
  account.stop=()=>{broker.accountStates[i].signedIn=false;broker.accountStates[i].stage='stopped';};account.close=account.stop;
  return [i+1,account];
 }));
 return {broker,natives,accounts,open,createClient:broker.createClient};
}
module.exports={fixture};
