// Offline lab fixtures only; no provider or relay sockets are opened.
'use strict';
const crypto=require('node:crypto'),{service}=require('./eitaa-call-session-fixture.cjs');
function description(type){return {type,sdp:['v=0','o=- 1 2 IN IP4 127.0.0.1','s=-','t=0 0','a=group:BUNDLE 0','a=fingerprint:sha-256 '+Array(32).fill('AA').join(':'),`a=setup:${type==='offer'?'actpass':'active'}`,'m=audio 9 UDP/TLS/RTP/SAVPF 111','c=IN IP4 0.0.0.0','a=ice-ufrag:fixture-ufrag','a=ice-pwd:fixture-private-ice-password','a=mid:0','a=sendrecv','a=rtcp-mux','a=rtpmap:111 opus/48000/2','a=ssrc:1234 cname:fixture','a=candidate:1 1 udp 1 192.0.2.1 40000 typ relay',''].join('\r\n')};}
function fixture(calls=[]){
 const api=service({ids:[8000001,8000002],identifyToken:token=>8000000+Number(token.split('-').at(-1))}),natives=[];
 const own=options=>Number(options.token.split('-').at(-1));
 function createAccountClient(options){const slot=own(options);return {close(){},async request(method){calls.push({slot,action:'eitaa-target-self'});if(method!=='users.getUsers')throw Error('Unexpected fixture metadata request');return [{_:'user',self:true,id:8000000n+BigInt(slot),username:'FixtureAccount'+slot}];}};}
 function createClient(options){const slot=own(options),client=api.createClient(options);return {close:()=>client.close(),async request(method,input={}){
  calls.push({slot,action:'eitaa-call-'+method});if(method==='contacts.getContacts'){const other=3-slot;return {_:'contacts.contacts',contacts:[{_:'contact',user_id:8000000n+BigInt(other),mutual:true}],users:[{_:'user',id:8000000n+BigInt(other),access_hash:-1000n-BigInt(slot)}]};}
  if(method==='contacts.resolveUsername'){const other=3-slot;return {_:'contacts.resolvedPeer',peer:{_:'peerUser',user_id:8000000n+BigInt(other)},users:[{_:'user',id:8000000n+BigInt(other),access_hash:-1000n-BigInt(slot),username:'FixtureAccount'+other}],chats:[]};}
  return client.request(method,input);
 }};}
 const open=async()=>{const certificate=crypto.randomBytes(80).toString('hex'),native={certificate,latest:{phase:'prepared'},get publicCertificate(){return certificate;},get state(){return {...this.latest};},
  async configure(call,options){this.call=call;this.options=options;this.latest={phase:'configured'};},async offer(){this.latest.phase='connecting';return description('offer');},async answer(){this.latest.phase='connecting';return description('answer');},async setAnswer(){
   const other=natives.find(n=>n.certificate===this.options.trustedCertificates[0]);if(!other||other.options.trustedCertificates[0]!==certificate)throw Error('Fixture pin mismatch');for(const n of [this,other])n.latest={phase:'connected',relayPair:true,mediaConnected:true,peerAuthenticated:true,proxyReady:n.options.role==='client',socksAddress:n.options.role==='client'?'127.0.0.1:'+n.options.socksPort:null,receivedBytes:1048576,sentBytes:65536,quic:{rttMs:18,lostPackets:2,sentPackets:1000,congestionWindow:12000,sendWindowBytes:81600,profile:n.options.throughput?'throughput':'balanced'}};
  },async addCandidate(){},close(){this.latest={phase:'closed'};}};natives.push(native);return native;};
 return {api,natives,open,createClient,createAccountClient};
}
module.exports={fixture};
