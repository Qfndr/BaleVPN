// Fixture only. No service connections or actual credentials.
const assert=require('node:assert/strict');
class FakeAuth{
 constructor(slot,calls){this.slot=slot;this.calls=calls;this.record=null;this.stage='idle';this.registrationProfile='independent';}
 get state(){return {stage:this.stage,registrationProfile:this.registrationProfile,busy:false,signedIn:this.stage==='authenticated',hasSession:!!this.record,connected:['code','authenticated'].includes(this.stage),userId:this.record?.userId||null,maskedPhone:this.record?'•••• 0001':'',deliveryMethod:this.stage==='code'?(this.slot===2?1:0):null,retryAfter:0,error:null};}
 async start(phone,{registrationProfile}={}){if(registrationProfile)this.registrationProfile=registrationProfile;this.calls.push({slot:this.slot,action:'start',phone,registrationProfile:this.registrationProfile});this.stage='code';return {method:0,digits:5};}
 async verify(code){this.calls.push({slot:this.slot,action:'verify'});assert.equal(code,'12345');this.record={provider:'igap',userId:String(this.slot),token:'fixture-secret-token-'+this.slot,profile:{}};this.stage='authenticated';return {authenticated:true};}
 async restore(record){this.calls.push({slot:this.slot,action:'restore'});this.record=record;this.stage='authenticated';return {authenticated:true};}
 async resume(){this.stage='authenticated';return {authenticated:true};}
 exportSession(){return this.record;}
 stop(){this.stage='stopped';}
 close(){this.record=null;this.stage='idle';}
 async logout(){this.close();return {loggedOut:true};}
}
// Two-party server fixture, including pushes delivered to the other account.
// It exercises the real CallSession/HTTP/UI without contacting iGap.
const {wire:w}=require('../experiments/igap/signaling.cjs');
const peers=new WeakMap();
class FakeCallAuth extends FakeAuth{
 constructor(slot,calls,onPush=()=>{}){
  super(slot,calls);this.onPush=onPush;
  if(!peers.has(calls))peers.set(calls,new Map());peers.get(calls).set(slot,this);
  this.connection={request:async(action,body)=>{
   const fields=w.parse(body),id=BigInt(slot),room=501n;let payload=Buffer.alloc(0);
   calls.push({slot,action});
   if(action===913)payload=w.field(2,room,0);
   else if(action===915){const target=peers.get(calls).get(Number(w.one(fields,2,0)));payload=Buffer.concat([w.field(2,id,0),w.field(3,room,0)]);await target.onPush(w.frame(30915,payload));}
   else if(action===916)payload=w.field(2,id,0);
   else if(action===914){payload=Buffer.concat([w.string(2,'fixture.payload.signature',100),w.field(3,id,0)]);const other=peers.get(calls).get(3-slot);if(other){await other.onPush(w.frame(30914,w.field(3,id,0)));const claims=Buffer.from(JSON.stringify({sub:String(3-slot),video:{room:String(room),roomJoin:true},exp:Math.floor(Date.now()/1000)+300})).toString('base64url'),token='fixture.'+claims+'.signature';await other.onPush(w.frame(30914,Buffer.concat([w.string(2,token,1024),w.field(3,BigInt(3-slot),0)])));}}
   else if(action===918){payload=w.field(2,id,0);await peers.get(calls).get(3-slot)?.onPush(w.frame(30918,payload));}
   else throw new Error('Unexpected fixture call');
   return {action:action+30000,fields:w.parse(payload)};
  }};
 }
}
function fakeBridgeFactory(){let index=0;return async()=>{
 const identity=++index;return {publicCertificate:identity.toString(16).repeat(160),state:{phase:'prepared'},
  async connect(session,options){this.state={phase:'connected',role:options.role,mediaConnected:true,
   peerAuthenticated:true,proxyReady:options.role==='client',socksAddress:options.role==='client'?'127.0.0.1:'+options.socksPort:null,
   receivedBytes:12345,sentBytes:2000,quic:options.role==='client'?{rttMs:110,lostPackets:2}:null};},
  close(){this.state={phase:'closed',role:this.state.role};}
 };
};}
class FakeNasimAuth extends FakeAuth{
 constructor(slot,calls){super(slot,calls);if(!nasimPeers.has(calls))nasimPeers.set(calls,new Map());nasimPeers.get(calls).set(slot,this);}
 get state(){const state=super.state;return {...state,provider:'nasim',clientId:this.record?.clientId||null,connected:state.signedIn,events:this.eventsState||{phase:'idle'},callReady:false};}
 async start(phone){this.calls.push({slot:this.slot,action:'nasim-start',phone});this.stage='code';return {codeRequested:true};}
 async verify(code){assert.equal(code,'12345');this.calls.push({slot:this.slot,action:'nasim-verify'});this.record={provider:'nasim',
  userId:String(40+this.slot),clientId:'client-'+this.slot,token:'fixture-nasim-secret-token-'+this.slot,deviceId:'web.fixture-nasim-device-'+this.slot,loginPhone:'+989120000001'};
  this.stage='authenticated';return {authenticated:true};}
 async restore(record){this.calls.push({slot:this.slot,action:'nasim-restore'});this.record=record;this.stage='authenticated';return {authenticated:true};}
 async connectSignals({onEvent=()=>{}}={}){assert.equal(this.stage,'authenticated');this.onEvent=onEvent;this.eventsState={phase:'connected',callEvents:0};
  this.signalConnection={send:async(signal,{peerId})=>{
   const codec=require('../experiments/nasim/call-codec.cjs'),request=codec.outgoing(signal,this.record.userId,peerId);
   this.calls.push({slot:this.slot,action:'nasim-signal',type:signal.type});
   const other=[...nasimPeers.get(this.calls).values()].find(a=>a.record?.userId===peerId);assert.ok(other);
   if(signal.type==='callRequest'){
    for(const target of [this,other])target.onEvent(codec.incoming({type:'msgGroupCall',senderClientID:this.record.clientId,time:Date.now(),data:{type:'config',callUUID:'fixture-nasim-call',callData:{method:'audio',
     participants:[{userID:Number(this.record.userId)},{userID:Number(peerId)}],invitedParticipantUserID:Number(peerId),stunServer:{url:'relay.fixture.gap.im:3478'},turnServer:{url:'relay.fixture.gap.im:3478',username:'fixture-private-turn-user',password:'fixture-private-turn-password'}}}},target.record.userId));
   }else other.onEvent?.(codec.incoming({type:'msgGroupCall',senderClientID:this.record.clientId,from:{id:Number(this.record.userId)},data:request.body.data},other.record.userId));
   return {acknowledged:true};
  }};return {eventsConnected:true};}
 disconnectSignals(){this.eventsState={phase:'closed'};this.signalConnection=null;this.onEvent=null;}
 stop(){this.disconnectSignals();super.stop();}
 close(){this.disconnectSignals();super.close();}
}
const nasimPeers=new WeakMap();
function fakeNasimBridgeFactory(){const peers=[];return async()=>{
 const cert=(peers.length+1).toString(16).padStart(2,'0').repeat(80),sdp=type=>({type,sdp:'v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=fingerprint:sha-256 '+Array(32).fill('AA').join(':')+'\r\na=ice-pwd:fixture-private-ice\r\n'});
 const peer={publicCertificate:cert,state:{phase:'prepared'},async configure(call,options){this.options=options;this.state={phase:'configured'};},
  async offer(){this.state.phase='connecting';return sdp('offer');},async answer(){this.state.phase='connecting';return sdp('answer');},
  async setAnswer(){const other=peers.find(p=>p.publicCertificate===this.options.trustedCertificates[0]);assert.equal(other.options.trustedCertificates[0],cert);
   for(const target of [this,other])target.state={phase:'connected',mediaConnected:true,peerAuthenticated:true,proxyReady:true,relayPair:true,socksAddress:target.options.role==='client'?'127.0.0.1:'+target.options.socksPort:null,receivedBytes:524288,sentBytes:1024,quic:{rttMs:23,lostPackets:0,sentPackets:100,profile:'throughput'}};
  },async addCandidate(){},close(){this.state={phase:'closed'};}};peers.push(peer);return peer;
};}
class FakeRubikaAuth extends FakeAuth{
 constructor(slot,calls,{saveSession=async()=>{}}={}, {challenge=false}={}){super(slot,calls);this.save=saveSession;this.challenge=challenge;}
 get state(){const base=super.state;return {...base,provider:'rubika',connected:base.signedIn,codeDigits:6,delivery:this.stage==='code'?'SMS':null,
  registration:this.record?'confirmed':null,selfConfirmed:base.signedIn,deviceModel:this.record?'BaleVPN Provider Lab (desktop)':null};}
 async start(phone){this.calls.push({slot:this.slot,action:'rubika-start',phone});this.stage=this.challenge?'password':'code';return this.challenge?{twoFactorRequired:true}:{codeRequested:true};}
 async password(value){assert.equal(value,'fixture-password');this.calls.push({slot:this.slot,action:'rubika-password'});this.stage='code';return {codeRequested:true};}
 async verify(code){assert.equal(code,'123456');this.calls.push({slot:this.slot,action:'rubika-verify'});this.record={provider:'rubika',userId:'u0'+String(this.slot).repeat(32),auth:'fixture-rubika-auth-secret-'+this.slot,
  privateKey:'fixture-rubika-private-key-'+this.slot,publicKey:'fixture-public-key',profile:{deviceHash:'a'.repeat(32),deviceModel:'BaleVPN Provider Lab (desktop)',systemVersion:'fixture-system'},registration:'confirmed',loginPhone:'+989120000001'};
  await this.save(this.record);this.stage='authenticated';return {authenticated:true};}
 async restore(record){this.calls.push({slot:this.slot,action:'rubika-restore'});this.record=record;this.stage='authenticated';return {authenticated:true};}
}
function eitaaFixture(slot,calls,options,{ack=false,challenge=false}={}){
 const {AuthSession}=require('../experiments/eitaa/auth-session.cjs'),{ApiError}=require('../experiments/eitaa/http-client.cjs'),{passwordHash}=require('../experiments/eitaa/account-client.cjs');
 const user={_:'user',id:8000000n+BigInt(slot),self:true,first_name:'Fixture Eitaa '+slot};
 return new AuthSession({...options,createClient:()=>({setToken(){},close(){},async request(method,input){
  calls.push({slot,action:'eitaa-'+method});
  if(method==='auth.sendCode')return ack?{acknowledged:true,codeIssued:false}:{_:'auth.sentCode',phone_code_hash:'fixture-eitaa-code-hash',type:{_:'auth.sentCodeTypeSms',length:6}};
  if(method==='auth.signIn'){assert.equal(input.phone_code,'123456');if(challenge){const e=new ApiError('service_rejected');e.serviceCode='SESSION_PASSWORD_NEEDED';throw e;}}
  if(method==='account.getPassword')return {_:'account.password2',current_salt:Buffer.alloc(24,0xa5),hint:'Fixture Eitaa password'};
  if(method==='auth.checkPassword2')assert.deepEqual(Buffer.from(input.password_hash),passwordHash('fixture-password',Buffer.alloc(24,0xa5)));
  if(method==='auth.signIn'||method==='auth.checkPassword2')return {_:'auth.authorization',token:'fixture-eitaa-token-'+slot,user};
  if(method==='users.getUsers')return [user];if(method==='auth.logOut')return true;
  throw Error('Unexpected Eitaa fixture method');
 }})});
}
module.exports={FakeAuth,FakeCallAuth,FakeNasimAuth,FakeRubikaAuth,eitaaFixture,fakeBridgeFactory,fakeNasimBridgeFactory};
