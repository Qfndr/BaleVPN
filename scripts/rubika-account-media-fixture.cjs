// Offline account-bound call broker. Real controllers, key checks and typed
// projections; synthetic authenticated accounts/HTTP service, no OTP or sockets.
'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto'),wire=require('../experiments/rubika/wire.cjs');
const {CallClient}=require('../experiments/rubika/call-client.cjs'),{CallSession}=require('../experiments/rubika/call-session.cjs');
const codec=require('../experiments/rubika/call-codec.cjs');
async function pair({connections=[{type:'WebRTC',ip:'192.0.2.1',port:3478,turn_username:'fixture',turn_password:'fixture-private-password'}],hook}={}){
 const ids=['fixture_account_01','fixture_account_02'],key=crypto.randomBytes(128).toString('hex'),callId='fixture_call_01',calls=[],events=[[],[]],signals=[[],[]],started=[0,0],records=[],accountStates=[],accounts=[];
 let timestamp=Math.floor(Date.now()/1000),accepted=false;
 const profile={min_layer:92,max_layer:92,library_versions:['6.0.0']};
 const update=(slot,state,action='Edit')=>({action,call_id:callId,timestamp:++timestamp,object_guid:ids[1-slot],type:'User',
  call:{call_id:callId,call_type:'Voice',state,protocol_layer:92,library_versions:['6.0.0'],connections:structuredClone(connections),...(state==='Accepted'?{key}:{}),other_participants:[{type:'User',object_guid:ids[1-slot]}]},
  ...(action==='Edit'?{updated_parameters:['call_type','state','protocol_layer','library_versions','connections','key','other_participants']}:{} )});
 for(let slot=0;slot<2;slot++){
  const identity=await wire.createIdentity();records.push({provider:'rubika',userId:ids[slot],auth:wire.temporarySession(),...identity});accountStates.push({provider:'rubika',userId:ids[slot],signedIn:true,selfConfirmed:true});
  accounts.push({get state(){return {...accountStates[slot]};},exportSession(){return {...records[slot]};}});
 }
 const create=slot=>account=>new CallClient(account,{createClient:()=>({closed:false,
  async discover(){calls.push({slot,method:'getDCs'});return {apiServerSelected:true};},
  async request(method,input,{credentials}){
   assert.equal(credentials.auth,records[slot].auth);assert.equal(credentials.privateKey,records[slot].privateKey);codec.validateInput(method,input);calls.push({slot,method,input:structuredClone(input)});
   if(hook){const result=await hook(slot,method,input);if(result!==undefined)return result;}
   if(method==='requestCall'){assert.equal(slot,0);assert.equal(input.user_guid,ids[1]);events[1].push(update(1,'Requested','New'));return {call_type:'WebRtc',call_update:update(0,'Waiting','New')};}
   if(method==='acceptCall'){assert.equal(slot,1);accepted=true;events[0].push(update(0,'Accepted'));return {call_update:update(1,'Accepted')};}
   if(method==='receivedCall')return {call_update:update(slot,'Waiting')};
   if(method==='getUpdate')return {update_data:{user_guid:ids[slot],call_updates:events[slot].splice(0),call_signal_data:signals[slot].splice(0)}};
   assert.equal(input.call_id,callId);
   if(method==='sendSignalingData'){assert.equal(accepted,true);signals[1-slot].push({call_id:callId,data:input.data});return {};}
   if(method==='getSignalingData')return {data_list:signals[slot].splice(0).map(v=>v.data)};
   if(method==='callStarted'){started[slot]++;return {};}
   if(method==='discardCall'){events[1-slot].push({action:'Delete',call_id:callId,timestamp:++timestamp});return {call_update:{action:'Delete',call_id:callId,timestamp:++timestamp}};}
   throw Error('Unexpected fixture request');
  },close(){this.closed=true;}})});
 const a=new CallSession(accounts[0],{allowedPeers:[ids[1]],protocol:profile,createClient:create(0)}),b=new CallSession(accounts[1],{allowedPeers:[ids[0]],protocol:profile,createClient:create(1)});
 return {a,b,ids,callId,key,calls,events,signals,started,records,accountStates,update,
  async negotiate(){await a.start();await b.start();await a.dial(ids[1]);await b.pollOnce();await b.accept();await a.pollOnce();assert.equal(a.state.phase,'accepted');assert.equal(b.state.phase,'accepted');},
  close(){a.close();b.close();}};
}
module.exports={pair};
