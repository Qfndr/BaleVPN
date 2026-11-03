// Synthetic private protocol fixtures only; no live identities or credentials.
'use strict';
const {protocol}=require('../experiments/eitaa/call-client.cjs');
const peer={_:'inputPhoneCall',id:9007199254740993n,access_hash:-9007199254740995n};
const user={_:'inputUser',user_id:101n,access_hash:-102n};
const base={id:peer.id,access_hash:peer.access_hash,date:1793660000,admin_id:101n,participant_id:202n,protocol:protocol()};
const waiting={_:'phoneCallWaiting',...base};
const requested={_:'phoneCallRequested',...base,g_a_hash:Buffer.alloc(32,1)};
const accepted={_:'phoneCallAccepted',...base,g_b:Buffer.alloc(256,2)};
const connection={_:'phoneConnectionWebrtc',turn:true,id:11n,ip:'192.0.2.1',ipv6:'2001:db8::1',port:3478,username:'fixture-turn-user',password:'fixture-turn-password'};
const active={_:'phoneCall',...base,g_a_or_b:Buffer.alloc(256,3),key_fingerprint:-123456789012345n,connections:[connection],start_date:1793660001};
const state={_:'updates.state',pts:10,qts:0,date:1793660001,seq:2,unread_count:0};
const discarded={_:'phoneCallDiscarded',id:peer.id,reason:{_:'phoneCallDiscardReasonHangup'},duration:5};
const wrap=phone_call=>({_:'phone.phoneCall',phone_call,users:[]});
const updates=values=>({_:'updates',updates:values,users:[],chats:[],date:state.date,seq:state.seq});
const inputs={
 'messages.getDhConfig':{version:0,random_length:256},'phone.getCallConfig':{},
 'phone.requestCall':{user_id:user,g_a_hash:requested.g_a_hash,random_id:-123,protocol:protocol()},
 'phone.acceptCall':{peer,g_b:accepted.g_b,protocol:protocol()},
 'phone.confirmCall':{peer,g_a:active.g_a_or_b,key_fingerprint:active.key_fingerprint,protocol:protocol()},
 'phone.receivedCall':{peer},'phone.discardCall':{peer,duration:5,reason:discarded.reason,connection_id:0n},
 'phone.sendSignalingData':{peer,data:Buffer.alloc(50,7)},'updates.getState':{},
 'updates.getDifference':{pts:10,pts_total_limit:256,date:state.date,qts:-1},
 'contacts.getContacts':{hash:0n},'contacts.resolveUsername':{username:'FixtureTarget'}
};
module.exports={peer,user,base,waiting,requested,accepted,active,discarded,state,connection,wrap,updates,inputs};
