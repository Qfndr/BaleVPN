'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {readCallHistory,decodeCallHistory,findCallHistoryCandidates}=require('../experiments/rubika/call-history.cjs');
const {HttpClient,DISCOVERY}=require('../experiments/rubika/http-client.cjs'),wire=require('../experiments/rubika/wire.cjs'),profiles=require('../experiments/rubika/client-profile.cjs');
const selfId='fixture_self_01',peerId='fixture_peer_02',auth='abcdefghijklmnopqrstuvwxyz012345';
const row=()=>({call_id:'fixture_call_01',call_type:'Voice',object_guid:peerId,other_participants:[{object_guid:selfId,type:'User',first_name:'private-name'}],request_type:'Caller',start_time:1234567890,duration:0,discard_reason:null,message_id:'private-message-id'});
const page=()=>({calls:[row()],has_continue:true,new_max_id:'private-cursor',message_updates:[{text:'private-chat'}]});
const reason=value=>error=>error.reason===value;
async function fixture(mode=profiles.WEB){
 const identity=await wire.createIdentity(),record={provider:'rubika',userId:selfId,auth,...identity,...mode===profiles.ANDROID?{profile:{protocolProfile:mode}}:{}};
 const state={provider:'rubika',userId:selfId,signedIn:true,selfConfirmed:true};return {record,state,account:{get state(){return {...state};},exportSession(){return {...record};}}};
}

test('one-page call metadata uses exact signed account profile V6 framing and never registers, paginates or discards',async()=>{
 for(const mode of [profiles.WEB,profiles.ANDROID]){
  const f=await fixture(mode),seen=[];let closed=false;
  const result=await readCallHistory(f.account,{createClient:options=>{
   assert.equal(options.protocolProfile,mode);assert.equal(options.updatesFactory,null);
   const client=new HttpClient({...options,fetchImpl:async(url,options)=>{
    const body=JSON.parse(options.body);seen.push({url,method:body.method});
    if(url===DISCOVERY){assert.equal(body.auth,undefined);assert.equal(body.sign,undefined);return Response.json({status:'OK',data:{default_api_urls:['https://messengerg2c1.iranlms.ir/']}});}
    assert.equal(body.auth,wire.transform(auth));assert.equal(body.tmp_session,undefined);assert.equal(body.api_version,mode===profiles.ANDROID?6:'6');
    assert.equal(crypto.verify('RSA-SHA256',Buffer.from(body.data_enc),f.record.publicKey,Buffer.from(body.sign,'base64')),true);
    const payload=wire.decrypt(body.data_enc,auth,mode);assert.equal(payload.method,'getCalls');assert.deepEqual(payload.input,{filter_type:'All',sort:'FromMax'});assert.deepEqual(payload.client,profiles.client(mode,'fa'));
    assert.equal(payload.is_background,mode===profiles.ANDROID?false:undefined);
    return Response.json({data_enc:wire.encrypt({status:'OK',data:page()},auth,mode)});
   }});return {discover:()=>client.discover(),request:(...args)=>client.request(...args),close(){closed=true;client.close();}};
  }});
  assert.equal(seen.length,2);assert.equal(closed,true);assert.equal(result.hasContinue,true);assert.equal(result.timeUnit,'unverified');assert.equal(result.activeStateAvailable,false);assert.equal(result.calls[0].start_time,'1234567890');
  const projected=JSON.stringify(result);for(const secret of ['private-chat','private-name','private-message-id','private-cursor',auth,f.record.privateKey])assert.ok(!projected.includes(secret));assert.equal(f.record.auth,auth);
 }
});

test('history parser fails closed on malformed or oversized pages and retains exact long values without claiming time units',()=>{
 const output=decodeCallHistory({...page(),calls:[{...row(),start_time:'9223372036854775807'}]});assert.equal(output.calls[0].start_time,'9223372036854775807');
 assert.equal(decodeCallHistory({...page(),calls:[{...row(),discard_reason:'UnknownPrivateServiceText'}]}).calls[0].discard_reason,undefined);
 assert.equal(decodeCallHistory({...page(),calls:[{...row(),discard_reason:'Busy'}]}).calls[0].discard_reason,'Busy');
 for(const invalid of [{...page(),calls:Array(129).fill(row())},{...page(),calls:[row(),row()]},{...page(),has_continue:1},{...page(),calls:[{...row(),call_id:'bad'}]},
  {...page(),calls:[{...row(),start_time:9007199254740992}]},{...page(),calls:[{...row(),start_time:'01'}]},{...page(),calls:[{...row(),start_time:'9223372036854775808'}]},
  {...page(),calls:[{...row(),duration:-1}]},{...page(),calls:[{...row(),request_type:'Active'}]},{...page(),calls:[{...row(),other_participants:[{object_guid:selfId,type:'Group'}]}]}])assert.throws(()=>decodeCallHistory(invalid),reason('invalid_call_history'));
 let executed=0;const accessor={...row()};Object.defineProperty(accessor,'call_id',{get(){executed++;return 'private';}});assert.throws(()=>decodeCallHistory({...page(),calls:[accessor]}),reason('invalid_call_history'));assert.equal(executed,0);
});

test('candidate metadata requires the exact two participants, Caller and Voice but never selects or claims an active call',()=>{
 const data=decodeCallHistory({calls:[row(),{...row(),call_id:'fixture_call_02'}],has_continue:false});const matches=findCallHistoryCandidates(data,{selfId,peerId});
 assert.equal(matches.candidates.length,2);assert.equal(matches.ambiguous,true);assert.equal(matches.selectedCallId,null);assert.equal(matches.timeUnit,'unverified');assert.equal(matches.activeStateAvailable,false);
 const single=findCallHistoryCandidates(decodeCallHistory({calls:[row()],has_continue:false}),{selfId,peerId});assert.equal(single.ambiguous,false);assert.equal(single.selectedCallId,null);
 for(const changed of [{request_type:'Receiver'},{call_type:'Video'},{object_guid:'fixture_other_03'},{other_participants:null},{other_participants:[{object_guid:peerId,type:'User'}]},
  {other_participants:[{object_guid:selfId,type:'User'},{object_guid:'fixture_extra_04',type:'User'}]}]){
  const p=decodeCallHistory({calls:[{...row(),...changed}],has_continue:false});assert.equal(findCallHistoryCandidates(p,{selfId,peerId}).candidates.length,0);
 }
 assert.throws(()=>findCallHistoryCandidates(data,{selfId,peerId:selfId}),reason('invalid_history_selection'));
});

test('account or retained profile replacement during I/O rejects the result and closes the private client without extra RPCs',async()=>{
 for(const stage of ['discover','getCalls']){
  const f=await fixture(),calls=[];let closed=false;
  await assert.rejects(readCallHistory(f.account,{createClient:()=>({async discover(){calls.push('getDCs');if(stage==='discover')f.record.auth='012345abcdefghijklmnopqrstuvwxyz';},async request(method){calls.push(method);f.record.profile={protocolProfile:profiles.ANDROID};return page();},close(){closed=true;}})}),reason('account_binding_changed'));
  assert.equal(closed,true);assert.deepEqual(calls,stage==='discover'?['getDCs']:['getDCs','getCalls']);
 }
 const f=await fixture();f.state.selfConfirmed=false;let created=0;await assert.rejects(readCallHistory(f.account,{createClient(){created++;}}),reason('invalid_account_binding'));assert.equal(created,0);
});

test('only the fixed first-page getCalls input reaches HTTP and raw failures are never exposed',async()=>{
 const f=await fixture();let count=0;
 const client=new HttpClient({fetchImpl:async()=>{count++;throw Error('private-network-secret');}});
 for(const input of [{},{filter_type:'All',sort:'FromMin'},{filter_type:'Missed',sort:'FromMax'},{filter_type:'All',sort:'FromMax',max_id:'private-cursor'},{filter_type:'All',sort:'FromMax',limit:1}])await assert.rejects(client.request('getCalls',input,{credentials:f.record}),reason('invalid_request'));
 assert.equal(count,0);client.close();let closed=false;
 await assert.rejects(readCallHistory(f.account,{createClient:()=>({async discover(){throw Error('private-network-secret');},close(){closed=true;throw Error('private-close-secret');}})}),error=>error.reason==='history_read_failed'&&!error.message.includes('private'));
 assert.equal(closed,true);
});
