'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {CallPrivacy,project}=require('../experiments/rubika/call-privacy.cjs');
function fixture({permission='Nobody',exceptions=[],hook}={}){
 const record={provider:'rubika',userId:'fixture_account_01',auth:'fixture-auth',privateKey:'fixture-private',publicKey:'fixture-public'},account={state:{provider:'rubika',userId:record.userId,signedIn:true,selfConfirmed:true},exportSession(){return {...record};}},calls=[];let current=permission,currentExceptions=structuredClone(exceptions),closed=0;
 const controller=new CallPrivacy(account,{createClient:()=>({async discover(){calls.push('discover');},async request(method,input,options){assert.equal(options.credentials.auth,record.auth);calls.push({method,input:structuredClone(input)});if(hook){const r=await hook(method,input,record,account);if(r!==undefined)return r;}if(method==='getPrivacySetting')return {privacy_setting:{can_called_by:current,exceptions:currentExceptions,show_my_phone_number:'Nobody',count_active_sessions:2}};if(method==='setSetting'){current=input.settings.can_called_by;if(input.settings.exceptions)currentExceptions=structuredClone(input.settings.exceptions);return {};}throw Error('Unexpected fixture method');},close(){closed++;}})});
 return {controller,calls,record,account,closed:()=>closed};
}
test('Rubika call permission is read/set/read back without exposing account data or changing unrelated settings',async()=>{
 const f=fixture();const result=await f.controller.allowEveryone();assert.deepEqual(result,{supported:true,permission:'Everybody',callExclusionCount:0,allowedForEveryone:true,changed:true,verified:true,needsExceptionUpdate:false});
 assert.deepEqual(f.calls.map(c=>typeof c==='string'?c:c.method),['discover','getPrivacySetting','setSetting','getPrivacySetting']);assert.deepEqual(f.calls[2].input,{settings:{can_called_by:'Everybody'},update_parameters:['can_called_by']});assert.equal(f.closed(),1);for(const secret of ['fixture-auth','fixture-private','show_my_phone_number'])assert.ok(!JSON.stringify(result).includes(secret));
});
test('call exclusions are removed while non-call exceptions remain private and unchanged',async()=>{
 const f=fixture({permission:'Everybody',exceptions:[{setting_type:'CanCalled',exclude_users:['fixture-user-guid']},{setting_type:'ShowPhone',exclude_users:['other-guid']}]});const result=await f.controller.allowEveryone();assert.equal(result.changed,true);assert.equal(result.callExclusionCount,0);assert.equal(result.verified,true);assert.equal(result.needsExceptionUpdate,false);assert.deepEqual(f.calls.find(c=>c.method==='setSetting').input,{settings:{can_called_by:'Everybody',exceptions:[{setting_type:'ShowPhone',exclude_users:['other-guid']}]},update_parameters:['can_called_by','exceptions']});assert.ok(!JSON.stringify(result).includes('guid'));
 const publicAccount=fixture({permission:'Everybody'});assert.equal((await publicAccount.controller.allowEveryone()).changed,false);assert.equal(publicAccount.calls.some(c=>c.method==='setSetting'),false);
});

test('a setter acknowledgment without the requested readback cannot claim verification or retry',async()=>{
 const f=fixture({hook:async method=>method==='setSetting'?{}:undefined});const result=await f.controller.allowEveryone();assert.equal(result.permission,'Nobody');assert.equal(result.verified,false);assert.equal(f.calls.filter(c=>c.method==='setSetting').length,1);
});
test('unsupported and malformed privacy responses do not trigger a setting mutation',async()=>{
 assert.deepEqual(project({privacy_setting:{}}),{supported:false,permission:null,callExclusionCount:null,allowedForEveryone:false});for(const value of [{},{privacy_setting:{can_called_by:'Unknown'}},{privacy_setting:{can_called_by:'Everybody',exceptions:[{setting_type:'CanCalled',exclude_users:'bad'}]}}])assert.throws(()=>project(value),/invalid_privacy_response/);
 const f=fixture({hook:async method=>method==='getPrivacySetting'?{privacy_setting:{}}:undefined});await assert.rejects(f.controller.allowEveryone(),/call_privacy_unavailable/);assert.equal(f.calls.some(c=>c.method==='setSetting'),false);
});
test('account changes and overlapping actions cannot cross an authenticated call-privacy boundary',async()=>{
 const f=fixture({hook:async(method,_input,record)=>{if(method==='getPrivacySetting')record.auth='other-account';}});await assert.rejects(f.controller.allowEveryone(),/account_binding_changed/);assert.equal(f.calls.some(c=>c.method==='setSetting'),false);assert.equal(f.closed(),1);
 let release;const g=fixture({hook:async method=>{if(method==='getPrivacySetting')await new Promise(r=>release=r);}});const reading=g.controller.read();while(!release)await Promise.resolve();await assert.rejects(g.controller.read(),/account_busy/);release();await reading;
});

test('closing a pending privacy read aborts its transport and prevents a late write',async()=>{
 let release;const f=fixture({hook:async method=>{if(method==='getPrivacySetting')await new Promise(r=>release=r);}}),operation=f.controller.allowEveryone();while(!release)await Promise.resolve();f.controller.close();assert.equal(f.closed(),1);release();await assert.rejects(operation,/closed/);assert.equal(f.calls.some(c=>c.method==='setSetting'),false);
});
