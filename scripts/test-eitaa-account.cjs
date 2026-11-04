'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const wire=require('../experiments/eitaa/wire.cjs'),codec=require('../experiments/eitaa/auth-wire.cjs');
const schema=require('../experiments/eitaa/auth-schema.json');
const {AccountClient,passwordHash}=require('../experiments/eitaa/account-client.cjs');
const imei='0123456789abcde__web',phone='+989120000001';
const user={_:'user',self:true,id:123456789012345n,access_hash:-123n,first_name:'کاربر',last_name:'Test',phone:'989120000001',photo:{_:'userProfilePhotoEmpty'},status:{_:'userStatusOnline',expires:12345678}};
const auth={_:'auth.authorization',token:'fixture-private-eitaa-token',user};
const sent={_:'auth.sentCode',type:{_:'auth.sentCodeTypeSms',length:6},phone_code_hash:'fixture-service-hash',timeout:60};
function unpack(body){const r=new wire.Reader(body);assert.equal(r.int(),wire.IDS.eitaaObject);const out={token:r.string(),imei:r.string(),payload:r.bytes(),layer:r.int(),flags:r.int()};r.end();return out;}
function vector(values){return Buffer.concat([new wire.Writer().int(481674261).int(values.length).finish(),...values.map(codec.object)]);}
test('selected auth declarations include all dependencies and encode current sendCode/signIn inputs',()=>{
 assert.equal(schema.methods.length,8);assert.equal(schema.constructors.length,73);
 const b=codec.method('auth.sendCode',{phone_number:phone,api_id:2496,api_hash:'8da85b0d5bfe62527e5b244c209159c3',settings:{_:'codeSettings'}}),r=new wire.Reader(b);
 assert.equal(r.int(),-1502141361);assert.equal(r.string(),phone);assert.equal(r.int(),2496);assert.equal(r.string(),'8da85b0d5bfe62527e5b244c209159c3');assert.equal(r.int(),-557924733);assert.equal(r.int(),0);r.end();
 assert.throws(()=>codec.method('messages.sendMessage',{}));assert.throws(()=>codec.method('auth.signIn',{phone_number:phone,phone_code_hash:'x',phone_code:'123456',unknown:true}));
 assert.throws(()=>codec.method('auth.sendCode',{phone_number:phone,api_id:2496,api_hash:'x',settings:{_:'inputUserSelf'}}));
});
test('auth response decoding retains exact private token/self fields without truncating signed longs or flags',()=>{
 assert.deepEqual(codec.response(codec.object(auth),'auth.signIn'),auth);
 assert.deepEqual(codec.response(codec.object(sent),'auth.sendCode'),sent);
 const wrapped=Buffer.concat([new wire.Writer().int(wire.IDS.rpcResult).long(5n).finish(),codec.object(auth)]);assert.deepEqual(codec.response(wrapped,'auth.signIn'),{_:'rpc_result',request_id:5n,result:auth});
 assert.deepEqual(codec.response(vector([user]),'users.getUsers'),[user]);
 const wrappedVector=Buffer.concat([new wire.Writer().int(wire.IDS.rpcResult).long(5n).finish(),vector([user])]);assert.deepEqual(codec.response(wrappedVector,'users.getUsers').result,[user]);
});

test('official Android sentCode bit-8 message extension parses without relaxing unknown flags or exposing a fake code',()=>{
 const value={...sent,message:'fixture-service-delivery-message'};
 const encoded=codec.object(value);assert.equal(encoded.readUInt32LE(4),260);assert.deepEqual(codec.response(encoded,'auth.sendCode'),value);
 const unknown=Buffer.from(encoded);unknown.writeUInt32LE(260|512,4);assert.throws(()=>codec.response(unknown,'auth.sendCode'),{reason:'unknown_flags'});
 assert.throws(()=>codec.response(encoded.subarray(0,encoded.length-4),'auth.sendCode'));
});

test('live sentCode flags 7 consume no bit-0 payload, matching the official Android reader',()=>{
 const value={...sent,next_type:{_:'auth.codeTypeSms'}},encoded=codec.object(value);
 assert.equal(encoded.readUInt32LE(4),6);encoded.writeUInt32LE(7,4);
 assert.deepEqual(codec.response(encoded,'auth.sendCode'),value);
 const extended={...value,message:'fixture-private-message'},withMessage=codec.object(extended);withMessage.writeUInt32LE(263,4);
 assert.deepEqual(codec.response(withMessage,'auth.sendCode'),extended);
 const unknown=Buffer.from(encoded);unknown.writeUInt32LE(15,4);assert.throws(()=>codec.response(unknown,'auth.sendCode'),{reason:'unknown_flags'});
 assert.throws(()=>codec.response(Buffer.concat([encoded,Buffer.alloc(4)]),'auth.sendCode'));
 assert.throws(()=>codec.response(encoded.subarray(0,encoded.length-4),'auth.sendCode'));
});
test('live authorization bit 10 is payload-free while Android bit 0 reads tmp_sessions before User',()=>{
 for(const value of [auth,{...auth,tmp_sessions:3}]){
  const encoded=codec.object(value),flags=encoded.readUInt32LE(4);encoded.writeUInt32LE(flags|1024,4);
  assert.deepEqual(codec.response(encoded,'auth.signIn'),value);
  const wrapped=Buffer.concat([new wire.Writer().int(wire.IDS.rpcResult).long(9n).finish(),encoded]);
  assert.deepEqual(codec.response(wrapped,'auth.signIn').result,value);
  assert.throws(()=>codec.response(encoded.subarray(0,encoded.length-4),'auth.signIn'));
  assert.throws(()=>codec.response(Buffer.concat([encoded,Buffer.alloc(4)]),'auth.signIn'));
 }
 const missing=codec.object(auth);missing.writeUInt32LE(1025,4);assert.throws(()=>codec.response(missing,'auth.signIn'));
});

test('trailing authorization diagnostics contain only constructor IDs and byte counts',()=>{
 const original=codec.object(auth),extra=Buffer.concat([original,Buffer.alloc(8,0xa5)]);
 assert.throws(()=>codec.response(extra,'auth.signIn'),error=>{
  assert.equal(error.reason,'trailing_data');assert.deepEqual(error.trailingDiagnostic,{constructorId:(-855308010)>>>0,lastConstructorId:(-306628279)>>>0,consumed:original.length,total:extra.length,remaining:8});
  assert.ok(!JSON.stringify(error).includes(auth.token));return true;
 });
});

test('observed authorization flag-10 appendix is bounded, canonical, opaque and restricted to login responses',()=>{
 const prefix=codec.object(auth);prefix.writeUInt32LE(1024,4);
 const appendix=new wire.Writer().bytes(Buffer.from('A'.repeat(56))).finish(),frame=Buffer.concat([prefix,appendix]);
 assert.deepEqual(codec.response(frame,'auth.signIn'),auth);assert.deepEqual(codec.response(frame,'auth.checkPassword2'),auth);
 assert.deepEqual(codec.response(prefix,'auth.signIn'),auth);
 const wrapped=Buffer.concat([new wire.Writer().int(wire.IDS.rpcResult).long(8n).finish(),frame]);assert.deepEqual(codec.response(wrapped,'auth.signIn').result,auth);
 assert.throws(()=>codec.decode(frame,'auth.Authorization'),{reason:'trailing_data'});
 assert.throws(()=>codec.response(frame,'auth.sendCode'));
 const noFlag=Buffer.from(frame);noFlag.writeUInt32LE(0,4);assert.throws(()=>codec.response(noFlag,'auth.signIn'),{reason:'trailing_data'});
 for(const tail of [Buffer.concat([appendix,appendix]),appendix.subarray(0,appendix.length-4),new wire.Writer().bytes(Buffer.alloc(257,65)).finish(),new wire.Writer().bytes(Buffer.alloc(56,255)).finish(),new wire.Writer().bytes(Buffer.alloc(0)).finish()])assert.throws(()=>codec.response(Buffer.concat([prefix,tail]),'auth.signIn'));
 const badPadding=Buffer.from(frame);badPadding[badPadding.length-1]=1;assert.throws(()=>codec.response(badPadding,'auth.signIn'));
 const noncanonical=Buffer.concat([prefix,Buffer.from([254,56,0,0]),Buffer.alloc(56,65)]);assert.throws(()=>codec.response(noncanonical,'auth.signIn'));
});

test('Android User booleans and modern photo/status IDs decode inside authorization without changing legacy output',()=>{
 const androidUser={...user,MXB_REGISTERED_USER:true,MXB_VIRTUAL_USER:true,oneWayMessaging:true};
 assert.deepEqual(codec.response(codec.object({...auth,user:androidUser}),'auth.signIn').user,androidUser);
 for(const [statusId,statusName]of [[2065268168,'userStatusRecently'],[1410997530,'userStatusLastWeek'],[1703516023,'userStatusLastMonth']]){
  const w=new wire.Writer().int(-855308010).int(1024).string(auth.token)
   .int(-321753653).int(1024|32|64|256|512).int(0).int(64).long(user.id)
   .int(-2100168954).int(7).long(55n).bytes(Buffer.from([1,2,3])).int(2)
   .int(statusId).int(1);
  const encoded=w.finish(),value=codec.response(encoded,'auth.signIn');
  assert.equal(value.token,auth.token);assert.equal(value.user.self,true);assert.equal(value.user.MXB_REGISTERED_USER,true);assert.equal(value.user.MXB_VIRTUAL_USER,true);assert.equal(value.user.oneWayMessaging,true);
  assert.deepEqual(value.user.photo,{_:'userProfilePhoto',has_video:true,personal:true,photo_id:55n,stripped_thumb:Buffer.from([1,2,3]),dc_id:2});
  assert.deepEqual(value.user.status,{_:statusName,by_me:true});
  assert.throws(()=>codec.response(encoded.subarray(0,encoded.length-4),'auth.signIn'));
  const unknown=Buffer.from(encoded);unknown.writeInt32LE(3,encoded.length-4);assert.throws(()=>codec.response(unknown,'auth.signIn'),{reason:'unknown_flags'});
 }
 assert.equal(codec.object({_:'userStatusRecently'}).readInt32LE(0),-496024847);
});

test('unknown flags, truncation, wrong result types, malformed vectors and nested RPC wrappers fail closed',()=>{
 const body=codec.object(auth),bad=Buffer.from(body);bad.writeInt32LE(2,4);assert.throws(()=>codec.response(bad,'auth.signIn'),{reason:'unknown_flags'});
 assert.throws(()=>codec.response(bad,'auth.signIn'),error=>{assert.deepEqual(error.schemaDiagnostic,{constructorId:(-855308010)>>>0,flags:2,knownMask:1025});assert.ok(!JSON.stringify(error).includes(auth.token));return true;});
 for(let length=4;length<body.length;length+=4)assert.throws(()=>codec.response(body.subarray(0,length),'auth.signIn'));
 assert.throws(()=>codec.response(codec.object(user),'auth.signIn'),{reason:'unexpected_constructor'});
 const nestedError=Buffer.concat([new wire.Writer().int(-855308010).int(0).string('fixture-token').finish(),codec.object({_:'error',code:400,text:'fixture-error'})]);assert.throws(()=>codec.response(nestedError,'auth.signIn'),{reason:'unexpected_constructor'});
 assert.throws(()=>codec.response(new wire.Writer().int(481674261).int(257).finish(),'users.getUsers'),{reason:'invalid_vector'});
 assert.throws(()=>codec.response(new wire.Writer().int(481674261).int(-1).finish(),'users.getUsers'),{reason:'invalid_vector'});
 const header=new wire.Writer().int(wire.IDS.rpcResult).long(1n).finish();assert.throws(()=>codec.response(Buffer.concat([header,header,body]),'auth.signIn'),{reason:'nesting_limit'});
 assert.throws(()=>codec.response(Buffer.concat([body,Buffer.alloc(4)]),'auth.signIn'),{reason:'trailing_data'});
 assert.throws(()=>codec.object({...user,bot:true}),{reason:'invalid_int'}); // The same bit also requires bot_info_version.
});
test('legacy password salt framing matches the observed SHA-256(salt || UTF8 password || salt)',()=>{
 const salt=Buffer.alloc(24,0xa5),password='fixture-رمز-۱۲۳';assert.deepEqual(passwordHash(password,salt),crypto.createHash('sha256').update(salt).update(password,'utf8').update(salt).digest());
 for(const [p,s]of [['',salt],['x',Buffer.alloc(0)],['x',Buffer.alloc(4097)],['\ud800',salt]])assert.throws(()=>passwordHash(p,s),{reason:'invalid_password_format'});
 const record={_:'account.password2',current_salt:salt,new_salt:Buffer.alloc(8),new_secure_salt:Buffer.alloc(8),secure_random:Buffer.alloc(32),hint:'fixture hint',email_unconfirmed_pattern:''};assert.deepEqual(codec.response(codec.object(record),'account.getPassword'),record);
});
test('anonymous account requests use a stable account device and official web API fields without adopting a token',async()=>{
 const calls=[];const client=new AccountClient({imei,fetchImpl:async(_url,o)=>{calls.push(unpack(o.body));return new Response(codec.object(sent));}});
 const result=await client.request('auth.sendCode',{phone_number:phone});assert.equal(result.phone_code_hash,'fixture-service-hash');assert.equal(calls[0].imei,imei);assert.equal(calls[0].token,'');
 await assert.rejects(client.request('users.getUsers'),{reason:'not_authorized'});assert.equal(calls.length,1);client.close();
});
test('sendCode pong remains an uncertain acknowledgement and is never a fabricated code hash or authorization',async()=>{
 const client=new AccountClient({imei,fetchImpl:async()=>new Response(codec.object({_:'pong',msg_id:1n,ping_id:2n}))});
 assert.deepEqual(await client.request('auth.sendCode',{phone_number:phone}),{acknowledged:true,codeIssued:false});
 await assert.rejects(client.request('auth.signIn',{phone_number:phone,phone_code_hash:'fixture-hash',phone_code:'123456'}),{reason:'unexpected_acknowledgement'});client.close();
});
test('two accounts keep stable independent tokens/devices and restore self reads cannot issue a fresh login',async()=>{
 const calls=[];const fetchImpl=async(_url,o)=>{const c=unpack(o.body);calls.push(c);return new Response(vector([user]));};
 const a=new AccountClient({imei,token:'fixture-token-a',fetchImpl}),b=new AccountClient({imei:'fedcba987654321__web',token:'fixture-token-b',fetchImpl});
 const [ra,rb]=await Promise.all([a.request('users.getUsers'),b.request('users.getUsers')]);assert.equal(ra[0].id,user.id);assert.equal(rb[0].id,user.id);
 assert.deepEqual(calls.map(c=>[c.imei,c.token]),[[imei,'fixture-token-a'],['fedcba987654321__web','fixture-token-b']]);for(const c of calls)assert.deepEqual(c.payload,codec.method('users.getUsers',{id:[{_:'inputUserSelf'}]}));
 await assert.rejects(a.request('auth.sendCode',{phone_number:phone}),{reason:'already_signed_in'});assert.equal(calls.length,2);a.close();b.close();
});

test('Web refresh advertises a stable neutral label only for the known legacy brand while preserving retained identity and metadata',async()=>{
 for(const deviceModel of ['BaleVPN Provider Lab (desktop)','Desktop 0123456789ab']){
  const profile=Object.freeze({deviceModel,systemVersion:'fixture platform'}),retained=Object.freeze({provider:'eitaa',imei,profile,token:'fixture-retained-token'}),snapshot=JSON.stringify(retained),calls=[],expectedModel=deviceModel.startsWith('BaleVPN ')?'Desktop '+crypto.createHash('sha256').update(imei).digest('hex').slice(0,12):deviceModel;
  const client=new AccountClient({...retained,fetchImpl:async(_url,o)=>{calls.push(unpack(o.body));return new Response(codec.object({_:'eitaa_updates_token',token:'fixture-retained-token',expire:123,date:100}));}});
  try{await client.request('eitaaRefreshToken');await client.request('eitaaRefreshToken');assert.equal(JSON.stringify(retained),snapshot);assert.equal(calls.length,2);
   for(const request of calls){assert.equal(request.imei,imei);assert.equal(request.token,'fixture-retained-token');assert.deepEqual(request.payload,codec.method('eitaaRefreshToken',{app_info:{_:'eitaaAppInfo',build_version:2496,device_model:expectedModel,system_version:profile.systemVersion,app_version:'5.2 K',lang_code:'fa',sign:''}}));assert.equal(request.payload.includes(Buffer.from('BaleVPN')),false);assert.equal(request.payload.includes(Buffer.from('VPN')),false);}
   assert.deepEqual(calls[0].payload,calls[1].payload);
  }finally{client.close();}
 }
});
test('only known service error metadata escapes; token expiry never silently refreshes or retries',async()=>{
 for(const [value,expected]of [[{_:'eitta_error',code:401,text:'SESSION_PASSWORD_NEEDED'},{reason:'service_rejected',serviceCode:'SESSION_PASSWORD_NEEDED'}],[{_:'error',code:400,text:'FLOOD_WAIT_123'},{reason:'rate_limited',waitSeconds:123}],[{_:'error',code:400,text:'raw-secret-token-phone'},{reason:'service_rejected'}],[{_:'eitaa_updates_expire_token'},{reason:'session_refresh_required'}]]){
  let count=0;const client=new AccountClient({imei,token:'fixture-token',fetchImpl:async()=>{count++;return new Response(codec.object(value));}});await assert.rejects(client.request('users.getUsers'),e=>{for(const[k,v]of Object.entries(expected))assert.equal(e[k],v);assert.ok(!JSON.stringify(e).includes('raw-secret'));assert.ok(!e.message.includes('raw-secret'));return true;});assert.equal(count,1);client.close();
 }
});
test('invalid credentials, methods and caller metadata cannot trigger network I/O',async()=>{
 for(const args of [{imei,provider:'rubika'},{imei:'invalid'},{imei,token:'secret\n'},{imei,language:'invalid'}])assert.throws(()=>new AccountClient(args),{reason:'invalid_credentials'});
 let count=0;const client=new AccountClient({imei,fetchImpl:async()=>{count++;throw Error('Unexpected network');}});
 for(const [name,input]of [['__proto__',{}],['constructor',{}],['phone.requestCall',{}],['auth.sendCode',{phone_number:'bad'}],['auth.sendCode',{phone_number:phone,api_id:1}],['auth.signIn',{phone_number:phone,phone_code_hash:'x',phone_code:'not-code'}],['auth.checkPassword2',{password_hash:Buffer.alloc(1),phone_number:phone,phone_code:'123456'}],['eitaaRefreshToken',{}]])await assert.rejects(client.request(name,input));assert.equal(count,0);client.close();
});
test('close invalidates late authenticated replies and preserves the single-request account boundary',async()=>{
 let finish;const client=new AccountClient({imei,token:'fixture-token',fetchImpl:()=>new Promise(resolve=>{finish=()=>resolve(new Response(vector([user])));})});const pending=client.request('users.getUsers');await assert.rejects(client.request('users.getUsers'),{reason:'account_busy'});client.close();finish();await assert.rejects(pending,{reason:'closed'});assert.throws(()=>client.setToken('fixture-other'),{reason:'closed'});
});
