'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const crypto=require('node:crypto'),zlib=require('node:zlib');
const codec=require('../experiments/eitaa/native-config-wire.cjs'),wire=require('../experiments/eitaa/wire.cjs'),profiles=require('../experiments/eitaa/client-profile.cjs');
const {NativeConfigClient,appInfo,validateConfig}=require('../experiments/eitaa/native-config-client.cjs');
const fixture=require('./fixtures/eitaa-native-config.json'),frame=()=>Buffer.from(fixture.configHex,'hex');
const record=()=>({provider:'eitaa',userId:'12345',token:'fixture-private-http-token',imei:'12345678-1234-4123-8123-123456789abc',profile:{protocolProfile:profiles.ANDROID,deviceModel:'Desktop 123456789abc',systemVersion:'fixture OS'}});

test('native configuration request and every optional field match independent APK-based bytes',()=>{
 const request=codec.method('help.getConfig',{app_info:appInfo(record(),'fa'),user_id:12345});assert.equal(request.toString('hex'),fixture.requestHex);
 const value=codec.response(frame(),'help.getConfig');assert.equal(value._,'androidConfig');assert.equal(value.this_dc,2);assert.equal(value.dc_options[0].port,443);assert.deepEqual(value.dc_options[0].secret,Buffer.from(Array.from({length:16},(_,i)=>i)));assert.equal(value.dc_options[0].isStatic,true);assert.equal(value.dc_options[0].tcpo_only,true);assert.equal(value.lang_pack_version,33);assert.equal(value.base_lang_pack_version,34);assert.equal(value.socketURL,'wss://fixture.invalid/socket');assert.equal(value.liveStreamConfig.maxVideoWidth,640);assert.equal(value.show_new_trend,true);
 assert.deepEqual(codec.object(value),frame());assert.equal(validateConfig(value),value);assert.throws(()=>require('../experiments/eitaa/auth-wire.cjs').method('help.getConfig',{}));
 const compressed=new wire.Writer().int(812830625).bytes(zlib.gzipSync(frame())).finish();assert.deepEqual(codec.response(compressed,'help.getConfig'),value);
});

test('strict native decoder rejects unknown flags, truncation, tails and the upstream/Web configuration constructor',()=>{
 const unknown=frame();unknown.writeUInt32LE(unknown.readUInt32LE(4)|8,4);assert.throws(()=>codec.response(unknown,'help.getConfig'),{reason:'unknown_flags'});
 const foreign=frame();foreign.writeInt32LE(-870702050,0);assert.throws(()=>codec.response(foreign,'help.getConfig'));
 for(const cut of [4,32,120,frame().length-4])assert.throws(()=>codec.response(frame().subarray(0,cut),'help.getConfig'));
 assert.throws(()=>codec.response(Buffer.concat([frame(),Buffer.alloc(4)]),'help.getConfig'),{reason:'trailing_data'});
 const decoded=codec.response(frame(),'help.getConfig');delete decoded.socketURL;delete decoded.liveStreamConfig;delete decoded.suggested_lang_code;delete decoded.lang_pack_version;delete decoded.base_lang_pack_version;delete decoded.tmp_sessions;assert.equal(codec.response(codec.object(decoded),'help.getConfig').socketURL,undefined);
});

test('native route flags consume no payload and match the pinned DataCenter routing masks without accepting unrelated bits or tails',()=>{
 const input=frame();assert.equal(input.readInt32LE(32),414687501);input.writeUInt32LE(input.readUInt32LE(36)|64,36);
 const baseline=codec.response(frame(),'help.getConfig'),decoded=codec.response(input,'help.getConfig');baseline.dc_options[0].native_transport=true;assert.deepEqual(decoded,baseline);assert.deepEqual(codec.object(decoded),input);
 const upload=Buffer.from(input);upload.writeUInt32LE(upload.readUInt32LE(36)|32,36);assert.equal(codec.response(upload,'help.getConfig').dc_options[0].native_upload,true);
 const unrelated=Buffer.from(input);unrelated.writeUInt32LE(unrelated.readUInt32LE(36)|128,36);assert.throws(()=>codec.response(unrelated,'help.getConfig'),{reason:'unknown_flags'});
 assert.throws(()=>codec.response(Buffer.concat([input,Buffer.alloc(4)]),'help.getConfig'),{reason:'trailing_data'});
});

test('APK update URL and payment host each require their own shared feature flag, including absent and independent combinations',()=>{
 for(const update of [false,true])for(const pay of [false,true]){
  const value=codec.response(frame(),'help.getConfig');if(!update){delete value.update_available;delete value.appURL;}if(!pay){delete value.payEnabled;delete value.payHost;}
  const encoded=codec.object(value),decoded=codec.response(encoded,'help.getConfig');assert.deepEqual(decoded,value);assert.equal(Object.hasOwn(decoded,'appURL'),update);assert.equal(Object.hasOwn(decoded,'payHost'),pay);assert.equal(encoded.readUInt32LE(4)&64,update?64:0);assert.equal(encoded.readUInt32LE(4)&128,pay?128:0);
 }
});

test('missing shared-flag payloads or payload bytes with a cleared feature flag cannot silently shift later config fields',()=>{
 for(const field of ['appURL','payHost']){const value=codec.response(frame(),'help.getConfig');delete value[field];assert.throws(()=>codec.object(value));}
 for(const bit of [6,7]){const raw=frame();raw.writeUInt32LE(raw.readUInt32LE(4)&~(1<<bit),4);assert.throws(()=>codec.response(raw,'help.getConfig'));}
});

test('one explicit verified HTTPS read uses retained native identity and never follows returned IPs, URLs or secret data',async()=>{
 const retained=record(),before=JSON.stringify(retained),seen=[];const client=new NativeConfigClient({record:retained,fetchImpl:async(url,o)=>{
  seen.push(url);assert.equal(url,profiles.ANDROID_ENDPOINT);assert.equal(o.redirect,'error');assert.deepEqual(o.headers,{'content-type':'text/stream'});const r=new wire.Reader(o.body);assert.equal(r.int(),2059302894);assert.equal(r.string(),retained.token);assert.equal(r.string(),retained.imei);assert.equal(r.int(),32);assert.equal(r.bytes().toString('hex'),fixture.requestHex);assert.equal(r.int(),138);assert.equal(r.int(),2637);assert.equal(r.string(),'fa');r.end();return new Response(frame());
 }});
 try{const config=await client.getConfig();assert.equal(config.dc_options.length,1);assert.equal(seen.length,1);assert.equal(JSON.stringify(retained),before);assert.equal(config.socketURL,'wss://fixture.invalid/socket');await assert.rejects(client.getConfig({server:'https://attacker.invalid'}),{reason:'invalid_request'});assert.equal(seen.length,1);}finally{client.close();}
});

test('AppInfo keeps truthful stable desktop metadata and uses only source-proven unavailable-version/signature literals',()=>{
 const r=record();r.profile.deviceModel='BaleVPN Provider Lab (desktop)';const before=JSON.stringify(r),a=appInfo(r,'en'),b=appInfo(r,'en');assert.deepEqual(a,b);assert.equal(a.device_model,'Desktop '+crypto.createHash('sha256').update(r.imei).digest('hex').slice(0,12));assert.equal(a.system_version,r.profile.systemVersion);assert.equal(a.app_version,'App version unknown');assert.equal(a.sign,'unknown');assert.equal(a.build_version,2637);assert.equal(JSON.stringify(r),before);assert.ok(!JSON.stringify(a).includes('BaleVPN'));
});

test('wrong profiles, oversized IDs, invalid DC data and service failures cannot enable calls or trigger retries',async()=>{
 for(const changes of [{provider:'rubika'},{userId:'2147483648'},{token:''},{imei:'bad'},{profile:{...record().profile,protocolProfile:'web'}}])assert.throws(()=>new NativeConfigClient({record:{...record(),...changes}}),{reason:'invalid_credentials'});
 for(const change of [{expires:-1},{this_dc:-1},{dc_options:[]},{dc_options:[{_:'dcOption',id:2,ip_address:'https://attacker.invalid/path',port:443}]},{dc_options:[{_:'dcOption',id:2,ip_address:'127.0.0.1',port:0}]}])assert.throws(()=>validateConfig({...codec.response(frame(),'help.getConfig'),...change}),{reason:'invalid_config_response'});
 let count=0;const client=new NativeConfigClient({record:record(),fetchImpl:async()=>{count++;return new Response(new wire.Writer().int(wire.IDS.error).int(400).string('INVALID_CONSTRUCTOR').finish());}});try{await assert.rejects(client.getConfig(),{reason:'service_rejected'});assert.equal(count,1);}finally{client.close();}
});

test('unspecified current DC and bounded DNS names are retained as inert configuration, without DNS lookup or connection',async()=>{
 const value=codec.response(frame(),'help.getConfig');value.this_dc=0;value.dc_options[0].ip_address='node.fixture.invalid';let count=0;
 const client=new NativeConfigClient({record:record(),fetchImpl:async()=>{count++;return new Response(codec.object(value));}});
 try{const decoded=await client.getConfig();assert.equal(decoded.this_dc,0);assert.equal(decoded.dc_options[0].ip_address,'node.fixture.invalid');assert.equal(count,1);}finally{client.close();}
 for(const invalid of ['bad host','-node.invalid','node-.invalid','node..invalid','x'.repeat(64)+'.invalid','node.invalid/path','node.invalid:443'])assert.throws(()=>validateConfig({...value,dc_options:[{...value.dc_options[0],ip_address:invalid}]}),{reason:'invalid_config_response'});
});

test('concurrent reads and changed or closed owners reject late results without persistence or a second request',async()=>{
 for(const close of [false,true]){const r=record();let release,count=0;const client=new NativeConfigClient({record:r,fetchImpl:async()=>{count++;return new Promise(resolve=>{release=resolve;});}});const pending=client.getConfig();await assert.rejects(client.getConfig(),{reason:'account_busy'});if(close)client.close();else r.token='fixture-replaced-token';release(new Response(frame()));await assert.rejects(pending,{reason:close?'closed':'account_binding_changed'});assert.equal(count,1);client.close();}
});
