// Offline parity against the pinned official serializer ONLY. Never executes
// the worker entry, imports, telemetry, fetch, account state, or login flow.
'use strict';
const fs=require('node:fs'),crypto=require('node:crypto'),vm=require('node:vm'),assert=require('node:assert/strict');
const wire=require('../experiments/eitaa/wire.cjs');
const codec=require('../experiments/eitaa/auth-wire.cjs'),account=require('../experiments/eitaa/account-client.cjs');
const {extract,authSchema}=require('./extract-eitaa-schema.cjs');
const source=fs.readFileSync(process.env.BALEVPN_EITAA_WORKER||'', 'utf8');
assert.equal(crypto.createHash('sha256').update(source).digest('hex'),'3f26a2a9706ac7a7761efae1fe1f96ef16c2063ede6b20397cf69e802b95825f','Unexpected official worker; review before executing extracted serializer');
assert.deepEqual(extract(source),require('../experiments/eitaa/service-schema.json'),'Committed service declarations must match the pinned source');
const auth=authSchema(source);assert.deepEqual(auth,require('../experiments/eitaa/auth-schema.json'),'Auth dependency closure must match the pinned source');
function method(name){const escaped=name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),match=source.match(new RegExp('\\{id:-?\\d+,method:"'+escaped+'",params:\\[.*?\\],type:"[^"]+"\\}'));assert.ok(match);return JSON.parse(match[0].replace(/([{,])(\w+):/g,'$1"$2":'));}
const outer=method('eitaaObject'),ping=method('ping');assert.equal(outer.id,wire.IDS.eitaaObject);assert.equal(ping.id,wire.IDS.ping);
assert.deepEqual(outer.params.map(p=>p.name+':'+p.type),['token:string','imei:string','packed_data:bytes','layer:int','flags:int']);
const a=source.indexOf('class Bt{'),b=source.indexOf('class Gt{',a);assert.ok(a>=0&&b>a&&b-a<12000);
const context=vm.createContext({At:{API:{methods:[outer,...auth.methods],constructors:auth.constructors},MTProto:{methods:[ping]}},Uint8Array,ArrayBuffer,Int32Array,encodeURIComponent,unescape,He:v=>v!==null&&typeof v==='object',Mr:481674261,_r:auth.constructors.find(c=>c.predicate==='boolTrue').id,yr:auth.constructors.find(c=>c.predicate==='boolFalse').id});
vm.runInContext(source.slice(a,b)+';globalThis.OfficialWriter=Bt;',context,{timeout:1000});
for(const length of [12,252,256,4096]){
 const packed=Buffer.alloc(length,0xa5),opts={imei:'0123456789abcde__web',token:length===12?'':'fixture-رمز',layer:135,flags:128};
 const official=new context.OfficialWriter();official.storeMethod('eitaaObject',{...opts,packed_data:packed});assert.deepEqual(Buffer.from(official.getBytes()),wire.envelope(packed,opts));
}
for(const id of [0n,1n,-1n,0x1234567890abcdefn]){
 const official=new context.OfficialWriter({mtproto:true}),u=BigInt.asUintN(64,id);official.storeMethod('ping',{ping_id:[Number(u>>32n),Number(u&0xffffffffn)]});assert.deepEqual(Buffer.from(official.getBytes()),wire.ping(id));
}
function officialValue(v){if(typeof v==='bigint'){const u=BigInt.asUintN(64,v);return [Number(u>>32n),Number(u&0xffffffffn)];}if(v instanceof Uint8Array)return v;if(Array.isArray(v))return v.map(officialValue);if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).map(([k,v])=>[k,officialValue(v)]));return v;}
const inputs={
 'auth.sendCode':{phone_number:'+989120000001',api_id:2496,api_hash:'8da85b0d5bfe62527e5b244c209159c3',settings:{_:'codeSettings'}},
 'auth.signIn':{phone_number:'+989120000001',phone_code_hash:'fixture-hash',phone_code:'123456'},
 'auth.checkPassword2':{password_hash:Buffer.alloc(32,0xa5),phone_number:'+989120000001',phone_code:'123456'},
 'account.getPassword':{},'account.getPasswordLayer68':{},'users.getUsers':{id:[{_:'inputUserSelf'}]},'auth.logOut':{},
 'eitaaRefreshToken':{app_info:{_:'eitaaAppInfo',build_version:2496,device_model:'Desktop '+crypto.createHash('sha256').update('0123456789abcde__web').digest('hex').slice(0,12),system_version:'fixture platform',app_version:'5.2 K',lang_code:'fa',sign:''}}
};
for(const [name,input]of Object.entries(inputs)){const official=new context.OfficialWriter();official.storeMethod(name,officialValue(input));assert.deepEqual(Buffer.from(official.getBytes()),codec.method(name,input));}
const user={_:'user',self:true,id:123456789012345n,access_hash:-42n,first_name:'کاربر',phone:'989120000001',photo:{_:'userProfilePhotoEmpty'},status:{_:'userStatusOffline',was_online:1234}};
const responses=[{_:'auth.authorization',token:'fixture-private-token',user},{_:'auth.sentCode',type:{_:'auth.sentCodeTypeSms',length:6},phone_code_hash:'fixture-service-hash',timeout:60},{_:'eitaa_updates_token',token:'fixture-refreshed-token',expire:1234,date:123},{_:'account.password2',current_salt:Buffer.alloc(24),new_salt:Buffer.alloc(24),new_secure_salt:Buffer.alloc(24),secure_random:Buffer.alloc(32),hint:'fixture-راهنما',email_unconfirmed_pattern:''}];
for(const response of responses){const official=new context.OfficialWriter();official.storeObject(officialValue(response),'Object');const binary=Buffer.from(official.getBytes());assert.deepEqual(binary,codec.object(response));assert.deepEqual(codec.decode(binary),response);}
const hashStart=source.indexOf('async function Es('),hashEnd=source.indexOf('const Et=',hashStart);assert.ok(hashStart>=0&&hashEnd>hashStart&&hashEnd-hashStart<1024);
context.pt=(a,b)=>Buffer.concat([a,b]);context.We={invokeCrypto:async(name,value)=>{assert.equal(name,'sha256');return crypto.createHash('sha256').update(value).digest();}};
vm.runInContext(source.slice(hashStart,hashEnd)+';globalThis.officialPasswordHash=Es;',context,{timeout:1000});
const timeClass=source.indexOf('class Cf extends de{'),timeStart=source.indexOf('generateId(){',timeClass),timeEnd=source.indexOf('applyServerTime(',timeStart);assert.ok(timeClass>=0&&timeEnd>timeStart&&timeEnd-timeStart<1024);
let fixtureNow=1793655000123;context.Date={now:()=>fixtureNow};context.Ns=bits=>{assert.equal(bits,16);return 42;};context.mr=(high,low)=>(BigInt(high)<<32n)|BigInt(low>>>0);
vm.runInContext('globalThis.OfficialTime=class{constructor(){this.lastMessageId=[0,0];this.timeOffset=0;}'+source.slice(timeStart,timeEnd)+'};',context,{timeout:1000});
const officialTime=new context.OfficialTime(),localTime=require('../experiments/eitaa/auth-session.cjs').requestIds({clock:()=>fixtureNow,random:()=>42});
for(const shift of [0,0,-1000,10000]){fixtureNow+=shift;assert.equal(localTime(),officialTime.generateId());}
(async()=>{for(const password of ['fixture-password','fixture-رمز-۱۲۳','fixture 😀']){const salt=Buffer.alloc(24,0xa5);assert.deepEqual(Buffer.from(await context.officialPasswordHash(password,salt)),account.passwordHash(password,salt));}console.log('PASS pinned official Eitaa parity: 4 envelopes, 4 pings, 8 account requests, 4 private account responses, 3 salted password hashes and 4 local request IDs; no network, worker startup or real account data');})().catch(e=>{console.error(e);process.exitCode=1;});
