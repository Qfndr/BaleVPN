const {test}=require('node:test'),assert=require('node:assert/strict');
const {AuthSession,createProfile}=require('../experiments/igap/auth-session.cjs'),{RpcError}=require('../experiments/igap/rpc-connection.cjs'),{wire:w}=require('../experiments/igap/signaling.cjs');
const {normalize}=require('../experiments/providers/phone.cjs');
class FakeRpc{
 constructor(id,{password=false,newUser=false,delay=0,loginId=id,failVerify=false}={}){Object.assign(this,{id,password,newUser,delay,loginId,failVerify,calls:[],status:{phase:'ready'}});}
 async request(action,body=Buffer.alloc(0)){const f=w.parse(body);this.calls.push({action,f});let payload=Buffer.alloc(0);
  if(action===100){assert.equal(w.str(f,3,2),'IR');assert.equal(w.one(f,2,0),9120000001n);payload=Buffer.concat([w.string(2,'username-'+this.id,128),w.field(3,BigInt(this.id),0),w.field(5,0,0),w.field(6,this.delay,0),w.field(9,5,0)]);}
  if(action===101){assert.equal(w.str(f,3,128),'username-'+this.id);assert.equal(w.one(f,9,0),BigInt(createProfile().platform));if(this.failVerify)throw new RpcError('rejected',102,1,25);if(this.password)throw new RpcError('rejected',184,0);payload=Buffer.concat([w.string(2,'fixture-token-'+this.id,100),w.field(3,this.newUser?1:0,0)]);}
  if(action===131)payload=w.string(4,'fixture hint',128);
  if(action===132){assert.equal(w.str(f,2,128),'fixture-password');payload=w.string(2,'fixture-token-'+this.id,100);}
  return {action:action+30000,fields:w.parse(payload)};
 }
 async login(body){const f=w.parse(body);this.calls.push({action:102,f});assert.equal(w.str(f,2,100),'fixture-token-'+this.id);assert.equal(w.parse(body).has(12),false);return {action:30102,fields:w.parse(w.field(14,BigInt(this.loginId),0))};}
 close(){this.status.phase='closed';}
}
const phone=normalize('IR','۰۹۱۲ ۰۰۰ ۰۰۰۱');
test('national phone formatting follows current API and preserves international prefix rules',()=>{
 assert.deepEqual(phone,{country:'IR',nationalNumber:'9120000001',internationalNumber:'+989120000001'});
 assert.equal(normalize('DE','+49 151 2345678').nationalNumber,'1512345678');assert.equal(normalize('GB','0044 7911 123456').internationalNumber,'+447911123456');
 assert.throws(()=>normalize('IR','+491512345678'),/phone_country_mismatch/);assert.throws(()=>normalize('../IR','123456'));assert.throws(()=>normalize('IR','1<script>'));
});
test('two concurrent pending login transactions and verified sessions remain separate and redacted',async()=>{
 const aRpc=new FakeRpc('41'),bRpc=new FakeRpc('42'),a=new AuthSession({connect:async()=>aRpc}),b=new AuthSession({connect:async()=>bRpc});
 try{await Promise.all([a.start(phone),b.start(phone)]);assert.equal(a.state.stage,'code');assert.equal(b.state.stage,'code');await b.verify('22222');assert.equal(a.state.signedIn,false);await a.verify('11111');assert.equal(a.state.signedIn,true);assert.equal(b.state.signedIn,true);assert.equal(a.exportSession().token,'fixture-token-41');assert.equal(b.exportSession().token,'fixture-token-42');assert.notEqual(a.exportSession().profile.deviceName,b.exportSession().profile.deviceName);
  const publicState=JSON.stringify([a.state,b.state]);for(const secret of ['fixture-token','username-','11111','22222','989120000001'])assert.ok(!publicState.includes(secret));
 }finally{a.close();b.close();}
});
test('server cooldown prevents duplicate OTP calls; failed verify preserves numeric wait without automatic retry',async()=>{
 const rpc=new FakeRpc('41',{delay:60,failVerify:true}),a=new AuthSession({connect:async()=>rpc});try{await a.start(phone);await assert.rejects(a.start(phone),e=>e.reason==='cooldown');assert.equal(rpc.calls.filter(x=>x.action===100).length,1);await assert.rejects(a.verify('bad'),e=>e.reason==='invalid_code_format');assert.equal(rpc.calls.filter(x=>x.action===101).length,0);await assert.rejects(a.verify('12345'),e=>e.major===102&&e.waitSeconds===25);assert.equal(rpc.calls.filter(x=>x.action===101).length,1);assert.ok(a.state.retryAfter>0);}finally{a.close();}
});
test('two-step password and new-account nickname flows use separate stages',async()=>{
 const rpc=new FakeRpc('41',{password:true}),a=new AuthSession({connect:async()=>rpc});try{await a.start(phone);assert.deepEqual(await a.verify('12345'),{twoFactorRequired:true});assert.equal(a.state.stage,'password');assert.equal(a.state.hint,'fixture hint');await a.password('fixture-password');assert.equal(a.state.signedIn,true);assert.equal(JSON.stringify(a.exportSession()).includes('fixture-password'),false);}finally{a.close();}
 const r=new FakeRpc('42',{newUser:true}),b=new AuthSession({connect:async()=>r});try{await b.start(phone);await b.verify('12345');assert.equal(b.state.stage,'profile_required');assert.throws(()=>b.connection);assert.equal(b.exportSession().needsProfile,true);await b.completeProfile('Test Name');assert.equal(r.calls.at(-1).action,105);assert.equal(b.state.signedIn,true);}finally{b.close();}
});
test('saved session restores without OTP and keeps device identity, including stop/resume and remote logout',async()=>{
 const original=new AuthSession({connect:async()=>new FakeRpc('41')});await original.start(phone);await original.verify('12345');const record=original.exportSession();original.close();
 const sockets=[],restored=new AuthSession({connect:async()=>{const rpc=new FakeRpc('41');sockets.push(rpc);return rpc;}});try{await restored.restore(record);assert.equal(restored.exportSession().profile.deviceName,record.profile.deviceName);assert.equal(restored.state.signedIn,true);restored.stop();assert.equal(restored.state.signedIn,false);await restored.resume();assert.equal(sockets.length,2);assert.equal(restored.state.signedIn,true);restored.stop();await restored.logout();assert.deepEqual(sockets.at(-1).calls.map(x=>x.action),[102,127]);assert.equal(restored.state.hasSession,false);assert.ok(sockets.flatMap(r=>r.calls).every(c=>![100,101].includes(c.action)));}finally{restored.close();}
});
test('late handshake after close cannot send OTP; mismatched login cannot expose an authenticated channel',async()=>{
 let release;const late=new FakeRpc('41'),a=new AuthSession({connect:()=>new Promise(r=>release=r)});const pending=a.start(phone);a.close();release(late);await assert.rejects(pending,e=>e.reason==='closed');assert.equal(late.calls.length,0);assert.equal(late.status.phase,'closed');
 const b=new AuthSession({connect:async()=>new FakeRpc('41',{loginId:'42'})});try{await b.start(phone);await assert.rejects(b.verify('12345'),e=>e.reason==='login_account_mismatch');assert.equal(b.state.signedIn,false);assert.throws(()=>b.connection);assert.throws(()=>b.exportSession());}finally{b.close();}
});
