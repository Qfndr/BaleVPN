const {test} = require('node:test'), assert = require('node:assert/strict');
const {AuthSession} = require('../experiments/nasim/auth-session.cjs');
const {ApiError} = require('../experiments/nasim/http-client.cjs');
const {normalize} = require('../experiments/providers/phone.cjs');
const phone = normalize('IR','۰۹۱۲۰۰۰۰۰۰۱');
function fixture({user='41',nextState='active',failLogin=false,registrationLoop=false}={}) {
  const calls=[],clients=[];
  const active=()=>({nextState:'active',token:'fixture-session-token-not-real-'+user,clientID:'client-'+user,userID:user});
  const session=new AuthSession({createClient:({deviceId})=>{
    const client={deviceId,closed:false,async request(path,body,options={}){
      calls.push({path,body,options,deviceId});
      if(path==='/otp/sendByMobile')return {sentOTPDescription:'fixture'};
      if(path==='/user/login'){
        if(failLogin)throw new ApiError('rejected',400,'inCorrectOTP');
        if(nextState==='active')return active();
        return {nextState,verifiedToken:'fixture-verified-token-'+user,twoFAPasswordHint:'fixture hint'};
      }
      if(path==='/device/register')return registrationLoop?{nextState:'newDevice',verifiedToken:'fixture-verified-token-'+user}:active();
      if(path==='/twoFA/checkInLogin'||path==='/user/register')return active();
      if(path==='/mxb/user/status')return {active:false};
      throw new Error('Unexpected fixture path');
    },async logout(options){calls.push({path:'logout',options});return {loggedOut:true};},close(){this.closed=true;}};
    clients.push(client);return client;
  }});
  return {session,calls,clients};
}

test('two Nasim accounts keep distinct devices, pending OTPs, response IDs and private credentials',async()=>{
  const a=fixture(),b=fixture({user:'42'});
  await Promise.all([a.session.start(phone),b.session.start(phone)]);
  assert.notEqual(a.clients[0].deviceId,b.clients[0].deviceId);
  assert.deepEqual(a.calls[0].body,{countryCode:'+98',mobile:'9120000001',subsystem:'client'});
  await Promise.all([a.session.verify('12345'),b.session.verify('67890')]);
  assert.equal(a.calls[1].body.otp,'12345');assert.equal(b.calls[1].body.otp,'67890');
  assert.equal(a.session.state.userId,'41');assert.equal(b.session.state.userId,'42');
  assert.equal(a.session.state.signedIn,true);assert.equal(a.session.state.callReady,false);
  for(const secret of ['12345','fixture-session-token','fixture-verified-token',a.clients[0].deviceId])assert.ok(!JSON.stringify(a.session.state).includes(secret));
});

test('code rejection does not report authentication or automatically resend an OTP',async()=>{
  const f=fixture({failLogin:true});await f.session.start(phone);
  await assert.rejects(f.session.start(phone),/cooldown/);
  await assert.rejects(f.session.verify('12345'),/rejected/);
  assert.equal(f.session.state.stage,'code');assert.equal(f.session.state.signedIn,false);
  assert.deepEqual(f.calls.map(c=>c.path),['/otp/sendByMobile','/user/login']);
});

test('new-device registration remains in the same device profile and waits for the actual registration response',async()=>{
  const f=fixture({nextState:'newDevice'});await f.session.start(phone);await f.session.verify('12345');
  assert.deepEqual(f.calls.map(c=>c.path),['/otp/sendByMobile','/user/login','/device/register']);
  assert.deepEqual(f.calls[2].body,{os:'web',company:'web'});
  assert.equal(f.calls[2].options.verifiedToken,'fixture-verified-token-41');
  assert.equal(f.calls[0].deviceId,f.calls[2].deviceId);assert.equal(f.session.state.signedIn,true);
  const loop=fixture({nextState:'newDevice',registrationLoop:true});await loop.session.start(phone);
  await assert.rejects(loop.session.verify('12345'),/invalid_auth_response/);assert.equal(loop.session.state.signedIn,false);
  assert.equal(loop.calls.length,3,'never automatically register a second device');
});

test('second password and new-user naming are explicit and never silently create a user',async()=>{
  const f=fixture({nextState:'checkTwoFA'});await f.session.start(phone);await f.session.verify('12345');
  assert.equal(f.session.state.stage,'password');assert.equal(f.session.state.hint,'fixture hint');assert.equal(f.calls.length,2);
  await f.session.password('fixture-password');assert.equal(f.calls[2].body.password,'fixture-password');assert.equal(f.session.state.signedIn,true);
  const n=fixture({nextState:'newUser'});await n.session.start(phone);await n.session.verify('12345');
  assert.equal(n.session.state.stage,'profile_required');assert.equal(n.calls.length,2);
  await n.session.completeProfile('نام آزمایشی');assert.equal(n.calls[2].body.firstname,'نام آزمایشی');assert.equal(n.session.state.signedIn,true);
});

test('saved session restoration preserves device/token and never sends OTP or registers another device',async()=>{
  const first=fixture();await first.session.start(phone);await first.session.verify('12345');const saved=first.session.exportSession();
  first.session.stop();assert.equal(first.session.state.signedIn,false);await first.session.resume();
  assert.equal(first.clients[1].deviceId,saved.deviceId);
  const restored=fixture();await restored.session.restore(saved);
  assert.deepEqual(restored.calls.map(c=>c.path),['/mxb/user/status']);
  assert.equal(restored.calls[0].deviceId,saved.deviceId);assert.equal(restored.calls[0].options.token,saved.token);
  assert.equal(restored.session.state.signedIn,true);assert.equal(restored.session.state.selfConfirmed,false,'protected status does not return self identity');
  await restored.session.logout();assert.equal(restored.session.state.hasSession,false);assert.equal(restored.calls.at(-1).path,'logout');
});

test('cross-provider records and changed response identity are rejected instead of rebinding another account',async()=>{
  const a=fixture();await assert.rejects(a.session.restore({provider:'igap'}),/invalid_saved_session/);
  await a.session.start(phone);await a.session.verify('12345');const record=a.session.exportSession();
  const f=fixture();const original=f.session;
  // Construct a separate transport whose protected response names another self.
  const changed=new AuthSession({createClient:()=>({request:async()=>({active:true,userID:'42'}),close(){}})});
  await assert.rejects(changed.restore(record),/login_account_mismatch/);assert.equal(changed.state.signedIn,false);
  original.close();
});

test('close during an in-flight code request discards a late reply and prevents overlapping requests',async()=>{
  let finish;const result=new Promise(resolve=>{finish=resolve;});let count=0;
  const session=new AuthSession({createClient:()=>({request(){count++;return result;},close(){}})});
  const starting=session.start(phone);await assert.rejects(session.start(phone),/account_busy/);session.close();finish({sentOTPDescription:'fixture'});
  await assert.rejects(starting,/closed/);assert.equal(session.state.stage,'idle');assert.equal(count,1);
});

test('an uncertain OTP request still enforces the resend delay without claiming the code was accepted',async()=>{
  let count=0;const session=new AuthSession({createClient:()=>({request(){count++;throw new ApiError('timeout');},close(){}})});
  await assert.rejects(session.start(phone),/timeout/);assert.equal(session.state.stage,'idle');assert.equal(session.state.signedIn,false);
  assert.ok(session.state.retryAfter>=89);await assert.rejects(session.start(phone),/cooldown/);assert.equal(count,1);
});

test('authenticated signaling has account ownership, delivers early events only after installation and closes on stop',async()=>{
  const f=fixture();await f.session.start(phone);await f.session.verify('12345');const record=f.session.exportSession();
  const events=[],channel={state:{phase:'connected',reason:null},closed:0,close(){this.closed++;this.state.phase='closed';}};
  let opened=0;
  const session=new AuthSession({createClient:()=>({request:async()=>({active:false}),close(){}}),
    createSignaling:async(saved,{onEvent})=>{opened++;assert.equal(saved.provider,'nasim');assert.equal(saved.token,record.token);await onEvent({type:'config',callUUID:'fixture-call'});return channel;}});
  await assert.rejects(session.connectSignals(),/not_authenticated/);assert.equal(opened,0);
  await session.restore(record);await session.connectSignals({onEvent:event=>{assert.equal(session.signalConnection,channel);events.push(event);}});
  assert.equal(events.length,1);assert.equal(session.state.events.phase,'connected');assert.equal(session.state.callReady,false);
  assert.ok(!JSON.stringify(session.state).includes(record.token));
  session.stop();assert.equal(channel.closed,1);assert.throws(()=>session.signalConnection,/event_stream_not_connected/);
});

test('explicit signaling recovery after EOF reuses the session and rejects stale events',async()=>{
  const f=fixture();await f.session.start(phone);await f.session.verify('12345');const record=f.session.exportSession();
  const channels=[],received=[];
  const session=new AuthSession({createClient:()=>({request:async()=>({active:false}),close(){}}),
    createSignaling:async(saved,options)=>{
      assert.equal(saved.token,record.token);
      const channel={state:{phase:'connected'},...options,close(){this.state.phase='closed';}};
      channels.push(channel);return channel;
    }});
  try{
    await session.restore(record);
    const onEvent=event=>received.push(event);
    await session.connectSignals({onEvent});
    const old=channels[0];
    old.state={phase:'failed',reason:'stream_ended'};
    assert.equal(session.state.signedIn,true);
    assert.throws(()=>session.signalConnection,/event_stream_not_connected/);
    assert.equal(channels.length,1);
    assert.deepEqual(await session.connectSignals({onEvent}),{eventsConnected:true});
    assert.equal(old.signal.aborted,true);
    assert.throws(()=>old.onEvent({type:'config'}),/closed/);
    const fresh=channels[1],event={type:'config',callUUID:'fresh-fixture-call'};
    await fresh.onEvent(event);
    assert.deepEqual(received,[event]);
    assert.equal(session.signalConnection,fresh);
    assert.deepEqual(session.exportSession(),record);
  }finally{session.close();}
});

test('closing an account during signal setup disposes a late connection and cannot deliver or resurrect old events',async()=>{
  const f=fixture();await f.session.start(phone);await f.session.verify('12345');const record=f.session.exportSession();
  let finish,wrapped;const pending=new Promise(resolve=>{finish=resolve;});
  const channel={state:{phase:'connected'},closed:0,close(){this.closed++;this.state.phase='closed';}};
  const session=new AuthSession({createClient:()=>({request:async()=>({active:false}),close(){}}),
    createSignaling:async(saved,options)=>{wrapped=options.onEvent;return pending;}});
  await session.restore(record);let events=0;const opening=session.connectSignals({onEvent:()=>events++});session.close();
  finish(channel);await assert.rejects(opening,/closed/);assert.throws(()=>wrapped({type:'config'}),/closed/);
  assert.equal(events,0);assert.equal(channel.closed,1);assert.equal(session.state.stage,'idle');assert.equal(session.state.hasSession,false);
});
