const {test} = require('node:test'), assert = require('node:assert/strict');
const {MediaPair} = require('../experiments/providers/media-pair.cjs');
function deferred() { let resolve, reject; const promise = new Promise((a,b) => {resolve=a;reject=b;}); return {promise,resolve,reject}; }
function fixture() {
  const accounts = new Map([1,2].map(slot => [slot,{state:{signedIn:true,userId:String(slot)}}]));
  const calls = new Map([1,2].map(slot => [slot,{
    state:{phase:'joined',roomId:'99',peerId:String(3-slot),credentialReady:true},
    takeTransportSession(){ this.state.credentialReady=false; return {provider:'igap',url:'wss://call.igap.net/',
      selfId:String(slot),peerId:String(3-slot),roomId:'99',token:'fixture.payload.signature'}; }
  }]));
  const created=[],connections=[];
  const makeBridge = () => {
    const bridge = {publicCertificate: String(created.length+1).repeat(160),state:{phase:'prepared'},closed:0,
      async connect(session,options){connections.push({slot:session.selfId,peer:session.peerId,options});
        this.state={phase:'connected',role:options.role,mediaConnected:true,peerAuthenticated:true,proxyReady:options.role==='client'};},
      close(){this.closed++;this.state.phase='closing';}
    };created.push(bridge);return bridge;
  };
  const options = {executable:'/fixture/helper',accounts,calls,open:async()=>makeBridge()};
  return {accounts,calls,created,connections,makeBridge,options,pair:new MediaPair(options)};
}

test('media pair exchanges only public trust, binds reciprocal accounts and reports running only after mutual authentication', async()=>{
  const f=fixture();await f.pair.start({clientSlot:2,socksPort:1089,throughput:true});
  assert.equal(f.pair.state.phase,'running');
  assert.equal(f.connections[0].options.role,'server');assert.equal(f.connections[1].options.role,'client');
  assert.deepEqual(f.connections[0].options.trustedCertificates,[f.created[1].publicCertificate]);
  assert.deepEqual(f.connections[1].options.trustedCertificates,[f.created[0].publicCertificate]);
  assert.ok(!JSON.stringify(f.pair.state).includes('fixture.payload.signature'));
  assert.equal(f.pair.state.billingVerified,false);assert.equal(f.pair.state.providerPathVerified,false);
  await assert.rejects(f.pair.start(),/media_busy/);
  f.created[1].state.peerAuthenticated=false;f.created[1].state.proxyReady=false;
  assert.equal(f.pair.state.phase,'starting');
  f.pair.close();assert.ok(f.created.every(b=>b.closed===1));
});

test('wrong room, unjoined/duplicate accounts, nonreciprocal peers and consumed credentials never spawn helpers',async()=>{
  for(const change of [f=>f.calls.get(2).state.roomId='100', f=>f.calls.get(1).state.phase='incoming',
    f=>f.accounts.get(2).state.userId='1', f=>f.accounts.get(1).state.signedIn=false,
    f=>f.calls.get(1).state.peerId='3',f=>f.calls.get(1).state.credentialReady=false]){
    const f=fixture();change(f);await assert.rejects(f.pair.start());assert.equal(f.created.length,0);
  }
});

test('loss or account/room replacement on either side closes both native processes',async()=>{
  for(const change of [f=>f.created[0].state.phase='failed',f=>f.accounts.get(2).state.signedIn=false,
    f=>f.calls.get(2).state.phase='ended',f=>{for(const c of f.calls.values())c.state.roomId='100';}]){
    const f=fixture();await f.pair.start();change(f);assert.equal(f.pair.state.phase,'failed');
    assert.ok(f.created.every(b=>b.closed===1));
  }
});

test('one failed preparation still closes a late successful partner without consuming credentials',async()=>{
  const f=fixture(),late=deferred();let index=0;
  const pair=new MediaPair({...f.options,open:()=>++index===1?Promise.reject(new Error('private error')):late.promise});
  const starting=pair.start();const second=f.makeBridge();late.resolve(second);
  await assert.rejects(starting,/media_prepare_failed/);assert.equal(second.closed,1);
  assert.equal(f.calls.get(1).state.credentialReady,true);assert.equal(pair.state.phase,'failed');
});

test('close during preparation cancels late children and cannot race a replacement start',async()=>{
  const f=fixture(),late=deferred();const pair=new MediaPair({...f.options,open:()=>late.promise});
  const starting=pair.start();pair.close();await assert.rejects(pair.start(),/media_busy/);
  const child=f.makeBridge();late.resolve(child);await assert.rejects(starting,/media_cancelled/);
  assert.equal(pair.state.phase,'stopped');assert.equal(pair.state.busy,false);assert.ok(child.closed>=1);
  assert.equal(f.connections.length,0);
});

test('account changes during preparation and identity collisions fail before private connect commands',async()=>{
  const f=fixture(),late=deferred();let index=0;
  const pair=new MediaPair({...f.options,open:async()=>{const b=f.makeBridge();if(++index===2)await late.promise;return b;}});
  const starting=pair.start();f.accounts.get(2).state.signedIn=false;late.resolve();
  await assert.rejects(starting,/media_pair_not_joined/);assert.ok(f.created.every(b=>b.closed===1));
  assert.equal(f.connections.length,0);
  const other=fixture();other.options.open=async()=>{const b=other.makeBridge();b.publicCertificate='a'.repeat(160);return b;};
  const collision=new MediaPair(other.options);await assert.rejects(collision.start(),/media_identity_collision/);
  assert.equal(other.connections.length,0);
});
