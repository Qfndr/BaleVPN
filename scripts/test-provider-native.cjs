const {test} = require('node:test');
const assert = require('node:assert/strict');
const {EventEmitter} = require('node:events');
const {PassThrough, Writable} = require('node:stream');
const path = require('node:path');
const {NativeBridge} = require('../experiments/providers/native-bridge.cjs');

const own = 'aa'.repeat(80), peer = 'bb'.repeat(80);
const session = {provider: 'igap', url: 'wss://call.igap.net/', token: 'fixture.payload.signature',
  selfId: '41', peerId: '42', roomId: '99'};
function fixture({prepared = true} = {}) {
  let invocation;
  const commands = [], child = new EventEmitter();
  child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.killed = false;
  child.stdin = new Writable({write(bytes, encoding, done) {
    for (const line of bytes.toString().trim().split('\n')) if (line) commands.push(JSON.parse(line));
    done();
  }});
  child.kill = () => { child.killed = true; queueMicrotask(() => child.emit('exit', 1)); };
  const emit = value => child.stdout.write(JSON.stringify(value) + '\n');
  const spawnImpl = (executable, args, options) => {
    invocation = {executable, args, options};
    if (prepared) queueMicrotask(() => emit({event: 'prepared', protocol: 1, publicCertificate: own}));
    return child;
  };
  return {open: () => NativeBridge.open(path.resolve('fixture-native-helper'), {spawnImpl, prepareTimeout: 100}),
    child, emit, commands, invocation: () => invocation};
}
const connected = (extra = {}) => ({event: 'connected', provider: 'igap', mediaConnected: true,
  socksAddress: '127.0.0.1:1080', peerAuthenticated: false, proxyReady: false,
  providerPathVerified: false, billingVerified: false, ...extra});
const metrics = (extra = {}) => ({event: 'metrics', mediaConnected: true, peerAuthenticated: true,
  proxyReady: true, receivedBytes: 10000, sentBytes: 2000, quic: {rttMs: 100, lostPackets: 2,
    sentPackets: 200, congestionWindow: 120000, sendWindowBytes: 4000000, profile: 'throughput'},
  providerPathVerified: false, billingVerified: false, ...extra});

test('native token crosses only stdin; process has no command arguments, shell, exposed window or secret state', async () => {
  const f = fixture(), bridge = await f.open();
  assert.equal(bridge.publicCertificate, own);
  assert.equal(bridge.state.phase, 'prepared');
  await bridge.connect(session, {role: 'client', trustedCertificates: [peer], throughput: true});
  assert.deepEqual(f.invocation().args, []);
  assert.equal(f.invocation().options.shell, false);
  assert.equal(f.invocation().options.windowsHide, true);
  assert.equal(f.invocation().options.env.SSLKEYLOGFILE, undefined);
  assert.ok(!JSON.stringify(f.invocation()).includes(session.token));
  assert.equal(f.commands[0].token, session.token);
  f.emit(connected());
  assert.equal(bridge.state.proxyReady, false);
  f.emit(metrics());
  assert.equal(bridge.state.peerAuthenticated, true);
  assert.equal(bridge.state.proxyReady, true);
  assert.equal(bridge.state.billingVerified, false);
  assert.equal(bridge.state.quic.rttMs, 100);
  const copy = bridge.state; copy.quic.rttMs = 0;
  assert.equal(bridge.state.quic.rttMs, 100);
  assert.ok(!JSON.stringify(bridge.state).includes(session.token));
  bridge.close();
  f.emit({event: 'stopped'}); f.child.emit('exit', 0);
  assert.equal(bridge.state.phase, 'closed');
  assert.equal(bridge.state.proxyReady, undefined);
});

test('cross-provider sessions, self pairing, duplicate trust and unsafe role/port cannot start a helper connection', async () => {
  const f = fixture(), bridge = await f.open();
  for (const change of [{provider: 'bale'}, {url: 'wss://foreign.invalid/'}, {peerId: '41'},
    {selfId: '18446744073709551616'}, {roomId: '0'}, {token: 'a.b.c?token'}]) {
    await assert.rejects(bridge.connect({...session, ...change}, {role: 'client', trustedCertificates: [peer]}));
  }
  for (const options of [{trustedCertificates: []}, {trustedCertificates: [own]},
    {trustedCertificates: [peer, peer]}, {role: 'other'}, {socksPort: 80}, {throughput: 'true'}]) {
    await assert.rejects(bridge.connect(session, {role: 'client', trustedCertificates: [peer], ...options}));
  }
  assert.equal(f.commands.length, 0);
  bridge.close(); f.emit({event: 'stopped'}); f.child.emit('exit', 0);
});

test('unsafe or secret-bearing native output fails closed rather than reaching public status', async () => {
  for (const output of [connected({token: session.token}), connected({socksAddress: '0.0.0.0:1080'}),
    connected({proxyReady: true}), metrics({billingVerified: true}), metrics({receivedBytes: -1}),
    {event: 'error', reason: session.token}, {event: 'prepared', protocol: 1, publicCertificate: own}]) {
    const f = fixture(), bridge = await f.open();
    await bridge.connect(session, {role: 'client', trustedCertificates: [peer]});
    f.emit(output);
    assert.equal(bridge.state.phase, 'failed');
    assert.equal(bridge.state.reason, 'invalid_native_output');
    assert.ok(!JSON.stringify(bridge.state).includes(session.token));
    assert.equal(f.child.killed, true);
  }
});

test('oversized output, raw stderr, early exit and prepare timeout do not leak data or leave a live helper', async () => {
  const f = fixture(), bridge = await f.open();
  f.child.stderr.write(session.token);
  assert.equal(bridge.state.stderrPresent, true);
  assert.ok(!JSON.stringify(bridge.state).includes(session.token));
  f.child.stdout.write(Buffer.alloc(65537, 65));
  assert.equal(bridge.state.phase, 'failed'); assert.equal(f.child.killed, true);
  const early = fixture({prepared: false}), opening = early.open(); early.child.emit('exit', 1);
  await assert.rejects(opening, /process_exited/);
  const late = fixture({prepared: false}); await assert.rejects(late.open(), /prepare_timeout/);
  assert.equal(late.child.killed, true);
  const stopped = fixture({prepared: false}), stopping = stopped.open(); stopped.emit({event:'stopped'});
  await assert.rejects(stopping, /invalid_native_output/);
});

test('the actual native helper prepares distinct public identities and stops on a private pipe command',
  {skip: !process.env.BALEVPN_PROVIDER_BRIDGE}, async () => {
    const [a, b] = await Promise.all([NativeBridge.open(process.env.BALEVPN_PROVIDER_BRIDGE),
      NativeBridge.open(process.env.BALEVPN_PROVIDER_BRIDGE)]);
    try {
      assert.notEqual(a.publicCertificate, b.publicCertificate);
      assert.ok(a.publicCertificate.startsWith('30'));
      assert.equal(a.state.phase, 'prepared');
      assert.ok(!JSON.stringify(a.state).includes('private'));
    } finally { a.close(); b.close(); }
    const end = Date.now() + 5000;
    while ((a.state.phase === 'closing' || b.state.phase === 'closing') && Date.now() < end) {
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.equal(a.state.phase, 'closed'); assert.equal(b.state.phase, 'closed');
  });

test('actual helper rejects unsafe configuration and bounded malformed input without echoing secrets or contacting a provider',
  {skip: !process.env.BALEVPN_PROVIDER_BRIDGE}, async () => {
    const run = (input, extraEnv = {}) => new Promise((resolve, reject) => {
      const env = {...process.env, RUST_LOG:'off', ...extraEnv}; delete env.SSLKEYLOGFILE;
      const child = require('node:child_process').spawn(process.env.BALEVPN_PROVIDER_BRIDGE, [],
        {windowsHide:true,shell:false,stdio:['pipe','pipe','pipe'],env});
      let stdout='',stderr='';
      const timer=setTimeout(()=>{child.kill();reject(new Error('Native helper did not terminate'));},5000);
      child.stdout.on('data',bytes=>{stdout+=bytes.toString();});child.stderr.on('data',bytes=>{stderr+=bytes.toString();});
      child.on('error',error=>{clearTimeout(timer);reject(error);});child.on('exit',code=>{
        clearTimeout(timer);resolve({code,stdout,stderr});
      });child.stdin.on('error',()=>{});child.stdin.end(input);
    });
    const config={command:'connect',provider:'igap',url:'wss://foreign.invalid/',role:'client',
      token:session.token,trustedCertificates:[peer],socksPort:1089,throughput:true};
    for(const input of [JSON.stringify(config)+'\n', JSON.stringify({...config,url:session.url,trustedCertificates:[]})+'\n',
      '{"private":"'+session.token, 'x'.repeat(65537)+'\n','']){
      const result=await run(input);assert.notEqual(result.code,0);assert.ok(result.stdout.length<3000);
      assert.ok(!result.stdout.includes(session.token));assert.ok(!result.stderr.includes(session.token));
      const events=result.stdout.trim().split('\n').map(line=>JSON.parse(line));
      assert.equal(events.at(-1).event,'error');
      assert.ok(['invalid_config','invalid_pairing','invalid_command','input_closed'].includes(events.at(-1).reason));
    }
    const unsafe=await run('',{NODE_TLS_REJECT_UNAUTHORIZED:'0'});
    assert.equal(JSON.parse(unsafe.stdout).reason,'unsafe_environment');
  });
