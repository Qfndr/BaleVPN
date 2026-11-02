// Child process control only. Private messenger credentials never enter argv,
// environment, files, diagnostics, or the public state returned to the UI.
const path = require('node:path');
const {spawn} = require('node:child_process');

const MAX_LINE = 64 * 1024;
const ENDPOINT = 'wss://call.igap.net/';
const REASONS = new Set(['arguments_not_allowed', 'unsafe_environment', 'identity_failed',
  'bridge_panic', 'config_timeout', 'input_closed', 'invalid_config', 'invalid_role',
  'invalid_token', 'invalid_pairing', 'invalid_port', 'invalid_profile', 'event_stream_unavailable',
  'output_closed', 'invalid_command', 'invalid_control_command', 'transport_closed',
  'transport_disconnected', 'transport_failed', 'connect_timeout', 'server_setup_failed', 'proxy_bind_failed']);
function fail(reason) { return Object.assign(new Error('Native bridge ' + reason), {reason}); }
function cert(value) { return typeof value === 'string' && value.length >= 128 &&
  value.length <= 16384 && value.length % 2 === 0 && /^[a-f0-9]+$/.test(value); }
function bool(value) { return typeof value === 'boolean'; }
function number(value) { return typeof value === 'number' && Number.isFinite(value) && value >= 0; }
function keys(value, allowed) { return value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).every(key => allowed.includes(key)); }
function identifier(value) { return typeof value === 'string' && /^[1-9]\d{0,19}$/.test(value) && BigInt(value) <= 0xffffffffffffffffn; }

class NativeBridge {
  #child;
  #buffer = Buffer.alloc(0);
  #certificate;
  #phase = 'starting';
  #role;
  #context;
  #latest = {};
  #reason = null;
  #stderrBytes = 0;
  #resolve;
  #reject;
  #timer;
  #killTimer;

  static async open(executable, {spawnImpl = spawn, prepareTimeout = 10000} = {}) {
    if (typeof executable !== 'string' || !path.isAbsolute(executable) ||
        !Number.isInteger(prepareTimeout) || prepareTimeout < 100 || prepareTimeout > 30000) {
      throw fail('invalid_executable');
    }
    if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') throw fail('unsafe_environment');
    const bridge = new NativeBridge();
    return new Promise((resolve, reject) => {
      bridge.#resolve = () => resolve(bridge);
      bridge.#reject = reject;
      bridge.#timer = setTimeout(() => bridge.#failed('prepare_timeout'), prepareTimeout);
      const env = {...process.env, RUST_LOG: 'off', RUST_BACKTRACE: '0'};
      delete env.SSLKEYLOGFILE;
      try {
        bridge.#child = spawnImpl(executable, [], {shell: false, windowsHide: true,
          stdio: ['pipe', 'pipe', 'pipe'], env});
        bridge.#child.stdout.on('data', data => bridge.#read(data));
        // Drain but never retain or forward native/third-party error text.
        bridge.#child.stderr.on('data', data => { bridge.#stderrBytes = Math.min(MAX_LINE, bridge.#stderrBytes + data.length); });
        bridge.#child.on('error', () => bridge.#failed('process_failed'));
        bridge.#child.stdin.on('error', () => bridge.#failed('input_closed'));
        bridge.#child.on('exit', () => {
          clearTimeout(bridge.#killTimer);
          if (!['closed', 'failed', 'closing'].includes(bridge.#phase)) bridge.#failed('process_exited');
          else if (bridge.#phase === 'closing') bridge.#phase = 'closed';
        });
      } catch { bridge.#failed('process_failed'); }
    });
  }

  #failed(reason) {
    if (['failed', 'closed'].includes(this.#phase)) return;
    this.#phase = 'failed'; this.#reason = reason; this.#latest = {};
    this.#buffer.fill(0); this.#buffer = Buffer.alloc(0);
    clearTimeout(this.#timer);
    this.#reject?.(fail(reason)); this.#reject = this.#resolve = null;
    this.#child?.stdin.destroy();
    this.#child?.kill();
  }

  #read(chunk) {
    if (['failed', 'closed'].includes(this.#phase)) return;
    try {
      // Do not accumulate oversized/unterminated output, even from a broken
      // helper. Protocol lines are small; token and SDP output is not allowed.
      if (this.#buffer.length + chunk.length > MAX_LINE) throw fail('invalid_native_output');
      this.#buffer = Buffer.concat([this.#buffer, chunk]);
      let end;
      while ((end = this.#buffer.indexOf(10)) >= 0) {
        const line = this.#buffer.subarray(0, end);
        this.#buffer = this.#buffer.subarray(end + 1);
        const value = JSON.parse(line.toString('utf8'));
        this.#event(value);
      }
    } catch { this.#failed('invalid_native_output'); }
  }

  #event(value) {
    if (value.event === 'prepared') {
      if (this.#phase !== 'starting' || value.protocol !== 1 || !cert(value.publicCertificate) ||
          !keys(value, ['event', 'protocol', 'publicCertificate'])) throw fail('invalid_native_output');
      this.#certificate = value.publicCertificate;
      this.#phase = 'prepared'; clearTimeout(this.#timer);
      this.#resolve?.(); this.#resolve = this.#reject = null;
      return;
    }
    if (value.event === 'error') {
      if (!keys(value, ['event', 'reason']) || !REASONS.has(value.reason)) throw fail('invalid_native_output');
      this.#failed(value.reason); return;
    }
    if (value.event === 'stopped' && keys(value, ['event'])) {
      if (this.#phase !== 'closing') throw fail('invalid_native_output');
      this.#phase = 'closed'; this.#latest = {}; return;
    }
    if (!['connecting', 'connected'].includes(this.#phase)) throw fail('invalid_native_output');
    const common = ['event', 'mediaConnected', 'peerAuthenticated', 'proxyReady', 'providerPathVerified', 'billingVerified'];
    if (!bool(value.mediaConnected) || !bool(value.peerAuthenticated) || !bool(value.proxyReady) ||
        value.providerPathVerified !== false || value.billingVerified !== false ||
        (value.proxyReady && (!value.mediaConnected || !value.peerAuthenticated))) throw fail('invalid_native_output');
    if (value.event === 'connected') {
      if (!keys(value, [...common, 'provider', 'socksAddress']) || value.provider !== 'igap' ||
          (this.#role === 'server' ? value.socksAddress !== null :
            typeof value.socksAddress !== 'string' || !/^127\.0\.0\.1:\d{1,5}$/.test(value.socksAddress))) {
        throw fail('invalid_native_output');
      }
      this.#phase = 'connected';
      this.#latest.socksAddress = value.socksAddress;
    } else if (value.event === 'metrics') {
      if (this.#phase !== 'connected' || !keys(value, [...common, 'receivedBytes', 'sentBytes', 'quic']) ||
          !Number.isSafeInteger(value.receivedBytes) || value.receivedBytes < 0 ||
          !Number.isSafeInteger(value.sentBytes) || value.sentBytes < 0) throw fail('invalid_native_output');
      const q = value.quic;
      if (q !== null && (!keys(q, ['rttMs', 'lostPackets', 'sentPackets', 'congestionWindow', 'sendWindowBytes', 'profile']) ||
          !['throughput', 'balanced'].includes(q.profile) ||
          !['rttMs', 'lostPackets', 'sentPackets', 'congestionWindow', 'sendWindowBytes'].every(key => number(q[key])))) {
        throw fail('invalid_native_output');
      }
      this.#latest.receivedBytes = value.receivedBytes;
      this.#latest.sentBytes = value.sentBytes;
      this.#latest.quic = q === null ? null : {...q};
    } else throw fail('invalid_native_output');
    this.#latest.mediaConnected = value.mediaConnected;
    this.#latest.peerAuthenticated = value.peerAuthenticated;
    this.#latest.proxyReady = value.proxyReady;
  }

  get publicCertificate() {
    if (this.#phase !== 'prepared') throw fail('not_prepared');
    return this.#certificate;
  }

  async connect(session, {role, trustedCertificates, socksPort = 1080, throughput = false} = {}) {
    if (this.#phase !== 'prepared') throw fail('not_prepared');
    if (!session || session.provider !== 'igap' || session.url !== ENDPOINT ||
        !identifier(session.selfId) || !identifier(session.peerId) || !identifier(session.roomId) ||
        session.selfId === session.peerId || typeof session.token !== 'string' || session.token.length > 16384 ||
        !/^[-\w]+\.[-\w]+\.[-\w]+$/.test(session.token)) throw fail('invalid_session');
    if (!['client', 'server'].includes(role) || !bool(throughput) || !Number.isInteger(socksPort) ||
        socksPort > 65535 || (socksPort !== 0 && socksPort < 1024) || socksPort < 0 ||
        !Array.isArray(trustedCertificates) || !trustedCertificates.length || trustedCertificates.length > 8 ||
        new Set(trustedCertificates).size !== trustedCertificates.length ||
        trustedCertificates.some(item => !cert(item) || item === this.#certificate)) throw fail('invalid_pairing');
    this.#role = role;
    this.#context = {selfId: session.selfId, peerId: session.peerId, roomId: session.roomId};
    this.#phase = 'connecting';
    const command = {command: 'connect', provider: 'igap', url: ENDPOINT, token: session.token,
      role, trustedCertificates, socksPort, throughput};
    await new Promise((resolve, reject) => this.#child.stdin.write(JSON.stringify(command) + '\n', error => {
      command.token = '';
      if (error) { this.#failed('input_closed'); reject(fail('input_closed')); } else resolve();
    }));
  }

  close() {
    if (['closed', 'failed', 'closing'].includes(this.#phase)) return;
    this.#phase = 'closing'; this.#latest = {};
    clearTimeout(this.#timer);
    this.#reject?.(fail('closed')); this.#resolve = this.#reject = null;
    try { this.#child.stdin.end('{"command":"stop"}\n'); } catch { this.#child.kill(); }
    this.#killTimer = setTimeout(() => this.#child.kill(), 2500);
    this.#killTimer.unref();
  }

  get state() {
    return {provider: 'igap', phase: this.#phase, role: this.#role || null,
      context: this.#context ? {...this.#context} : null,
      ...this.#latest, quic: this.#latest.quic ? {...this.#latest.quic} : null,
      reason: this.#reason, stderrPresent: this.#stderrBytes > 0,
      providerPathVerified: false, billingVerified: false, internationalOutageVerified: false};
  }
}

module.exports = {NativeBridge};
