const {NativeBridge} = require('./native-bridge.cjs');
function failure(reason) { return Object.assign(new Error('Media pair ' + reason), {reason}); }

// Only a same-panel pair of previously admitted, joined accounts is supported.
// No token is persisted or returned by this controller. Media never goes via JS.
class MediaPair {
  #executable;
  #accounts;
  #calls;
  #open;
  #bridges = new Map();
  #phase = 'idle';
  #reason = null;
  #busy = false;
  #epoch = 0;
  #timer;
  #context;

  constructor({executable, accounts, calls, open = NativeBridge.open}) {
    this.#executable = executable; this.#accounts = accounts; this.#calls = calls; this.#open = open;
  }

  #validate(requireCredentials) {
    const a = this.#accounts.get(1)?.state, b = this.#accounts.get(2)?.state;
    const first = this.#calls.get(1)?.state, second = this.#calls.get(2)?.state;
    if (!a?.signedIn || !b?.signedIn || a.userId === b.userId || first?.phase !== 'joined' ||
        second?.phase !== 'joined' || !first.roomId || first.roomId !== second.roomId ||
        first.peerId !== b.userId || second.peerId !== a.userId) throw failure('media_pair_not_joined');
    if (requireCredentials && (!first.credentialReady || !second.credentialReady)) throw failure('media_credentials_required');
    return {firstId: a.userId, secondId: b.userId, roomId: first.roomId};
  }

  #stopChildren() {
    clearInterval(this.#timer); this.#timer = null;
    for (const bridge of this.#bridges.values()) bridge.close();
  }

  #check() {
    if (!['starting', 'running'].includes(this.#phase) || this.#busy) return;
    try {
      const context = this.#validate(false);
      if (JSON.stringify(context) !== JSON.stringify(this.#context)) throw failure('media_account_changed');
      if ([...this.#bridges.values()].some(bridge => ['failed', 'closed', 'closing'].includes(bridge.state.phase))) {
        throw failure('media_transport_ended');
      }
      const authenticated = [...this.#bridges.values()].every(bridge => bridge.state.mediaConnected && bridge.state.peerAuthenticated);
      const client = [...this.#bridges.values()].find(bridge => bridge.state.role === 'client');
      this.#phase = authenticated && client?.state.proxyReady ? 'running' : 'starting';
    } catch (error) {
      this.#phase = 'failed'; this.#reason = error.reason || 'media_transport_ended';
      this.#stopChildren();
    }
  }

  async start({clientSlot = 1, socksPort = 1089, throughput = false} = {}) {
    if (this.#busy || ['starting', 'running'].includes(this.#phase)) throw failure('media_busy');
    if (![1, 2].includes(clientSlot) || !Number.isInteger(socksPort) || socksPort < 1024 || socksPort > 65535 ||
        typeof throughput !== 'boolean') throw failure('invalid_media_options');
    this.#validate(true);
    const epoch = ++this.#epoch;
    this.#busy = true; this.#phase = 'preparing'; this.#reason = null; this.#bridges.clear();
    try {
      // Wait for both results, including a late successful child after its
      // partner failed, so no prepared process is abandoned.
      const results = await Promise.allSettled([this.#open(this.#executable), this.#open(this.#executable)]);
      const prepared = results.filter(result => result.status === 'fulfilled').map(result => result.value);
      if (epoch !== this.#epoch || results.some(result => result.status === 'rejected')) {
        for (const bridge of prepared) bridge.close();
        throw failure(epoch !== this.#epoch ? 'media_cancelled' : 'media_prepare_failed');
      }
      this.#bridges.set(1, results[0].value); this.#bridges.set(2, results[1].value);
      this.#context = this.#validate(true);
      const credentials = [1, 2].map(slot => this.#calls.get(slot).takeTransportSession());
      if (credentials[0].provider !== 'igap' || credentials[1].provider !== 'igap' ||
          credentials[0].selfId !== this.#context.firstId || credentials[1].selfId !== this.#context.secondId ||
          credentials[0].peerId !== this.#context.secondId || credentials[1].peerId !== this.#context.firstId ||
          credentials.some(item => item.roomId !== this.#context.roomId)) throw failure('media_account_changed');
      const certificates = [this.#bridges.get(1).publicCertificate, this.#bridges.get(2).publicCertificate];
      if (certificates[0] === certificates[1]) throw failure('media_identity_collision');
      try {
        await Promise.all([1, 2].map(slot => this.#bridges.get(slot).connect(credentials[slot - 1],
          {role: slot === clientSlot ? 'client' : 'server', trustedCertificates: [certificates[2 - slot]], socksPort, throughput})));
      } finally {
        for (const credential of credentials) credential.token = '';
      }
      if (epoch !== this.#epoch) throw failure('media_cancelled');
      this.#phase = 'starting';
      this.#timer = setInterval(() => this.#check(), 500); this.#timer.unref();
    } catch (error) {
      this.#stopChildren();
      if (epoch === this.#epoch) { this.#phase = 'failed'; this.#reason = error.reason || 'media_start_failed'; }
      throw failure(error.reason || 'media_start_failed');
    } finally { this.#busy = false; }
    return this.state;
  }

  close() {
    // Keep an outstanding start busy until all preparation results settle;
    // otherwise its late cleanup could terminate a newly started pair.
    this.#epoch++; this.#stopChildren(); this.#phase = 'stopped'; this.#reason = null;
  }

  get state() {
    this.#check();
    return {available: true, phase: this.#phase, busy: this.#busy, reason: this.#reason,
      bridges: [...this.#bridges].map(([slot, bridge]) => ({slot, ...bridge.state})),
      providerPathVerified: false, billingVerified: false, internationalOutageVerified: false};
  }
}

module.exports = {MediaPair};
