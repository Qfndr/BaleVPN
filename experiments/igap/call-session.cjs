// Experimental signaling lifecycle. No microphone, media, SOCKS listener or
// automatic dialing. Credentials are available only to an in-process transport.
const {wire: w} = require('./signaling.cjs');
const {RpcError} = require('./rpc-connection.cjs');
const {roomRequestFields, decodeRoomResponse, liveKitSession, liveKitPushBinding, liveKitMediaGrants} = require('./room-signaling.cjs');

function identifier(value) {
  if (typeof value !== 'string' || !/^[1-9]\d{0,19}$/.test(value) || BigInt(value) > 0xffffffffffffffffn) {
    throw new RpcError('invalid_call_identifier');
  }
  return value;
}

class CallSession {
  #account;
  #rpc;
  #self;
  #peer;
  #allowed = new Set();
  #room;
  #phase = 'idle';
  #busy = false;
  #epoch = 0;
  #credential;
  #error = null;
  #peerJoined = false;
  #ringing = false;
  #ignored = 0;
  #terminalDiagnostic = null;
  #joinPushDiagnostic = null;
  #pendingReceiverJoin = null;
  #pendingLocalLeave = null;
  #mediaGrants = null;

  constructor(account) { this.#account = account; }

  // Pin the actual authenticated connection, not a caller-provided boolean.
  #context() {
    const state = this.#account.state;
    if (!state.signedIn) throw new RpcError('not_authenticated');
    const self = identifier(state.userId), rpc = this.#account.connection;
    if (this.#rpc && (this.#rpc !== rpc || this.#self !== self)) {
      this.reset();
      throw new RpcError('call_connection_changed');
    }
    this.#self = self;
    this.#rpc = rpc;
    return rpc;
  }

  setAllowedPeers(peers) {
    if (this.#busy || !['idle', 'ended'].includes(this.#phase)) throw new RpcError('call_busy');
    if (!Array.isArray(peers) || peers.length > 16) throw new RpcError('invalid_call_peers');
    const allowed = new Set(peers.map(identifier));
    if (allowed.size !== peers.length) throw new RpcError('invalid_call_peers');
    this.#allowed = allowed;
  }

  async #run(action) {
    if (this.#busy) throw new RpcError('call_busy');
    const rpc = this.#context(), epoch = this.#epoch;
    this.#busy = true;
    this.#error = null;
    const guard = () => {
      if (epoch !== this.#epoch) throw new RpcError('call_cancelled');
      if (!this.#account.state.signedIn || this.#account.connection !== rpc) {
        throw new RpcError('call_connection_changed');
      }
    };
    const request = async (code, args) => {
      guard();
      const response = await rpc.request(code, roomRequestFields(code, args));
      guard();
      if (response.action !== code + 30000) throw new RpcError('invalid_call_response');
      // Reuse the same bounded decoder for pushes and correlated replies.
      const fields = [...response.fields.entries()].flatMap(([key, values]) =>
        values.map(field => w.field(key, field.value, field.wire)));
      return decodeRoomResponse(w.frame(response.action, Buffer.concat(fields)));
    };
    try { return await action(request, guard); }
    catch (e) {
      const error = e instanceof RpcError ? e : new RpcError('invalid_call_response');
      if (epoch === this.#epoch) {
        this.#credential = null;
        this.#error = {reason: error.reason,
          ...(error.major === undefined ? {} : {major: error.major, minor: error.minor})};
        // A timed out create/join may have reached the service. Do not redial.
        this.#phase = 'uncertain';
      }
      throw error;
    } finally {
      if (epoch === this.#epoch) this.#busy = false;
    }
  }

  async dial(peerId) {
    identifier(peerId);
    if (!this.#allowed.has(peerId)) throw new RpcError('call_peer_not_allowed');
    if (!['idle', 'ended'].includes(this.#phase)) throw new RpcError('call_busy');
    this.#context();
    if (peerId === this.#self) throw new RpcError('call_self_not_allowed');
    return this.#run(async request => {
      this.#terminalDiagnostic = null;
      this.#joinPushDiagnostic = null;
      this.#mediaGrants = null;
      this.#peer = peerId;
      this.#room = null;
      this.#credential = null;
      this.#peerJoined = this.#ringing = false;
      this.#phase = 'creating';
      const created = await request(913, {type: 0, initialMethod: 0});
      this.#room = identifier(created.roomId);
      this.#phase = 'offering';
      const offered = await request(915, {peerId, roomId: this.#room});
      if (offered.roomId !== this.#room || offered.peerId !== this.#self ||
          offered.type !== 0 || offered.initialMethod !== 0) {
        throw new RpcError('call_offer_mismatch');
      }
      this.#phase = 'outgoing';
      return this.state;
    });
  }

  // Admission is local and explicit. No unknown caller is answered or rung.
  async handlePush(bytes) {
    try {
      this.#context();
      const response = decodeRoomResponse(bytes);
      if (response.id) { this.#ignored++; return; } // stale correlated reply
      if (response.action === 30915) {
        if (response.type !== 0 || response.initialMethod !== 0 ||
            !this.#allowed.has(response.peerId) || response.peerId === this.#self ||
            !['idle', 'ended'].includes(this.#phase) || this.#busy) {
          this.#ignored++; return;
        }
        identifier(response.roomId);
        // Limit this laboratory to two-party calls; no inherited group members.
        if (response.participants.some(id => ![this.#self, response.peerId].includes(id))) {
          this.#ignored++; return;
        }
        this.#room = response.roomId;
        this.#peer = response.peerId;
        this.#terminalDiagnostic = null;
        this.#joinPushDiagnostic = null;
        this.#mediaGrants = null;
        this.#phase = 'incoming';
        this.#credential = null;
        this.#peerJoined = this.#ringing = false;
        return;
      }
      if (!this.#room || ['idle', 'ended', 'uncertain'].includes(this.#phase)) {
        this.#ignored++; return;
      }
      if (response.action === 30916 && response.receiverId === this.#peer) {
        this.#ringing = true;
      } else if (response.action === 30914 && response.token) {
        const binding = liveKitPushBinding(response.token, this.#self, this.#room);
        const contextMatches = this.#phase === 'outgoing' && !this.#busy && this.#allowed.has(this.#peer) && response.joinedUserId === this.#self && !this.#credential;
        this.#joinPushDiagnostic = {...binding, contextMatches};
        if (contextMatches && Object.values(binding).every(value => value === true)) {
          this.#credential = liveKitSession(response, this.#self, this.#peer);
          this.#mediaGrants = liveKitMediaGrants(response.token);
          this.#phase = 'joined';
        } else this.#ignored++;
      } else if (response.action === 30914 && response.joinedUserId === this.#peer && !response.token) {
        this.#peerJoined = true;
      } else if (response.action === 30918 && [this.#self, this.#peer].includes(response.leftUserId)) {
        const leaving = this.#pendingLocalLeave;
        if (this.#phase === 'leaving' && this.#busy && leaving && leaving.epoch === this.#epoch && leaving.rpc === this.#rpc && leaving.room === this.#room) {
          leaving.confirmed = true;
          this.#terminalDiagnostic = {cause:'service_leave',endingActor:response.leftUserId === this.#self?'self':'peer',phaseBeforeEnd:'leaving',localLeaveConfirmed:true};
          this.#credential = null;
          this.#phase = 'ended';
          this.#room = null;
          this.#ringing = this.#peerJoined = false;
          return;
        }
        const pending = this.#pendingReceiverJoin;
        if (response.leftUserId === this.#self && this.#phase === 'joining' && this.#busy && pending && pending.epoch === this.#epoch && pending.rpc === this.#rpc && pending.room === this.#room) {
          pending.selfLeaveDeferred = true;
          this.#terminalDiagnostic = {cause: 'service_leave', endingActor: 'self', phaseBeforeEnd: 'joining', selfLeaveDeferred: true};
          return;
        }
        this.#terminalDiagnostic = {cause: 'service_leave', endingActor: response.leftUserId === this.#self ? 'self' : 'peer', phaseBeforeEnd: this.#phase};
        this.reset('ended');
      } else {
        // Other roomless pushes cannot authorize transport credentials.
        this.#ignored++;
      }
    } catch {
      this.#ignored++;
      if (!this.#account.state.signedIn) this.reset('ended');
    }
  }

  async ring() {
    if (this.#phase !== 'incoming') throw new RpcError('no_incoming_call');
    return this.#run(async request => {
      const response = await request(916);
      if (response.receiverId !== this.#self) throw new RpcError('call_ringing_mismatch');
      this.#ringing = true;
      return this.state;
    });
  }

  async join() {
    // A caller's matching service push already supplies the official join;
    // pressing the acceptance control again must not issue a redundant RPC.
    if (this.#phase === 'joined') { this.#context(); return this.state; }
    if (!['incoming', 'outgoing'].includes(this.#phase) || !this.#room) throw new RpcError('no_joinable_call');
    const pending = this.#phase === 'incoming' ? {epoch:this.#epoch,rpc:this.#rpc,room:this.#room,selfLeaveDeferred:false} : null;
    this.#pendingReceiverJoin = pending;
    try { return await this.#run(async request => {
        this.#phase = 'joining';
        const response = await request(914, {roomId: this.#room});
        // A roomless self-leave cannot identify which room ended. Only the
        // same correlated join, still on its pinned connection/epoch, may
        // resolve that ambiguity; require exact usable current-room claims.
        if (pending?.selfLeaveDeferred) {
          const binding = liveKitPushBinding(response.token, this.#self, pending.room);
          this.#joinPushDiagnostic = {...binding,contextMatches:response.joinedUserId === this.#self};
          if (!this.#joinPushDiagnostic.contextMatches || !Object.values(binding).every(value=>value===true)) throw new RpcError('call_join_binding_mismatch');
        }
        this.#credential = liveKitSession(response, this.#self, this.#peer);
        this.#mediaGrants = liveKitMediaGrants(response.token);
        if (pending?.selfLeaveDeferred) this.#terminalDiagnostic = {...this.#terminalDiagnostic,joinConfirmed:true};
        this.#phase = 'joined';
        return this.state;
      });
    } catch (error) {
      if (pending?.selfLeaveDeferred && pending.epoch === this.#epoch) this.reset('ended');
      throw error;
    } finally { if (this.#pendingReceiverJoin === pending) this.#pendingReceiverJoin = null; }
  }

  async leave({terminate = false} = {}) {
    if (typeof terminate !== 'boolean') throw new RpcError('invalid_leave_intent');
    if (!this.#room || ['idle', 'ended'].includes(this.#phase)) throw new RpcError('no_active_call');
    const phaseBeforeEnd = this.#phase;
    let pending;
    try { return await this.#run(async request => {
        pending = {epoch:this.#epoch,rpc:this.#rpc,self:this.#self,peer:this.#peer,room:this.#room,confirmed:false};
        this.#pendingLocalLeave = pending;
        this.#credential = null;
        this.#phase = 'leaving';
        const response = await request(918, {terminate});
        if (!pending.confirmed && response.leftUserId !== this.#self) throw new RpcError('call_leave_mismatch');
        if (!pending.confirmed) this.#terminalDiagnostic = {cause: 'local_leave', endingActor: 'self', phaseBeforeEnd};
        this.#phase = 'ended';
        this.#room = null;
        return this.state;
      });
    } catch(error) {
      // The matched service event already confirmed that this specific local
      // leave ended. A lost RPC reply must not turn that success into failure.
      // A reset/new call or account/connection replacement still cancels it.
      let current=false;
      try { current=!!pending?.confirmed && this.#pendingLocalLeave===pending && pending.epoch===this.#epoch && this.#rpc===pending.rpc && this.#self===pending.self && this.#peer===pending.peer && this.#account.state.signedIn===true && this.#account.state.userId===pending.self && this.#account.connection===pending.rpc; } catch {}
      if (!current) throw error;
      this.#credential=null;this.#error=null;this.#phase='ended';this.#room=null;
      return this.state;
    } finally { if (this.#pendingLocalLeave===pending) this.#pendingLocalLeave=null; }
  }

  takeTransportSession() {
    this.#context();
    if (this.#phase !== 'joined' || !this.#credential) throw new RpcError('call_transport_not_ready');
    const credential = this.#credential;
    this.#credential = null;
    return {...credential, roomId: this.#room, selfId: this.#self};
  }

  reset(phase = 'idle') {
    this.#pendingLocalLeave = null;
    if (phase !== 'ended') this.#mediaGrants = null;
    this.#pendingReceiverJoin = null;
    if (phase !== 'ended') this.#joinPushDiagnostic = null;
    if (phase !== 'ended') this.#terminalDiagnostic = null;
    this.#epoch++;
    this.#busy = false;
    this.#credential = null;
    this.#rpc = this.#self = this.#peer = this.#room = null;
    this.#phase = phase;
    this.#ringing = this.#peerJoined = false;
    this.#error = null;
  }

  get state() {
    if (this.#rpc && (!this.#account.state.signedIn || this.#account.connection !== this.#rpc)) {
      this.reset('ended');
    }
    return {provider: 'igap', phase: this.#phase, busy: this.#busy,
      roomId: this.#room || null, peerId: this.#peer || null,
      ringing: this.#ringing, peerJoined: this.#peerJoined,
      credentialReady: !!this.#credential, ignoredEvents: this.#ignored, error: this.#error,
      terminalDiagnostic: this.#terminalDiagnostic ? {...this.#terminalDiagnostic} : null,
      joinPushDiagnostic: this.#joinPushDiagnostic ? {...this.#joinPushDiagnostic} : null,
      mediaGrants: this.#mediaGrants ? {...this.#mediaGrants} : null,
      liveCallVerified: false, tunnelReady: false, billingVerified: false};
  }
}

module.exports = {CallSession};
