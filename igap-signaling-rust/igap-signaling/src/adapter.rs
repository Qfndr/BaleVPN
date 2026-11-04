use crate::{
    auth::{self, Challenge, Profile, RegistrationProfile, SessionRecord},
    room,
    rpc::{Connection, Response, Rpc},
    wire as w, Error,
};
use async_trait::async_trait;
use lk_signaling::{
    CallDecision, ContactPage, EndReason, EventsSink, IncomingHandler, PeerId, PeerRef,
    PlaceCallError, Signaling, SignalingError, SignalingEvent, TokenStore, TransportSession,
    TunnelHooks,
};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot, watch};
use zeroize::Zeroizing;

#[async_trait]
pub trait Connector: Send + Sync {
    async fn open(&self) -> Result<(Arc<dyn Rpc>, mpsc::Receiver<Response>), Error>;
}
struct SocketConnector;
#[async_trait]
impl Connector for SocketConnector {
    async fn open(&self) -> Result<(Arc<dyn Rpc>, mpsc::Receiver<Response>), Error> {
        let (c, rx) = Connection::open().await?;
        Ok((c, rx))
    }
}
struct Peer(String);
impl PeerRef for Peer {
    fn id_str(&self) -> &str {
        &self.0
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Outgoing,
    Incoming,
    Joining,
    Joined,
}
struct Call {
    epoch: u64,
    peer: PeerId,
    room: String,
    phase: Phase,
    reply: Option<oneshot::Sender<Result<TransportSession, Error>>>,
    deferred_self_leave: bool,
    transport_digest: Option<[u8; 32]>,
    incoming_timestamp: Option<u32>,
    receiver_join_order: Option<u64>,
    local_leave_confirmed: Option<Arc<AtomicBool>>,
}
struct Auth {
    profile: Profile,
    record: Option<SessionRecord>,
    challenge: Option<Challenge>,
    phone: String,
    stage: &'static str,
    retry_at: std::time::Instant,
    signed: bool,
}
struct Inner {
    store: Arc<dyn TokenStore>,
    connector: Arc<dyn Connector>,
    rpc: Mutex<Option<Arc<dyn Rpc>>>,
    epoch: AtomicU64,
    call_revision: AtomicU64,
    flow: tokio::sync::Mutex<()>,
    auth: Mutex<Auth>,
    call: Mutex<Option<Call>>,
    last_service_leave: Mutex<Option<ServiceLeaveDiagnostic>>,
    peers: Mutex<HashMap<String, PeerId>>,
    allowed: Mutex<HashSet<String>>,
    handler: Mutex<(u64, Option<Arc<dyn IncomingHandler>>)>,
    accepted_tx: mpsc::UnboundedSender<(PeerId, TransportSession)>,
    accepted_rx: Mutex<Option<mpsc::UnboundedReceiver<(PeerId, TransportSession)>>>,
    events: EventsSink<SignalingEvent>,
    teardown: watch::Sender<u64>,
    foreground: watch::Sender<bool>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(rpc) = self.rpc.get_mut().take() {
            rpc.close();
        }
    }
}
#[derive(Clone)]
pub struct IgapSignaling {
    inner: Arc<Inner>,
}
/// Fixed enums only: no account IDs, room IDs, tokens or service text.
#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceLeaveDiagnostic {
    pub actor: &'static str,
    pub phase: &'static str,
    pub deferred: bool,
    pub metadata_timestamp_order: &'static str,
}
struct CallLease {
    owner: IgapSignaling,
    epoch: u64,
    room: String,
    call_revision: u64,
    armed: bool,
}
impl Drop for CallLease {
    fn drop(&mut self) {
        if self.armed {
            self.owner.end_call_if(
                self.epoch,
                &self.room,
                self.call_revision,
                EndReason::NetworkDrop,
            );
        }
    }
}
#[derive(Clone, Debug)]
pub struct AuthState {
    pub stage: &'static str,
    pub signed_in: bool,
    pub delivery_method: Option<u8>,
    pub code_digits: Option<u8>,
    pub retry_after: u64,
    pub profile: RegistrationProfile,
}
#[derive(Clone, Debug)]
pub struct CodeRequest {
    pub delivery_method: u8,
    pub digits: u8,
    pub retry_after: u32,
}
impl IgapSignaling {
    /// A revision changes when the adapter starts handling a call, even if
    /// signaling drops before a joined transport reaches the application.
    pub fn call_revision(&self) -> u64 {
        self.inner.call_revision.load(Ordering::Acquire)
    }

    /// Bind a consumer to the exact accepted transport, without retaining its token.
    pub fn joined_call_revision(&self, session: &TransportSession) -> Option<u64> {
        let digest: [u8; 32] = Sha256::digest(session.token.as_bytes()).into();
        let call = self.inner.call.lock();
        call.as_ref()
            .filter(|c| {
                c.epoch == self.epoch()
                    && c.phase == Phase::Joined
                    && c.peer == session.peer_id
                    && c.transport_digest == Some(digest)
            })
            .map(|_| self.inner.call_revision.load(Ordering::Acquire))
    }
    /// Local event queues can contain an earlier call's end event. This checks
    /// the exact locally accepted generation; it does not reinterpret wire pushes.
    pub fn is_joined_call_revision(&self, revision: u64) -> bool {
        let call = self.inner.call.lock();
        self.inner.call_revision.load(Ordering::Acquire) == revision
            && call
                .as_ref()
                .is_some_and(|c| c.epoch == self.epoch() && c.phase == Phase::Joined)
    }
    pub fn service_leave_diagnostic(&self) -> Option<ServiceLeaveDiagnostic> {
        *self.inner.last_service_leave.lock()
    }
    pub fn new(store: Arc<dyn TokenStore>, profile: RegistrationProfile) -> Self {
        Self::with_connector(store, profile, Arc::new(SocketConnector))
    }
    pub fn with_connector(
        store: Arc<dyn TokenStore>,
        profile: RegistrationProfile,
        connector: Arc<dyn Connector>,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            inner: Arc::new(Inner {
                store,
                connector,
                rpc: Mutex::new(None),
                epoch: AtomicU64::new(0),
                call_revision: AtomicU64::new(0),
                flow: tokio::sync::Mutex::new(()),
                auth: Mutex::new(Auth {
                    profile: Profile::new(profile),
                    record: None,
                    challenge: None,
                    phone: String::new(),
                    stage: "idle",
                    retry_at: std::time::Instant::now(),
                    signed: false,
                }),
                call: Mutex::new(None),
                last_service_leave: Mutex::new(None),
                peers: Mutex::new(HashMap::new()),
                allowed: Mutex::new(HashSet::new()),
                handler: Mutex::new((0, None)),
                accepted_tx: tx,
                accepted_rx: Mutex::new(Some(rx)),
                events: EventsSink::new(),
                teardown: watch::channel(0).0,
                foreground: watch::channel(true).0,
            }),
        }
    }
    fn epoch(&self) -> u64 {
        self.inner.epoch.load(Ordering::Acquire)
    }
    fn guard(&self, epoch: u64, rpc: &Arc<dyn Rpc>) -> Result<(), Error> {
        if epoch != self.epoch() {
            return Err(Error::Cancelled);
        }
        if !rpc.ready()
            || !self
                .inner
                .rpc
                .lock()
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, rpc))
        {
            return Err(Error::NotConnected);
        }
        Ok(())
    }
    async fn channel(&self) -> Result<Arc<dyn Rpc>, Error> {
        if let Some(rpc) = self.inner.rpc.lock().clone() {
            if rpc.ready() {
                return Ok(rpc);
            }
        }
        self.end_call(EndReason::NetworkDrop);
        let epoch = self.epoch();
        let (rpc, mut pushes) = self.inner.connector.open().await?;
        if epoch != self.epoch() {
            rpc.close();
            return Err(Error::Cancelled);
        }
        self.inner.auth.lock().signed = false;
        *self.inner.rpc.lock() = Some(rpc.clone());
        let weak = Arc::downgrade(&self.inner);
        let context = rpc.clone();
        tokio::spawn(async move {
            while let Some(response) = pushes.recv().await {
                let Some(inner) = weak.upgrade() else { break };
                let this = Self { inner };
                if this.guard(epoch, &context).is_err() {
                    break;
                }
                this.handle_push(epoch, context.clone(), response).await;
            }
            if let Some(inner) = weak.upgrade() {
                let this = Self { inner };
                let current_context = this.epoch() == epoch
                    && this
                        .inner
                        .rpc
                        .lock()
                        .as_ref()
                        .is_some_and(|current| Arc::ptr_eq(current, &context));
                if current_context {
                    this.inner.auth.lock().signed = false;
                    this.end_call(EndReason::NetworkDrop);
                }
            }
        });
        Ok(rpc)
    }
    fn self_id(&self) -> Result<String, Error> {
        let auth = self.inner.auth.lock();
        if !auth.signed || !self.is_connected() {
            return Err(Error::NotAuthenticated);
        }
        Ok(auth
            .record
            .as_ref()
            .ok_or(Error::NotAuthenticated)?
            .user_id
            .clone())
    }
    fn peer(&self, id: &str) -> Result<PeerId, Error> {
        room::id(id)?;
        let mut peers = self.inner.peers.lock();
        if peers.len() >= 1024 && !peers.contains_key(id) {
            return Err(Error::Busy);
        }
        Ok(peers
            .entry(id.to_owned())
            .or_insert_with(|| PeerId::new(Peer(id.to_owned())))
            .clone())
    }
    pub fn set_allowed_peers(&self, peers: &[String]) -> Result<(), Error> {
        if peers.len() > 64 || self.inner.call.lock().is_some() {
            return Err(Error::Busy);
        }
        for peer in peers {
            room::id(peer)?;
        }
        let values: HashSet<_> = peers.iter().cloned().collect();
        if values.len() != peers.len() {
            return Err(Error::InvalidInput);
        }
        *self.inner.allowed.lock() = values;
        Ok(())
    }
    pub fn state(&self) -> AuthState {
        let a = self.inner.auth.lock();
        AuthState {
            stage: a.stage,
            signed_in: a.signed && self.is_connected(),
            delivery_method: if a.stage == "code" && self.is_connected() {
                a.challenge.as_ref().map(|c| c.delivery_method)
            } else {
                None
            },
            code_digits: a.challenge.as_ref().map(|c| c.digits),
            retry_after: {
                let wait = a
                    .retry_at
                    .saturating_duration_since(std::time::Instant::now());
                wait.as_secs() + u64::from(wait.subsec_nanos() > 0)
            },
            profile: a.profile.mode().unwrap_or_default(),
        }
    }
    fn persist(&self) -> Result<(), Error> {
        let a = self.inner.auth.lock();
        if !["authenticated", "profile_required"].contains(&a.stage) {
            return Err(Error::NotAuthenticated);
        }
        let record = a.record.as_ref().ok_or(Error::NotAuthenticated)?;
        record.validate().map_err(|_| Error::InvalidInput)?;
        let bytes = Zeroizing::new(serde_json::to_vec(record).map_err(|_| Error::InvalidResponse)?);
        self.inner.store.save(&bytes);
        Ok(())
    }
    fn remember_wait(&self, epoch: u64, error: Error) -> Result<Error, Error> {
        if epoch != self.epoch() {
            return Err(Error::Cancelled);
        }
        if let Error::Rejected { wait_seconds, .. } = error {
            if wait_seconds > 0 {
                let retry = std::time::Instant::now()
                    .checked_add(Duration::from_secs(u64::from(wait_seconds)))
                    .ok_or(Error::InvalidResponse)?;
                let mut a = self.inner.auth.lock();
                a.retry_at = a.retry_at.max(retry);
            }
        }
        Ok(error)
    }
    async fn auth_request(
        &self,
        rpc: &Arc<dyn Rpc>,
        epoch: u64,
        action: u16,
        fields: Vec<u8>,
    ) -> Result<Response, Error> {
        self.guard(epoch, rpc)?;
        match rpc.request(action, fields).await {
            Ok(reply) => {
                self.guard(epoch, rpc)?;
                if reply.action != action + 30000 {
                    return Err(Error::InvalidResponse);
                }
                Ok(reply)
            }
            Err(error) => {
                self.guard(epoch, rpc)?;
                Err(self.remember_wait(epoch, error)?)
            }
        }
    }
    async fn login_record(&self, rpc: Arc<dyn Rpc>, epoch: u64) -> Result<(), Error> {
        self.guard(epoch, &rpc)?;
        let record = {
            let mut a = self.inner.auth.lock();
            a.signed = false;
            a.stage = "authenticating";
            a.record.clone().ok_or(Error::NotAuthenticated)?
        };
        record.validate().map_err(|_| Error::InvalidInput)?;
        let fields =
            auth::login_fields(&record.token, &record.profile).map_err(|_| Error::InvalidInput)?;
        let reply = match rpc.login(fields).await {
            Ok(reply) => reply,
            Err(error) => {
                self.guard(epoch, &rpc)?;
                return Err(self.remember_wait(epoch, error)?);
            }
        };
        self.guard(epoch, &rpc)?;
        if reply.action != 30102
            || auth::parse_login(&reply.fields).map_err(|_| Error::InvalidResponse)?
                != record.user_id
        {
            return Err(Error::InvalidResponse);
        }
        {
            let mut a = self.inner.auth.lock();
            a.signed = !record.needs_profile;
            a.stage = if record.needs_profile {
                "profile_required"
            } else {
                "authenticated"
            };
        }
        self.persist()
    }
    pub async fn start(
        &self,
        country: &str,
        national: &str,
        international: &str,
        profile: Option<RegistrationProfile>,
    ) -> Result<CodeRequest, Error> {
        let _flow = self.inner.flow.try_lock().map_err(|_| Error::Busy)?;
        if !auth::valid_international(international) {
            return Err(Error::InvalidInput);
        }
        let epoch = self.epoch();
        let fields = {
            let mut a = self.inner.auth.lock();
            if a.record.is_some() {
                return Err(Error::Busy);
            }
            if a.retry_at > std::time::Instant::now() {
                return Err(Error::Busy);
            }
            let chosen = profile
                .map(Profile::new)
                .unwrap_or_else(|| a.profile.clone());
            let fields = auth::register_fields(country, national, &chosen)
                .map_err(|_| Error::InvalidInput)?;
            a.profile = chosen;
            a.challenge = None;
            a.stage = "requesting";
            fields
        };
        let rpc = self.channel().await?;
        let reply = self.auth_request(&rpc, epoch, 100, fields).await?;
        let challenge = auth::parse_register(&reply.fields).map_err(|_| Error::InvalidResponse)?;
        let result = CodeRequest {
            delivery_method: challenge.delivery_method,
            digits: challenge.digits,
            retry_after: challenge.retry_after,
        };
        let mut a = self.inner.auth.lock();
        a.retry_at = std::time::Instant::now() + Duration::from_secs(challenge.retry_after as u64);
        a.challenge = Some(challenge);
        a.phone = international.to_owned();
        a.stage = "code";
        Ok(result)
    }
    pub async fn verify(&self, code: &str) -> Result<AuthState, Error> {
        let _flow = self.inner.flow.try_lock().map_err(|_| Error::Busy)?;
        let epoch = self.epoch();
        let rpc = self.inner.rpc.lock().clone().ok_or(Error::NotConnected)?;
        let fields = {
            let a = self.inner.auth.lock();
            if a.stage != "code" {
                return Err(Error::InvalidInput);
            }
            auth::verify_fields(
                code,
                a.challenge.as_ref().ok_or(Error::InvalidInput)?,
                &a.profile,
            )
            .map_err(|_| Error::InvalidInput)?
        };
        match self.auth_request(&rpc, epoch, 101, fields).await {
            Err(Error::Rejected { major: 184, .. }) => {
                self.guard(epoch, &rpc)?;
                let mut a = self.inner.auth.lock();
                a.stage = "password";
                drop(a);
                Ok(self.state())
            }
            Err(e) => Err(e),
            Ok(reply) => {
                self.verified(reply, rpc, epoch).await?;
                Ok(self.state())
            }
        }
    }
    async fn verified(&self, reply: Response, rpc: Arc<dyn Rpc>, epoch: u64) -> Result<(), Error> {
        self.guard(epoch, &rpc)?;
        let verified = auth::parse_verify(&reply.fields).map_err(|_| Error::InvalidResponse)?;
        {
            let mut a = self.inner.auth.lock();
            let uid = a
                .challenge
                .as_ref()
                .ok_or(Error::InvalidResponse)?
                .user_id
                .clone();
            a.record = Some(SessionRecord {
                provider: "igap".into(),
                user_id: uid,
                token: verified.token,
                profile: a.profile.clone(),
                login_phone: a.phone.clone(),
                needs_profile: verified.needs_profile,
            });
            a.challenge = None;
            a.stage = "authenticating";
        }
        self.login_record(rpc, epoch).await
    }
    pub async fn password(&self, value: &str) -> Result<AuthState, Error> {
        let _flow = self.inner.flow.try_lock().map_err(|_| Error::Busy)?;
        if self.inner.auth.lock().stage != "password" {
            return Err(Error::InvalidInput);
        }
        let epoch = self.epoch();
        let rpc = self.inner.rpc.lock().clone().ok_or(Error::NotConnected)?;
        let reply = self
            .auth_request(
                &rpc,
                epoch,
                132,
                auth::password_fields(value).map_err(|_| Error::InvalidInput)?,
            )
            .await?;
        self.verified(reply, rpc, epoch).await?;
        Ok(self.state())
    }
    pub async fn complete_profile(&self, name: &str) -> Result<(), Error> {
        let _flow = self.inner.flow.try_lock().map_err(|_| Error::Busy)?;
        if self.inner.auth.lock().stage != "profile_required" {
            return Err(Error::InvalidInput);
        }
        let epoch = self.epoch();
        let rpc = self.inner.rpc.lock().clone().ok_or(Error::NotConnected)?;
        self.auth_request(
            &rpc,
            epoch,
            105,
            auth::complete_profile_fields(name).map_err(|_| Error::InvalidInput)?,
        )
        .await?;
        let mut a = self.inner.auth.lock();
        a.record
            .as_mut()
            .ok_or(Error::NotAuthenticated)?
            .needs_profile = false;
        a.stage = "authenticated";
        a.signed = true;
        drop(a);
        self.persist()
    }
    pub async fn restore(&self, record: SessionRecord) -> Result<(), Error> {
        let _flow = self.inner.flow.try_lock().map_err(|_| Error::Busy)?;
        record.validate().map_err(|_| Error::InvalidInput)?;
        let epoch = self.epoch();
        {
            let mut a = self.inner.auth.lock();
            if a.record.is_some() {
                return Err(Error::Busy);
            }
            a.profile = record.profile.clone();
            a.record = Some(record);
            a.stage = "restoring";
        }
        let rpc = self.channel().await?;
        self.login_record(rpc, epoch).await
    }
    fn privacy_guard(&self, epoch: u64, rpc: &Arc<dyn Rpc>, self_id: &str) -> Result<(), Error> {
        self.guard(epoch, rpc)?;
        if self.self_id()? != self_id {
            return Err(Error::Cancelled);
        }
        Ok(())
    }
    async fn privacy_read(
        &self,
        epoch: u64,
        rpc: &Arc<dyn Rpc>,
        self_id: &str,
    ) -> Result<crate::privacy::Snapshot, Error> {
        let mut levels = [0u8; 2];
        for (index, kind) in [crate::privacy::VOICE, crate::privacy::VIDEO]
            .into_iter()
            .enumerate()
        {
            self.privacy_guard(epoch, rpc, self_id)?;
            let response = self
                .auth_request(
                    rpc,
                    epoch,
                    crate::privacy::GET,
                    crate::privacy::get_fields(kind).map_err(|_| Error::InvalidInput)?,
                )
                .await?;
            self.privacy_guard(epoch, rpc, self_id)?;
            levels[index] =
                crate::privacy::rule(&response.fields, kind).map_err(|_| Error::InvalidResponse)?;
        }
        crate::privacy::Snapshot::new(levels[0], levels[1]).map_err(|_| Error::InvalidResponse)
    }
    pub async fn read_call_privacy(&self) -> Result<crate::privacy::Snapshot, Error> {
        let _flow = self.inner.flow.try_lock().map_err(|_| Error::Busy)?;
        let epoch = self.epoch();
        let self_id = self.self_id()?;
        let rpc = self.inner.rpc.lock().clone().ok_or(Error::NotConnected)?;
        self.privacy_read(epoch, &rpc, &self_id).await
    }
    pub async fn ensure_call_privacy_everyone(&self) -> Result<crate::privacy::Snapshot, Error> {
        let _flow = self.inner.flow.try_lock().map_err(|_| Error::Busy)?;
        let epoch = self.epoch();
        let self_id = self.self_id()?;
        let rpc = self.inner.rpc.lock().clone().ok_or(Error::NotConnected)?;
        let before = self.privacy_read(epoch, &rpc, &self_id).await?;
        for kind in before.changes() {
            self.privacy_guard(epoch, &rpc, &self_id)?;
            let response = self
                .auth_request(
                    &rpc,
                    epoch,
                    crate::privacy::SET,
                    crate::privacy::set_fields(kind, 0).map_err(|_| Error::InvalidInput)?,
                )
                .await?;
            self.privacy_guard(epoch, &rpc, &self_id)?;
            crate::privacy::parse_set(&response.fields, kind, 0)
                .map_err(|_| Error::InvalidResponse)?;
        }
        let after = self.privacy_read(epoch, &rpc, &self_id).await?;
        after
            .require_everyone()
            .map_err(|_| Error::InvalidResponse)?;
        Ok(after)
    }
    pub async fn hang_up(&self) -> Result<(), Error> {
        let _flow = self.inner.flow.try_lock().map_err(|_| Error::Busy)?;
        let rpc = self.inner.rpc.lock().clone().ok_or(Error::NotConnected)?;
        let epoch = self.epoch();
        self.self_id()?;
        let confirmed = Arc::new(AtomicBool::new(false));
        let (room_id, revision) = {
            let mut current = self.inner.call.lock();
            let call = current.as_mut().ok_or(Error::InvalidInput)?;
            call.local_leave_confirmed = Some(confirmed.clone());
            (
                call.room.clone(),
                self.inner.call_revision.load(Ordering::Acquire),
            )
        };
        let result = rpc.request(918, room::leave()?).await;
        self.guard(epoch, &rpc)?;
        self.self_id()?;
        // A matching service push can arrive before the correlated reply, or
        // replace a reply which times out. Never confirm a different call or
        // consume errors from a replaced/revoked authenticated channel.
        if revision != self.inner.call_revision.load(Ordering::Acquire) {
            return Err(Error::Cancelled);
        }
        if confirmed.load(Ordering::Acquire) {
            if matches!(&result, Ok(reply) if reply.action == 30918)
                || matches!(result, Err(Error::Timeout))
            {
                return Ok(());
            }
        }
        let reply = result?;
        if reply.action != 30918 {
            return Err(Error::InvalidResponse);
        }
        let mut current = self.inner.call.lock();
        if revision != self.inner.call_revision.load(Ordering::Acquire)
            || !current.as_ref().is_some_and(|call| {
                call.epoch == epoch
                    && call.room == room_id
                    && call
                        .local_leave_confirmed
                        .as_ref()
                        .is_some_and(|token| Arc::ptr_eq(token, &confirmed))
            })
        {
            return Err(Error::Cancelled);
        }
        if let Some(mut call) = current.take() {
            if let Some(reply) = call.reply.take() {
                let _ = reply.send(Err(Error::Cancelled));
            }
            self.inner.events.emit(SignalingEvent::CallEnded {
                peer_id: call.peer,
                reason: EndReason::CallerHangup,
            });
        }
        Ok(())
    }
    /// Revoke this service session before clearing local credentials. A lost
    /// or rejected reply retains the record so callers can recover explicitly.
    pub async fn logout(&self) -> Result<(), Error> {
        let _flow = self.inner.flow.try_lock().map_err(|_| Error::Busy)?;
        self.self_id()?;
        let epoch = self.epoch();
        let rpc = self.inner.rpc.lock().clone().ok_or(Error::NotConnected)?;
        self.auth_request(&rpc, epoch, 127, vec![]).await?;
        self.sign_out().await;
        Ok(())
    }
    fn end_call(&self, reason: EndReason) {
        if let Some(mut call) = self.inner.call.lock().take() {
            if let Some(reply) = call.reply.take() {
                let _ = reply.send(Err(Error::Cancelled));
            }
            self.inner.events.emit(SignalingEvent::CallEnded {
                peer_id: call.peer,
                reason,
            });
        }
    }
    fn end_call_if(&self, epoch: u64, room: &str, call_revision: u64, reason: EndReason) {
        let mut current = self.inner.call.lock();
        if self.inner.call_revision.load(Ordering::Acquire) != call_revision
            || !current
                .as_ref()
                .is_some_and(|c| c.epoch == epoch && c.room == room)
        {
            return;
        }
        if let Some(mut call) = current.take() {
            if let Some(reply) = call.reply.take() {
                let _ = reply.send(Err(Error::Cancelled));
            }
            self.inner.events.emit(SignalingEvent::CallEnded {
                peer_id: call.peer,
                reason,
            });
        }
    }
    async fn handle_push(&self, epoch: u64, rpc: Arc<dyn Rpc>, reply: Response) {
        if self.guard(epoch, &rpc).is_err() {
            return;
        }
        let Ok(self_id) = self.self_id() else { return };
        let result: Result<(), Error> = async {
            match reply.action {
                30915 => {
                    let (peer, room) = room::incoming(&reply.fields, &self_id)?;
                    if !self.inner.allowed.lock().contains(&peer) {
                        return Ok(());
                    }
                    let (handler_revision, handler) = self.inner.handler.lock().clone();
                    let Some(handler) = handler else {
                        return Ok(());
                    };
                    let peer = self.peer(&peer)?;
                    let call_revision = {
                        let mut current = self.inner.call.lock();
                        self.guard(epoch, &rpc)?;
                        if current.is_some() {
                            return Ok(());
                        }
                        let revision = self
                            .inner
                            .call_revision
                            .fetch_add(1, Ordering::AcqRel)
                            .wrapping_add(1);
                        *self.inner.last_service_leave.lock() = None;
                        *current = Some(Call {
                            epoch,
                            peer: peer.clone(),
                            room: room.clone(),
                            phase: Phase::Incoming,
                            reply: None,
                            deferred_self_leave: false,
                            transport_digest: None,
                            incoming_timestamp: room::response_timestamp(&reply.fields),
                            receiver_join_order: None,
                            local_leave_confirmed: None,
                        });
                        revision
                    };
                    let this = self.clone();
                    tokio::spawn(async move {
                        let decision = tokio::time::timeout(
                            Duration::from_secs(20),
                            handler.decide(peer.clone(), None),
                        )
                        .await
                        .unwrap_or(CallDecision::SilentlyIgnore);
                        if this.guard_admission(epoch, &rpc, handler_revision).is_err() {
                            this.end_call_if(epoch, &room, call_revision, EndReason::Rejected);
                            return;
                        }
                        if !this.inner.call.lock().as_ref().is_some_and(|c| {
                            c.epoch == epoch
                                && c.room == room
                                && c.phase == Phase::Incoming
                                && this.inner.call_revision.load(Ordering::Acquire) == call_revision
                        }) {
                            return;
                        }
                        if decision != CallDecision::Accept {
                            if decision == CallDecision::Reject {
                                let _ = rpc.request(918, room::leave().unwrap_or_default()).await;
                            }
                            this.end_call_if(epoch, &room, call_revision, EndReason::Rejected);
                            return;
                        }
                        let result = this
                            .accept(
                                epoch,
                                rpc,
                                peer,
                                room.clone(),
                                handler_revision,
                                call_revision,
                            )
                            .await;
                        if result.is_err() {
                            this.end_call_if(epoch, &room, call_revision, EndReason::NetworkDrop);
                        }
                    });
                }
                30914 => {
                    let mut call = self.inner.call.lock();
                    self.guard(epoch, &rpc)?;
                    if let Some(c) = call.as_mut() {
                        if c.phase == Phase::Outgoing && c.epoch == epoch {
                            if let Ok(token) = room::bound_token(&reply.fields, &self_id, &c.room) {
                                c.transport_digest = Some(Sha256::digest(token.as_bytes()).into());
                                c.phase = Phase::Joined;
                                if let Some(sender) = c.reply.take() {
                                    let _ = sender.send(Ok(TransportSession {
                                        url: room::LIVEKIT_URL.into(),
                                        token,
                                        peer_id: c.peer.clone(),
                                    }));
                                }
                            }
                        }
                    }
                }
                30918 => {
                    let actor = room::response_id(&reply.fields, 2)?;
                    let mut current = self.inner.call.lock();
                    let Some(call) = current.as_mut() else {
                        return Ok(());
                    };
                    // Authentication/channel replacement may race the outer
                    // check while this handler waits for the call lock.
                    if call.epoch != epoch || self.guard(epoch, &rpc).is_err() {
                        return Ok(());
                    }
                    if actor != self_id && actor != call.peer.id_str() {
                        return Ok(());
                    }
                    // The reader can enqueue this push before resolving the
                    // join reply, while task scheduling delivers it afterward.
                    // Preserve wire causality only for the exact receiver join.
                    let earlier_than_join = match (reply.received_order, call.receiver_join_order) {
                        (Some(leave), Some(join)) => leave < join,
                        _ => false,
                    };
                    let defer_self_leave = actor == self_id
                        && (call.phase == Phase::Joining
                            || (call.phase == Phase::Joined && earlier_than_join));
                    *self.inner.last_service_leave.lock() = Some(ServiceLeaveDiagnostic {
                        actor: if actor == self_id { "self" } else { "peer" },
                        phase: match call.phase {
                            Phase::Incoming => "incoming",
                            Phase::Outgoing => "outgoing",
                            Phase::Joining => "joining",
                            Phase::Joined => "joined",
                        },
                        deferred: defer_self_leave,
                        metadata_timestamp_order: room::timestamp_order(
                            call.incoming_timestamp,
                            room::response_timestamp(&reply.fields),
                        ),
                    });
                    if defer_self_leave {
                        call.deferred_self_leave = true;
                        return Ok(());
                    }
                    if let Some(confirmed) = &call.local_leave_confirmed {
                        confirmed.store(true, Ordering::Release);
                    }
                    // Consume the validated call under the same lock. Releasing
                    // it and invoking end_call() could end a newly admitted call
                    // after a concurrent local hang-up cleared this one.
                    if let Some(mut ended) = current.take() {
                        if let Some(reply) = ended.reply.take() {
                            let _ = reply.send(Err(Error::Cancelled));
                        }
                        self.inner.events.emit(SignalingEvent::CallEnded {
                            peer_id: ended.peer,
                            reason: EndReason::CallerHangup,
                        });
                    }
                }
                _ => {}
            }
            Ok(())
        }
        .await;
        if result.is_err() { /* Invalid pushes never authorize a call or expose protocol data. */ }
    }
    fn guard_admission(&self, epoch: u64, rpc: &Arc<dyn Rpc>, revision: u64) -> Result<(), Error> {
        self.guard(epoch, rpc)?;
        if self.inner.handler.lock().0 != revision {
            return Err(Error::Cancelled);
        }
        Ok(())
    }
    async fn accept(
        &self,
        epoch: u64,
        rpc: Arc<dyn Rpc>,
        peer: PeerId,
        room: String,
        handler_revision: u64,
        call_revision: u64,
    ) -> Result<(), Error> {
        self.guard_admission(epoch, &rpc, handler_revision)?;
        {
            let current = self.inner.call.lock();
            self.guard(epoch, &rpc)?;
            if self.inner.call_revision.load(Ordering::Acquire) != call_revision
                || !current.as_ref().is_some_and(|c| {
                    c.epoch == epoch && c.room == room && c.phase == Phase::Incoming
                })
            {
                return Err(Error::Cancelled);
            }
        }
        let self_id = self.self_id()?;
        let ring = rpc.request(916, vec![]).await?;
        self.guard_admission(epoch, &rpc, handler_revision)?;
        if ring.action != 30916 || room::response_id(&ring.fields, 2)? != self_id {
            return Err(Error::InvalidResponse);
        }
        {
            let mut call = self.inner.call.lock();
            self.guard(epoch, &rpc)?;
            let c = call.as_mut().ok_or(Error::Cancelled)?;
            if self.inner.call_revision.load(Ordering::Acquire) != call_revision
                || c.room != room
                || c.epoch != epoch
            {
                return Err(Error::Cancelled);
            }
            c.phase = Phase::Joining;
        }
        self.guard_admission(epoch, &rpc, handler_revision)?;
        let response = rpc.request(914, room::join(&room)?).await?;
        self.guard_admission(epoch, &rpc, handler_revision)?;
        if response.action != 30914 {
            return Err(Error::InvalidResponse);
        }
        let token = room::bound_token(&response.fields, &self_id, &room)?;
        // Serialize final publication with handler replacement. A revoked
        // decision must not surface an accepted session after its owner stops.
        let handler = self.inner.handler.lock();
        if handler.0 != handler_revision {
            return Err(Error::Cancelled);
        }
        {
            let mut call = self.inner.call.lock();
            self.guard(epoch, &rpc)?;
            let c = call.as_mut().ok_or(Error::Cancelled)?;
            if self.inner.call_revision.load(Ordering::Acquire) != call_revision
                || c.room != room
                || c.epoch != epoch
                || c.phase != Phase::Joining
            {
                return Err(Error::Cancelled);
            }
            c.transport_digest = Some(Sha256::digest(token.as_bytes()).into());
            c.receiver_join_order = response.received_order;
            c.phase = Phase::Joined;
        }
        self.inner
            .accepted_tx
            .send((
                peer.clone(),
                TransportSession {
                    url: room::LIVEKIT_URL.into(),
                    token,
                    peer_id: peer,
                },
            ))
            .map_err(|_| Error::Closed)
    }
}
fn se(e: Error) -> SignalingError {
    match e {
        Error::NotAuthenticated => SignalingError::NotAuthenticated,
        Error::NotConnected => SignalingError::NotConnected,
        Error::NotSupported => SignalingError::NotSupported,
        _ => SignalingError::Transport(e.to_string()),
    }
}
#[async_trait]
impl Signaling for IgapSignaling {
    fn is_connected(&self) -> bool {
        self.inner.rpc.lock().as_ref().is_some_and(|r| r.ready())
    }
    async fn connect(&self) -> Result<(), SignalingError> {
        let _flow = self.inner.flow.try_lock().map_err(|_| se(Error::Busy))?;
        if self.is_authenticated() {
            return Ok(());
        }
        let epoch = self.epoch();
        if self.inner.auth.lock().record.is_none() {
            let bytes = self
                .inner
                .store
                .load()
                .ok_or(SignalingError::NotAuthenticated)?;
            let bytes = Zeroizing::new(bytes);
            if bytes.len() > 128 * 1024 {
                return Err(se(Error::InvalidInput));
            }
            let record: SessionRecord =
                serde_json::from_slice(&bytes).map_err(|_| se(Error::InvalidInput))?;
            record.validate().map_err(|_| se(Error::InvalidInput))?;
            let mut a = self.inner.auth.lock();
            a.profile = record.profile.clone();
            a.record = Some(record);
        }
        let rpc = self.channel().await.map_err(se)?;
        self.login_record(rpc, epoch).await.map_err(se)
    }
    async fn disconnect(&self) {
        self.inner.epoch.fetch_add(1, Ordering::AcqRel);
        if let Some(rpc) = self.inner.rpc.lock().take() {
            rpc.close()
        }
        self.inner.auth.lock().signed = false;
        self.end_call(EndReason::NetworkDrop);
        self.inner.teardown.send_modify(|n| *n = n.wrapping_add(1));
    }
    async fn sign_out(&self) {
        self.disconnect().await;
        {
            let mut a = self.inner.auth.lock();
            a.record = None;
            a.challenge = None;
            a.stage = "idle";
            a.phone.clear();
        }
        self.inner.store.clear();
    }
    fn events(&self) -> mpsc::UnboundedReceiver<SignalingEvent> {
        self.inner.events.subscribe()
    }
    fn is_authenticated(&self) -> bool {
        self.inner.auth.lock().signed && self.is_connected()
    }
    async fn whoami(&self) -> Option<PeerId> {
        self.self_id().ok().and_then(|id| self.peer(&id).ok())
    }
    fn set_foreground(&self, value: bool) {
        self.inner.foreground.send_replace(value);
    }
    fn tunnel_hooks(&self) -> &dyn TunnelHooks {
        self
    }
    async fn list_contacts(
        &self,
        _: Option<&str>,
        _: Option<&str>,
        _: usize,
    ) -> Result<ContactPage, SignalingError> {
        Err(SignalingError::NotSupported)
    }
    async fn search_contact_by_phone(&self, _: &str) -> Result<Vec<PeerId>, SignalingError> {
        Err(SignalingError::NotSupported)
    }
    async fn add_to_contacts(&self, _: &PeerId) -> Result<(), SignalingError> {
        Err(SignalingError::NotSupported)
    }
    async fn remove_contact(&self, _: &PeerId) -> Result<(), SignalingError> {
        Err(SignalingError::NotSupported)
    }
    fn peer_display_name(&self, _: &PeerId) -> Option<String> {
        None
    }
    async fn fetch_display_name(&self, _: &PeerId) -> Option<String> {
        None
    }
    async fn resolve_peer(&self, id: &str) -> Option<PeerId> {
        self.peer(id).ok()
    }
}
#[async_trait]
impl TunnelHooks for IgapSignaling {
    async fn place_call(&self, peer: PeerId) -> Result<TransportSession, PlaceCallError> {
        let result: Result<TransportSession, Error> = async {
            let _flow = self.inner.flow.try_lock().map_err(|_| Error::Busy)?;
            let epoch = self.epoch();
            let self_id = self.self_id()?;
            if peer.id_str() == self_id
                || !self.inner.allowed.lock().contains(peer.id_str())
                || !self
                    .inner
                    .peers
                    .lock()
                    .get(peer.id_str())
                    .is_some_and(|p| p == &peer)
            {
                return Err(Error::InvalidInput);
            }
            if self.inner.call.lock().is_some() {
                return Err(Error::Busy);
            }
            let rpc = self.inner.rpc.lock().clone().ok_or(Error::NotConnected)?;
            let created = rpc.request(913, room::create()?).await?;
            self.guard(epoch, &rpc)?;
            if created.action != 30913 {
                return Err(Error::InvalidResponse);
            }
            let room = room::response_id(&created.fields, 2)?;
            let (tx, rx) = oneshot::channel();
            let call_revision = {
                let mut current = self.inner.call.lock();
                self.guard(epoch, &rpc)?;
                if current.is_some() {
                    return Err(Error::Busy);
                }
                let revision = self
                    .inner
                    .call_revision
                    .fetch_add(1, Ordering::AcqRel)
                    .wrapping_add(1);
                *self.inner.last_service_leave.lock() = None;
                *current = Some(Call {
                    epoch,
                    peer: peer.clone(),
                    room: room.clone(),
                    phase: Phase::Outgoing,
                    reply: Some(tx),
                    deferred_self_leave: false,
                    transport_digest: None,
                    incoming_timestamp: None,
                    receiver_join_order: None,
                    local_leave_confirmed: None,
                });
                revision
            };
            let mut lease = CallLease {
                owner: self.clone(),
                epoch,
                room: room.clone(),
                call_revision,
                armed: true,
            };
            let offered = rpc.request(915, room::offer(peer.id_str(), &room)?).await?;
            self.guard(epoch, &rpc)?;
            if offered.action != 30915
                || room::response_id(&offered.fields, 2)? != self_id
                || room::response_id(&offered.fields, 3)? != room
                || w::number(&offered.fields, 5, 1)? != 0
                || w::number(&offered.fields, 8, 2)? != 0
            {
                return Err(Error::InvalidResponse);
            }
            let session = tokio::time::timeout(Duration::from_secs(35), rx)
                .await
                .map_err(|_| Error::Timeout)?
                .map_err(|_| Error::Closed)??;
            lease.armed = false;
            Ok(session)
        }
        .await;
        match result {
            Ok(session) => Ok(session),
            Err(e) => Err(match e {
                Error::NotAuthenticated => PlaceCallError::NotAuthenticated,
                Error::Timeout => PlaceCallError::NoPeer,
                _ => PlaceCallError::Transport(e.to_string()),
            }),
        }
    }
    fn set_incoming_handler(&self, h: Box<dyn IncomingHandler>) {
        let mut handler = self.inner.handler.lock();
        handler.0 = handler.0.wrapping_add(1);
        handler.1 = Some(Arc::from(h));
    }
    fn accepted_sessions(&self) -> mpsc::UnboundedReceiver<(PeerId, TransportSession)> {
        self.inner
            .accepted_rx
            .lock()
            .take()
            .unwrap_or_else(|| mpsc::unbounded_channel().1)
    }
    fn activate(&self) {} // iGap has no Bale activation RPC; its channel stays up during calls.
    fn deactivate(&self) {}
    fn subscribe_foreground(&self) -> watch::Receiver<bool> {
        self.inner.foreground.subscribe()
    }
    fn subscribe_teardown(&self) -> watch::Receiver<u64> {
        self.inner.teardown.subscribe()
    }
}
