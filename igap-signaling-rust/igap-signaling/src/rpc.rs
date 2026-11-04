//! TLS-verified, connection-encrypted account RPC. No token/packet logging.
use crate::{security as s, wire as w, Error};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use rand::RngCore;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::{protocol::WebSocketConfig, Message};
use zeroize::Zeroizing;
pub const ENDPOINT: &str = "wss://secure.igap.net/hybrid/?apiVersion=3&version=1";
fn tls_config() -> Result<rustls::ClientConfig, Error> {
    // Select the crypto implementation per connection; feature unification with
    // other providers must neither panic nor replace their process-wide default.
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| Error::InvalidInput)?
    .with_root_certificates(roots)
    .with_no_client_auth())
}
async fn bounded_io<F, E>(operation: F, timeout: Duration) -> Result<(), Error>
where
    F: std::future::Future<Output = Result<(), E>>,
{
    tokio::time::timeout(timeout, operation)
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::Closed)
}
fn correlated_response(expected: u16, action: u16, fields: w::Fields) -> Result<Response, Error> {
    if action != 0 && action != expected + 30000 {
        return Err(Error::InvalidResponse);
    }
    if action == 0 {
        return Err(Error::Rejected {
            major: w::number(&fields, 2, u32::MAX as u64)? as u32,
            minor: w::number(&fields, 3, u32::MAX as u64)? as u32,
            wait_seconds: w::number(&fields, 4, 86400)? as u32,
        });
    }
    Ok(Response {
        action,
        fields,
        received_order: None,
    })
}
fn fatal_response(expected: u16, response: &Result<Response, Error>) -> Option<Error> {
    match response {
        Err(error)
            if expected == 502
                || matches!(error, Error::InvalidResponse | Error::InvalidPacket) =>
        {
            Some(*error)
        }
        _ => None,
    }
}
fn validate_request(action: u16, fields: &[u8]) -> Result<(), Error> {
    if ![
        3, 100, 101, 102, 105, 127, 131, 132, 143, 144, 145, 502, 506, 913, 914, 915, 916, 917, 918,
    ]
    .contains(&action)
        || fields.len() > 46 * 1024
    {
        return Err(Error::InvalidInput);
    }
    let parsed = w::parse(fields)?;
    if parsed.contains_key(&1) || (action == 102 && parsed.contains_key(&12)) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
pub struct Response {
    pub action: u16,
    pub fields: w::Fields,
    /// Monotonic receipt order within this physical RPC connection. This is
    /// assigned before splitting pushes and replies onto separate task queues.
    pub received_order: Option<u64>,
}
#[async_trait]
pub trait Rpc: Send + Sync {
    async fn request(&self, action: u16, fields: Vec<u8>) -> Result<Response, Error>;
    async fn login(&self, fields: Vec<u8>) -> Result<Response, Error>;
    fn ready(&self) -> bool;
    fn close(&self);
}
struct Command {
    action: u16,
    fields: Vec<u8>,
    reply: oneshot::Sender<Result<Response, Error>>,
}
pub struct Connection {
    tx: mpsc::Sender<Command>,
    stop: Mutex<Option<oneshot::Sender<()>>>,
    ready: Arc<AtomicBool>,
}
impl Connection {
    pub async fn open() -> Result<(Arc<Self>, mpsc::Receiver<Response>), Error> {
        let mut config = WebSocketConfig::default();
        config.max_message_size = Some(52 * 1024);
        config.max_frame_size = Some(52 * 1024);
        let (mut ws, _) = tokio::time::timeout(
            Duration::from_secs(10),
            tokio_tungstenite::connect_async_tls_with_config(
                ENDPOINT,
                Some(config),
                false,
                Some(tokio_tungstenite::Connector::Rustls(
                    Arc::new(tls_config()?),
                )),
            ),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::NotConnected)?;
        let mut key = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(key.as_mut());
        let (cipher, heartbeat) = tokio::time::timeout(Duration::from_secs(10), async {
            let packet = ws
                .next()
                .await
                .ok_or(Error::Closed)?
                .map_err(|_| Error::Closed)?;
            let Message::Binary(packet) = packet else {
                return Err(Error::InvalidPacket);
            };
            let greeting = s::decode_greeting(&packet).map_err(|_| Error::InvalidPacket)?;
            let heartbeat = greeting.heartbeat_seconds.clamp(10, 120);
            ws.send(Message::Binary(
                s::key_exchange(&greeting, &key).map_err(|_| Error::InvalidPacket)?,
            ))
            .await
            .map_err(|_| Error::Closed)?;
            let packet = ws
                .next()
                .await
                .ok_or(Error::Closed)?
                .map_err(|_| Error::Closed)?;
            let Message::Binary(packet) = packet else {
                return Err(Error::InvalidPacket);
            };
            Ok((
                s::decode_accepted(&packet).map_err(|_| Error::InvalidPacket)?,
                heartbeat,
            ))
        })
        .await
        .map_err(|_| Error::Timeout)??;
        let (tx, mut commands) = mpsc::channel::<Command>(32);
        let (push, rx) = mpsc::channel(64);
        let (stop_tx, mut stop) = oneshot::channel();
        let ready = Arc::new(AtomicBool::new(true));
        let out = Arc::new(Self {
            tx,
            stop: Mutex::new(Some(stop_tx)),
            ready: ready.clone(),
        });
        tokio::spawn(async move {
            let mut pending: HashMap<
                String,
                (
                    u16,
                    oneshot::Sender<Result<Response, Error>>,
                    tokio::time::Instant,
                ),
            > = HashMap::new();
            let mut heartbeat_tick =
                tokio::time::interval(Duration::from_millis(heartbeat as u64 * 500));
            heartbeat_tick.tick().await;
            let mut sweep = tokio::time::interval(Duration::from_millis(100));
            let mut received_order = 0u64;
            let result:Result<(),Error>=async{loop{tokio::select!{
    _=&mut stop=>break Err(Error::Closed),
    Some(mut c)=commands.recv()=>{if c.reply.is_closed(){continue;}if pending.len()>=32{let _=c.reply.send(Err(Error::Busy));continue;}
     if c.action==102{c.fields.extend(w::bytes_field(12,key.as_ref())?);}
     let id=uuid::Uuid::new_v4().to_string();let meta=w::string_field(1,&id,128)?;let mut fields=w::bytes_field(1,&meta)?;fields.extend(c.fields);let plain=w::frame(c.action,&fields)?;let encrypted=s::encrypt(&plain,&key,cipher).map_err(|_|Error::InvalidPacket)?;
     bounded_io(ws.send(Message::Binary(encrypted)),Duration::from_secs(5)).await?;pending.insert(id,(c.action,c.reply,tokio::time::Instant::now()+Duration::from_secs(8)));
    },
    message=ws.next()=>{let message=message.ok_or(Error::Closed)?.map_err(|_|Error::Closed)?;match message{
     Message::Binary(bytes) => {
      let plain = s::decrypt(&bytes, &key, cipher).map_err(|_| Error::InvalidPacket)?;
      let (action, fields) = w::packet(&plain)?;
      received_order = received_order.checked_add(1).ok_or(Error::InvalidPacket)?;
      let meta = w::parse(w::bytes(&fields, 1, 1024)?)?;
      let id = w::text(&meta, 1, 128)?;
      if let Some((expected, reply, _)) = pending.remove(id) {
       let response = correlated_response(expected, action, fields).map(|mut response| {
        response.received_order = Some(received_order);
        response
       });
       let fatal = fatal_response(expected, &response);
       let _ = reply.send(response);
       if let Some(error) = fatal {
        return Err(error);
       }
      } else if id.is_empty() && [30914, 30915, 30916, 30917, 30918].contains(&action) {
       push.try_send(Response {
        action,
        fields,
        received_order: Some(received_order),
       }).map_err(|_| Error::Busy)?;
      }
     },Message::Ping(bytes)=>bounded_io(ws.send(Message::Pong(bytes)),Duration::from_secs(5)).await?,Message::Pong(_)=>{},Message::Close(_)=>return Err(Error::Closed),_=>return Err(Error::InvalidPacket)}
    },
    _=heartbeat_tick.tick()=>{if pending.len()>=32{return Err(Error::Busy)}let id=uuid::Uuid::new_v4().to_string();let fields=w::bytes_field(1,&w::string_field(1,&id,128)?)?;let packet=s::encrypt(&w::frame(502,&fields)?,&key,cipher).map_err(|_|Error::InvalidPacket)?;bounded_io(ws.send(Message::Binary(packet)),Duration::from_secs(5)).await?;let (reply,_rx)=oneshot::channel();pending.insert(id,(502,reply,tokio::time::Instant::now()+Duration::from_secs(8)));},
    _=sweep.tick()=>{let now=tokio::time::Instant::now();let ids:Vec<_>=pending.iter().filter(|(_,(_,_,deadline))|*deadline<=now).map(|(id,_)|id.clone()).collect();for id in ids{if let Some((action,reply,_))=pending.remove(&id){let _=reply.send(Err(Error::Timeout));if action==502{return Err(Error::Timeout)}}}}
   }}}.await;
            ready.store(false, Ordering::Release);
            for (_, (_, reply, _)) in pending {
                let _ = reply.send(Err(result.err().unwrap_or(Error::Closed)));
            }
            while let Ok(c) = commands.try_recv() {
                let _ = c.reply.send(Err(Error::Closed));
            }
            let _ = bounded_io(ws.close(None), Duration::from_secs(2)).await;
        });
        Ok((out, rx))
    }
    async fn send(&self, action: u16, fields: Vec<u8>) -> Result<Response, Error> {
        if !self.ready() {
            return Err(Error::NotConnected);
        }
        validate_request(action, &fields)?;
        let (tx, rx) = oneshot::channel();
        self.tx
            .try_send(Command {
                action,
                fields,
                reply: tx,
            })
            .map_err(|_| Error::Busy)?;
        tokio::time::timeout(Duration::from_secs(9), rx)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Closed)?
    }
}
#[async_trait]
impl Rpc for Connection {
    async fn request(&self, action: u16, fields: Vec<u8>) -> Result<Response, Error> {
        if action == 102 {
            return Err(Error::InvalidInput);
        }
        self.send(action, fields).await
    }
    async fn login(&self, fields: Vec<u8>) -> Result<Response, Error> {
        self.send(102, fields).await
    }
    fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
    fn close(&self) {
        self.ready.store(false, Ordering::Release);
        if let Some(tx) = self.stop.lock().take() {
            let _ = tx.send(());
        }
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn connection_tls_provider_is_explicit_and_certificate_verification_rejects_invalid_der() {
        use rustls::{
            client::{danger::ServerCertVerifier, WebPkiServerVerifier},
            pki_types::{CertificateDer, ServerName, UnixTime},
        };
        let config = tls_config().unwrap();
        assert!(!config.crypto_provider().cipher_suites.is_empty());
        assert_eq!(config.alpn_protocols.len(), 0);
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        assert!(!roots.is_empty());
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        let certificate = CertificateDer::from(vec![0x30, 0x00]);
        let name = ServerName::try_from("secure.igap.net").unwrap();
        assert!(verifier
            .verify_server_cert(&certificate, &[], &name, &[], UnixTime::now())
            .is_err());
    }
    #[test]
    fn rejected_heartbeat_is_fatal_but_an_ordinary_service_rejection_remains_account_scoped() {
        let mut fields = w::parse(&w::uint_field(2, 991).unwrap()).unwrap();
        fields.extend(w::parse(&w::uint_field(3, 2).unwrap()).unwrap());
        let ordinary = correlated_response(100, 0, fields.clone());
        assert!(matches!(
            ordinary,
            Err(Error::Rejected {
                major: 991,
                minor: 2,
                ..
            })
        ));
        assert_eq!(fatal_response(100, &ordinary), None);
        assert!(fatal_response(502, &correlated_response(502, 0, fields)).is_some());
        assert_eq!(format!("{:?}", ordinary.err().unwrap()), "service_rejected");
        assert_eq!(
            fatal_response(502, &correlated_response(502, 30502, w::Fields::new())),
            None
        );
        assert_eq!(
            fatal_response(100, &correlated_response(100, 30101, w::Fields::new())),
            Some(Error::InvalidResponse)
        );
    }
    #[tokio::test(start_paused = true)]
    async fn stalled_writes_and_close_have_explicit_time_bounds() {
        for seconds in [5, 2] {
            let before = tokio::time::Instant::now();
            assert_eq!(
                bounded_io(
                    std::future::pending::<Result<(), ()>>(),
                    Duration::from_secs(seconds)
                )
                .await,
                Err(Error::Timeout)
            );
            assert_eq!(
                tokio::time::Instant::now() - before,
                Duration::from_secs(seconds)
            );
        }
        assert_eq!(
            bounded_io(
                async { Err::<(), _>("fixture-private-transport-error") },
                Duration::from_secs(5)
            )
            .await,
            Err(Error::Closed)
        );
    }
    #[test]
    fn request_validation_keeps_correlation_and_shared_key_owned_by_connection() {
        for action in [100, 101, 102, 143, 144, 913, 914, 918] {
            assert_eq!(validate_request(action, &[]), Ok(()));
        }
        assert_eq!(validate_request(999, &[]), Err(Error::InvalidInput));
        assert_eq!(
            validate_request(100, &vec![0; 46 * 1024 + 1]),
            Err(Error::InvalidInput)
        );
        let mut injected = w::bytes_field(1, b"fixture-private-id").unwrap();
        injected.extend(w::bytes_field(1, b"fixture-other-id").unwrap());
        assert_eq!(validate_request(100, &injected), Err(Error::InvalidInput));
        assert_eq!(
            validate_request(102, &w::bytes_field(12, b"fixture-private-key").unwrap()),
            Err(Error::InvalidInput)
        );
        assert_eq!(validate_request(100, &[128]), Err(Error::InvalidPacket));
    }
    fn fixture() -> (
        Arc<Connection>,
        mpsc::Receiver<Command>,
        oneshot::Receiver<()>,
    ) {
        let (tx, rx) = mpsc::channel(32);
        let (stop, stopped) = oneshot::channel();
        (
            Arc::new(Connection {
                tx,
                stop: Mutex::new(Some(stop)),
                ready: Arc::new(AtomicBool::new(true)),
            }),
            rx,
            stopped,
        )
    }
    #[tokio::test]
    async fn closed_connection_and_generic_login_cannot_enqueue_requests() {
        let (connection, mut queued, stopped) = fixture();
        assert!(matches!(
            connection.request(102, vec![]).await,
            Err(Error::InvalidInput)
        ));
        assert!(queued.try_recv().is_err());
        connection.close();
        stopped.await.unwrap();
        assert!(!connection.ready());
        assert!(matches!(
            connection.request(100, vec![]).await,
            Err(Error::NotConnected)
        ));
        assert!(queued.try_recv().is_err());
    }
    #[tokio::test]
    async fn command_backpressure_fails_bounded_without_sending_another_request() {
        let (connection, mut queued, _) = fixture();
        for _ in 0..32 {
            let (reply, _) = oneshot::channel();
            connection
                .tx
                .try_send(Command {
                    action: 100,
                    fields: Vec::new(),
                    reply,
                })
                .ok()
                .unwrap();
        }
        assert!(matches!(
            connection.request(100, vec![]).await,
            Err(Error::Busy)
        ));
        let mut count = 0;
        while queued.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 32);
    }
    #[tokio::test(start_paused = true)]
    async fn caller_timeout_closes_queued_reply_so_actor_can_skip_unsent_request() {
        let (connection, mut queued, _) = fixture();
        let waiting = tokio::spawn(async move { connection.request(100, vec![]).await });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(matches!(waiting.await.unwrap(), Err(Error::Timeout)));
        assert!(queued.recv().await.unwrap().reply.is_closed());
    }
}
