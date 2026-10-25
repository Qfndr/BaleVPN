//! Opt-in byte-stream bonding over independently authenticated QUIC tunnels.
//! The egress TCP socket exists exactly once. Offset/credit/ACK frames permit
//! bounded reordering and reinjection without replaying application requests.
use parking_lot::Mutex;
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    collections::{BTreeMap, HashMap},
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, watch, Semaphore},
    task::JoinSet,
    time::timeout,
};

pub const CHUNK: usize = 16 * 1024;
pub const WINDOW: u64 = 2 * 1024 * 1024;
const MAX_LANES: usize = 8;
const MAX_FLOWS: usize = 16;
pub const MAGIC: &[u8; 8] = b"BLVBND01";
const DATA: u8 = 1;
const ACK: u8 = 2;
const FIN: u8 = 3;
const FIN_ACK: u8 = 4;
const CREDIT: u8 = 5;
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type Stream = Box<dyn Io>;
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Invalid bonding frame or receive window",
    )
}
fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut b = [0; N];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| io::Error::other("Secure random unavailable"))?;
    Ok(b)
}

#[derive(Default)]
pub struct Counters {
    pub active: AtomicUsize,
    pub opened: AtomicU64,
    pub retransmitted: AtomicU64,
    pub duplicates: AtomicU64,
    pub failed_lanes: AtomicU64,
    pub reorder_peak: AtomicU64,
    pub received: AtomicU64,
    pub sent: AtomicU64,
}
impl Counters {
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({"activeStreams":self.active.load(Ordering::Relaxed),"openedStreams":self.opened.load(Ordering::Relaxed),"reinjectedBytes":self.retransmitted.load(Ordering::Relaxed),"duplicateBytesDiscarded":self.duplicates.load(Ordering::Relaxed),"failedLanes":self.failed_lanes.load(Ordering::Relaxed),"reorderPeakBytes":self.reorder_peak.load(Ordering::Relaxed),"receivedBytes":self.received.load(Ordering::Relaxed),"sentBytes":self.sent.load(Ordering::Relaxed),"windowBytes":WINDOW,"maximumStreams":MAX_FLOWS})
    }
}
#[derive(Clone)]
struct Frame {
    kind: u8,
    seq: u64,
    credit: u64,
    data: Arc<Vec<u8>>,
}
impl Frame {
    fn control(kind: u8, seq: u64, credit: u64) -> Self {
        Self {
            kind,
            seq,
            credit,
            data: Arc::new(Vec::new()),
        }
    }
    async fn read<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Self> {
        let kind = r.read_u8().await?;
        let seq = r.read_u64().await?;
        let credit = r.read_u64().await?;
        let len = r.read_u16().await? as usize;
        if !(DATA..=CREDIT).contains(&kind) || len > CHUNK || (kind == DATA) == (len == 0) {
            return Err(invalid());
        }
        let mut bytes = vec![0; len];
        r.read_exact(&mut bytes).await?;
        Ok(Self {
            kind,
            seq,
            credit,
            data: Arc::new(bytes),
        })
    }
    async fn write<W: AsyncWrite + Unpin>(&self, w: &mut W) -> io::Result<()> {
        let mut h = [0; 19];
        h[0] = self.kind;
        h[1..9].copy_from_slice(&self.seq.to_be_bytes());
        h[9..17].copy_from_slice(&self.credit.to_be_bytes());
        h[17..19].copy_from_slice(&(self.data.len() as u16).to_be_bytes());
        w.write_all(&h).await?;
        w.write_all(&self.data).await
    }
}
enum Event {
    Frame(usize, Frame),
    Down(usize),
    Delivered,
    WriteClosed,
    WriteError,
    FinAckSent,
}
struct Lane {
    tx: mpsc::Sender<Frame>,
    alive: bool,
    inflight: usize,
    rate: f64,
    rtt: f64,
    variance: f64,
    measured: bool,
    at: Instant,
    bytes: usize,
    confirmed: usize,
    cooldown: Option<Instant>,
}
struct Pending {
    frame: Frame,
    lane: Option<usize>,
    at: Instant,
    attempts: u8,
}
fn add_lane(
    stream: Stream,
    lanes: &mut Vec<Lane>,
    events: &mpsc::Sender<Event>,
    jobs: &mut JoinSet<()>,
) {
    let index = lanes.len();
    let (mut read, mut write) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<Frame>(8);
    let e = events.clone();
    jobs.spawn(async move {
        while let Ok(frame) = Frame::read(&mut read).await {
            if e.send(Event::Frame(index, frame)).await.is_err() {
                return;
            }
        }
        let _ = e.send(Event::Down(index)).await;
    });
    let e = events.clone();
    jobs.spawn(async move {
        while let Some(frame) = rx.recv().await {
            if frame.write(&mut write).await.is_err() {
                let _ = e.send(Event::Down(index)).await;
                return;
            }
            if frame.kind == FIN_ACK {
                let _ = e.send(Event::FinAckSent).await;
            }
        }
        let _ = write.shutdown().await;
    });
    lanes.push(Lane {
        tx,
        alive: true,
        inflight: 0,
        rate: 1024.0 * 1024.0,
        rtt: 0.2,
        variance: 0.05,
        measured: false,
        at: Instant::now(),
        bytes: 0,
        confirmed: 0,
        cooldown: None,
    });
}
fn choose(lanes: &[Lane], now: Instant, size: usize) -> Option<usize> {
    let warm = lanes.first().is_some_and(|l| {
        l.alive && l.confirmed < 64 * 1024 && l.cooldown.is_none_or(|at| at <= now)
    });
    lanes
        .iter()
        .enumerate()
        .filter(|(_, l)| l.alive && l.tx.capacity() > 0 && l.cooldown.is_none_or(|at| at <= now))
        .filter(|(index, _)| !warm || *index == 0)
        .filter(|(_, l)| {
            l.inflight + size
                <= if l.measured {
                    (l.rate * l.rtt * 2.0 + 2.0 * CHUNK as f64)
                        .clamp(64.0 * 1024.0, WINDOW as f64 / 2.0) as usize
                } else {
                    128 * 1024
                }
        })
        .min_by(|(_, a), (_, b)| {
            ((a.inflight + size) as f64 / a.rate + a.rtt * 0.5)
                .total_cmp(&((b.inflight + size) as f64 / b.rate + b.rtt * 0.5))
        })
        .map(|(i, _)| i)
}
fn send_control(lanes: &[Lane], preferred: usize, frame: Frame) {
    if lanes
        .get(preferred)
        .is_some_and(|l| l.alive && l.tx.try_send(frame.clone()).is_ok())
    {
        return;
    }
    for (i, l) in lanes.iter().enumerate() {
        if i != preferred && l.alive && l.tx.try_send(frame.clone()).is_ok() {
            return;
        }
    }
}
fn drain(
    buffer: &mut BTreeMap<u64, Arc<Vec<u8>>>,
    next: &mut u64,
    end: Option<u64>,
    finished: &mut bool,
    deliver: &mpsc::Sender<Option<Arc<Vec<u8>>>>,
) {
    while let Some(bytes) = buffer.remove(next) {
        let len = bytes.len();
        match deliver.try_send(Some(bytes)) {
            Ok(()) => *next += len as u64,
            Err(e) => {
                if let Some(bytes) = e.into_inner() {
                    buffer.insert(*next, bytes);
                }
                break;
            }
        }
    }
    if end == Some(*next) && !*finished && deliver.try_send(None).is_ok() {
        *finished = true;
    }
}
pub async fn transfer(
    app: TcpStream,
    initial: Vec<Stream>,
    mut additions: mpsc::Receiver<Stream>,
    stats: Arc<Counters>,
) -> io::Result<()> {
    if initial.is_empty() || initial.len() > MAX_LANES {
        return Err(invalid());
    }
    struct Active(Arc<Counters>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.active.fetch_sub(1, Ordering::Relaxed);
        }
    }
    stats.active.fetch_add(1, Ordering::Relaxed);
    let _active = Active(stats.clone());
    app.set_nodelay(true)?;
    let (mut app_read, mut app_write) = app.into_split();
    let (events, mut incoming) = mpsc::channel(32);
    let mut jobs = JoinSet::new();
    let mut lanes = Vec::new();
    for lane in initial {
        add_lane(lane, &mut lanes, &events, &mut jobs);
    }
    let (deliver, mut delivery) = mpsc::channel::<Option<Arc<Vec<u8>>>>(4);
    let e = events.clone();
    let delivered_stats = stats.clone();
    jobs.spawn(async move {
        while let Some(item) = delivery.recv().await {
            match item {
                Some(bytes) => {
                    if app_write.write_all(&bytes).await.is_err() {
                        let _ = e.send(Event::WriteError).await;
                        return;
                    }
                    delivered_stats
                        .received
                        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                    let _ = e.send(Event::Delivered).await;
                }
                None => {
                    if app_write.shutdown().await.is_err() {
                        let _ = e.send(Event::WriteError).await;
                    } else {
                        let _ = e.send(Event::WriteClosed).await;
                    }
                    return;
                }
            }
        }
    });
    let (mut tx_next, mut remote_credit, mut rx_next) = (0u64, 0u64, 0u64);
    let (mut tx_end, mut tx_finished, mut rx_end, mut rx_finished, mut write_closed) =
        (false, false, None, false, false);
    let mut pending = BTreeMap::<u64, Pending>::new();
    let mut reorder = BTreeMap::<u64, Arc<Vec<u8>>>::new();
    let mut readbuf = vec![0u8; CHUNK];
    let mut tick = tokio::time::interval(Duration::from_millis(25));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut more = true;
    let mut fin_ack_sent = false;
    let mut last_progress = Instant::now();
    loop {
        if tx_finished && write_closed && fin_ack_sent {
            tokio::time::sleep(Duration::from_millis(50)).await;
            return Ok(());
        }
        if !lanes.iter().any(|l| l.alive) {
            // CREATE's first lane can disappear while a parallel JOIN is in
            // flight. Preserve the existing destination briefly; never redial it.
            if more && lanes.len() < MAX_LANES {
                if let Ok(Some(lane)) = timeout(Duration::from_millis(500), additions.recv()).await
                {
                    add_lane(lane, &mut lanes, &events, &mut jobs);
                    continue;
                }
            }
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "All bonding paths closed",
            ));
        }
        let now = Instant::now();
        if !pending.is_empty() && last_progress.elapsed() > Duration::from_secs(30) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Bonding peer stopped acknowledging data",
            ));
        }
        for p in pending.values_mut() {
            if let Some(index) = p.lane {
                let l = &mut lanes[index];
                let rto = (l.rtt + 4.0 * l.variance).clamp(0.15, 2.0);
                if !l.alive || p.at.elapsed().as_secs_f64() > rto {
                    l.inflight = l.inflight.saturating_sub(p.frame.data.len());
                    l.cooldown = Some(now + Duration::from_secs(3));
                    p.lane = None;
                }
            }
        }
        for p in pending.values_mut().filter(|p| p.lane.is_none()) {
            if p.attempts >= 12 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Bonding peer stopped acknowledging data",
                ));
            }
            if let Some(index) = choose(&lanes, now, p.frame.data.len()) {
                if lanes[index].tx.try_send(p.frame.clone()).is_ok() {
                    if p.attempts > 0 {
                        stats
                            .retransmitted
                            .fetch_add(p.frame.data.len() as u64, Ordering::Relaxed);
                    }
                    p.attempts += 1;
                    p.lane = Some(index);
                    p.at = now;
                    lanes[index].inflight += p.frame.data.len();
                }
            }
        }
        let room = WINDOW.saturating_sub(tx_next.saturating_sub(remote_credit)) as usize;
        let limit = room.min(CHUNK);
        tokio::select! {
         received=app_read.read(&mut readbuf[..limit]),if !tx_end&&limit>0=>{
          let len=received?;
          if pending.is_empty(){last_progress=Instant::now();}
          if len==0{tx_end=true;pending.insert(tx_next,Pending{frame:Frame::control(FIN,tx_next,0),lane:None,at:Instant::now(),attempts:0});}
          else{let seq=tx_next;tx_next=tx_next.checked_add(len as u64).ok_or_else(invalid)?;stats.sent.fetch_add(len as u64,Ordering::Relaxed);pending.insert(seq,Pending{frame:Frame{kind:DATA,seq,credit:0,data:Arc::new(readbuf[..len].to_vec())},lane:None,at:Instant::now(),attempts:0});}
         },
         event=incoming.recv()=>match event{
          Some(Event::Frame(index,frame))=>match frame.kind{
           DATA=>{
            let end=frame.seq.checked_add(frame.data.len()as u64).ok_or_else(invalid)?;
            if end>rx_next.saturating_add(WINDOW)||rx_end.is_some_and(|fin|end>fin){return Err(invalid());}
            if frame.seq<rx_next {if end>rx_next{return Err(invalid());}stats.duplicates.fetch_add(frame.data.len()as u64,Ordering::Relaxed);}
            else if let Some(old)=reorder.get(&frame.seq){if old.as_slice()!=frame.data.as_slice(){return Err(invalid());}stats.duplicates.fetch_add(frame.data.len()as u64,Ordering::Relaxed);}
            else{
             if reorder.range(..frame.seq).next_back().is_some_and(|(seq,b)|*seq+b.len()as u64>frame.seq)||reorder.range(frame.seq..).next().is_some_and(|(seq,_)|*seq<end){return Err(invalid());}
             reorder.insert(frame.seq,frame.data);let bytes=reorder.values().map(|v|v.len()as u64).sum();stats.reorder_peak.fetch_max(bytes,Ordering::Relaxed);
            }
            drain(&mut reorder,&mut rx_next,rx_end,&mut rx_finished,&deliver);send_control(&lanes,index,Frame::control(ACK,frame.seq,rx_next));
            if rx_finished{send_control(&lanes,index,Frame::control(FIN_ACK,rx_next,rx_next));}
           },
           ACK|CREDIT|FIN_ACK=>{
            if frame.credit>tx_next{return Err(invalid());}if frame.credit>remote_credit{last_progress=Instant::now();}remote_credit=remote_credit.max(frame.credit);
            if frame.kind==CREDIT{continue;}
            if frame.kind==FIN_ACK{if !tx_end||frame.seq!=tx_next{return Err(invalid());}tx_finished=true;}
            if let Some(p)=pending.remove(&frame.seq){
             last_progress=Instant::now();
             if (frame.kind==FIN_ACK)!=(p.frame.kind==FIN){return Err(invalid());}
             if let Some(i)=p.lane{let l=&mut lanes[i];l.inflight=l.inflight.saturating_sub(p.frame.data.len());l.confirmed+=p.frame.data.len();
              if p.attempts==1{let elapsed=p.at.elapsed().as_secs_f64().max(0.001);let delta=(l.rtt-elapsed).abs();l.variance=l.variance*0.75+delta*0.25;l.rtt=l.rtt*0.875+elapsed*0.125;l.bytes+=p.frame.data.len();let window=l.at.elapsed().as_secs_f64();if window>=0.05&&l.bytes>0{let rate=(l.bytes as f64/window).clamp(16.0*1024.0,64.0*1024.0*1024.0);l.rate=if l.measured{l.rate*0.5+rate*0.5}else{rate};l.measured=true;l.bytes=0;l.at=Instant::now();}}
             }
            }
           },
           FIN=>{if frame.seq<rx_next||frame.seq>rx_next.saturating_add(WINDOW)||rx_end.is_some_and(|end|end!=frame.seq)||reorder.iter().any(|(seq,bytes)|*seq+bytes.len()as u64>frame.seq){return Err(invalid());}rx_end=Some(frame.seq);drain(&mut reorder,&mut rx_next,rx_end,&mut rx_finished,&deliver);if rx_finished{send_control(&lanes,index,Frame::control(FIN_ACK,rx_next,rx_next));}},
           _=>return Err(invalid())
          },
          Some(Event::Down(index))=>{if lanes[index].alive{stats.failed_lanes.fetch_add(1,Ordering::Relaxed);lanes[index].alive=false;}},
          Some(Event::Delivered)=>{drain(&mut reorder,&mut rx_next,rx_end,&mut rx_finished,&deliver);send_control(&lanes,0,Frame::control(CREDIT,0,rx_next));if rx_finished{send_control(&lanes,0,Frame::control(FIN_ACK,rx_next,rx_next));}},
          Some(Event::WriteClosed)=>write_closed=true,
          Some(Event::FinAckSent)=>fin_ack_sent=true,
          Some(Event::WriteError)|None=>return Err(io::Error::new(io::ErrorKind::BrokenPipe,"Bonded destination closed")),
         },
         lane=additions.recv(),if more&&lanes.len()<MAX_LANES=>match lane{Some(lane)=>add_lane(lane,&mut lanes,&events,&mut jobs),None=>more=false},
         _=tick.tick()=>{},
        }
    }
}

struct Entry {
    lanes: mpsc::Sender<Stream>,
    count: AtomicUsize,
}
pub struct Server {
    session_created: tokio::sync::Notify,
    address: SocketAddr,
    key: [u8; 32],
    cluster: [u8; 16],
    enabled: AtomicBool,
    generation: watch::Sender<u64>,
    sessions: Mutex<HashMap<[u8; 32], Arc<Entry>>>,
    slots: Arc<Semaphore>,
    pub counters: Arc<Counters>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    #[cfg(test)]
    pub test_destination: Option<SocketAddr>,
}
impl Server {
    #[cfg(test)]
    pub(crate) async fn start_test(destination: SocketAddr) -> io::Result<Arc<Self>> {
        Self::start_inner(true, Some(destination)).await
    }
    pub async fn start(enabled: bool) -> io::Result<Arc<Self>> {
        Self::start_inner(
            enabled,
            #[cfg(test)]
            None,
        )
        .await
    }
    async fn start_inner(
        enabled: bool,
        #[cfg(test)] test_destination: Option<SocketAddr>,
    ) -> io::Result<Arc<Self>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let (generation, _) = watch::channel(0);
        let value = Arc::new(Self {
            session_created: tokio::sync::Notify::new(),
            address: listener.local_addr()?,
            key: random()?,
            cluster: random()?,
            enabled: AtomicBool::new(enabled),
            generation,
            sessions: Mutex::new(HashMap::new()),
            slots: Arc::new(Semaphore::new(MAX_FLOWS)),
            counters: Arc::new(Counters::default()),
            task: Mutex::new(None),
            #[cfg(test)]
            test_destination,
        });
        let weak = Arc::downgrade(&value);
        let task = tokio::spawn(async move {
            let cap = Arc::new(Semaphore::new(256));
            let mut jobs = JoinSet::new();
            loop {
                tokio::select! {
                 accepted=listener.accept()=>{let Ok((stream,_))=accepted else{break;};let Ok(permit)=cap.clone().try_acquire_owned()else{continue;};let Some(server)=weak.upgrade()else{break;};jobs.spawn(async move{let _permit=permit;let _=server.accept(stream).await;});},
                 _=jobs.join_next(),if !jobs.is_empty()=>{},
                }
            }
        });
        *value.task.lock() = Some(task);
        Ok(value)
    }
    pub fn gateway(&self) -> (SocketAddr, [u8; 32]) {
        (self.address, self.key)
    }
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
        if !enabled {
            self.sessions.lock().clear();
            self.generation.send_modify(|v| *v += 1);
        }
    }
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({"enabled":self.enabled.load(Ordering::Relaxed),"exitId":crate::settings::hex(&self.cluster),"metrics":self.counters.snapshot()})
    }
    pub fn shutdown(&self) {
        self.set_enabled(false);
        if let Some(task) = self.task.lock().take() {
            task.abort();
        }
    }
    async fn accept(self: Arc<Self>, mut stream: TcpStream) -> io::Result<()> {
        let mut cancel = self.generation.subscribe();
        stream.set_nodelay(true)?;
        let (id, create, target) = timeout(Duration::from_secs(25), async {
            let mut key = [0; 32];
            stream.read_exact(&mut key).await?;
            // Constant-time verification of the fixed-length local capability. This is
            // not a payload cipher; the capability never enters a remote tunnel.
            let domain = b"balevpn-local-bond-v1";
            let candidate =
                ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key), domain);
            let authorized = ring::hmac::verify(
                &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &self.key),
                domain,
                candidate.as_ref(),
            )
            .is_ok();
            if !authorized || !self.enabled.load(Ordering::SeqCst) {
                let _ = stream.write_all(&[2]).await;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Bonding relay disabled",
                ));
            }
            stream.write_all(&[0]).await?;
            stream.write_all(MAGIC).await?;
            stream.write_all(&self.cluster).await?;
            let mut id = [0; 32];
            stream.read_exact(&mut id).await?;
            let create = stream.read_u8().await?;
            let len = stream.read_u16().await? as usize;
            if len > 259 || create > 1 || (create == 0 && len != 0) || (create == 1 && len == 0) {
                return Err(invalid());
            }
            let mut target = vec![0; len];
            stream.read_exact(&mut target).await?;
            Ok::<_, io::Error>((id, create == 1, target))
        })
        .await
        .map_err(io::Error::other)??;
        if !self.enabled.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Bonding disabled",
            ));
        }
        if !create {
            let wait = async {
                loop {
                    let changed = self.session_created.notified();
                    tokio::pin!(changed);
                    changed.as_mut().enable();
                    if let Some(entry) = self.sessions.lock().get(&id).cloned() {
                        return entry;
                    }
                    changed.await;
                }
            };
            let entry = tokio::select! {value=timeout(Duration::from_secs(2),wait)=>value.map_err(|_|invalid())?,_=cancel.changed()=>return Err(invalid())};
            if entry
                .count
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    if n < MAX_LANES {
                        Some(n + 1)
                    } else {
                        None
                    }
                })
                .is_err()
            {
                return Err(invalid());
            }
            stream.write_all(&[0]).await?;
            entry
                .lanes
                .try_send(Box::new(stream))
                .map_err(|_| invalid())?;
            return Ok(());
        }
        let _permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| io::Error::other("Bonding stream limit reached"))?;
        let (tx, rx) = mpsc::channel(MAX_LANES - 1);
        let entry = Arc::new(Entry {
            lanes: tx,
            count: AtomicUsize::new(1),
        });
        {
            let mut sessions = self.sessions.lock();
            if sessions.contains_key(&id) {
                return Err(invalid());
            }
            sessions.insert(id, entry.clone());
        }
        self.session_created.notify_waiters();
        struct Remove {
            server: Arc<Server>,
            id: [u8; 32],
            entry: Arc<Entry>,
        }
        impl Drop for Remove {
            fn drop(&mut self) {
                let mut sessions = self.server.sessions.lock();
                if sessions
                    .get(&self.id)
                    .is_some_and(|v| Arc::ptr_eq(v, &self.entry))
                {
                    sessions.remove(&self.id);
                }
            }
        }
        let _remove = Remove {
            server: self.clone(),
            id,
            entry,
        };
        let destination = async {
            #[cfg(test)]
            if let Some(address) = self.test_destination {
                return TcpStream::connect(address).await;
            }
            lktunnel::socks5_quic::connect_public_target(&target).await
        };
        let destination = tokio::select! {v=destination=>v,_=cancel.changed()=>return Err(io::Error::other("Bonding disabled"))};
        let destination = match destination {
            Ok(stream) => stream,
            Err(error) => {
                let code = match error.kind() {
                    io::ErrorKind::PermissionDenied => 2,
                    io::ErrorKind::ConnectionRefused => 5,
                    io::ErrorKind::NotFound | io::ErrorKind::HostUnreachable => 4,
                    io::ErrorKind::NetworkUnreachable => 3,
                    io::ErrorKind::TimedOut => 6,
                    _ => 1,
                };
                let _ = stream.write_all(&[code]).await;
                return Err(error);
            }
        };
        if !self.enabled.load(Ordering::SeqCst) || cancel.has_changed().unwrap_or(true) {
            return Err(io::Error::other("Bonding disabled"));
        }
        self.counters.opened.fetch_add(1, Ordering::Relaxed);
        stream.write_all(&[0]).await?;
        tokio::select! {v=transfer(destination,vec![Box::new(stream)],rx,self.counters.clone())=>v,_=cancel.changed()=>Err(io::Error::other("Bonding disabled"))}
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(task) = self.task.get_mut().take() {
            task.abort();
        }
    }
}

/// All lanes must identify the same owning server controller, before CREATE.
#[derive(Debug)]
pub struct TargetStatus(pub u8);
impl std::fmt::Display for TargetStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bonded destination refused or unreachable ({})", self.0)
    }
}
impl std::error::Error for TargetStatus {}
pub async fn bind(mut streams: Vec<Stream>, target: &[u8]) -> io::Result<Vec<Stream>> {
    if streams.is_empty() || streams.len() > MAX_LANES || target.len() < 7 || target.len() > 259 {
        return Err(invalid());
    }
    let mut cluster = None;
    for stream in &mut streams {
        let mut hello = [0; 24];
        stream.read_exact(&mut hello).await?;
        if &hello[..8] != MAGIC {
            return Err(invalid());
        }
        if cluster
            .as_ref()
            .is_some_and(|c: &[u8; 16]| c.as_slice() != &hello[8..])
        {
            return Err(io::Error::other(
                "Bonding requires accounts under the same server controller",
            ));
        }
        let mut id = [0; 16];
        id.copy_from_slice(&hello[8..]);
        cluster = Some(id);
    }
    let session: [u8; 32] = random()?;
    let mut pending = JoinSet::new();
    for (index, mut stream) in streams.into_iter().enumerate() {
        let target = target.to_vec();
        pending.spawn(async move {
            stream.write_all(&session).await?;
            stream.write_u8(u8::from(index == 0)).await?;
            let envelope = if index == 0 { target.as_slice() } else { &[] };
            stream.write_u16(envelope.len() as u16).await?;
            stream.write_all(envelope).await?;
            let status = stream.read_u8().await?;
            if status != 0 {
                return Err(io::Error::other(TargetStatus(
                    if (1..=8).contains(&status) { status } else { 1 },
                )));
            }
            Ok::<_, io::Error>((index, stream))
        });
    }
    let mut bound = Vec::new();
    while let Some(value) = pending.join_next().await {
        bound.push(value.map_err(io::Error::other)??);
    }
    bound.sort_by_key(|(index, _)| *index);
    Ok(bound.into_iter().map(|(_, stream)| stream).collect())
}

pub fn gateway_from_environment() -> io::Result<(SocketAddr, [u8; 32])> {
    let address: SocketAddr = std::env::var("BALEVPN_BOND_GATEWAY")
        .map_err(|_| invalid())?
        .parse()
        .map_err(|_| invalid())?;
    let secret = std::env::var("BALEVPN_BOND_GATEWAY_KEY").map_err(|_| invalid())?;
    let mut key = [0; 32];
    if secret.len() != 64 || !secret.is_ascii() || !address.ip().is_loopback() {
        return Err(invalid());
    }
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&secret[i * 2..i * 2 + 2], 16).map_err(|_| invalid())?;
    }
    Ok((address, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = TcpStream::connect(listener.local_addr().unwrap());
        let b = listener.accept();
        let (a, b) = tokio::join!(a, b);
        (a.unwrap(), b.unwrap().0)
    }
    async fn exchange(
        left: Vec<Stream>,
        right: Vec<Stream>,
        size: usize,
    ) -> (Arc<Counters>, Arc<Counters>) {
        let (user, a) = pair().await;
        let (b, mut echo) = pair().await;
        let ac = Arc::new(Counters::default());
        let bc = Arc::new(Counters::default());
        let (tx, rx) = mpsc::channel(1);
        drop(tx);
        let a_task = tokio::spawn(transfer(a, left, rx, ac.clone()));
        let (tx, rx) = mpsc::channel(1);
        drop(tx);
        let b_task = tokio::spawn(transfer(b, right, rx, bc.clone()));
        let echo_task = tokio::spawn(async move {
            let (mut r, mut w) = echo.split();
            tokio::io::copy(&mut r, &mut w).await.unwrap();
            w.shutdown().await.unwrap();
        });
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let (mut r, mut w) = user.into_split();
        timeout(Duration::from_secs(20), async {
            let send = async move {
                w.write_all(&payload).await.unwrap();
                w.shutdown().await.unwrap();
            };
            let receive = async {
                let mut bytes = Vec::new();
                r.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, expected);
            };
            tokio::join!(send, receive);
            a_task.await.unwrap().unwrap();
            b_task.await.unwrap().unwrap();
            echo_task.await.unwrap();
        })
        .await
        .unwrap();
        assert!(ac.reorder_peak.load(Ordering::Relaxed) <= WINDOW);
        assert!(bc.reorder_peak.load(Ordering::Relaxed) <= WINDOW);
        (ac, bc)
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_lanes_preserve_exact_bytes_full_duplex_and_half_close() {
        let (a, b) = tokio::io::duplex(128 * 1024);
        let (c, d) = tokio::io::duplex(128 * 1024);
        let (ac, bc) = exchange(
            vec![Box::new(a), Box::new(c)],
            vec![Box::new(b), Box::new(d)],
            4 * 1024 * 1024,
        )
        .await;
        assert_eq!(ac.sent.load(Ordering::Relaxed), 4 * 1024 * 1024);
        assert_eq!(ac.received.load(Ordering::Relaxed), 4 * 1024 * 1024);
        assert_eq!(bc.received.load(Ordering::Relaxed), 4 * 1024 * 1024);
    }
    #[tokio::test]
    async fn malformed_length_is_rejected_before_allocating_payload() {
        for (kind, len) in [(DATA, 0), (DATA, CHUNK + 1), (ACK, 1), (99, 0)] {
            let (mut a, mut b) = tokio::io::duplex(100);
            a.write_u8(kind).await.unwrap();
            a.write_u64(0).await.unwrap();
            a.write_u64(0).await.unwrap();
            a.write_u16(len as u16).await.unwrap();
            assert!(Frame::read(&mut b).await.is_err());
        }
    }
    #[tokio::test]
    async fn public_target_guard_and_local_gateway_credentials_fail_closed() {
        assert!(
            lktunnel::socks5_quic::connect_public_target(&[1, 127, 0, 0, 1, 0, 80])
                .await
                .is_err()
        );
        let server = Server::start(true).await.unwrap();
        let mut outsider = TcpStream::connect(server.address).await.unwrap();
        outsider.write_all(&[0; 32]).await.unwrap();
        assert_eq!(outsider.read_u8().await.unwrap(), 2);
        assert_eq!(server.counters.opened.load(Ordering::Relaxed), 0);
        server.shutdown();
    }
    #[tokio::test]
    async fn different_server_controllers_are_rejected_before_any_destination_is_opened() {
        let a = Server::start(true).await.unwrap();
        let b = Server::start(true).await.unwrap();
        let mut streams = Vec::<Stream>::new();
        for server in [&a, &b] {
            let mut s = TcpStream::connect(server.address).await.unwrap();
            s.write_all(&server.key).await.unwrap();
            assert_eq!(s.read_u8().await.unwrap(), 0);
            streams.push(Box::new(s));
        }
        assert!(bind(streams, &[1, 8, 8, 8, 8, 0, 80]).await.is_err());
        assert_eq!(a.counters.opened.load(Ordering::Relaxed), 0);
        assert_eq!(b.counters.opened.load(Ordering::Relaxed), 0);
        a.shutdown();
        b.shutdown();
    }
    async fn ipc(server: &Server) -> TcpStream {
        let mut stream = TcpStream::connect(server.address).await.unwrap();
        stream.write_all(&server.key).await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), 0);
        stream
    }
    async fn command(server: &Server, id: [u8; 32], create: bool, target: &[u8]) -> TcpStream {
        let mut s = ipc(server).await;
        let mut hello = [0; 24];
        s.read_exact(&mut hello).await.unwrap();
        s.write_all(&id).await.unwrap();
        s.write_u8(u8::from(create)).await.unwrap();
        s.write_u16(target.len() as u16).await.unwrap();
        s.write_all(target).await.unwrap();
        s
    }
    #[tokio::test]
    async fn duplicate_creation_unknown_joins_lane_limit_and_disable_do_not_leak_egress_sockets() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = Server::start_test(target.local_addr().unwrap())
            .await
            .unwrap();
        let id = [7; 32];
        let envelope = [1, 8, 8, 8, 8, 0, 80];
        let mut first = command(&server, id, true, &envelope).await;
        assert_eq!(first.read_u8().await.unwrap(), 0);
        let mut lanes = vec![first];
        let mut duplicate = command(&server, id, true, &envelope).await;
        assert!(duplicate.read_u8().await.is_err());
        assert_eq!(server.counters.opened.load(Ordering::Relaxed), 1);
        let mut unknown = command(&server, [8; 32], false, &[]).await;
        assert!(unknown.read_u8().await.is_err());
        for _ in 1..MAX_LANES {
            let mut lane = command(&server, id, false, &[]).await;
            assert_eq!(lane.read_u8().await.unwrap(), 0);
            lanes.push(lane);
        }
        let mut extra = command(&server, id, false, &[]).await;
        assert!(extra.read_u8().await.is_err());
        server.set_enabled(false);
        timeout(Duration::from_secs(2), async {
            for lane in &mut lanes {
                assert!(lane.read_u8().await.is_err());
            }
            while server.counters.active.load(Ordering::Relaxed) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(server.sessions.lock().is_empty());
        assert_eq!(server.counters.opened.load(Ordering::Relaxed), 1);
        server.shutdown();
    }
    #[tokio::test]
    async fn live_private_destination_is_refused_by_the_production_bond_connector() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = Server::start(true).await.unwrap();
        let port = target.local_addr().unwrap().port().to_be_bytes();
        assert!(bind(
            vec![Box::new(ipc(&server).await)],
            &[1, 127, 0, 0, 1, port[0], port[1]]
        )
        .await
        .is_err());
        assert_eq!(server.counters.opened.load(Ordering::Relaxed), 0);
        assert!(timeout(Duration::from_millis(50), target.accept())
            .await
            .is_err());
        server.shutdown();
    }
    #[tokio::test]
    async fn parallel_join_can_replace_the_first_lane_during_setup_without_redialing() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = Server::start_test(target.local_addr().unwrap())
            .await
            .unwrap();
        let id = [17; 32];
        let mut primary = command(&server, id, true, &[1, 8, 8, 8, 8, 0, 80]).await;
        assert_eq!(primary.read_u8().await.unwrap(), 0);
        drop(primary);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut replacement = command(&server, id, false, &[]).await;
        assert_eq!(replacement.read_u8().await.unwrap(), 0);
        assert_eq!(server.counters.opened.load(Ordering::Relaxed), 1);
        assert_eq!(server.counters.active.load(Ordering::Relaxed), 1);
        server.shutdown();
    }
    #[tokio::test]
    async fn invalid_offsets_overlaps_ack_credit_and_fin_are_bounded_and_rejected() {
        for case in 0..4 {
            let (_user, app) = pair().await;
            let (a, mut peer) = tokio::io::duplex(65536);
            let stats = Arc::new(Counters::default());
            let (tx, rx) = mpsc::channel(1);
            drop(tx);
            let task = tokio::spawn(transfer(app, vec![Box::new(a)], rx, stats.clone()));
            let data = |seq, n| Frame {
                kind: DATA,
                seq,
                credit: 0,
                data: Arc::new(vec![1; n]),
            };
            match case {
                0 => data(WINDOW + 1, 1).write(&mut peer).await.unwrap(),
                1 => {
                    data(1, 4).write(&mut peer).await.unwrap();
                    data(3, 5).write(&mut peer).await.unwrap();
                }
                2 => Frame::control(CREDIT, 0, 1).write(&mut peer).await.unwrap(),
                _ => {
                    data(5, 1).write(&mut peer).await.unwrap();
                    Frame::control(FIN, 4, 0).write(&mut peer).await.unwrap();
                }
            }
            let result = timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            assert!(stats.reorder_peak.load(Ordering::Relaxed) <= WINDOW);
        }
    }
    struct Shape {
        rate: u64,
        latency: Duration,
        cut: Option<u64>,
        blackhole: bool,
        budget: Option<Arc<tokio::sync::Mutex<tokio::time::Instant>>>,
    }
    async fn forward<R: AsyncRead + Unpin + Send + 'static, W: AsyncWrite + Unpin>(
        mut read: R,
        mut write: W,
        shape: Shape,
        bytes: Arc<AtomicU64>,
    ) -> io::Result<()> {
        let (tx, mut rx) = mpsc::channel::<(Vec<u8>, tokio::time::Instant)>(32);
        let mut reader = JoinSet::new();
        reader.spawn(async move {
            let mut b = vec![0; CHUNK];
            loop {
                let Ok(n) = read.read(&mut b).await else {
                    break;
                };
                if n == 0 {
                    break;
                }
                if tx
                    .send((b[..n].to_vec(), tokio::time::Instant::now()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let local = Arc::new(tokio::sync::Mutex::new(tokio::time::Instant::now()));
        let budget = shape.budget.unwrap_or(local);
        while let Some((block, at)) = rx.recv().await {
            if shape
                .cut
                .is_some_and(|cut| bytes.load(Ordering::Relaxed) >= cut)
            {
                if shape.blackhole {
                    continue;
                }
                return Ok(());
            }
            let due = {
                let mut next = budget.lock().await;
                let due = (*next).max(at + shape.latency)
                    + Duration::from_secs_f64(block.len() as f64 / shape.rate as f64);
                *next = due;
                due
            };
            tokio::time::sleep_until(due).await;
            write.write_all(&block).await?;
            bytes.fetch_add(block.len() as u64, Ordering::Relaxed);
        }
        write.shutdown().await
    }
    fn shaped(
        rate: u64,
        latency: u64,
        cut: Option<u64>,
        blackhole: bool,
        budget: Option<Arc<tokio::sync::Mutex<tokio::time::Instant>>>,
    ) -> (Stream, Stream, tokio::task::JoinHandle<()>, Arc<AtomicU64>) {
        let (a, b) = tokio::io::duplex(256 * 1024);
        let (c, d) = tokio::io::duplex(256 * 1024);
        let (br, bw) = tokio::io::split(b);
        let (cr, cw) = tokio::io::split(c);
        let down = Arc::new(AtomicU64::new(0));
        let dc = down.clone();
        let task = tokio::spawn(async move {
            let mut jobs = JoinSet::new();
            jobs.spawn(forward(
                br,
                cw,
                Shape {
                    rate,
                    latency: Duration::from_millis(latency),
                    cut: None,
                    blackhole: false,
                    budget: budget.clone(),
                },
                Arc::new(AtomicU64::new(0)),
            ));
            jobs.spawn(forward(
                cr,
                bw,
                Shape {
                    rate,
                    latency: Duration::from_millis(latency),
                    cut,
                    blackhole,
                    budget,
                },
                dc,
            ));
            let _ = jobs.join_next().await;
        });
        (Box::new(a), Box::new(d), task, down)
    }
    async fn download_fixture(
        rates: &[(u64, u64, Option<u64>, bool)],
        shared: bool,
        size: usize,
    ) -> serde_json::Value {
        let (user, a) = pair().await;
        let (b, mut destination) = pair().await;
        let mut bridges = Vec::new();
        let mut left = Vec::new();
        let mut right = Vec::new();
        let mut totals = Vec::new();
        let budget = if shared {
            Some(Arc::new(tokio::sync::Mutex::new(
                tokio::time::Instant::now(),
            )))
        } else {
            None
        };
        for (rate, latency, cut, blackhole) in rates {
            let (l, r, task, count) = shaped(*rate, *latency, *cut, *blackhole, budget.clone());
            left.push(l);
            right.push(r);
            bridges.push(task);
            totals.push(count);
        }
        let ac = Arc::new(Counters::default());
        let bc = Arc::new(Counters::default());
        let (tx, rx) = mpsc::channel(1);
        drop(tx);
        let at = tokio::spawn(transfer(a, left, rx, ac.clone()));
        let (tx, rx) = mpsc::channel(1);
        drop(tx);
        let bt = tokio::spawn(transfer(b, right, rx, bc.clone()));
        let expected: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let payload = expected.clone();
        let target = tokio::spawn(async move {
            assert_eq!(destination.read_u8().await.unwrap(), 42);
            destination.write_all(&payload).await.unwrap();
            destination.shutdown().await.unwrap();
            let mut final_bytes = Vec::new();
            destination.read_to_end(&mut final_bytes).await.unwrap();
            assert!(final_bytes.is_empty());
        });
        let (mut read, mut write) = user.into_split();
        write.write_all(&[42]).await.unwrap();
        write.shutdown().await.unwrap();
        let started = Instant::now();
        timeout(Duration::from_secs(40), async {
            let mut received = Vec::new();
            read.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, expected);
        })
        .await
        .unwrap();
        let seconds = started.elapsed().as_secs_f64();
        timeout(Duration::from_secs(5), async {
            at.await.unwrap().unwrap();
            bt.await.unwrap().unwrap();
            target.await.unwrap();
        })
        .await
        .unwrap();
        let result = serde_json::json!({"seconds":seconds,"bytes":size,"bytesPerSecond":size as f64/seconds,"laneDownloadBytes":totals.iter().map(|c|c.load(Ordering::Relaxed)).collect::<Vec<_>>(),"client":ac.snapshot(),"server":bc.snapshot()});
        for bridge in bridges {
            bridge.abort();
        }
        result
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn single_download_uses_both_independent_lanes_and_survives_a_lane_cut() {
        let normal = download_fixture(
            &[
                (1024 * 1024, 10, None, false),
                (1024 * 1024, 10, None, false),
            ],
            false,
            4 * 1024 * 1024,
        )
        .await;
        assert!(normal["laneDownloadBytes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v.as_u64().unwrap() > 512 * 1024));
        let cut = download_fixture(
            &[
                (1024 * 1024, 10, None, false),
                (1024 * 1024, 10, Some(192 * 1024), false),
            ],
            false,
            4 * 1024 * 1024,
        )
        .await;
        assert!(cut["server"]["reinjectedBytes"].as_u64().unwrap() > 0);
        assert!(cut["server"]["failedLanes"].as_u64().unwrap() > 0);
        println!(
            "BOND_FIXTURES {}",
            serde_json::json!({"normal":normal,"cut":cut})
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn blackholed_lane_is_reinjected_without_duplicate_download_bytes() {
        let result = download_fixture(
            &[
                (1024 * 1024, 10, None, false),
                (1024 * 1024, 10, Some(96 * 1024), true),
            ],
            false,
            3 * 1024 * 1024,
        )
        .await;
        assert!(result["server"]["reinjectedBytes"].as_u64().unwrap() > 0);
        println!("BOND_BLACKHOLE {}", result);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "Controlled timing benchmark; run explicitly after compilation finishes"]
    async fn compare_single_stream_independent_asymmetric_and_shared_capacity() {
        let mut samples = Vec::new();
        for trial in 0..3 {
            let mut order = vec![
                "singlePlain",
                "singleLaneBond",
                "independent",
                "asymmetric",
                "shared",
            ];
            if trial % 2 == 1 {
                order.reverse();
            }
            let mut row = serde_json::json!({"trial":trial});
            for name in order {
                let value = match name {
                    "singlePlain" => plain_download(4 * 1024 * 1024).await,
                    "singleLaneBond" => {
                        download_fixture(&[(1024 * 1024, 10, None, false)], false, 4 * 1024 * 1024)
                            .await
                    }
                    "independent" => {
                        download_fixture(
                            &[
                                (1024 * 1024, 10, None, false),
                                (1024 * 1024, 10, None, false),
                            ],
                            false,
                            4 * 1024 * 1024,
                        )
                        .await
                    }
                    "asymmetric" => {
                        download_fixture(
                            &[
                                (1024 * 1024, 10, None, false),
                                (128 * 1024, 120, None, false),
                            ],
                            false,
                            4 * 1024 * 1024,
                        )
                        .await
                    }
                    _ => {
                        download_fixture(
                            &[
                                (1024 * 1024, 10, None, false),
                                (1024 * 1024, 10, None, false),
                            ],
                            true,
                            4 * 1024 * 1024,
                        )
                        .await
                    }
                };
                row[name] = value;
            }
            samples.push(row);
        }
        let report = serde_json::json!({"localFixturesOnly":true,"singleDestinationTcpPerDownload":true,"exactBytesVerified":true,"samples":samples});
        if let Ok(path) = std::env::var("BALEVPN_BOND_BENCHMARK_REPORT") {
            std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
        }
        println!("BOND_BENCHMARK {}", report);
    }
    async fn plain_download(size: usize) -> serde_json::Value {
        let (mut client, mut server, bridge, _) = shaped(1024 * 1024, 10, None, false, None);
        let expected: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let payload = expected.clone();
        let task = tokio::spawn(async move {
            assert_eq!(server.read_u8().await.unwrap(), 42);
            server.write_all(&payload).await.unwrap();
            server.shutdown().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
        let started = Instant::now();
        client.write_all(&[42]).await.unwrap();
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await.unwrap();
        let seconds = started.elapsed().as_secs_f64();
        assert_eq!(bytes, expected);
        task.await.unwrap();
        bridge.abort();
        serde_json::json!({"bytes":size,"seconds":seconds,"bytesPerSecond":size as f64/seconds})
    }
}
