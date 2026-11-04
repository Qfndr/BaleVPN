//! Regression for a remote nomination arriving before its triggered check succeeds.
use super::*;
use crate::candidate::candidate_base::CandidateBaseConfig;
use crate::candidate::candidate_host::CandidateHostConfig;
use crate::control::AttrControlling;
use crate::priority::PriorityAttr;
use crate::use_candidate::UseCandidateAttr;
use async_trait::async_trait;
use std::any::Any;
use std::sync::Mutex as StdMutex;
use stun::textattrs::Username;
use util::Conn;

#[derive(Default)]
struct RecordedPackets(StdMutex<Vec<Vec<u8>>>);

#[async_trait]
impl Conn for RecordedPackets {
    async fn connect(&self, _: SocketAddr) -> std::result::Result<(), util::Error> { Ok(()) }
    async fn recv(&self, _: &mut [u8]) -> std::result::Result<usize, util::Error> { unreachable!() }
    async fn recv_from(&self, _: &mut [u8]) -> std::result::Result<(usize, SocketAddr), util::Error> { unreachable!() }
    async fn send(&self, bytes: &[u8]) -> std::result::Result<usize, util::Error> {
        self.0.lock().unwrap().push(bytes.to_vec()); Ok(bytes.len())
    }
    async fn send_to(&self, bytes: &[u8], _: SocketAddr) -> std::result::Result<usize, util::Error> { self.send(bytes).await }
    fn local_addr(&self) -> std::result::Result<SocketAddr, util::Error> { Ok("127.0.0.1:41001".parse().unwrap()) }
    fn remote_addr(&self) -> Option<SocketAddr> { None }
    async fn close(&self) -> std::result::Result<(), util::Error> { Ok(()) }
    fn as_any(&self) -> &(dyn Any + Send + Sync) { self }
}

#[tokio::test]
async fn controlled_early_nomination_selects_only_after_triggered_check_success() -> Result<()> {
    // No sockets, background task loops, timing, or external service are involved.
    let (agent, _receivers) = AgentInternal::new(&AgentConfig::default());
    let packets = Arc::new(RecordedPackets::default());
    let local: Arc<dyn Candidate + Send + Sync> = Arc::new(CandidateHostConfig {
        base_config: CandidateBaseConfig { network: "udp".into(), address: "127.0.0.1".into(), port: 41001, component: 1, conn: Some(packets.clone()), ..Default::default() },
        ..Default::default()
    }.new_candidate_host()?);
    let remote: Arc<dyn Candidate + Send + Sync> = Arc::new(CandidateHostConfig {
        base_config: CandidateBaseConfig { network: "udp".into(), address: "127.0.0.1".into(), port: 41002, component: 1, ..Default::default() },
        ..Default::default()
    }.new_candidate_host()?);
    agent.add_pair(local.clone(), remote.clone()).await;
    let pair = agent.find_pair(&local, &remote).await.unwrap();
    let mut nomination = Message::new();
    nomination.build(&[Box::new(BINDING_REQUEST), Box::new(TransactionId::new()), Box::new(UseCandidateAttr::new())])?;
    agent.handle_binding_request(&nomination, &local, &remote).await;
    assert!(agent.agent_conn.get_selected_pair().is_none(), "nomination must not bypass a successful connectivity check");
    assert_eq!(pair.state.load(Ordering::SeqCst), CandidatePairState::Waiting as u8);
    let sent = packets.0.lock().unwrap().clone();
    assert_eq!(sent.len(), 2, "acknowledge the nomination and send its triggered connectivity check");
    let mut ack = Message::new(); ack.raw = sent[0].clone(); ack.decode()?;
    assert_eq!(ack.typ, BINDING_SUCCESS);
    assert_eq!(ack.transaction_id, nomination.transaction_id);
    let pending = agent.pending_binding_requests.lock().await;
    assert_eq!(pending.len(), 1);
    let mut success = Message::new();
    success.transaction_id = pending[0].transaction_id;
    drop(pending);
    agent.handle_success_response(&success, &local, &remote, remote.addr()).await;
    assert_eq!(pair.state.load(Ordering::SeqCst), CandidatePairState::Succeeded as u8);
    assert!(Arc::ptr_eq(&agent.agent_conn.get_selected_pair().expect("early nomination must survive until success"), &pair));
    Ok(())
}

fn negative_fixture() -> Result<(AgentInternal, Arc<RecordedPackets>, Arc<dyn Candidate + Send + Sync>, Arc<dyn Candidate + Send + Sync>)> {
    let (agent, _) = AgentInternal::new(&AgentConfig::default());
    let packets = Arc::new(RecordedPackets::default());
    let local: Arc<dyn Candidate + Send + Sync> = Arc::new(CandidateHostConfig {
        base_config: CandidateBaseConfig { network: "udp".into(), address: "127.0.0.1".into(), port: 42001, component: 1, conn: Some(packets.clone()), ..Default::default() },
        ..Default::default()
    }.new_candidate_host()?);
    let remote: Arc<dyn Candidate + Send + Sync> = Arc::new(CandidateHostConfig {
        base_config: CandidateBaseConfig { network: "udp".into(), address: "127.0.0.1".into(), port: 42002, component: 1, ..Default::default() },
        ..Default::default()
    }.new_candidate_host()?);
    Ok((agent, packets, local, remote))
}

#[tokio::test]
async fn controlled_early_nomination_rejects_unknown_transaction_and_wrong_source() -> Result<()> {
    let (agent, _packets, local, remote) = negative_fixture()?;
    agent.add_pair(local.clone(), remote.clone()).await;
    let pair = agent.find_pair(&local, &remote).await.unwrap();
    let mut nomination = Message::new();
    nomination.build(&[Box::new(BINDING_REQUEST), Box::new(TransactionId::new()), Box::new(UseCandidateAttr::new())])?;
    agent.handle_binding_request(&nomination, &local, &remote).await;
    let transaction = agent.pending_binding_requests.lock().await[0].transaction_id;
    let mut unknown = Message::new();
    unknown.transaction_id = transaction;
    unknown.transaction_id.0[0] ^= 1;
    agent.handle_success_response(&unknown, &local, &remote, remote.addr()).await;
    assert!(agent.agent_conn.get_selected_pair().is_none());
    assert_eq!(pair.state.load(Ordering::SeqCst), CandidatePairState::Waiting as u8);
    assert_eq!(agent.pending_binding_requests.lock().await.len(), 1, "unknown transaction must not consume the actual check");
    let mut wrong_source = Message::new();
    wrong_source.transaction_id = transaction;
    agent.handle_success_response(&wrong_source, &local, &remote, "127.0.0.1:42003".parse().unwrap()).await;
    assert!(agent.agent_conn.get_selected_pair().is_none(), "wrong source cannot nominate the pending pair");
    assert_eq!(pair.state.load(Ordering::SeqCst), CandidatePairState::Waiting as u8);
    Ok(())
}

#[tokio::test]
async fn controlled_early_nomination_rejects_invalid_integrity_before_selector() -> Result<()> {
    let (agent, packets, local, remote) = negative_fixture()?;
    {
        let mut credentials = agent.ufrag_pwd.lock().await;
        credentials.local_ufrag = "local-fixture".into();
        credentials.remote_ufrag = "remote-fixture".into();
        credentials.local_pwd = "local".into();
        credentials.remote_pwd = "remote".into();
    }
    agent.add_pair(local.clone(), remote.clone()).await;
    agent.remote_candidates.lock().await.insert(remote.network_type(), vec![remote.clone()]);
    let pair = agent.find_pair(&local, &remote).await.unwrap();
    let request = |password: &str| -> Result<Message> {
        let mut message = Message::new();
        message.build(&[
            Box::new(BINDING_REQUEST), Box::new(TransactionId::new()),
            Box::new(Username::new(ATTR_USERNAME, "local-fixture:remote-fixture".into())),
            Box::new(UseCandidateAttr::new()), Box::new(AttrControlling(7)),
            Box::new(PriorityAttr(remote.priority())),
            Box::new(MessageIntegrity::new_short_term_integrity(password.to_owned())),
            Box::new(FINGERPRINT),
        ])?;
        Ok(message)
    };
    let mut invalid = request("wrong")?;
    agent.handle_inbound(&mut invalid, &local, remote.addr()).await;
    assert!(packets.0.lock().unwrap().is_empty(), "unauthenticated nomination must not be acknowledged or trigger a check");
    assert!(agent.pending_binding_requests.lock().await.is_empty());
    assert_eq!(pair.state.load(Ordering::SeqCst), CandidatePairState::Waiting as u8);
    assert!(agent.agent_conn.get_selected_pair().is_none());
    // Positive control proves the same username, source and packet route can
    // reach the selector once its integrity authenticates correctly.
    let mut valid = request("local")?;
    agent.handle_inbound(&mut valid, &local, remote.addr()).await;
    assert!(!packets.0.lock().unwrap().is_empty());
    assert_eq!(agent.pending_binding_requests.lock().await.len(), 1);
    assert!(agent.agent_conn.get_selected_pair().is_none());
    Ok(())
}
// Nomination diagnostics regression below.
#[tokio::test]
async fn nomination_diagnostics_count_only_authenticated_requests_and_pending_checks() -> Result<()> {
    let (agent, _packets, local, remote) = negative_fixture()?;
    {
        let mut credentials = agent.ufrag_pwd.lock().await;
        credentials.local_ufrag = "local-fixture".into();
        credentials.remote_ufrag = "remote-fixture".into();
        credentials.local_pwd = "local".into();
        credentials.remote_pwd = "remote".into();
    }
    agent.add_pair(local.clone(), remote.clone()).await;
    agent
        .remote_candidates
        .lock()
        .await
        .insert(remote.network_type(), vec![remote.clone()]);
    let request = |password: &str| -> Result<Message> {
        let mut message = Message::new();
        message.build(&[
            Box::new(BINDING_REQUEST),
            Box::new(TransactionId::new()),
            Box::new(Username::new(
                ATTR_USERNAME,
                "local-fixture:remote-fixture".into(),
            )),
            Box::new(UseCandidateAttr::new()),
            Box::new(AttrControlling(7)),
            Box::new(PriorityAttr(remote.priority())),
            Box::new(MessageIntegrity::new_short_term_integrity(
                password.to_owned(),
            )),
            Box::new(FINGERPRINT),
        ])?;
        Ok(message)
    };
    let mut invalid = request("wrong")?;
    agent.handle_inbound(&mut invalid, &local, remote.addr()).await;
    let snapshot = agent.nomination_diagnostic().await;
    assert_eq!(
        (snapshot.accepted, snapshot.pending, snapshot.selected),
        (0, 0, false),
    );
    for _ in 0..2 {
        let mut valid = request("local")?;
        agent.handle_inbound(&mut valid, &local, remote.addr()).await;
    }
    let snapshot = agent.nomination_diagnostic().await;
    assert_eq!(
        (snapshot.accepted, snapshot.pending, snapshot.selected),
        (2, 1, false),
    );
    assert!(!snapshot.truncated);
    let transaction = agent.pending_binding_requests.lock().await[0].transaction_id;
    let mut success = Message::new();
    success.build(&[
        Box::new(BINDING_SUCCESS),
        Box::new(transaction),
        Box::new(MessageIntegrity::new_short_term_integrity("remote".into())),
        Box::new(FINGERPRINT),
    ])?;
    agent.handle_inbound(&mut success, &local, remote.addr()).await;
    let snapshot = agent.nomination_diagnostic().await;
    assert_eq!(
        (snapshot.accepted, snapshot.pending, snapshot.selected),
        (2, 0, true),
    );
    Ok(())
}
