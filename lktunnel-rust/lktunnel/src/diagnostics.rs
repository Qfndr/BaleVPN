//! Bounded setup/teardown events. Never record free-form error strings, IDs,
//! addresses, certificates, credentials, target names or packet payloads.
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::sync::atomic::{AtomicU64, Ordering};
use serde_json::{json, Value};

static EVENTS: OnceLock<Mutex<VecDeque<Value>>> = OnceLock::new();
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
pub fn record(stage: &'static str, reason: &'static str, code: Option<u64>) {
    let mut events=EVENTS.get_or_init(Default::default).lock().unwrap_or_else(|e|e.into_inner());
    if events.len()==128 { events.pop_front(); }
    events.push_back(json!({"sequence":SEQUENCE.fetch_add(1,Ordering::Relaxed)+1,"unixMs":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
        "stage":stage,"reason":reason,"code":code}));
}
pub fn snapshot() -> Vec<Value> {
    EVENTS.get_or_init(Default::default).lock().unwrap_or_else(|e|e.into_inner()).iter().cloned().collect()
}
pub fn reason(error: &str) -> &'static str {
    let text=error.to_ascii_lowercase();
    if text.contains("quic authentication timed out") {return "timeout";}
    for (needle,reason) in [("cryptographic handshake failed","authentication_failure"),("crypto_error","authentication_failure"),("callnotapproved","call_not_approved"),("rejected","call_rejected"),("certificate","certificate_failure"),("authentication","authentication_failure"),("pairing","pairing_failure"),("flood","rate_limited"),("timeout","timeout"),("timed out","timeout"),("lk failed","carrier_setup_failed"),("disconnected","carrier_closed"),("unknown peer","unknown_peer")] {
        if text.contains(needle) {return reason;}
    }
    "other_failure"
}
pub fn connection(stage: &'static str, error: &quinn::ConnectionError) {
    use quinn::ConnectionError::*;
    let (reason,code)=match error {
        TimedOut => ("timeout",None),
        LocallyClosed => ("locally_closed",None),
        Reset => ("reset",None),
        VersionMismatch => ("version_mismatch",None),
        ConnectionClosed(e) => ("remote_closed",Some(u64::from(e.error_code))),
        ApplicationClosed(e) => ("application_closed",Some(e.error_code.into_inner())),
        TransportError(e) => {
            let code=u64::from(e.code);
            let reason=if (0x100..0x200).contains(&code) {
                if e.reason.contains("UnknownIssuer") {"unknown_issuer"}
                else if e.reason.contains("BadSignature") {"bad_signature"}
                else if e.reason.contains("Expired") {"certificate_expired"}
                else {"tls_alert"}
            } else {"transport_error"};
            (reason,Some(code))
        },
        _ => ("connection_error",None),
    };
    record(stage,reason,code);
}
pub fn endpoint(stage: &'static str, error: &crate::quic_tunnel::QuicEndpointError) {
    use crate::quic_tunnel::QuicEndpointError::*;
    match error {
        Connection(e)=>connection(stage,e),
        Io(e)=>record(stage,if e.kind()==std::io::ErrorKind::TimedOut {"timeout"}else{"carrier_or_io_closed"},None),
        Config(_)|Connect(_)=>record(stage,"local_config",None),
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn errors_cannot_export_free_form_secrets() {
        let error=crate::quic_tunnel::QuicEndpointError::Io(std::io::Error::other("token=secret https://private.invalid phone +123456789"));
        super::endpoint("test_setup",&error);
        let text=serde_json::to_string(&super::snapshot()).unwrap();
        assert!(!text.contains("secret")&&!text.contains("private.invalid")&&!text.contains("123456789"));
        assert_eq!(super::reason("QUIC authentication timed out; check pairing codes"),"timeout");
    }
}
