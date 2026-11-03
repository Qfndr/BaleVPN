//! Experimental native iGap foundation. Not wired into the production application.
//! Every account owns its authenticated channel, credential store and call epoch.
pub mod adapter;
pub mod auth;
pub mod privacy;
pub mod room;
pub mod rpc;
pub mod security;
pub mod wire;
pub use adapter::IgapSignaling;
pub use rpc::{Response, Rpc};
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidPacket,
    NotConnected,
    Timeout,
    Closed,
    Busy,
    InvalidInput,
    NotAuthenticated,
    Cancelled,
    Rejected {
        major: u32,
        minor: u32,
        wait_seconds: u32,
    },
    InvalidResponse,
    NotSupported,
}
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPacket => "invalid_packet",
            Self::NotConnected => "not_connected",
            Self::Timeout => "timeout",
            Self::Closed => "closed",
            Self::Busy => "busy",
            Self::InvalidInput => "invalid_input",
            Self::NotAuthenticated => "not_authenticated",
            Self::Cancelled => "cancelled",
            Self::Rejected { .. } => "service_rejected",
            Self::InvalidResponse => "invalid_response",
            Self::NotSupported => "not_supported",
        })
    }
}
impl std::error::Error for Error {}
impl From<wire::Error> for Error {
    fn from(_: wire::Error) -> Self {
        Self::InvalidPacket
    }
}
