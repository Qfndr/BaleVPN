//! Private Eitaa relay helper. Provider identity is fixed at compilation.
const PROVIDER: &str = "eitaa";
const BRIDGE_ENV: &str = "BALEVPN_EITAA_BRIDGE";
include!("support/relay_bridge.rs");
