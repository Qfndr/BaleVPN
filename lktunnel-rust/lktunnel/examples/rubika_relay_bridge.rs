//! Private Rubika relay helper. Provider identity is fixed at compilation.
const PROVIDER: &str = "rubika";
const BRIDGE_ENV: &str = "BALEVPN_RUBIKA_BRIDGE";
include!("support/relay_bridge.rs");
