//! Private Nasim relay helper. Provider identity is fixed at compilation.
const PROVIDER: &str = "nasim";
const BRIDGE_ENV: &str = "BALEVPN_NASIM_BRIDGE";
include!("support/relay_bridge.rs");
