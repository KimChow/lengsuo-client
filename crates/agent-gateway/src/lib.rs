//! Authenticated loopback gateway. Protocol: AGENT-KICKOFF.md §2.
#![forbid(unsafe_code)]
mod rpc;
mod server;
pub use server::{GatewayConfig, GatewayHandle};
