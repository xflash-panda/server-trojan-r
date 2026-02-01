//! Core proxy server module
//!
//! This module contains the core proxy functionality:
//! - Protocol parsing (Trojan)
//! - Connection management
//! - Bidirectional relay
//! - Hook traits for extensibility

mod connection;
pub mod hooks;
pub mod ip_filter;
mod protocol;
mod relay;
mod server;

pub use connection::ConnectionManager;
pub use hooks::UserId;
pub use protocol::{Address, DecodeResult, TrojanCmd, TrojanRequest};
pub use relay::copy_bidirectional_with_stats;
pub use server::Server;
