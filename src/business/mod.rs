//! Business logic implementations
//!
//! This module contains the business-specific implementations:
//! - API integration (user management, traffic reporting, heartbeat)
//! - Authentication implementations
//! - Statistics collection

pub mod api;
mod auth;
mod stats;

pub use api::{ApiManager, BackgroundTasks, TaskConfig, UserManager};
pub use auth::ApiAuthenticator;
pub use stats::ApiStatsCollector;

use sha2::{Digest, Sha224};

/// Hash password using SHA224
fn hash_password(password: &str) -> [u8; 28] {
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 28];
    hash.copy_from_slice(&result);
    hash
}

/// Convert password to hex (56 bytes)
pub fn password_to_hex(password: &str) -> [u8; 56] {
    let hash = hash_password(password);
    let hex_string = hex::encode(hash);
    let mut hex_bytes: [u8; 56] = [0u8; 56];
    hex_bytes.copy_from_slice(hex_string.as_bytes());
    hex_bytes
}
