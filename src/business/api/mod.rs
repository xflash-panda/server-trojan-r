//! Remote panel API integration
//!
//! This module handles:
//! - Node registration and verification
//! - User fetching with hot-reload
//! - Traffic reporting
//! - Heartbeat sending
//! - State persistence

mod client;
mod tasks;
mod user_manager;

pub use client::ApiManager;
pub use tasks::{BackgroundTasks, TaskConfig};
pub use user_manager::UserManager;
