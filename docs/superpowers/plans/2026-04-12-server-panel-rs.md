# server-r-panel Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract panel business logic from `server-trojan-rs` into a standalone reusable crate `server-r-panel`.

**Architecture:** Code moves from `server-trojan-rs/src/business/` into a new sibling crate `server-r-panel/`. The new crate re-exports `User`, `UserTraffic`, `TrafficStats`, `NodeType` from `server-r-client` (no duplication). Protocol-specific traits (`Authenticator`, `StatsCollector`) stay in consumer crates — panel crate exposes only public methods, consumers bridge via newtype wrappers.

**Tech Stack:** Rust, tokio, tonic (gRPC), arc-swap, dashmap, tracing, sha2

**Spec:** `docs/superpowers/specs/2026-04-12-server-r-panel-design.md`

---

## File Structure

### New crate: `/Users/alex/code/rust/xflash-panda/server-r-panel/`

| File | Responsibility |
|------|---------------|
| `Cargo.toml` | Crate metadata and dependencies |
| `src/lib.rs` | Public exports, `password_to_hex()`, re-exports from `server-r-client` |
| `src/config.rs` | `PanelConfig` struct |
| `src/stats.rs` | `StatsCollector`, `UserStatsSnapshot` — lock-free traffic stats |
| `src/user_manager.rs` | `UserManager`, `UserDiff` — user table with ArcSwap hot-reload |
| `src/client.rs` | `ApiManager` — gRPC panel communication |
| `src/tasks.rs` | `BackgroundTasks`, `BackgroundTasksHandle`, `TaskConfig` — periodic tasks |

### Modified in `server-trojan-rs`:

| File | Change |
|------|--------|
| `Cargo.toml` | Add `server-r-panel` dep, remove `server-r-agent-proto`, `hostname` |
| `src/business/mod.rs` | Replace with thin newtype wrappers (~40 lines) |
| `src/business/api/` | Delete entire directory |
| `src/business/auth.rs` | Delete (logic moves to `mod.rs` wrapper) |
| `src/business/stats.rs` | Delete (moved to panel crate) |
| `src/config.rs` | Remove `User` struct and `From<server_r_client::User>` impl |
| `src/main.rs` | Rewire to use `server_r_panel` types |

---

### Task 1: Create crate scaffold

**Files:**
- Create: `server-r-panel/Cargo.toml`
- Create: `server-r-panel/src/lib.rs`
- Create: `server-r-panel/src/config.rs`

- [ ] **Step 1: Create project directory**

```bash
mkdir -p /Users/alex/code/rust/xflash-panda/server-r-panel/src
```

- [ ] **Step 2: Create Cargo.toml**

Create `server-r-panel/Cargo.toml`:

```toml
[package]
name = "server-r-panel"
version = "0.1.0"
edition = "2021"
rust-version = "1.83.0"
description = "Reusable panel integration library for xflash-panda proxy servers"
license = "MIT"
repository = "https://github.com/xflash-panda/server-r-panel"
keywords = ["proxy", "panel", "grpc"]
categories = ["network-programming"]

[dependencies]
server-r-agent-proto = { git = "https://github.com/xflash-panda/server-r-agent-proto.git", tag = "v0.1.2" }
server-r-client = { git = "https://github.com/xflash-panda/server-r-client.git", tag = "v0.1.8" }
tonic = "0.14"
tokio = { version = "1.49", features = ["rt-multi-thread", "time", "sync"] }
anyhow = "1.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
sha2 = "0.10"
hex = "0.4"
arc-swap = "1"
dashmap = "6.1"
scopeguard = "1.2.0"
hostname = "0.4"

[dev-dependencies]
tokio-test = "0.4"
```

- [ ] **Step 3: Create config.rs with PanelConfig**

Create `server-r-panel/src/config.rs`:

```rust
//! Panel configuration types

use server_r_client::NodeType;
use std::path::PathBuf;
use std::time::Duration;

/// Configuration for connecting to the panel service
#[derive(Debug, Clone)]
pub struct PanelConfig {
    /// gRPC server host (e.g., "127.0.0.1")
    pub server_host: String,
    /// gRPC server port (e.g., 8082)
    pub server_port: u16,
    /// Node ID for this server
    pub node_id: u32,
    /// Node type (Trojan, TUIC, etc.) — determines protocol for gRPC calls
    pub node_type: NodeType,
    /// Data directory for persisting state and other data
    pub data_dir: PathBuf,
    /// API request timeout
    pub api_timeout: Duration,
}
```

- [ ] **Step 4: Create lib.rs skeleton**

Create `server-r-panel/src/lib.rs`:

```rust
//! # server-r-panel
//!
//! Reusable panel integration library for xflash-panda proxy servers.
//!
//! Provides protocol-agnostic panel communication, user management,
//! traffic statistics collection, and background task orchestration.

mod config;

pub use config::PanelConfig;

// Re-export common types from server-r-client
pub use server_r_client::{
    NodeType, NodeConfigEnum, User, UserTraffic, TrafficStats,
    unmarshal_users, parse_raw_config_response,
};

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

/// Convert password (UUID) to 56-byte hex via SHA224
pub fn password_to_hex(password: &str) -> [u8; 56] {
    let hash = hash_password(password);
    let hex_string = hex::encode(hash);
    let mut hex_bytes: [u8; 56] = [0u8; 56];
    hex_bytes.copy_from_slice(hex_string.as_bytes());
    hex_bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_to_hex_deterministic() {
        let hex1 = password_to_hex("test-uuid");
        let hex2 = password_to_hex("test-uuid");
        assert_eq!(hex1, hex2);
    }

    #[test]
    fn test_password_to_hex_different_inputs() {
        let hex1 = password_to_hex("uuid-1");
        let hex2 = password_to_hex("uuid-2");
        assert_ne!(hex1, hex2);
    }

    #[test]
    fn test_password_to_hex_length() {
        let hex = password_to_hex("any-password");
        assert_eq!(hex.len(), 56);
        // All bytes should be valid hex characters
        for &b in &hex {
            assert!(b.is_ascii_hexdigit());
        }
    }
}
```

- [ ] **Step 5: Verify scaffold compiles**

```bash
cd /Users/alex/code/rust/xflash-panda/server-r-panel && cargo check
```

Expected: compiles successfully.

- [ ] **Step 6: Run tests**

```bash
cd /Users/alex/code/rust/xflash-panda/server-r-panel && cargo test
```

Expected: 3 tests pass.

- [ ] **Step 7: Commit**

```bash
cd /Users/alex/code/rust/xflash-panda/server-r-panel && git init && git add -A && git commit -m "feat: initial crate scaffold with PanelConfig and password_to_hex"
```

---

### Task 2: StatsCollector module

**Files:**
- Create: `server-r-panel/src/stats.rs`
- Modify: `server-r-panel/src/lib.rs`

This is the simplest module — no dependencies on other panel modules.

- [ ] **Step 1: Create stats.rs**

Create `server-r-panel/src/stats.rs` — moved from `server-trojan-rs/src/business/stats.rs` with `UserId` replaced by `i64` and no trait impl:

```rust
//! Lock-free traffic statistics collection
//!
//! Uses DashMap + AtomicU64 for concurrent, lock-free writes.
//! Consumers bridge to their own trait via newtype wrapper.

use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// User statistics data (internal)
#[derive(Debug, Default)]
struct UserStatsData {
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
    request_count: AtomicU64,
}

/// Statistics snapshot for a user
#[derive(Debug, Clone)]
pub struct UserStatsSnapshot {
    pub user_id: i64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub request_count: u64,
}

/// Lock-free traffic statistics collector
///
/// Collects per-user traffic statistics that can be reported to the remote panel.
/// Uses atomic operations — no locks on the write path.
///
/// Consumers should bridge this to their own `StatsCollector` trait via newtype:
/// ```ignore
/// struct MyStats(Arc<StatsCollector>);
/// impl MyTrait for MyStats {
///     fn record_upload(&self, uid: i64, bytes: u64) { self.0.record_upload(uid, bytes) }
/// }
/// ```
pub struct StatsCollector {
    stats: Arc<DashMap<i64, UserStatsData>>,
    resetting: AtomicBool,
}

impl Default for StatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsCollector {
    /// Create a new stats collector
    pub fn new() -> Self {
        Self {
            stats: Arc::new(DashMap::new()),
            resetting: AtomicBool::new(false),
        }
    }

    /// Record a proxy request for a user
    pub fn record_request(&self, user_id: i64) {
        self.stats
            .entry(user_id)
            .or_default()
            .request_count
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record upload bytes (client -> remote)
    pub fn record_upload(&self, user_id: i64, bytes: u64) {
        self.stats
            .entry(user_id)
            .or_default()
            .upload_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record download bytes (remote -> client)
    pub fn record_download(&self, user_id: i64, bytes: u64) {
        self.stats
            .entry(user_id)
            .or_default()
            .download_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get stats for a specific user
    pub fn get_stats(&self, user_id: i64) -> Option<UserStatsSnapshot> {
        self.stats.get(&user_id).map(|entry| {
            let data = entry.value();
            UserStatsSnapshot {
                user_id,
                upload_bytes: data.upload_bytes.load(Ordering::Relaxed),
                download_bytes: data.download_bytes.load(Ordering::Relaxed),
                request_count: data.request_count.load(Ordering::Relaxed),
            }
        })
    }

    /// Get all stats snapshots
    pub fn get_all_snapshots(&self) -> Vec<UserStatsSnapshot> {
        self.stats
            .iter()
            .map(|entry| {
                let data = entry.value();
                UserStatsSnapshot {
                    user_id: *entry.key(),
                    upload_bytes: data.upload_bytes.load(Ordering::Relaxed),
                    download_bytes: data.download_bytes.load(Ordering::Relaxed),
                    request_count: data.request_count.load(Ordering::Relaxed),
                }
            })
            .collect()
    }

    /// Reset all stats and return snapshots
    ///
    /// Single-pass swap-and-collect:
    /// 1. Iterate all entries, atomically swap values to 0
    /// 2. Collect non-zero entries as snapshots
    /// 3. Remove zero-traffic entries to prevent unbounded growth
    ///
    /// Any writes during this process will either be counted in this snapshot
    /// or accumulated for the next snapshot (no data loss).
    pub fn reset_all(&self) -> Vec<UserStatsSnapshot> {
        if self
            .resetting
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Vec::new();
        }

        let _guard = scopeguard::guard((), |_| {
            self.resetting.store(false, Ordering::Release);
        });

        let mut snapshots = Vec::new();
        let mut all_keys = Vec::new();

        for entry in self.stats.iter() {
            let user_id = *entry.key();
            let data = entry.value();

            let upload = data.upload_bytes.swap(0, Ordering::AcqRel);
            let download = data.download_bytes.swap(0, Ordering::AcqRel);
            let requests = data.request_count.swap(0, Ordering::AcqRel);

            all_keys.push(user_id);

            if upload > 0 || download > 0 || requests > 0 {
                snapshots.push(UserStatsSnapshot {
                    user_id,
                    upload_bytes: upload,
                    download_bytes: download,
                    request_count: requests,
                });
            }
        }

        for key in all_keys {
            self.stats.remove_if(&key, |_, data| {
                data.upload_bytes.load(Ordering::Relaxed) == 0
                    && data.download_bytes.load(Ordering::Relaxed) == 0
                    && data.request_count.load(Ordering::Relaxed) == 0
            });
        }

        snapshots
    }

    /// Get number of tracked users
    pub fn user_count(&self) -> usize {
        self.stats.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_collector_new() {
        let collector = StatsCollector::new();
        assert_eq!(collector.user_count(), 0);
    }

    #[test]
    fn test_stats_collector_record_request() {
        let collector = StatsCollector::new();
        collector.record_request(1);
        collector.record_request(1);
        collector.record_request(2);

        assert_eq!(collector.get_stats(1).unwrap().request_count, 2);
        assert_eq!(collector.get_stats(2).unwrap().request_count, 1);
    }

    #[test]
    fn test_stats_collector_record_upload_download() {
        let collector = StatsCollector::new();
        collector.record_upload(1, 100);
        collector.record_download(1, 200);
        collector.record_upload(1, 50);

        let stats = collector.get_stats(1).unwrap();
        assert_eq!(stats.upload_bytes, 150);
        assert_eq!(stats.download_bytes, 200);
    }

    #[test]
    fn test_stats_collector_reset_all() {
        let collector = StatsCollector::new();
        collector.record_upload(1, 100);
        collector.record_download(1, 200);
        collector.record_request(1);

        let snapshots = collector.reset_all();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].upload_bytes, 100);
        assert_eq!(snapshots[0].download_bytes, 200);
        assert_eq!(snapshots[0].request_count, 1);

        // After reset, entry should be cleaned up
        assert!(collector.get_stats(1).is_none());
    }

    #[test]
    fn test_stats_collector_reset_filters_empty() {
        let collector = StatsCollector::new();
        collector.record_upload(1, 100);
        collector.record_request(2);

        let snapshots = collector.reset_all();
        assert_eq!(snapshots.len(), 2);
    }

    #[test]
    fn test_stats_collector_get_all_snapshots() {
        let collector = StatsCollector::new();
        collector.record_upload(1, 100);
        collector.record_upload(2, 200);
        collector.record_upload(3, 300);

        let snapshots = collector.get_all_snapshots();
        assert_eq!(snapshots.len(), 3);

        let total_upload: u64 = snapshots.iter().map(|s| s.upload_bytes).sum();
        assert_eq!(total_upload, 600);
    }

    #[test]
    fn test_stats_collector_concurrent() {
        use std::thread;

        let collector = Arc::new(StatsCollector::new());
        let mut handles = vec![];

        for i in 0..10 {
            let c = Arc::clone(&collector);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    c.record_request(i % 3);
                    c.record_upload(i % 3, 1);
                    c.record_download(i % 3, 2);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let snapshots = collector.get_all_snapshots();
        assert_eq!(snapshots.len(), 3);

        let total_requests: u64 = snapshots.iter().map(|s| s.request_count).sum();
        assert_eq!(total_requests, 10000);
    }

    #[test]
    fn test_stats_collector_concurrent_with_reset() {
        use std::thread;

        let collector = Arc::new(StatsCollector::new());
        let mut write_handles = vec![];

        for i in 0..5 {
            let c = Arc::clone(&collector);
            write_handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    c.record_upload(i % 3, 1);
                    c.record_download(i % 3, 1);
                }
            }));
        }

        let c = Arc::clone(&collector);
        let reset_handle = thread::spawn(move || {
            let mut total_upload = 0u64;
            let mut total_download = 0u64;
            for _ in 0..10 {
                thread::sleep(std::time::Duration::from_millis(1));
                let snapshots = c.reset_all();
                for s in snapshots {
                    total_upload += s.upload_bytes;
                    total_download += s.download_bytes;
                }
            }
            (total_upload, total_download)
        });

        for h in write_handles {
            h.join().unwrap();
        }

        let (_collected_upload, _collected_download) = reset_handle.join().unwrap();

        let final_snapshots = collector.reset_all();
        let remaining: u64 = final_snapshots.iter().map(|s| s.upload_bytes).sum();

        assert!(remaining <= 5000);
    }

    /// Strict invariant: total collected via resets + final remaining == total written.
    #[test]
    fn test_reset_all_no_data_loss_strict() {
        use std::thread;

        for _ in 0..50 {
            let collector = Arc::new(StatsCollector::new());
            let total_per_thread = 2000u64;
            let num_writers = 5;
            let expected_total = num_writers * total_per_thread;

            let mut write_handles = vec![];

            for _ in 0..num_writers {
                let c = Arc::clone(&collector);
                write_handles.push(thread::spawn(move || {
                    for _ in 0..total_per_thread {
                        c.record_upload(1, 1);
                    }
                }));
            }

            let c = Arc::clone(&collector);
            let reset_handle = thread::spawn(move || {
                let mut total_collected = 0u64;
                for _ in 0..200 {
                    let snapshots = c.reset_all();
                    for s in &snapshots {
                        total_collected += s.upload_bytes;
                    }
                    thread::yield_now();
                }
                total_collected
            });

            for h in write_handles {
                h.join().unwrap();
            }

            let collected = reset_handle.join().unwrap();

            let final_snapshots = collector.reset_all();
            let remaining: u64 = final_snapshots.iter().map(|s| s.upload_bytes).sum();

            assert_eq!(
                collected + remaining,
                expected_total,
                "Data loss: collected={}, remaining={}, expected={}",
                collected,
                remaining,
                expected_total
            );
        }
    }

    #[test]
    fn test_user_stats_snapshot_clone() {
        let snapshot = UserStatsSnapshot {
            user_id: 1,
            upload_bytes: 100,
            download_bytes: 200,
            request_count: 10,
        };
        let cloned = snapshot.clone();
        assert_eq!(cloned.user_id, snapshot.user_id);
        assert_eq!(cloned.upload_bytes, snapshot.upload_bytes);
    }
}
```

- [ ] **Step 2: Add stats module to lib.rs**

Add to `server-r-panel/src/lib.rs` after the `mod config;` line:

```rust
mod stats;

pub use stats::{StatsCollector, UserStatsSnapshot};
```

- [ ] **Step 3: Run tests**

```bash
cd /Users/alex/code/rust/xflash-panda/server-r-panel && cargo test
```

Expected: all stats tests pass (11 tests total including lib tests).

- [ ] **Step 4: Commit**

```bash
cd /Users/alex/code/rust/xflash-panda/server-r-panel && git add -A && git commit -m "feat: add StatsCollector with lock-free traffic statistics"
```

---

### Task 3: UserManager module

**Files:**
- Create: `server-r-panel/src/user_manager.rs`
- Modify: `server-r-panel/src/lib.rs`

Key change from original: `update()` returns `UserDiff` instead of doing kick logic.

- [ ] **Step 1: Create user_manager.rs**

Create `server-r-panel/src/user_manager.rs`:

```rust
//! User management with hot-reload and diff reporting
//!
//! Uses ArcSwap for lock-free reads on the authentication hot path.
//! Updates compute diffs and atomically swap the map pointer.
//! Kick logic is NOT handled here — consumers react to `UserDiff`.

use arc_swap::ArcSwap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::password_to_hex;
use crate::User;

/// Result of a user list update — consumers use this to handle kicks, logging, etc.
#[derive(Debug, Clone)]
pub struct UserDiff {
    /// Number of newly added users
    pub added: usize,
    /// Number of removed users
    pub removed: usize,
    /// Number of users whose UUID changed
    pub uuid_changed: usize,
    /// User IDs that were removed
    pub removed_ids: Vec<i64>,
    /// User IDs whose UUID changed
    pub uuid_changed_ids: Vec<i64>,
    /// Total user count after update
    pub total: usize,
}

/// User manager with ArcSwap hot-reload
///
/// Maintains a `password_hex -> user_id` mapping using ArcSwap for lock-free reads.
/// Updates build a new map, compute diffs, and atomically swap the pointer.
///
/// Does NOT handle connection kicking — consumers should inspect `UserDiff`
/// returned by `update()` and kick connections for `removed_ids` and `uuid_changed_ids`.
pub struct UserManager {
    users: Arc<ArcSwap<HashMap<[u8; 56], i64>>>,
}

impl Default for UserManager {
    fn default() -> Self {
        Self::new()
    }
}

impl UserManager {
    /// Create a new user manager with an empty user table
    pub fn new() -> Self {
        Self {
            users: Arc::new(ArcSwap::from_pointee(HashMap::new())),
        }
    }

    /// Get a clone of the current users map
    pub fn get_users(&self) -> HashMap<[u8; 56], i64> {
        (**self.users.load()).clone()
    }

    /// Get arc reference to users map (for sharing with authenticators)
    pub fn get_users_arc(&self) -> Arc<ArcSwap<HashMap<[u8; 56], i64>>> {
        Arc::clone(&self.users)
    }

    /// Initialize with a list of users (replaces all existing users)
    pub fn init(&self, users: &[User]) {
        let mut users_map = HashMap::with_capacity(users.len());

        for user in users {
            let hex = password_to_hex(&user.uuid);
            users_map.insert(hex, user.id);
        }

        self.users.store(Arc::new(users_map));
        tracing::info!(count = users.len(), "Users initialized");
    }

    /// Update users with hot-reload, returning a diff
    ///
    /// All diff computation happens without holding any lock.
    /// Only the final map swap is atomic (nanosecond-level).
    pub fn update(&self, new_users: &[User]) -> UserDiff {
        let old_map = self.users.load();

        // Build new map
        let mut new_map: HashMap<[u8; 56], i64> = HashMap::with_capacity(new_users.len());
        let new_user_ids: HashSet<i64> = new_users.iter().map(|u| u.id).collect();

        for user in new_users {
            let hex = password_to_hex(&user.uuid);
            new_map.insert(hex, user.id);
        }

        // Compute diff
        let old_user_ids: HashSet<i64> = old_map.values().copied().collect();

        let added = new_user_ids.difference(&old_user_ids).count();
        let removed_ids: Vec<i64> = old_user_ids.difference(&new_user_ids).copied().collect();
        let removed = removed_ids.len();

        // Detect UUID changes
        let mut uuid_changed_ids: Vec<i64> = Vec::new();
        for (new_hex, &new_id) in &new_map {
            if old_user_ids.contains(&new_id) {
                if old_map.get(new_hex) != Some(&new_id) {
                    uuid_changed_ids.push(new_id);
                }
            }
        }
        let uuid_changed = uuid_changed_ids.len();

        let total = new_map.len();

        // Atomic swap
        self.users.store(Arc::new(new_map));

        if added > 0 || removed > 0 || uuid_changed > 0 {
            tracing::info!(
                added = added,
                removed = removed,
                uuid_changed = uuid_changed,
                total = total,
                "Users updated"
            );
        }

        UserDiff {
            added,
            removed,
            uuid_changed,
            removed_ids,
            uuid_changed_ids,
            total,
        }
    }

    /// Get user count
    pub fn user_count(&self) -> usize {
        self.users.load().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_user(id: i64, uuid: &str) -> User {
        User {
            id,
            uuid: uuid.to_string(),
        }
    }

    #[test]
    fn test_user_manager_new() {
        let um = UserManager::new();
        assert_eq!(um.user_count(), 0);
    }

    #[test]
    fn test_user_manager_init() {
        let um = UserManager::new();
        let users = vec![create_user(1, "uuid-1"), create_user(2, "uuid-2")];
        um.init(&users);
        assert_eq!(um.user_count(), 2);
    }

    #[test]
    fn test_user_manager_update_add_users() {
        let um = UserManager::new();
        um.init(&[create_user(1, "uuid-1")]);

        let diff = um.update(&[
            create_user(1, "uuid-1"),
            create_user(2, "uuid-2"),
            create_user(3, "uuid-3"),
        ]);
        assert_eq!(diff.added, 2);
        assert_eq!(diff.removed, 0);
        assert_eq!(diff.uuid_changed, 0);
        assert_eq!(diff.total, 3);
        assert!(diff.removed_ids.is_empty());
        assert!(diff.uuid_changed_ids.is_empty());
    }

    #[test]
    fn test_user_manager_update_remove_users() {
        let um = UserManager::new();
        um.init(&[
            create_user(1, "uuid-1"),
            create_user(2, "uuid-2"),
            create_user(3, "uuid-3"),
        ]);

        let diff = um.update(&[create_user(1, "uuid-1")]);
        assert_eq!(diff.added, 0);
        assert_eq!(diff.removed, 2);
        assert_eq!(diff.uuid_changed, 0);
        assert_eq!(diff.total, 1);
        assert_eq!(diff.removed_ids.len(), 2);
        assert!(diff.removed_ids.contains(&2));
        assert!(diff.removed_ids.contains(&3));
    }

    #[test]
    fn test_user_manager_update_mixed() {
        let um = UserManager::new();
        um.init(&[create_user(1, "uuid-1"), create_user(2, "uuid-2")]);

        let diff = um.update(&[create_user(2, "uuid-2"), create_user(3, "uuid-3")]);
        assert_eq!(diff.added, 1);
        assert_eq!(diff.removed, 1);
        assert_eq!(diff.uuid_changed, 0);
        assert_eq!(diff.total, 2);
        assert_eq!(diff.removed_ids, vec![1]);
    }

    #[test]
    fn test_user_manager_update_uuid_changed() {
        let um = UserManager::new();
        um.init(&[create_user(1, "uuid-1"), create_user(2, "uuid-2")]);

        // User 1's UUID changed
        let diff = um.update(&[create_user(1, "uuid-1-new"), create_user(2, "uuid-2")]);
        assert_eq!(diff.added, 0);
        assert_eq!(diff.removed, 0);
        assert_eq!(diff.uuid_changed, 1);
        assert_eq!(diff.uuid_changed_ids, vec![1]);
    }

    #[test]
    fn test_user_manager_get_users_arc() {
        let um = UserManager::new();
        um.init(&[create_user(1, "uuid-1")]);

        let users_arc = um.get_users_arc();
        let users_map = users_arc.load();
        assert_eq!(users_map.len(), 1);
    }

    #[test]
    fn test_user_manager_update_does_not_block_reads() {
        let um = UserManager::new();
        um.init(&[create_user(1, "uuid-1")]);

        // Take a snapshot
        let snapshot = um.users.load();
        assert_eq!(snapshot.len(), 1);

        // Update while snapshot is held
        let diff = um.update(&[create_user(2, "uuid-2"), create_user(3, "uuid-3")]);
        assert_eq!(diff.added, 2);
        assert_eq!(diff.removed, 1);

        // Snapshot still sees old data
        assert_eq!(snapshot.len(), 1);

        // New reads see new data
        assert_eq!(um.user_count(), 2);
    }
}
```

- [ ] **Step 2: Add user_manager module to lib.rs**

Add to `server-r-panel/src/lib.rs` after the `mod stats;` line:

```rust
mod user_manager;

pub use user_manager::{UserManager, UserDiff};
```

- [ ] **Step 3: Run tests**

```bash
cd /Users/alex/code/rust/xflash-panda/server-r-panel && cargo test
```

Expected: all tests pass (lib + stats + user_manager).

- [ ] **Step 4: Commit**

```bash
cd /Users/alex/code/rust/xflash-panda/server-r-panel && git add -A && git commit -m "feat: add UserManager with hot-reload and UserDiff"
```

---

### Task 4: ApiManager module

**Files:**
- Create: `server-r-panel/src/client.rs`
- Modify: `server-r-panel/src/lib.rs`

Key changes from original: takes `PanelConfig` instead of `CliArgs`, uses `node_type` from config instead of hardcoded Trojan, returns `NodeConfigEnum` from `fetch_config()`, uses `server_r_client::User` directly.

- [ ] **Step 1: Create client.rs**

Create `server-r-panel/src/client.rs`:

```rust
//! gRPC API client for remote panel communication

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use server_r_agent_proto::pkg::{
    agent_client::AgentClient, ConfigRequest, ConfigResponse, HeartbeatRequest,
    NodeType as GrpcNodeType, RegisterRequest as GrpcRegisterRequest, SubmitRequest,
    UnregisterRequest, UsersRequest, VerifyRequest,
};
use server_r_client::{
    parse_raw_config_response, unmarshal_users, NodeConfigEnum, NodeType, TrafficStats, User,
    UserTraffic,
};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::RwLock;
use tonic::transport::Channel;

use crate::PanelConfig;

/// State file name
const STATE_FILE: &str = "state.json";

/// Persistent state for the panel
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PanelState {
    register_id: Option<String>,
    node_id: Option<u32>,
    server_port: Option<u16>,
}

/// Convert `server_r_client::NodeType` to gRPC proto `NodeType` i32 value
fn node_type_to_grpc(nt: NodeType) -> i32 {
    match nt {
        NodeType::ShadowSocks => GrpcNodeType::Shadowsocks as i32,
        NodeType::Trojan => GrpcNodeType::Trojan as i32,
        NodeType::VMess => GrpcNodeType::Vmess as i32,
        NodeType::Hysteria => GrpcNodeType::Hysteria as i32,
        NodeType::Hysteria2 => GrpcNodeType::Hysteria2 as i32,
        NodeType::AnyTLS => GrpcNodeType::Anytls as i32,
        NodeType::Tuic => GrpcNodeType::Tuic as i32,
    }
}

fn get_hostname() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// API manager for handling all remote panel operations via gRPC
pub struct ApiManager {
    client: RwLock<Option<AgentClient<Channel>>>,
    config: PanelConfig,
    register_id: RwLock<Option<String>>,
}

impl ApiManager {
    /// Create a new API manager
    pub fn new(config: PanelConfig) -> Result<Self> {
        Ok(Self {
            client: RwLock::new(None),
            config,
            register_id: RwLock::new(None),
        })
    }

    /// Get the node type as gRPC i32 value
    fn grpc_node_type(&self) -> i32 {
        node_type_to_grpc(self.config.node_type)
    }

    /// Connect to the gRPC server
    async fn connect(&self) -> Result<AgentClient<Channel>> {
        let endpoint = format!(
            "http://{}:{}",
            self.config.server_host, self.config.server_port
        );
        let timeout = self.config.api_timeout;
        tracing::info!(
            endpoint = %endpoint,
            timeout_secs = timeout.as_secs(),
            "Connecting to gRPC server"
        );

        let channel = Channel::from_shared(endpoint.clone())
            .map_err(|e| anyhow!("Invalid endpoint: {}", e))?
            .connect_timeout(timeout)
            .timeout(timeout)
            .tcp_keepalive(Some(Duration::from_secs(60)))
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(10))
            .keep_alive_while_idle(true)
            .connect()
            .await
            .map_err(|e| anyhow!("Failed to connect to gRPC server {}: {}", endpoint, e))?;

        let client = AgentClient::new(channel);
        tracing::info!("Connected to gRPC server");
        Ok(client)
    }

    /// Get or create gRPC client
    async fn get_client(&self) -> Result<AgentClient<Channel>> {
        let client_guard = self.client.read().await;
        if let Some(client) = client_guard.clone() {
            return Ok(client);
        }
        drop(client_guard);

        let client = self.connect().await?;
        *self.client.write().await = Some(client.clone());
        Ok(client)
    }

    /// Reset cached gRPC client, forcing a fresh connection on next request.
    pub async fn reset_client(&self) {
        let mut client_guard = self.client.write().await;
        if client_guard.is_some() {
            *client_guard = None;
            tracing::warn!("gRPC client reset, will reconnect on next request");
        }
    }

    fn state_file_path(&self) -> PathBuf {
        self.config.data_dir.join(STATE_FILE)
    }

    fn load_state(&self) -> Option<PanelState> {
        let path = self.state_file_path();
        if !path.exists() {
            return None;
        }

        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(state) => {
                    tracing::info!(path = %path.display(), "Loaded state from file");
                    Some(state)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to parse state file");
                    None
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "Failed to read state file");
                None
            }
        }
    }

    fn save_state(&self, state: &PanelState) -> Result<()> {
        let path = self.state_file_path();
        let content = serde_json::to_string_pretty(state)
            .map_err(|e| anyhow!("Failed to serialize state: {}", e))?;

        std::fs::write(&path, content)
            .map_err(|e| anyhow!("Failed to write state file {:?}: {}", path, e))?;

        tracing::info!(path = %path.display(), "Saved state to file");
        Ok(())
    }

    fn delete_state(&self) {
        let path = self.state_file_path();
        if path.exists() {
            if let Err(e) = std::fs::remove_file(&path) {
                tracing::warn!(error = %e, path = %path.display(), "Failed to delete state file");
            } else {
                tracing::info!(path = %path.display(), "Deleted state file");
            }
        }
    }

    /// Get the current register_id
    pub async fn get_register_id(&self) -> Option<String> {
        self.register_id.read().await.clone()
    }

    async fn verify_register_id(&self, register_id: &str) -> Result<bool> {
        let mut client = self.get_client().await?;

        let request = tonic::Request::new(VerifyRequest {
            node_type: self.grpc_node_type(),
            register_id: register_id.to_string(),
        });

        let response = client
            .verify(request)
            .await
            .map_err(|e| anyhow!("gRPC verify request failed: {}", e))?;

        Ok(response.into_inner().result)
    }

    /// Fetch config from gRPC server
    pub async fn fetch_config(&self) -> Result<NodeConfigEnum> {
        let mut client = self.get_client().await?;

        let request = tonic::Request::new(ConfigRequest {
            node_id: self.config.node_id as i32,
            node_type: self.grpc_node_type(),
        });

        let response = client
            .config(request)
            .await
            .map_err(|e| anyhow!("gRPC config request failed: {}", e))?;

        let config_response: ConfigResponse = response.into_inner();

        if !config_response.result {
            return Err(anyhow!("Server returned failure for config request"));
        }

        let raw_data_str = String::from_utf8_lossy(&config_response.raw_data);
        tracing::debug!(raw_data = %raw_data_str, "Raw config data from server");

        let node_config =
            parse_raw_config_response(self.config.node_type, &config_response.raw_data).map_err(
                |e| anyhow!("Failed to parse config: {} - raw_data: {}", e, raw_data_str),
            )?;

        tracing::info!(
            node_id = self.config.node_id,
            node_type = %self.config.node_type,
            "Configuration fetched"
        );

        Ok(node_config)
    }

    async fn register_node(&self, hostname: String, port: u16) -> Result<String> {
        let mut client = self.get_client().await?;

        let request = tonic::Request::new(GrpcRegisterRequest {
            node_id: self.config.node_id as i32,
            node_type: self.grpc_node_type(),
            host_name: hostname,
            port: port.to_string(),
            ip: String::new(),
        });

        let response = client
            .register(request)
            .await
            .map_err(|e| anyhow!("gRPC register request failed: {}", e))?;

        Ok(response.into_inner().register_id)
    }

    /// Initialize node - try to verify existing registration or register new
    pub async fn initialize(&self, port: u16) -> Result<String> {
        tracing::info!("Panel service initializing...");

        if !self.config.data_dir.exists() {
            tracing::info!(path = %self.config.data_dir.display(), "Creating data directory");
            std::fs::create_dir_all(&self.config.data_dir).map_err(|e| {
                anyhow!(
                    "Failed to create data directory {:?}: {}",
                    self.config.data_dir,
                    e
                )
            })?;
        }

        let mut need_register = true;

        if let Some(state) = self.load_state() {
            if let Some(saved_register_id) = &state.register_id {
                tracing::info!(register_id = %saved_register_id, "Found saved register_id, verifying...");
                match self.verify_register_id(saved_register_id).await {
                    Ok(true) => {
                        tracing::info!(register_id = %saved_register_id, "Saved register_id is valid");
                        *self.register_id.write().await = Some(saved_register_id.clone());
                        need_register = false;
                    }
                    Ok(false) => {
                        tracing::warn!("Saved register_id is invalid, will re-register");
                        self.delete_state();
                    }
                    Err(e) => {
                        return Err(anyhow!("Failed to verify register_id: {}", e));
                    }
                }
            }
        }

        if need_register {
            let hostname = get_hostname();

            tracing::info!(
                node_id = self.config.node_id,
                hostname = %hostname,
                port = port,
                "Registering node"
            );

            let register_id = self
                .register_node(hostname, port)
                .await
                .map_err(|e| anyhow!("Failed to register node, cannot continue: {}", e))?;

            tracing::info!(register_id = %register_id, "Node registered successfully");

            *self.register_id.write().await = Some(register_id.clone());

            let state = PanelState {
                register_id: Some(register_id.clone()),
                node_id: Some(self.config.node_id),
                server_port: Some(port),
            };
            self.save_state(&state)?;

            return Ok(register_id);
        }

        let register_id = self.register_id.read().await.clone();
        Ok(register_id.expect("register_id should be set"))
    }

    /// Unregister the node from the panel
    pub async fn unregister(&self) -> Result<()> {
        let register_id = self.register_id.read().await.clone();

        if let Some(id) = register_id {
            tracing::info!(register_id = %id, "Unregistering node");

            let mut client = self.get_client().await?;

            let request = tonic::Request::new(UnregisterRequest {
                node_type: self.grpc_node_type(),
                register_id: id.clone(),
            });

            let response = client
                .unregister(request)
                .await
                .map_err(|e| anyhow!("gRPC unregister request failed: {}", e))?;

            if response.into_inner().result {
                tracing::info!("Node unregistered successfully");
                self.delete_state();
                *self.register_id.write().await = None;
            } else {
                tracing::warn!("Unregister failed: server returned false");
            }
        }

        Ok(())
    }

    /// Fetch users from gRPC server
    pub async fn fetch_users(&self) -> Result<Vec<User>> {
        let mut client = self.get_client().await?;

        let request = tonic::Request::new(UsersRequest {
            node_type: self.grpc_node_type(),
            node_id: self.config.node_id as i32,
        });

        let response = client
            .users(request)
            .await
            .map_err(|e| anyhow!("gRPC users request failed: {}", e))?;

        let users_response = response.into_inner();
        let raw_data_str = String::from_utf8_lossy(&users_response.raw_data);
        tracing::debug!(raw_data = %raw_data_str, "Raw users data from server");

        let users = unmarshal_users(&users_response.raw_data).map_err(|e| {
            anyhow!(
                "Failed to parse users response: {} - raw_data: {}",
                e,
                raw_data_str
            )
        })?;

        tracing::debug!(count = users.len(), "Users fetched");
        Ok(users)
    }

    /// Submit traffic data to panel
    pub async fn submit_traffic(&self, data: Vec<UserTraffic>) -> Result<()> {
        if data.is_empty() {
            tracing::debug!("No traffic to submit");
            return Ok(());
        }

        let register_id = self
            .register_id
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Not registered"))?;

        let count = data.len();

        let mut stats = TrafficStats::new();
        for traffic in &data {
            stats.add_user(traffic.user_id, traffic.n as i64);
        }

        let raw_data = serde_json::to_vec(&data)
            .map_err(|e| anyhow!("Failed to serialize traffic data: {}", e))?;
        let raw_stats = serde_json::to_vec(&stats)
            .map_err(|e| anyhow!("Failed to serialize traffic stats: {}", e))?;

        let mut client = self.get_client().await?;

        let request = tonic::Request::new(SubmitRequest {
            node_type: self.grpc_node_type(),
            register_id,
            raw_data,
            raw_stats,
        });

        let response = client
            .submit(request)
            .await
            .map_err(|e| anyhow!("gRPC submit request failed: {}", e))?;

        if response.into_inner().result {
            tracing::debug!(count = count, "Traffic submitted successfully");
            Ok(())
        } else {
            Err(anyhow!("Failed to submit traffic: server returned false"))
        }
    }

    /// Send heartbeat to panel
    pub async fn heartbeat(&self) -> Result<()> {
        let register_id = self
            .register_id
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Not registered"))?;

        let mut client = self.get_client().await?;

        let request = tonic::Request::new(HeartbeatRequest {
            node_type: self.grpc_node_type(),
            register_id,
        });

        let response = client
            .heartbeat(request)
            .await
            .map_err(|e| anyhow!("gRPC heartbeat request failed: {}", e))?;

        if response.into_inner().result {
            tracing::debug!("Heartbeat sent successfully");
            Ok(())
        } else {
            Err(anyhow!("Heartbeat failed: server returned false"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_panel_state_serialization() {
        let state = PanelState {
            register_id: Some("test-id".to_string()),
            node_id: Some(1),
            server_port: Some(443),
        };

        let json = serde_json::to_string(&state).unwrap();
        let parsed: PanelState = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.register_id, Some("test-id".to_string()));
        assert_eq!(parsed.node_id, Some(1));
        assert_eq!(parsed.server_port, Some(443));
    }

    #[test]
    fn test_node_type_to_grpc() {
        assert_eq!(node_type_to_grpc(NodeType::Trojan), GrpcNodeType::Trojan as i32);
        assert_eq!(node_type_to_grpc(NodeType::ShadowSocks), GrpcNodeType::Shadowsocks as i32);
        assert_eq!(node_type_to_grpc(NodeType::VMess), GrpcNodeType::Vmess as i32);
        assert_eq!(node_type_to_grpc(NodeType::Hysteria), GrpcNodeType::Hysteria as i32);
        assert_eq!(node_type_to_grpc(NodeType::Hysteria2), GrpcNodeType::Hysteria2 as i32);
        assert_eq!(node_type_to_grpc(NodeType::AnyTLS), GrpcNodeType::Anytls as i32);
        assert_eq!(node_type_to_grpc(NodeType::Tuic), GrpcNodeType::Tuic as i32);
    }
}
```

- [ ] **Step 2: Add client module to lib.rs**

Add to `server-r-panel/src/lib.rs` after the `mod user_manager;` line:

```rust
mod client;

pub use client::ApiManager;
```

- [ ] **Step 3: Run tests**

```bash
cd /Users/alex/code/rust/xflash-panda/server-r-panel && cargo test
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
cd /Users/alex/code/rust/xflash-panda/server-r-panel && git add -A && git commit -m "feat: add ApiManager with gRPC panel communication"
```

---

### Task 5: BackgroundTasks module

**Files:**
- Create: `server-r-panel/src/tasks.rs`
- Modify: `server-r-panel/src/lib.rs`

Key change: `fetch_users_once` calls `user_manager.update()` and invokes optional `on_user_diff` callback instead of direct kick logic.

- [ ] **Step 1: Create tasks.rs**

Create `server-r-panel/src/tasks.rs`:

```rust
//! Background tasks for periodic API operations

use server_r_client::UserTraffic;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{interval, MissedTickBehavior};

use crate::client::ApiManager;
use crate::stats::StatsCollector;
use crate::user_manager::{UserDiff, UserManager};

/// Number of worker threads for the dedicated background task runtime.
const BG_RUNTIME_WORKERS: usize = 2;

/// Format bytes into human-readable string (KB, MB, GB)
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2}KB", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

/// Background task configuration
#[derive(Debug, Clone)]
pub struct TaskConfig {
    /// Interval for fetching users
    pub fetch_users_interval: Duration,
    /// Interval for reporting traffic
    pub report_traffic_interval: Duration,
    /// Interval for sending heartbeat
    pub heartbeat_interval: Duration,
}

impl Default for TaskConfig {
    fn default() -> Self {
        Self {
            fetch_users_interval: Duration::from_secs(60),
            report_traffic_interval: Duration::from_secs(60),
            heartbeat_interval: Duration::from_secs(60),
        }
    }
}

impl TaskConfig {
    /// Create task config from durations
    pub fn new(fetch_users: Duration, report_traffic: Duration, heartbeat: Duration) -> Self {
        Self {
            fetch_users_interval: fetch_users,
            report_traffic_interval: report_traffic,
            heartbeat_interval: heartbeat,
        }
    }
}

/// Callback type for user diff notifications
type UserDiffCallback = Arc<dyn Fn(UserDiff) + Send + Sync>;

/// Background tasks manager
pub struct BackgroundTasks {
    config: TaskConfig,
    api_manager: Arc<ApiManager>,
    user_manager: Arc<UserManager>,
    stats_collector: Arc<StatsCollector>,
    on_user_diff: Option<UserDiffCallback>,
    shutdown_rx: watch::Receiver<bool>,
    shutdown_tx: watch::Sender<bool>,
}

/// Handle for running background tasks with graceful shutdown support
pub struct BackgroundTasksHandle {
    shutdown_tx: watch::Sender<bool>,
    handles: Vec<JoinHandle<()>>,
    _runtime: tokio::runtime::Runtime,
}

impl BackgroundTasksHandle {
    /// Gracefully shutdown all background tasks
    pub async fn shutdown(self) {
        tracing::info!("Stopping background tasks...");
        let BackgroundTasksHandle {
            shutdown_tx,
            handles,
            _runtime: runtime,
        } = self;
        let _ = shutdown_tx.send(true);

        for (i, handle) in handles.into_iter().enumerate() {
            match tokio::time::timeout(Duration::from_secs(5), handle).await {
                Ok(Ok(())) => tracing::debug!(task = i, "Background task stopped"),
                Ok(Err(e)) => tracing::warn!(task = i, error = %e, "Background task panicked"),
                Err(_) => tracing::warn!(task = i, "Background task shutdown timeout"),
            }
        }

        runtime.shutdown_background();

        tracing::info!("Background tasks stopped");
    }
}

impl BackgroundTasks {
    /// Create a new background tasks manager
    pub fn new(
        config: TaskConfig,
        api_manager: Arc<ApiManager>,
        user_manager: Arc<UserManager>,
        stats_collector: Arc<StatsCollector>,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            config,
            api_manager,
            user_manager,
            stats_collector,
            on_user_diff: None,
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Set optional callback invoked after each user diff (e.g., for kicking connections)
    pub fn on_user_diff(mut self, f: Arc<dyn Fn(UserDiff) + Send + Sync>) -> Self {
        self.on_user_diff = Some(f);
        self
    }

    /// Start all background tasks and return a handle for shutdown
    pub fn start(self) -> BackgroundTasksHandle {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(BG_RUNTIME_WORKERS)
            .thread_name("api-bg")
            .enable_all()
            .build()
            .expect("Failed to create background task runtime");

        let rt_handle = runtime.handle();
        let handles = vec![
            self.start_fetch_users_task(rt_handle),
            self.start_report_traffic_task(rt_handle),
            self.start_heartbeat_task(rt_handle),
        ];
        tracing::info!("Background tasks started on dedicated runtime");

        BackgroundTasksHandle {
            shutdown_tx: self.shutdown_tx,
            handles,
            _runtime: runtime,
        }
    }

    fn start_fetch_users_task(&self, rt: &tokio::runtime::Handle) -> JoinHandle<()> {
        let api_manager = Arc::clone(&self.api_manager);
        let user_manager = Arc::clone(&self.user_manager);
        let on_diff = self.on_user_diff.clone();
        let interval_duration = self.config.fetch_users_interval;
        let mut shutdown_rx = self.shutdown_rx.clone();

        rt.spawn(async move {
            let mut interval = interval(interval_duration);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        match fetch_users_once(&api_manager, &user_manager, &on_diff).await {
                            Ok(()) => {}
                            Err(e) => {
                                tracing::debug!(error = %e, "Fetch users tick skipped");
                                api_manager.reset_client().await;
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        tracing::debug!("Fetch users task shutting down");
                        break;
                    }
                }
            }
        })
    }

    fn start_report_traffic_task(&self, rt: &tokio::runtime::Handle) -> JoinHandle<()> {
        let api_manager = Arc::clone(&self.api_manager);
        let stats_collector = Arc::clone(&self.stats_collector);
        let interval_duration = self.config.report_traffic_interval;
        let mut shutdown_rx = self.shutdown_rx.clone();

        rt.spawn(async move {
            let mut interval = interval(interval_duration);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = report_traffic_once(&api_manager, &stats_collector).await {
                            tracing::warn!(error = %e, "Failed to report traffic");
                            api_manager.reset_client().await;
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        tracing::debug!("Report traffic task shutting down");
                        if let Err(e) = report_traffic_once(&api_manager, &stats_collector).await {
                            tracing::warn!(error = %e, "Failed to report final traffic");
                        }
                        break;
                    }
                }
            }
        })
    }

    fn start_heartbeat_task(&self, rt: &tokio::runtime::Handle) -> JoinHandle<()> {
        let api_manager = Arc::clone(&self.api_manager);
        let interval_duration = self.config.heartbeat_interval;
        let mut shutdown_rx = self.shutdown_rx.clone();

        rt.spawn(async move {
            let mut interval = interval(interval_duration);
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        match api_manager.heartbeat().await {
                            Ok(()) => tracing::info!("Heartbeat sent"),
                            Err(e) => {
                                tracing::warn!(error = %e, "Failed to send heartbeat");
                                api_manager.reset_client().await;
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        tracing::debug!("Heartbeat task shutting down");
                        break;
                    }
                }
            }
        })
    }
}

/// Fetch users once and update user manager
async fn fetch_users_once(
    api_manager: &ApiManager,
    user_manager: &UserManager,
    on_diff: &Option<UserDiffCallback>,
) -> anyhow::Result<()> {
    let users = api_manager.fetch_users().await?;
    let total = users.len();
    let diff = user_manager.update(&users);

    tracing::info!(
        total = total,
        added = diff.added,
        removed = diff.removed,
        uuid_changed = diff.uuid_changed,
        "Users synchronized"
    );

    // Notify consumer (e.g., for kicking connections)
    if let Some(callback) = on_diff {
        if diff.removed > 0 || diff.uuid_changed > 0 {
            callback(diff);
        }
    }

    Ok(())
}

/// Report traffic once
async fn report_traffic_once(
    api_manager: &ApiManager,
    stats_collector: &StatsCollector,
) -> anyhow::Result<()> {
    let snapshots = stats_collector.reset_all();

    if snapshots.is_empty() {
        return Ok(());
    }

    let traffic_data: Vec<UserTraffic> = snapshots
        .into_iter()
        .filter(|s| s.upload_bytes > 0 || s.download_bytes > 0)
        .map(|s| {
            UserTraffic::with_count(s.user_id, s.upload_bytes, s.download_bytes, s.request_count)
        })
        .collect();

    if traffic_data.is_empty() {
        return Ok(());
    }

    let count = traffic_data.len();
    let total_upload: u64 = traffic_data.iter().map(|t| t.u).sum();
    let total_download: u64 = traffic_data.iter().map(|t| t.d).sum();
    api_manager.submit_traffic(traffic_data).await?;
    tracing::info!(
        users = count,
        upload = %format_bytes(total_upload),
        download = %format_bytes(total_download),
        "Traffic reported"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_config_default() {
        let config = TaskConfig::default();
        assert_eq!(config.fetch_users_interval, Duration::from_secs(60));
        assert_eq!(config.report_traffic_interval, Duration::from_secs(60));
        assert_eq!(config.heartbeat_interval, Duration::from_secs(60));
    }

    #[test]
    fn test_task_config_new() {
        let config = TaskConfig::new(
            Duration::from_secs(30),
            Duration::from_secs(45),
            Duration::from_secs(120),
        );
        assert_eq!(config.fetch_users_interval, Duration::from_secs(30));
        assert_eq!(config.report_traffic_interval, Duration::from_secs(45));
        assert_eq!(config.heartbeat_interval, Duration::from_secs(120));
    }

    #[test]
    fn test_task_config_clone() {
        let config = TaskConfig::new(
            Duration::from_secs(10),
            Duration::from_secs(20),
            Duration::from_secs(30),
        );
        let cloned = config.clone();
        assert_eq!(cloned.fetch_users_interval, config.fetch_users_interval);
        assert_eq!(
            cloned.report_traffic_interval,
            config.report_traffic_interval
        );
        assert_eq!(cloned.heartbeat_interval, config.heartbeat_interval);
    }

    const _: () = assert!(BG_RUNTIME_WORKERS >= 1);
    const _: () = assert!(BG_RUNTIME_WORKERS <= 4);

    #[test]
    fn test_dedicated_runtime_creates_successfully() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(BG_RUNTIME_WORKERS)
            .thread_name("test-bg")
            .enable_all()
            .build()
            .expect("Failed to create background task runtime");

        let result = runtime.block_on(async {
            let handle = tokio::spawn(async { 42 });
            handle.await.unwrap()
        });
        assert_eq!(result, 42);
    }

    #[test]
    fn test_dedicated_runtime_tasks_complete_independently() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let bg_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(BG_RUNTIME_WORKERS)
            .thread_name("test-bg")
            .enable_all()
            .build()
            .unwrap();

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        bg_runtime.block_on(async move {
            let handle = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                counter_clone.fetch_add(1, Ordering::Relaxed);
            });
            handle.await.unwrap();
        });

        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_shutdown_does_not_panic_when_tasks_timeout() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("test-bg")
            .enable_all()
            .build()
            .unwrap();

        let handle = runtime.spawn(async {
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });

        let (shutdown_tx, _) = watch::channel(false);

        let bg_handle = BackgroundTasksHandle {
            shutdown_tx,
            handles: vec![handle],
            _runtime: runtime,
        };

        bg_handle.shutdown().await;
    }

    #[test]
    fn test_dedicated_runtime_isolated_from_other_runtime() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let main_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("test-main")
            .enable_all()
            .build()
            .unwrap();

        let bg_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("test-bg")
            .enable_all()
            .build()
            .unwrap();

        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = Arc::clone(&completed);

        let bg_handle = bg_runtime.spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            completed_clone.store(true, Ordering::Relaxed);
        });

        main_runtime.block_on(async {
            let mut flood = vec![];
            for _ in 0..200 {
                flood.push(tokio::spawn(async {
                    tokio::task::yield_now().await;
                }));
            }
            for h in flood {
                let _ = h.await;
            }
        });

        bg_runtime.block_on(async { bg_handle.await.unwrap() });
        assert!(completed.load(Ordering::Relaxed));
    }

    #[tokio::test(start_paused = true)]
    async fn test_unregister_completes_before_bg_shutdown() {
        use std::sync::atomic::{AtomicU8, Ordering};
        use tokio::time::Instant;

        let order = Arc::new(AtomicU8::new(0));
        let unregister_order = Arc::new(AtomicU8::new(0));
        let bg_shutdown_order = Arc::new(AtomicU8::new(0));

        let seq = Arc::clone(&order);
        let unreg_ord = Arc::clone(&unregister_order);

        tokio::time::sleep(Duration::from_millis(100)).await;
        let n = seq.fetch_add(1, Ordering::SeqCst) + 1;
        unreg_ord.store(n, Ordering::SeqCst);

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("test-bg")
            .enable_all()
            .build()
            .unwrap();

        let handle = runtime.spawn(async {
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });

        let (shutdown_tx, _) = watch::channel(false);
        let bg_handle = BackgroundTasksHandle {
            shutdown_tx,
            handles: vec![handle],
            _runtime: runtime,
        };

        let seq = Arc::clone(&order);
        let bg_ord = Arc::clone(&bg_shutdown_order);

        let before_bg = Instant::now();
        bg_handle.shutdown().await;
        let bg_elapsed = before_bg.elapsed();
        let n = seq.fetch_add(1, Ordering::SeqCst) + 1;
        bg_ord.store(n, Ordering::SeqCst);

        assert_eq!(
            unregister_order.load(Ordering::SeqCst),
            1,
            "unregister must execute first"
        );
        assert_eq!(
            bg_shutdown_order.load(Ordering::SeqCst),
            2,
            "bg shutdown must execute second"
        );

        assert!(
            bg_elapsed >= Duration::from_secs(5),
            "bg shutdown should have waited for timeout, elapsed: {:?}",
            bg_elapsed
        );
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0B");
        assert_eq!(format_bytes(512), "512B");
        assert_eq!(format_bytes(1024), "1.00KB");
        assert_eq!(format_bytes(1536), "1.50KB");
        assert_eq!(format_bytes(1048576), "1.00MB");
        assert_eq!(format_bytes(1073741824), "1.00GB");
    }
}
```

- [ ] **Step 2: Add tasks module to lib.rs**

Add to `server-r-panel/src/lib.rs` after the `mod client;` line:

```rust
mod tasks;

pub use tasks::{BackgroundTasks, BackgroundTasksHandle, TaskConfig};
```

- [ ] **Step 3: Run tests**

```bash
cd /Users/alex/code/rust/xflash-panda/server-r-panel && cargo test
```

Expected: all tests pass.

- [ ] **Step 4: Run clippy**

```bash
cd /Users/alex/code/rust/xflash-panda/server-r-panel && cargo clippy -- -D warnings
```

Expected: no warnings.

- [ ] **Step 5: Commit**

```bash
cd /Users/alex/code/rust/xflash-panda/server-r-panel && git add -A && git commit -m "feat: add BackgroundTasks with periodic fetch/report/heartbeat"
```

---

### Task 6: Final lib.rs cleanup and crate verification

**Files:**
- Modify: `server-r-panel/src/lib.rs`

- [ ] **Step 1: Verify final lib.rs looks correct**

The complete `server-r-panel/src/lib.rs` should be:

```rust
//! # server-r-panel
//!
//! Reusable panel integration library for xflash-panda proxy servers.
//!
//! Provides protocol-agnostic panel communication, user management,
//! traffic statistics collection, and background task orchestration.

mod config;
mod stats;
mod user_manager;
mod client;
mod tasks;

pub use config::PanelConfig;
pub use stats::{StatsCollector, UserStatsSnapshot};
pub use user_manager::{UserManager, UserDiff};
pub use client::ApiManager;
pub use tasks::{BackgroundTasks, BackgroundTasksHandle, TaskConfig};

// Re-export common types from server-r-client
pub use server_r_client::{
    NodeType, NodeConfigEnum, User, UserTraffic, TrafficStats,
    unmarshal_users, parse_raw_config_response,
};

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

/// Convert password (UUID) to 56-byte hex via SHA224
pub fn password_to_hex(password: &str) -> [u8; 56] {
    let hash = hash_password(password);
    let hex_string = hex::encode(hash);
    let mut hex_bytes: [u8; 56] = [0u8; 56];
    hex_bytes.copy_from_slice(hex_string.as_bytes());
    hex_bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_to_hex_deterministic() {
        let hex1 = password_to_hex("test-uuid");
        let hex2 = password_to_hex("test-uuid");
        assert_eq!(hex1, hex2);
    }

    #[test]
    fn test_password_to_hex_different_inputs() {
        let hex1 = password_to_hex("uuid-1");
        let hex2 = password_to_hex("uuid-2");
        assert_ne!(hex1, hex2);
    }

    #[test]
    fn test_password_to_hex_length() {
        let hex = password_to_hex("any-password");
        assert_eq!(hex.len(), 56);
        for &b in &hex {
            assert!(b.is_ascii_hexdigit());
        }
    }
}
```

- [ ] **Step 2: Run full test suite**

```bash
cd /Users/alex/code/rust/xflash-panda/server-r-panel && cargo test
```

Expected: all tests pass.

- [ ] **Step 3: Run clippy + fmt**

```bash
cd /Users/alex/code/rust/xflash-panda/server-r-panel && cargo fmt --check && cargo clippy -- -D warnings
```

Expected: no issues.

- [ ] **Step 4: Commit if any changes**

```bash
cd /Users/alex/code/rust/xflash-panda/server-r-panel && git add -A && git diff --cached --quiet || git commit -m "chore: finalize lib.rs exports"
```

---

### Task 7: Update server-trojan-rs Cargo.toml

**Files:**
- Modify: `server-trojan-rs/Cargo.toml`

- [ ] **Step 1: Update dependencies**

In `server-trojan-rs/Cargo.toml`, make these changes:

Remove these lines:
```toml
server-r-agent-proto = { git = "https://github.com/xflash-panda/server-r-agent-proto.git", tag = "v0.1.2" }
hostname = "0.4"
```

Note: keep `scopeguard` (still used by handler.rs, core/connection.rs, transport/grpc), keep `tonic` (still used by transport/grpc.rs), keep `arc-swap` (used by newtype wrapper), keep `dashmap` (used by connection.rs).

Add this line (after `server-r-client`):
```toml
server-r-panel = { path = "../server-r-panel" }
```

Note: using `path` for local development. Switch to `git` when publishing.

- [ ] **Step 2: Verify cargo check**

```bash
cd /Users/alex/code/rust/xflash-panda/server-trojan-rs && cargo check 2>&1 | head -30
```

Expected: compilation errors about missing `business::` types — this is expected, we fix them in the next task.

- [ ] **Step 3: Commit**

```bash
cd /Users/alex/code/rust/xflash-panda/server-trojan-rs && git add Cargo.toml Cargo.lock && git commit -m "chore: add server-r-panel dependency, remove server-r-agent-proto"
```

---

### Task 8: Replace business/ module in server-trojan-rs

**Files:**
- Rewrite: `server-trojan-rs/src/business/mod.rs`
- Delete: `server-trojan-rs/src/business/api/` (entire directory)
- Delete: `server-trojan-rs/src/business/auth.rs`
- Delete: `server-trojan-rs/src/business/stats.rs`

- [ ] **Step 1: Delete old business files**

```bash
rm -rf /Users/alex/code/rust/xflash-panda/server-trojan-rs/src/business/api
rm /Users/alex/code/rust/xflash-panda/server-trojan-rs/src/business/auth.rs
rm /Users/alex/code/rust/xflash-panda/server-trojan-rs/src/business/stats.rs
```

- [ ] **Step 2: Rewrite business/mod.rs with thin wrappers**

Replace `server-trojan-rs/src/business/mod.rs` with:

```rust
//! Business logic bridge
//!
//! Thin newtype wrappers that bridge `server_r_panel` types
//! to the core hook traits (`Authenticator`, `StatsCollector`).

use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::Arc;

use crate::core::hooks::{Authenticator, StatsCollector};
use crate::core::UserId;

// Re-export panel types for convenience
pub use server_r_panel::{
    ApiManager, BackgroundTasks, BackgroundTasksHandle, PanelConfig, StatsCollector as PanelStatsCollector,
    TaskConfig, UserDiff, UserManager,
};

/// Bridge: panel StatsCollector → core::hooks::StatsCollector
pub struct TrojanStatsCollector(pub Arc<PanelStatsCollector>);

impl StatsCollector for TrojanStatsCollector {
    fn record_request(&self, user_id: UserId) {
        self.0.record_request(user_id);
    }

    fn record_upload(&self, user_id: UserId, bytes: u64) {
        self.0.record_upload(user_id, bytes);
    }

    fn record_download(&self, user_id: UserId, bytes: u64) {
        self.0.record_download(user_id, bytes);
    }
}

/// Bridge: ArcSwap user map → core::hooks::Authenticator
pub struct TrojanAuthenticator {
    users: Arc<ArcSwap<HashMap<[u8; 56], UserId>>>,
}

impl TrojanAuthenticator {
    pub fn new(users: Arc<ArcSwap<HashMap<[u8; 56], UserId>>>) -> Self {
        Self { users }
    }
}

impl Authenticator for TrojanAuthenticator {
    fn authenticate(&self, password: &[u8; 56]) -> Option<UserId> {
        self.users.load().get(password).copied()
    }
}
```

- [ ] **Step 3: Verify cargo check**

```bash
cd /Users/alex/code/rust/xflash-panda/server-trojan-rs && cargo check 2>&1 | head -30
```

Expected: errors in `main.rs` and `config.rs` about removed types — fixed in next task.

- [ ] **Step 4: Commit**

```bash
cd /Users/alex/code/rust/xflash-panda/server-trojan-rs && git add src/business/ && git commit -m "refactor: replace business/ with thin panel wrappers"
```

---

### Task 9: Update config.rs and main.rs in server-trojan-rs

**Files:**
- Modify: `server-trojan-rs/src/config.rs`
- Modify: `server-trojan-rs/src/main.rs`

- [ ] **Step 1: Update config.rs**

In `server-trojan-rs/src/config.rs`:

Remove the `User` struct and its `From` impl (lines 239-255):
```rust
// DELETE these lines:
/// User configuration with id for tracking and uuid for authentication
#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub uuid: String,
}

impl From<server_r_client::User> for User {
    fn from(u: server_r_client::User) -> Self {
        Self {
            id: u.id,
            uuid: u.uuid,
        }
    }
}
```

In `ServerConfig::from_remote`, change the parameter type from `&server_r_client::TrojanConfig` to `&server_r_panel::TrojanConfig` — actually both come from `server_r_client` which is re-exported. No change needed since we keep the `server-r-client` direct dependency.

Update the test `test_user_from_remote` (remove it since `User` no longer exists locally) and `test_user_clone` (remove it too).

- [ ] **Step 2: Update main.rs**

Replace `server-trojan-rs/src/main.rs` with:

```rust
//! Trojan proxy server with layered architecture
//!
//! Architecture:
//! - `core/`: Core proxy logic with hook traits for extensibility
//! - `transport/`: Transport layer abstraction (TCP, WebSocket, gRPC)
//! - `business/`: Thin bridge wrappers to panel crate
//! - `handler`: Connection processing logic
//! - `server_runner`: Server startup and accept loop

mod acl;
mod business;
mod config;
mod core;
mod error;
mod handler;
mod logger;
mod server_runner;
mod transport;

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use logger::log;

use anyhow::Result;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::business::{
    ApiManager, BackgroundTasks, PanelConfig, PanelStatsCollector, TaskConfig,
    TrojanAuthenticator, TrojanStatsCollector, UserManager,
};
use crate::core::{ConnectionManager, Server};

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = config::CliArgs::parse_args();
    cli.validate()?;

    logger::init_logger(&cli.log_mode);

    log::info!(
        node = cli.node,
        "Starting Trojan server with layered architecture"
    );

    // Create connection manager
    let conn_manager = ConnectionManager::new();

    // Create panel config
    let panel_config = PanelConfig {
        server_host: cli.server_host.clone(),
        server_port: cli.port,
        node_id: cli.node,
        node_type: server_r_panel::NodeType::Trojan,
        data_dir: cli.data_dir.clone(),
        api_timeout: cli.api_timeout,
    };

    // Create API manager
    let api_manager = Arc::new(ApiManager::new(panel_config)?);

    // Create user manager
    let user_manager = Arc::new(UserManager::new());

    // Fetch configuration from remote panel
    let node_config_enum = api_manager.fetch_config().await?;
    let remote_config = node_config_enum
        .as_trojan()
        .map_err(|e| anyhow::anyhow!("Expected Trojan config: {}", e))?;

    // Initialize node with port from config
    let register_id = api_manager.initialize(remote_config.server_port).await?;
    log::info!(register_id = %register_id, "Node initialized");

    // Fetch initial users
    let users = api_manager.fetch_users().await?;
    user_manager.init(&users);

    // Build server config
    let server_config = config::ServerConfig::from_remote(remote_config, &cli)?;

    // Create authenticator using shared user map
    let authenticator = Arc::new(TrojanAuthenticator::new(user_manager.get_users_arc()));

    // Create stats collector (panel + bridge)
    let panel_stats = Arc::new(PanelStatsCollector::new());
    let stats_collector = Arc::new(TrojanStatsCollector(Arc::clone(&panel_stats)));

    // Build router from ACL config
    let router = server_runner::build_router(&server_config, cli.refresh_geodata).await?;

    // Build connection config from CLI args
    let conn_config = config::ConnConfig::from_cli(&cli);

    // Clone conn_manager before moving into Server
    let conn_manager_for_shutdown = conn_manager.clone();

    // Build server
    let server = Arc::new(
        Server::builder()
            .authenticator(authenticator)
            .stats(stats_collector as Arc<dyn core::hooks::StatsCollector>)
            .router(router)
            .conn_manager(conn_manager)
            .conn_config(conn_config)
            .build(),
    );

    // User diff callback for kicking connections
    let conn_mgr_for_kick = conn_manager_for_shutdown.clone();
    let on_user_diff = Arc::new(move |diff: server_r_panel::UserDiff| {
        let mut kicked = 0usize;
        for uid in diff.removed_ids.iter().chain(diff.uuid_changed_ids.iter()) {
            kicked += conn_mgr_for_kick.kick_user(*uid);
        }
        if kicked > 0 {
            log::info!(kicked = kicked, "Users kicked on diff");
        }
    });

    // Start background tasks
    let task_config = TaskConfig::new(
        cli.fetch_users_interval,
        cli.report_traffics_interval,
        cli.heartbeat_interval,
    );
    let background_tasks = BackgroundTasks::new(
        task_config,
        Arc::clone(&api_manager),
        Arc::clone(&user_manager),
        Arc::clone(&panel_stats),
    )
    .on_user_diff(on_user_diff);
    let background_handle = background_tasks.start();

    // Create cancellation token for graceful shutdown
    let cancel_token = CancellationToken::new();
    let cancel_token_clone = cancel_token.clone();

    // Setup shutdown handler
    let api_for_shutdown = Arc::clone(&api_manager);
    let shutdown_handle = tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigint = signal(SignalKind::interrupt()).expect("Failed to setup SIGINT");
            let mut sigterm = signal(SignalKind::terminate()).expect("Failed to setup SIGTERM");

            tokio::select! {
                _ = sigint.recv() => {
                    log::info!("SIGINT received, shutting down...");
                }
                _ = sigterm.recv() => {
                    log::info!("SIGTERM received, shutting down...");
                }
                _ = cancel_token_clone.cancelled() => {}
            }
        }

        #[cfg(not(unix))]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    log::info!("Shutdown signal received...");
                }
                _ = cancel_token_clone.cancelled() => {}
            }
        }

        cancel_token_clone.cancel();
        api_for_shutdown
    });

    // Run server
    let server_result = tokio::select! {
        result = server_runner::run_server(server, &server_config) => result,
        _ = cancel_token.cancelled() => Ok(()),
    };

    cancel_token.cancel();

    // Graceful shutdown sequence
    log::info!("Server stopped, performing graceful shutdown...");

    let cancelled = conn_manager_for_shutdown.cancel_all();
    if cancelled > 0 {
        log::info!("Cancelled {cancelled} connections, draining...");
        let drain_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let remaining = conn_manager_for_shutdown.connection_count();
            if remaining == 0 {
                log::info!("All connections drained");
                break;
            }
            if tokio::time::Instant::now() >= drain_deadline {
                log::warn!("{remaining} connections remaining after drain timeout");
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    if let Ok(api_for_shutdown) = shutdown_handle.await {
        log::info!("Unregistering node...");
        if let Err(e) = api_for_shutdown.unregister().await {
            log::warn!(error = %e, "Failed to unregister node");
        } else {
            log::info!("Node unregistered successfully");
        }

        background_handle.shutdown().await;
    }

    log::info!("Shutdown complete");
    server_result
}
```

- [ ] **Step 3: Verify cargo check**

```bash
cd /Users/alex/code/rust/xflash-panda/server-trojan-rs && cargo check
```

Expected: compiles successfully.

- [ ] **Step 4: Commit**

```bash
cd /Users/alex/code/rust/xflash-panda/server-trojan-rs && git add src/config.rs src/main.rs && git commit -m "refactor: rewire main.rs and config.rs to use server-r-panel"
```

---

### Task 10: Verify everything passes

**Files:** None (verification only)

- [ ] **Step 1: Run server-r-panel tests**

```bash
cd /Users/alex/code/rust/xflash-panda/server-r-panel && cargo test
```

Expected: all tests pass.

- [ ] **Step 2: Run server-trojan-rs fmt + clippy**

```bash
cd /Users/alex/code/rust/xflash-panda/server-trojan-rs && cargo fmt --check && cargo clippy -- -D warnings
```

Expected: no issues. Fix any warnings that appear.

- [ ] **Step 3: Run server-trojan-rs full test suite**

```bash
cd /Users/alex/code/rust/xflash-panda/server-trojan-rs && cargo test
```

Expected: all tests pass. Some tests that referenced old `business::` types may need minor fixes — specifically the `UserManager` tests that asserted kick counts now need to be removed (they moved to the panel crate with different assertions).

If config.rs tests referencing `User` struct fail, remove `test_user_from_remote` and `test_user_clone` tests.

- [ ] **Step 4: Final commit**

```bash
cd /Users/alex/code/rust/xflash-panda/server-trojan-rs && cargo fmt && git add -A && git commit -m "refactor: complete server-r-panel extraction"
```
