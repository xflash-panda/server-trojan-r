# server-panel-rs Extraction Design

## Goal

Extract panel-related business logic from `server-trojan-rs` into a standalone reusable crate `server-panel-rs`, so that all proxy server implementations (Trojan, TUIC, etc.) can share the same panel integration code.

## Architecture

`server-panel-rs` is a protocol-agnostic business library providing four core capabilities: panel communication (gRPC), user management (hot-reload with diff), traffic statistics collection (lock-free), and background task orchestration (dedicated runtime). It defines NO protocol-specific traits — consumers bridge via newtype wrappers.

## Tech Stack

- Rust, tokio (async runtime), tonic (gRPC)
- arc-swap, dashmap (concurrent data structures)
- sha2, hex (password hashing)
- tracing (logging)

---

## Module Structure

```
server-panel-rs/
├── Cargo.toml
└── src/
    ├── lib.rs            # Public exports + password_to_hex()
    ├── client.rs         # ApiManager — gRPC panel communication
    ├── user_manager.rs   # UserManager — user storage + hot-reload + diff
    ├── stats.rs          # StatsCollector — lock-free traffic statistics
    ├── tasks.rs          # BackgroundTasks — periodic task orchestration
    └── types.rs          # User, UserTraffic, TrafficStats, PanelConfig
```

## Module Responsibilities

### `types.rs` — Shared Types

Public types used across the crate and by consumers:

- `User { id: i64, uuid: String }` — user identity
- `UserTraffic { user_id: i64, u: u64, d: u64, n: u64 }` — traffic submission payload
- `TrafficStats { count, requests, user_ids, user_requests }` — aggregated stats for gRPC submission
- `PanelConfig { server_host, server_port, node_id, node_type, data_dir, api_timeout }` — panel connection configuration. `node_type` is `NodeType` from `server-r-client`, making the crate protocol-agnostic (Trojan, TUIC, etc.)

### `client.rs` — ApiManager

gRPC client for panel communication. Moved from `business/api/client.rs` with these changes:

- Constructor takes `PanelConfig` instead of `CliArgs`
- `NodeType` comes from `PanelConfig.node_type` instead of hardcoded `NodeType::Trojan`
- `fetch_config()` returns `NodeConfigEnum` (enum from `server-r-client`) instead of `TrojanConfig` — consumers call `.as_trojan()` / `.as_tuic()` themselves
- Logging uses `tracing` macros directly instead of `crate::logger::log`
- `PanelState`, state file management, gRPC channel config — all move as-is
- `UserTraffic`, `TrafficStats` move to `types.rs`, imported here

Public API:

```rust
impl ApiManager {
    pub fn new(config: PanelConfig) -> Result<Self>
    pub async fn initialize(&self, port: u16) -> Result<String>
    pub async fn fetch_config(&self) -> Result<NodeConfigEnum>
    pub async fn fetch_users(&self) -> Result<Vec<User>>
    pub async fn submit_traffic(&self, data: Vec<UserTraffic>) -> Result<()>
    pub async fn heartbeat(&self) -> Result<()>
    pub async fn unregister(&self) -> Result<()>
    pub async fn reset_client(&self)
}
```

### `user_manager.rs` — UserManager

User table with ArcSwap hot-reload. Moved from `business/api/user_manager.rs` with this key change:

- **No longer handles kick logic.** `update()` returns a `UserDiff` struct instead of `(added, removed, uuid_changed, kicked)` tuple.
- Consumers use the diff to handle kick logic themselves.
- Still depends on `password_to_hex()` from `lib.rs`.
- `User` type comes from `types.rs` (crate-local), not from `crate::config`.

```rust
pub struct UserDiff {
    pub added: usize,
    pub removed: usize,
    pub uuid_changed: usize,
    /// User IDs that were removed (consumers should kick these)
    pub removed_ids: Vec<i64>,
    /// User IDs whose UUID changed (consumers should kick these)
    pub uuid_changed_ids: Vec<i64>,
}

impl UserManager {
    pub fn new() -> Self
    pub fn init(&self, users: &[User])
    pub fn update(&self, new_users: &[User]) -> UserDiff
    pub fn get_users_arc(&self) -> Arc<ArcSwap<HashMap<[u8; 56], i64>>>
    pub fn user_count(&self) -> usize
}
```

### `stats.rs` — StatsCollector

Lock-free traffic statistics using DashMap + AtomicU64. Moved from `business/stats.rs` with minimal changes:

- Renamed from `ApiStatsCollector` to `StatsCollector` (the "Api" prefix is redundant in a panel crate)
- Does NOT implement any external trait — consumers bridge via newtype
- `UserId` is just `i64` directly, no type alias dependency on core

```rust
impl StatsCollector {
    pub fn new() -> Self
    pub fn record_request(&self, user_id: i64)
    pub fn record_upload(&self, user_id: i64, bytes: u64)
    pub fn record_download(&self, user_id: i64, bytes: u64)
    pub fn reset_all(&self) -> Vec<UserStatsSnapshot>
    pub fn get_stats(&self, user_id: i64) -> Option<UserStatsSnapshot>
}

pub struct UserStatsSnapshot {
    pub user_id: i64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub request_count: u64,
}
```

### `tasks.rs` — BackgroundTasks

Periodic task orchestration on a dedicated tokio runtime. Moved from `business/api/tasks.rs` with these changes:

- References updated to crate-local types (`StatsCollector`, `ApiManager`, `UserManager`)
- `fetch_users_once` calls `user_manager.update()` and logs the `UserDiff` — no kick logic
- `report_traffic_once` unchanged (calls `stats.reset_all()` → convert to `UserTraffic` → `api.submit_traffic()`)
- `format_bytes` helper moves here as-is

```rust
impl BackgroundTasks {
    pub fn new(
        config: TaskConfig,
        api_manager: Arc<ApiManager>,
        user_manager: Arc<UserManager>,
        stats_collector: Arc<StatsCollector>,
    ) -> Self
    /// Optional callback invoked after each user diff (e.g., for kicking connections)
    pub fn on_user_diff(self, f: Arc<dyn Fn(UserDiff) + Send + Sync>) -> Self
    pub fn start(self) -> BackgroundTasksHandle
}

impl BackgroundTasksHandle {
    pub async fn shutdown(self)
}
```

**Consumer note:** `BackgroundTasks` handles user fetching + diff logging, but does NOT kick connections. If consumers need to kick users on diff, they should run their own periodic task or hook into a callback. However, for the common case (periodic fetch), the diff is logged but kick is not performed — this is acceptable because kicks are mainly needed for immediate security response, and a 60s delay is tolerable.

Alternative: `BackgroundTasks::new()` could accept an optional `on_user_diff: Option<Arc<dyn Fn(UserDiff) + Send + Sync>>` callback. This allows consumers to react to diffs without running their own fetch loop. This is the recommended approach.

### `lib.rs` — Public Exports

```rust
pub mod types;
mod client;
mod user_manager;
mod stats;
mod tasks;

pub use types::*;
pub use client::ApiManager;
pub use user_manager::{UserManager, UserDiff};
pub use stats::{StatsCollector, UserStatsSnapshot};
pub use tasks::{BackgroundTasks, BackgroundTasksHandle, TaskConfig};

// Re-export NodeType from server-r-client for convenience
pub use server_r_client::models::NodeType;

/// Convert password (UUID) to 56-byte hex via SHA224
pub fn password_to_hex(password: &str) -> [u8; 56] { ... }
```

## Dependencies

```toml
[dependencies]
server-r-agent-proto = { git = "...", tag = "v0.1.2" }
server-r-client = { git = "...", tag = "v0.1.8" }
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

## Consumer Integration Pattern (server-trojan-rs)

### Cargo.toml change

```toml
# Remove direct deps that are now in server-panel-rs:
# - server-r-agent-proto (used only by ApiManager)
# - hostname (used only by ApiManager)
# - scopeguard (used only by StatsCollector)

# Add:
server-panel-rs = { git = "...", tag = "v0.1.0" }
# Keep server-r-client (still needed for TrojanConfig, WebSocketConfig, etc.)
```

### business/ module replacement

The entire `business/` module is replaced with thin wrappers:

```rust
// src/business/mod.rs (simplified)
use server_panel_rs as panel;

// Newtype: bridge panel::StatsCollector → core::hooks::StatsCollector
pub struct TrojanStatsCollector(pub Arc<panel::StatsCollector>);

impl core::hooks::StatsCollector for TrojanStatsCollector {
    fn record_request(&self, user_id: i64) { self.0.record_request(user_id) }
    fn record_upload(&self, user_id: i64, bytes: u64) { self.0.record_upload(user_id, bytes) }
    fn record_download(&self, user_id: i64, bytes: u64) { self.0.record_download(user_id, bytes) }
}

// Newtype: bridge ArcSwap user map → core::hooks::Authenticator
pub struct TrojanAuthenticator(pub Arc<ArcSwap<HashMap<[u8; 56], i64>>>);

impl core::hooks::Authenticator for TrojanAuthenticator {
    fn authenticate(&self, password: &[u8; 56]) -> Option<i64> {
        self.0.load().get(password).copied()
    }
}
```

### main.rs changes

```rust
use server_panel_rs::{self as panel, NodeType};

// Create panel config
let panel_config = panel::PanelConfig {
    server_host: cli.server_host.clone(),
    server_port: cli.port,
    node_id: cli.node,
    node_type: NodeType::Trojan,
    data_dir: cli.data_dir.clone(),
    api_timeout: cli.api_timeout,
};

let api_manager = Arc::new(panel::ApiManager::new(panel_config)?);
let user_manager = Arc::new(panel::UserManager::new());
let stats = Arc::new(panel::StatsCollector::new());

// Fetch config — consumer extracts protocol-specific config
let node_config_enum = api_manager.fetch_config().await?;
let trojan_config = node_config_enum.as_trojan()?.clone();

// User diff callback for kick
let conn_mgr = conn_manager.clone();
let on_diff = Arc::new(move |diff: panel::UserDiff| {
    for uid in diff.removed_ids.iter().chain(diff.uuid_changed_ids.iter()) {
        conn_mgr.kick_user(*uid);
    }
});

// Background tasks with diff callback
let bg_tasks = panel::BackgroundTasks::new(task_config, api_manager, user_manager, stats)
    .on_user_diff(on_diff);
```

## What Stays in server-trojan-rs

- `core/` — all core proxy logic, hooks traits, connection management
- `transport/` — TCP, WebSocket, gRPC transport
- `handler.rs` — connection processing
- `server_runner.rs` — server startup
- `config.rs` — CLI args (CliArgs, ConnConfig, ServerConfig), trojan-specific config parsing
- `business/` — reduced to thin newtype wrappers (~30 lines)
- `acl.rs`, `logger.rs`, `error.rs` — unchanged

## Testing Strategy

- All existing tests in `business/` move to the new crate (unit tests stay inline with `#[cfg(test)]`)
- `UserManager` tests: remove kick assertions, verify `UserDiff` fields instead
- `StatsCollector` tests: move as-is (no behavioral change)
- `BackgroundTasks` tests: move as-is
- `ApiManager` tests: move as-is
- `server-trojan-rs` tests: should still pass after rewiring (275 tests total)
