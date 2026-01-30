//! API integration module for remote panel communication
//!
//! This module handles:
//! - Node registration and verification
//! - User fetching with hot-reload
//! - Traffic reporting
//! - Heartbeat sending
//! - State persistence

use anyhow::{anyhow, Result};
use server_r_client::{
    ApiClient, ApiError, Config as ApiConfig, NodeType, RegisterRequest, TrojanConfig, UserTraffic,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::config::{CliArgs, User};
use crate::logger::log;
use crate::stats::{ConnectionManager, StatsManager};
use crate::utils::password_to_hex;

/// State file content for persistence
#[derive(Debug, Clone)]
struct PersistentState {
    register_id: String,
    node_id: i64,
}

impl PersistentState {
    fn serialize(&self) -> String {
        format!("{}:{}", self.node_id, self.register_id)
    }

    fn deserialize(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() == 2 {
            let node_id = parts[0].parse().ok()?;
            let register_id = parts[1].to_string();
            Some(Self {
                register_id,
                node_id,
            })
        } else {
            None
        }
    }
}

/// API manager for handling all remote panel operations
pub struct ApiManager {
    client: ApiClient,
    node_id: i64,
    register_id: RwLock<Option<String>>,
    state_file_path: std::path::PathBuf,
}

impl ApiManager {
    /// Create a new API manager
    pub fn new(cli: &CliArgs) -> Result<Self> {
        let config = ApiConfig::new(&cli.api, &cli.token)
            .with_timeout(Duration::from_secs(30))
            .with_debug(cli.log_mode == "debug");

        let client = ApiClient::new(config)?;

        Ok(Self {
            client,
            node_id: cli.node,
            register_id: RwLock::new(None),
            state_file_path: cli.get_state_file_path(),
        })
    }

    /// Load persisted state from disk
    fn load_state(&self) -> Option<PersistentState> {
        if self.state_file_path.exists() {
            match std::fs::read_to_string(&self.state_file_path) {
                Ok(content) => {
                    let state = PersistentState::deserialize(content.trim())?;
                    // Only use state if node_id matches
                    if state.node_id == self.node_id {
                        return Some(state);
                    }
                }
                Err(e) => {
                    log::warn!(error = %e, "Failed to read state file");
                }
            }
        }
        None
    }

    /// Save state to disk
    fn save_state(&self, register_id: &str) -> Result<()> {
        let state = PersistentState {
            register_id: register_id.to_string(),
            node_id: self.node_id,
        };

        // Ensure parent directory exists
        if let Some(parent) = self.state_file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&self.state_file_path, state.serialize())?;
        log::debug!(path = %self.state_file_path.display(), "State saved");
        Ok(())
    }

    /// Clear persisted state
    fn clear_state(&self) {
        if self.state_file_path.exists() {
            if let Err(e) = std::fs::remove_file(&self.state_file_path) {
                log::warn!(error = %e, "Failed to remove state file");
            }
        }
    }

    /// Get the current register_id
    #[allow(dead_code)]
    pub async fn get_register_id(&self) -> Option<String> {
        self.register_id.read().await.clone()
    }

    /// Fetch node configuration from remote panel
    pub async fn fetch_config(&self) -> Result<TrojanConfig> {
        log::info!(node_id = self.node_id, "Fetching node configuration");

        let config_enum = self.client.config(NodeType::Trojan, self.node_id).await?;
        let config = config_enum.as_trojan()?;

        log::info!(
            node_id = self.node_id,
            port = config.server_port,
            network = ?config.network,
            "Configuration fetched"
        );

        Ok(config.clone())
    }

    /// Initialize node - try to verify existing registration or register new
    pub async fn initialize(&self) -> Result<String> {
        // Try to load and verify existing state
        if let Some(state) = self.load_state() {
            log::info!(
                register_id = %state.register_id,
                "Found existing registration, verifying"
            );

            match self
                .client
                .verify(NodeType::Trojan, &state.register_id)
                .await
            {
                Ok(true) => {
                    log::info!(register_id = %state.register_id, "Registration verified");
                    *self.register_id.write().await = Some(state.register_id.clone());
                    return Ok(state.register_id);
                }
                Ok(false) => {
                    log::warn!("Existing registration is invalid, re-registering");
                    self.clear_state();
                }
                Err(e) => {
                    log::warn!(error = %e, "Failed to verify registration, re-registering");
                    self.clear_state();
                }
            }
        }

        // Register new node
        self.register().await
    }

    /// Register the node with the panel
    async fn register(&self) -> Result<String> {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        log::info!(
            node_id = self.node_id,
            hostname = %hostname,
            "Registering node"
        );

        let request = RegisterRequest::new(hostname, 0); // Port will be filled by panel

        let register_id = self
            .client
            .register(NodeType::Trojan, self.node_id, request)
            .await?;

        log::info!(register_id = %register_id, "Node registered successfully");

        // Save state
        if let Err(e) = self.save_state(&register_id) {
            log::warn!(error = %e, "Failed to save state");
        }

        *self.register_id.write().await = Some(register_id.clone());
        Ok(register_id)
    }

    /// Unregister the node from the panel
    pub async fn unregister(&self) -> Result<()> {
        let register_id = self.register_id.read().await.clone();

        if let Some(id) = register_id {
            log::info!(register_id = %id, "Unregistering node");

            if let Err(e) = self.client.unregister(NodeType::Trojan, &id).await {
                log::warn!(error = %e, "Failed to unregister node");
            }

            self.clear_state();
            *self.register_id.write().await = None;
        }

        Ok(())
    }

    /// Fetch users from remote panel
    pub async fn fetch_users(&self) -> Result<Vec<User>> {
        let register_id = self
            .register_id
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Not registered"))?;

        match self.client.users(NodeType::Trojan, &register_id).await {
            Ok(users) => {
                log::debug!(count = users.len(), "Users fetched");
                Ok(users.into_iter().map(User::from).collect())
            }
            Err(ApiError::NotModified { .. }) => {
                log::debug!("Users not modified (ETag match)");
                Err(anyhow!("Not modified"))
            }
            Err(e) => {
                log::error!(error = %e, "Failed to fetch users");
                Err(e.into())
            }
        }
    }

    /// Submit traffic data to panel
    pub async fn submit_traffic(&self, data: Vec<UserTraffic>) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let register_id = self
            .register_id
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Not registered"))?;

        log::debug!(count = data.len(), "Submitting traffic data");

        self.client
            .submit_with_agent(NodeType::Trojan, &register_id, data)
            .await?;

        log::debug!("Traffic data submitted");
        Ok(())
    }

    /// Send heartbeat to panel
    pub async fn heartbeat(&self) -> Result<()> {
        let register_id = self
            .register_id
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Not registered"))?;

        self.client
            .heartbeat(NodeType::Trojan, &register_id)
            .await?;

        log::debug!("Heartbeat sent");
        Ok(())
    }
}

/// User manager for handling user hot-reload with kick-off capability
pub struct UserManager {
    /// Current users map: password_hex -> user_id
    users: Arc<RwLock<HashMap<[u8; 56], i64>>>,
    /// Current user IDs set for quick lookup
    user_ids: Arc<RwLock<HashSet<i64>>>,
    /// Connection manager for kick-off
    connections: ConnectionManager,
}

impl UserManager {
    /// Create a new user manager
    pub fn new(connections: ConnectionManager) -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            user_ids: Arc::new(RwLock::new(HashSet::new())),
            connections,
        }
    }

    /// Get a clone of the current users map
    #[allow(dead_code)]
    pub async fn get_users(&self) -> HashMap<[u8; 56], i64> {
        self.users.read().await.clone()
    }

    /// Get arc reference to users for Server
    pub fn get_users_arc(&self) -> Arc<RwLock<HashMap<[u8; 56], i64>>> {
        Arc::clone(&self.users)
    }

    /// Initialize with users
    pub async fn init(&self, users: &[User]) {
        let mut users_map = self.users.write().await;
        let mut user_ids = self.user_ids.write().await;

        users_map.clear();
        user_ids.clear();

        for user in users {
            let hex = password_to_hex(&user.uuid);
            users_map.insert(hex, user.id);
            user_ids.insert(user.id);
        }

        log::info!(count = users.len(), "Users initialized");
    }

    /// Update users with hot-reload
    ///
    /// - Add new users
    /// - Remove deleted users and kick their connections
    pub async fn update(&self, new_users: &[User]) -> (usize, usize, usize) {
        let mut users_map = self.users.write().await;
        let mut user_ids = self.user_ids.write().await;

        // Build new user set
        let new_user_ids: HashSet<i64> = new_users.iter().map(|u| u.id).collect();

        // Find users to remove (in current but not in new)
        let to_remove: Vec<i64> = user_ids.difference(&new_user_ids).copied().collect();

        // Find users to add (in new but not in current)
        let to_add: Vec<&User> = new_users
            .iter()
            .filter(|u| !user_ids.contains(&u.id))
            .collect();

        let added = to_add.len();
        let removed = to_remove.len();
        let mut kicked = 0;

        // Remove old users
        for user_id in &to_remove {
            // Find and remove from users_map
            users_map.retain(|_, id| id != user_id);
            user_ids.remove(user_id);

            // Kick connections
            let k = self.connections.kick_user(*user_id as u64);
            kicked += k;
            if k > 0 {
                log::info!(user_id = user_id, kicked = k, "User removed and kicked");
            }
        }

        // Add new users
        for user in to_add {
            let hex = password_to_hex(&user.uuid);
            users_map.insert(hex, user.id);
            user_ids.insert(user.id);
        }

        if added > 0 || removed > 0 {
            log::info!(
                added = added,
                removed = removed,
                kicked = kicked,
                total = users_map.len(),
                "Users updated"
            );
        }

        (added, removed, kicked)
    }
}

/// Background task runner for periodic operations
pub struct BackgroundTasks {
    api: Arc<ApiManager>,
    user_manager: Arc<UserManager>,
    stats: StatsManager,
    cli: CliArgs,
}

impl BackgroundTasks {
    /// Create a new background task runner
    pub fn new(
        api: Arc<ApiManager>,
        user_manager: Arc<UserManager>,
        stats: StatsManager,
        cli: CliArgs,
    ) -> Self {
        Self {
            api,
            user_manager,
            stats,
            cli,
        }
    }

    /// Start all background tasks
    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let fetch_users_interval = Duration::from_secs(self.cli.fetch_users_interval);
            let report_traffics_interval = Duration::from_secs(self.cli.report_traffics_interval);
            let heartbeat_interval = Duration::from_secs(self.cli.heartbeat_interval);

            let mut fetch_users_timer = tokio::time::interval(fetch_users_interval);
            let mut report_traffics_timer = tokio::time::interval(report_traffics_interval);
            let mut heartbeat_timer = tokio::time::interval(heartbeat_interval);

            // Skip first tick (fires immediately)
            fetch_users_timer.tick().await;
            report_traffics_timer.tick().await;
            heartbeat_timer.tick().await;

            loop {
                tokio::select! {
                    _ = fetch_users_timer.tick() => {
                        self.fetch_users_task().await;
                    }
                    _ = report_traffics_timer.tick() => {
                        self.report_traffics_task().await;
                    }
                    _ = heartbeat_timer.tick() => {
                        self.heartbeat_task().await;
                    }
                }
            }
        })
    }

    async fn fetch_users_task(&self) {
        match self.api.fetch_users().await {
            Ok(users) => {
                self.user_manager.update(&users).await;
            }
            Err(e) => {
                // "Not modified" is not an error
                if !e.to_string().contains("Not modified") {
                    log::warn!(error = %e, "Failed to fetch users");
                }
            }
        }
    }

    async fn report_traffics_task(&self) {
        // Get and reset all stats
        let snapshots = self.stats.reset_all();

        if snapshots.is_empty() {
            return;
        }

        // Convert to UserTraffic
        let traffic_data: Vec<UserTraffic> = snapshots
            .into_iter()
            .filter(|s| s.upload_bytes > 0 || s.download_bytes > 0)
            .map(|s| {
                UserTraffic::with_count(
                    s.user_id as i64,
                    s.upload_bytes,
                    s.download_bytes,
                    s.request_count,
                )
            })
            .collect();

        if traffic_data.is_empty() {
            return;
        }

        if let Err(e) = self.api.submit_traffic(traffic_data).await {
            log::warn!(error = %e, "Failed to submit traffic");
        }
    }

    async fn heartbeat_task(&self) {
        if let Err(e) = self.api.heartbeat().await {
            log::warn!(error = %e, "Failed to send heartbeat");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistent_state_serialization() {
        let state = PersistentState {
            register_id: "abc-123".to_string(),
            node_id: 42,
        };

        let s = state.serialize();
        assert_eq!(s, "42:abc-123");

        let parsed = PersistentState::deserialize(&s).unwrap();
        assert_eq!(parsed.node_id, 42);
        assert_eq!(parsed.register_id, "abc-123");
    }

    #[test]
    fn test_persistent_state_with_colon_in_id() {
        let state = PersistentState {
            register_id: "abc:123:xyz".to_string(),
            node_id: 1,
        };

        let s = state.serialize();
        let parsed = PersistentState::deserialize(&s).unwrap();
        assert_eq!(parsed.register_id, "abc:123:xyz");
    }
}
