//! User traffic statistics and connection management module
//!
//! Tracks per-user upload/download bytes, proxy request count,
//! and manages active connections with kick-off capability.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Statistics for a single user
#[derive(Debug, Default)]
pub struct UserStats {
    /// Total bytes uploaded (client -> remote)
    upload_bytes: AtomicU64,
    /// Total bytes downloaded (remote -> client)
    download_bytes: AtomicU64,
    /// Number of proxy requests (not connections, but actual proxy requests)
    request_count: AtomicU64,
}

impl UserStats {
    /// Create a new UserStats instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Add upload bytes
    #[inline]
    pub fn add_upload(&self, bytes: u64) {
        self.upload_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add download bytes
    #[inline]
    pub fn add_download(&self, bytes: u64) {
        self.download_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increment request count
    #[inline]
    pub fn inc_request(&self) {
        self.request_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current upload bytes
    pub fn upload_bytes(&self) -> u64 {
        self.upload_bytes.load(Ordering::Relaxed)
    }

    /// Get current download bytes
    pub fn download_bytes(&self) -> u64 {
        self.download_bytes.load(Ordering::Relaxed)
    }

    /// Get current request count
    pub fn request_count(&self) -> u64 {
        self.request_count.load(Ordering::Relaxed)
    }

    /// Get all stats as a tuple (upload, download, requests)
    pub fn get_all(&self) -> (u64, u64, u64) {
        (
            self.upload_bytes.load(Ordering::Relaxed),
            self.download_bytes.load(Ordering::Relaxed),
            self.request_count.load(Ordering::Relaxed),
        )
    }

    /// Reset all counters and return the previous values
    pub fn reset(&self) -> (u64, u64, u64) {
        let upload = self.upload_bytes.swap(0, Ordering::Relaxed);
        let download = self.download_bytes.swap(0, Ordering::Relaxed);
        let requests = self.request_count.swap(0, Ordering::Relaxed);
        (upload, download, requests)
    }
}

/// Snapshot of user statistics
#[derive(Debug, Clone)]
pub struct UserStatsSnapshot {
    pub user_id: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub request_count: u64,
}

/// Manager for all user statistics
#[derive(Debug, Clone)]
pub struct StatsManager {
    /// Map from user_id to their stats
    users: Arc<DashMap<u64, Arc<UserStats>>>,
}

impl Default for StatsManager {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsManager {
    /// Create a new StatsManager
    pub fn new() -> Self {
        Self {
            users: Arc::new(DashMap::new()),
        }
    }

    /// Get or create stats for a user
    pub fn get_or_create(&self, user_id: u64) -> Arc<UserStats> {
        self.users
            .entry(user_id)
            .or_insert_with(|| Arc::new(UserStats::new()))
            .clone()
    }

    /// Get stats for a user if they exist
    pub fn get(&self, user_id: u64) -> Option<Arc<UserStats>> {
        self.users.get(&user_id).map(|r| r.clone())
    }

    /// Record a proxy request for a user
    #[inline]
    pub fn record_request(&self, user_id: u64) {
        self.get_or_create(user_id).inc_request();
    }

    /// Get snapshot of all users' stats
    pub fn get_all_snapshots(&self) -> Vec<UserStatsSnapshot> {
        self.users
            .iter()
            .map(|entry| {
                let (upload, download, requests) = entry.value().get_all();
                UserStatsSnapshot {
                    user_id: *entry.key(),
                    upload_bytes: upload,
                    download_bytes: download,
                    request_count: requests,
                }
            })
            .collect()
    }

    /// Get snapshot of a single user's stats
    pub fn get_snapshot(&self, user_id: u64) -> Option<UserStatsSnapshot> {
        self.users.get(&user_id).map(|entry| {
            let (upload, download, requests) = entry.value().get_all();
            UserStatsSnapshot {
                user_id,
                upload_bytes: upload,
                download_bytes: download,
                request_count: requests,
            }
        })
    }

    /// Reset all stats for a user and return the previous values
    pub fn reset_user(&self, user_id: u64) -> Option<(u64, u64, u64)> {
        self.users.get(&user_id).map(|entry| entry.value().reset())
    }

    /// Reset all users' stats and return snapshots of previous values
    pub fn reset_all(&self) -> Vec<UserStatsSnapshot> {
        self.users
            .iter()
            .map(|entry| {
                let (upload, download, requests) = entry.value().reset();
                UserStatsSnapshot {
                    user_id: *entry.key(),
                    upload_bytes: upload,
                    download_bytes: download,
                    request_count: requests,
                }
            })
            .collect()
    }

    /// Get the number of tracked users
    pub fn user_count(&self) -> usize {
        self.users.len()
    }
}

// ==================== Connection Management ====================

/// Unique connection identifier
pub type ConnectionId = u64;

/// Information about an active connection
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub conn_id: ConnectionId,
    pub user_id: u64,
    pub peer_addr: String,
    pub connected_at: std::time::Instant,
}

/// Snapshot of connection info for external use
#[derive(Debug, Clone)]
pub struct ConnectionSnapshot {
    pub conn_id: ConnectionId,
    pub user_id: u64,
    pub peer_addr: String,
    /// Connection duration in seconds
    pub duration_secs: u64,
}

/// Active connection handle with cancellation support
#[derive(Debug)]
struct ActiveConnection {
    info: ConnectionInfo,
    cancel_token: CancellationToken,
}

/// Manager for active connections with kick-off capability
#[derive(Debug, Clone)]
pub struct ConnectionManager {
    /// Counter for generating unique connection IDs
    next_conn_id: Arc<AtomicU64>,
    /// Map from connection_id to active connection
    connections: Arc<DashMap<ConnectionId, ActiveConnection>>,
    /// Map from user_id to set of connection_ids (for quick user lookup)
    user_connections: Arc<DashMap<u64, Vec<ConnectionId>>>,
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionManager {
    /// Create a new ConnectionManager
    pub fn new() -> Self {
        Self {
            next_conn_id: Arc::new(AtomicU64::new(1)),
            connections: Arc::new(DashMap::new()),
            user_connections: Arc::new(DashMap::new()),
        }
    }

    /// Register a new connection and return its ID and cancellation token
    pub fn register(&self, user_id: u64, peer_addr: String) -> (ConnectionId, CancellationToken) {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let cancel_token = CancellationToken::new();

        let info = ConnectionInfo {
            conn_id,
            user_id,
            peer_addr,
            connected_at: std::time::Instant::now(),
        };

        let conn = ActiveConnection {
            info,
            cancel_token: cancel_token.clone(),
        };

        // Insert into connections map
        self.connections.insert(conn_id, conn);

        // Add to user's connection list
        self.user_connections
            .entry(user_id)
            .or_default()
            .push(conn_id);

        (conn_id, cancel_token)
    }

    /// Unregister a connection (called when connection ends normally)
    pub fn unregister(&self, conn_id: ConnectionId) {
        if let Some((_, conn)) = self.connections.remove(&conn_id) {
            // Remove from user's connection list
            if let Some(mut user_conns) = self.user_connections.get_mut(&conn.info.user_id) {
                user_conns.retain(|&id| id != conn_id);
            }
        }
    }

    /// Kick a specific connection by ID
    /// Returns true if the connection was found and kicked
    pub fn kick_connection(&self, conn_id: ConnectionId) -> bool {
        if let Some(conn) = self.connections.get(&conn_id) {
            conn.cancel_token.cancel();
            true
        } else {
            false
        }
    }

    /// Kick all connections for a user
    /// Returns the number of connections kicked
    pub fn kick_user(&self, user_id: u64) -> usize {
        let conn_ids: Vec<ConnectionId> = self
            .user_connections
            .get(&user_id)
            .map(|v| v.clone())
            .unwrap_or_default();

        let mut kicked = 0;
        for conn_id in conn_ids {
            if self.kick_connection(conn_id) {
                kicked += 1;
            }
        }
        kicked
    }

    /// Get the number of active connections
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Get the number of active connections for a specific user
    pub fn user_connection_count(&self, user_id: u64) -> usize {
        self.user_connections
            .get(&user_id)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Get a list of all active connections as snapshots
    pub fn get_all_connections(&self) -> Vec<ConnectionSnapshot> {
        self.connections
            .iter()
            .map(|entry| {
                let conn = entry.value();
                ConnectionSnapshot {
                    conn_id: conn.info.conn_id,
                    user_id: conn.info.user_id,
                    peer_addr: conn.info.peer_addr.clone(),
                    duration_secs: conn.info.connected_at.elapsed().as_secs(),
                }
            })
            .collect()
    }

    /// Get all connections for a specific user
    pub fn get_user_connections(&self, user_id: u64) -> Vec<ConnectionSnapshot> {
        let conn_ids: Vec<ConnectionId> = self
            .user_connections
            .get(&user_id)
            .map(|v| v.clone())
            .unwrap_or_default();

        conn_ids
            .iter()
            .filter_map(|&conn_id| {
                self.connections
                    .get(&conn_id)
                    .map(|conn| ConnectionSnapshot {
                        conn_id: conn.info.conn_id,
                        user_id: conn.info.user_id,
                        peer_addr: conn.info.peer_addr.clone(),
                        duration_secs: conn.info.connected_at.elapsed().as_secs(),
                    })
            })
            .collect()
    }

    /// Get list of online user IDs
    pub fn get_online_users(&self) -> Vec<u64> {
        self.user_connections
            .iter()
            .filter(|entry| !entry.value().is_empty())
            .map(|entry| *entry.key())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_stats_new() {
        let stats = UserStats::new();
        assert_eq!(stats.upload_bytes(), 0);
        assert_eq!(stats.download_bytes(), 0);
        assert_eq!(stats.request_count(), 0);
    }

    #[test]
    fn test_user_stats_add_upload() {
        let stats = UserStats::new();
        stats.add_upload(100);
        stats.add_upload(50);
        assert_eq!(stats.upload_bytes(), 150);
    }

    #[test]
    fn test_user_stats_add_download() {
        let stats = UserStats::new();
        stats.add_download(200);
        stats.add_download(100);
        assert_eq!(stats.download_bytes(), 300);
    }

    #[test]
    fn test_user_stats_inc_request() {
        let stats = UserStats::new();
        stats.inc_request();
        stats.inc_request();
        stats.inc_request();
        assert_eq!(stats.request_count(), 3);
    }

    #[test]
    fn test_user_stats_get_all() {
        let stats = UserStats::new();
        stats.add_upload(100);
        stats.add_download(200);
        stats.inc_request();
        let (upload, download, requests) = stats.get_all();
        assert_eq!(upload, 100);
        assert_eq!(download, 200);
        assert_eq!(requests, 1);
    }

    #[test]
    fn test_user_stats_reset() {
        let stats = UserStats::new();
        stats.add_upload(100);
        stats.add_download(200);
        stats.inc_request();

        let (upload, download, requests) = stats.reset();
        assert_eq!(upload, 100);
        assert_eq!(download, 200);
        assert_eq!(requests, 1);

        // After reset, all should be 0
        assert_eq!(stats.upload_bytes(), 0);
        assert_eq!(stats.download_bytes(), 0);
        assert_eq!(stats.request_count(), 0);
    }

    #[test]
    fn test_stats_manager_new() {
        let manager = StatsManager::new();
        assert_eq!(manager.user_count(), 0);
    }

    #[test]
    fn test_stats_manager_get_or_create() {
        let manager = StatsManager::new();
        let stats1 = manager.get_or_create(1);
        let stats2 = manager.get_or_create(1);
        // Should return the same Arc
        assert!(Arc::ptr_eq(&stats1, &stats2));
        assert_eq!(manager.user_count(), 1);
    }

    #[test]
    fn test_stats_manager_record_request() {
        let manager = StatsManager::new();
        manager.record_request(1);
        manager.record_request(1);
        manager.record_request(2);

        let stats1 = manager.get(1).unwrap();
        let stats2 = manager.get(2).unwrap();

        assert_eq!(stats1.request_count(), 2);
        assert_eq!(stats2.request_count(), 1);
    }

    #[test]
    fn test_stats_manager_get_snapshot() {
        let manager = StatsManager::new();
        let stats = manager.get_or_create(42);
        stats.add_upload(1000);
        stats.add_download(2000);
        stats.inc_request();

        let snapshot = manager.get_snapshot(42).unwrap();
        assert_eq!(snapshot.user_id, 42);
        assert_eq!(snapshot.upload_bytes, 1000);
        assert_eq!(snapshot.download_bytes, 2000);
        assert_eq!(snapshot.request_count, 1);
    }

    #[test]
    fn test_stats_manager_get_all_snapshots() {
        let manager = StatsManager::new();

        let stats1 = manager.get_or_create(1);
        stats1.add_upload(100);

        let stats2 = manager.get_or_create(2);
        stats2.add_download(200);

        let snapshots = manager.get_all_snapshots();
        assert_eq!(snapshots.len(), 2);
    }

    #[test]
    fn test_stats_manager_reset_user() {
        let manager = StatsManager::new();
        let stats = manager.get_or_create(1);
        stats.add_upload(100);
        stats.add_download(200);

        let (upload, download, _) = manager.reset_user(1).unwrap();
        assert_eq!(upload, 100);
        assert_eq!(download, 200);

        // After reset
        assert_eq!(stats.upload_bytes(), 0);
        assert_eq!(stats.download_bytes(), 0);
    }

    #[test]
    fn test_stats_manager_reset_all() {
        let manager = StatsManager::new();

        manager.get_or_create(1).add_upload(100);
        manager.get_or_create(2).add_download(200);

        let snapshots = manager.reset_all();
        assert_eq!(snapshots.len(), 2);

        // All should be reset
        assert_eq!(manager.get(1).unwrap().upload_bytes(), 0);
        assert_eq!(manager.get(2).unwrap().download_bytes(), 0);
    }

    #[test]
    fn test_stats_concurrent_updates() {
        use std::thread;

        let manager = StatsManager::new();
        let manager_clone = manager.clone();

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let m = manager_clone.clone();
                thread::spawn(move || {
                    for _ in 0..1000 {
                        m.record_request(i % 3); // 3 different users
                        m.get_or_create(i % 3).add_upload(1);
                        m.get_or_create(i % 3).add_download(2);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let snapshots = manager.get_all_snapshots();
        assert_eq!(snapshots.len(), 3);

        let total_requests: u64 = snapshots.iter().map(|s| s.request_count).sum();
        assert_eq!(total_requests, 10000); // 10 threads * 1000 iterations
    }

    // ==================== ConnectionManager Tests ====================

    #[test]
    fn test_connection_manager_new() {
        let manager = ConnectionManager::new();
        assert_eq!(manager.connection_count(), 0);
    }

    #[test]
    fn test_connection_manager_register() {
        let manager = ConnectionManager::new();
        let (conn_id1, _token1) = manager.register(1, "127.0.0.1:1234".to_string());
        let (conn_id2, _token2) = manager.register(1, "127.0.0.1:1235".to_string());
        let (conn_id3, _token3) = manager.register(2, "127.0.0.1:1236".to_string());

        assert_eq!(manager.connection_count(), 3);
        assert_eq!(manager.user_connection_count(1), 2);
        assert_eq!(manager.user_connection_count(2), 1);
        assert!(conn_id1 < conn_id2);
        assert!(conn_id2 < conn_id3);
    }

    #[test]
    fn test_connection_manager_unregister() {
        let manager = ConnectionManager::new();
        let (conn_id, _token) = manager.register(1, "127.0.0.1:1234".to_string());
        assert_eq!(manager.connection_count(), 1);

        manager.unregister(conn_id);
        assert_eq!(manager.connection_count(), 0);
        assert_eq!(manager.user_connection_count(1), 0);
    }

    #[test]
    fn test_connection_manager_kick_connection() {
        let manager = ConnectionManager::new();
        let (conn_id, token) = manager.register(1, "127.0.0.1:1234".to_string());

        assert!(!token.is_cancelled());
        assert!(manager.kick_connection(conn_id));
        assert!(token.is_cancelled());

        // Kicking non-existent connection returns false
        assert!(!manager.kick_connection(999));
    }

    #[test]
    fn test_connection_manager_kick_user() {
        let manager = ConnectionManager::new();
        let (_, token1) = manager.register(1, "127.0.0.1:1234".to_string());
        let (_, token2) = manager.register(1, "127.0.0.1:1235".to_string());
        let (_, token3) = manager.register(2, "127.0.0.1:1236".to_string());

        assert!(!token1.is_cancelled());
        assert!(!token2.is_cancelled());
        assert!(!token3.is_cancelled());

        let kicked = manager.kick_user(1);
        assert_eq!(kicked, 2);
        assert!(token1.is_cancelled());
        assert!(token2.is_cancelled());
        assert!(!token3.is_cancelled()); // User 2 should not be affected
    }

    #[test]
    fn test_connection_manager_get_all_connections() {
        let manager = ConnectionManager::new();
        manager.register(1, "127.0.0.1:1234".to_string());
        manager.register(2, "127.0.0.1:1235".to_string());

        let conns = manager.get_all_connections();
        assert_eq!(conns.len(), 2);
    }

    #[test]
    fn test_connection_manager_get_user_connections() {
        let manager = ConnectionManager::new();
        manager.register(1, "127.0.0.1:1234".to_string());
        manager.register(1, "127.0.0.1:1235".to_string());
        manager.register(2, "127.0.0.1:1236".to_string());

        let user1_conns = manager.get_user_connections(1);
        let user2_conns = manager.get_user_connections(2);

        assert_eq!(user1_conns.len(), 2);
        assert_eq!(user2_conns.len(), 1);
    }

    #[test]
    fn test_connection_manager_get_online_users() {
        let manager = ConnectionManager::new();
        manager.register(1, "127.0.0.1:1234".to_string());
        manager.register(2, "127.0.0.1:1235".to_string());
        manager.register(1, "127.0.0.1:1236".to_string());

        let online = manager.get_online_users();
        assert_eq!(online.len(), 2);
        assert!(online.contains(&1));
        assert!(online.contains(&2));
    }

    #[test]
    fn test_connection_manager_concurrent() {
        use std::thread;

        let manager = ConnectionManager::new();
        let manager_clone = manager.clone();

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let m = manager_clone.clone();
                thread::spawn(move || {
                    for j in 0..100 {
                        let (conn_id, _) = m.register(i % 3, format!("127.0.0.1:{}", i * 1000 + j));
                        // Simulate some work
                        std::thread::sleep(std::time::Duration::from_micros(10));
                        m.unregister(conn_id);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // All connections should be cleaned up
        assert_eq!(manager.connection_count(), 0);
    }
}
