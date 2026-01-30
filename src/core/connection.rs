//! Connection management module
//!
//! Tracks active connections and provides kick-off capability.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio_util::sync::CancellationToken;

use super::hooks::UserId;

/// Unique connection identifier
pub type ConnectionId = u64;

/// Information about an active connection
#[derive(Debug, Clone)]
struct ConnectionInfo {
    user_id: UserId,
    #[allow(dead_code)]
    peer_addr: String,
    #[allow(dead_code)]
    connected_at: Instant,
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
    user_connections: Arc<DashMap<UserId, Vec<ConnectionId>>>,
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
    pub fn register(&self, user_id: UserId, peer_addr: String) -> (ConnectionId, CancellationToken) {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let cancel_token = CancellationToken::new();

        let info = ConnectionInfo {
            user_id,
            peer_addr,
            connected_at: Instant::now(),
        };

        let conn = ActiveConnection {
            info,
            cancel_token: cancel_token.clone(),
        };

        self.connections.insert(conn_id, conn);
        self.user_connections
            .entry(user_id)
            .or_default()
            .push(conn_id);

        (conn_id, cancel_token)
    }

    /// Unregister a connection
    pub fn unregister(&self, conn_id: ConnectionId) {
        if let Some((_, conn)) = self.connections.remove(&conn_id) {
            let user_id = conn.info.user_id;
            // Remove from user_connections and clean up empty entries
            if let Some(mut conn_ids) = self.user_connections.get_mut(&user_id) {
                conn_ids.retain(|&id| id != conn_id);
                // Drop the mutable reference before removing
                if conn_ids.is_empty() {
                    drop(conn_ids);
                    self.user_connections.remove(&user_id);
                }
            }
        }
    }

    /// Kick all connections for a user
    pub fn kick_user(&self, user_id: UserId) -> usize {
        let mut kicked = 0;
        if let Some(conn_ids) = self.user_connections.get(&user_id) {
            for &conn_id in conn_ids.iter() {
                if let Some(conn) = self.connections.get(&conn_id) {
                    conn.cancel_token.cancel();
                    kicked += 1;
                }
            }
        }
        kicked
    }

    /// Get the number of active connections
    #[allow(dead_code)]
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Get the number of users with active connections
    #[allow(dead_code)]
    pub fn user_count(&self) -> usize {
        self.user_connections.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_manager_new() {
        let manager = ConnectionManager::new();
        assert_eq!(manager.connection_count(), 0);
        assert_eq!(manager.user_count(), 0);
    }

    #[test]
    fn test_connection_manager_register() {
        let manager = ConnectionManager::new();
        let (conn_id1, _token1) = manager.register(1, "127.0.0.1:1234".to_string());
        let (conn_id2, _token2) = manager.register(1, "127.0.0.1:1235".to_string());
        let (conn_id3, _token3) = manager.register(2, "127.0.0.1:1236".to_string());

        assert_eq!(manager.connection_count(), 3);
        assert_eq!(manager.user_count(), 2);
        assert!(conn_id1 < conn_id2);
        assert!(conn_id2 < conn_id3);
    }

    #[test]
    fn test_connection_manager_unregister() {
        let manager = ConnectionManager::new();
        let (conn_id, _token) = manager.register(1, "127.0.0.1:1234".to_string());
        assert_eq!(manager.connection_count(), 1);
        assert_eq!(manager.user_count(), 1);

        manager.unregister(conn_id);
        assert_eq!(manager.connection_count(), 0);
        // user_connections should also be cleaned up
        assert_eq!(manager.user_count(), 0);
    }

    #[test]
    fn test_connection_manager_unregister_partial() {
        let manager = ConnectionManager::new();
        let (conn_id1, _token1) = manager.register(1, "127.0.0.1:1234".to_string());
        let (conn_id2, _token2) = manager.register(1, "127.0.0.1:1235".to_string());

        assert_eq!(manager.connection_count(), 2);
        assert_eq!(manager.user_count(), 1);

        // Unregister one connection
        manager.unregister(conn_id1);
        assert_eq!(manager.connection_count(), 1);
        assert_eq!(manager.user_count(), 1); // User still has one connection

        // Unregister the last connection
        manager.unregister(conn_id2);
        assert_eq!(manager.connection_count(), 0);
        assert_eq!(manager.user_count(), 0); // User entry should be removed
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
        // All user entries should also be cleaned up
        assert_eq!(manager.user_count(), 0);
    }
}
