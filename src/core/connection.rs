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
    pub fn register(
        &self,
        user_id: UserId,
        peer_addr: String,
    ) -> (ConnectionId, CancellationToken) {
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
            // Atomically remove conn_id from the Vec and delete the entry if empty.
            // remove_if holds the shard lock for the entire check, so a concurrent
            // register() cannot insert into the Vec between our retain and remove.
            self.user_connections
                .remove_if_mut(&user_id, |_, conn_ids| {
                    conn_ids.retain(|&id| id != conn_id);
                    conn_ids.is_empty()
                });
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

    /// Test that unregister of the last connection for a user does NOT
    /// delete a new connection registered by another thread in between.
    ///
    /// Race scenario (same user_id):
    ///   Thread A: unregister(conn1) -> retain removes conn1, vec is empty
    ///            -> drop(guard) releases DashMap lock
    ///            ---- window ----
    ///   Thread B: register(user, conn2) -> pushes conn2 into vec
    ///            ---- window ----
    ///   Thread A: user_connections.remove(user_id) -> deletes vec containing conn2!
    ///
    /// After this, conn2 exists in `connections` but NOT in `user_connections`,
    /// so kick_user will miss it, and user_count is wrong.
    #[test]
    fn test_unregister_register_race_same_user() {
        use std::sync::Barrier;
        use std::thread;

        // Run many iterations to increase chance of hitting the race window
        for _ in 0..200 {
            let manager = ConnectionManager::new();
            let user_id: UserId = 42;

            // Register initial connection
            let (conn_id1, _token1) = manager.register(user_id, "127.0.0.1:1000".to_string());

            let barrier = Arc::new(Barrier::new(2));

            // Thread A: unregister conn1 (the last conn for this user)
            let m_a = manager.clone();
            let b_a = Arc::clone(&barrier);
            let handle_a = thread::spawn(move || {
                b_a.wait();
                m_a.unregister(conn_id1);
            });

            // Thread B: register a new conn for the same user
            let m_b = manager.clone();
            let b_b = Arc::clone(&barrier);
            let handle_b = thread::spawn(move || {
                b_b.wait();
                m_b.register(user_id, "127.0.0.1:2000".to_string())
            });

            handle_a.join().unwrap();
            let (conn_id2, _token2) = handle_b.join().unwrap();

            // conn1 should be gone
            assert!(
                manager.connections.get(&conn_id1).is_none(),
                "conn1 should have been removed from connections"
            );

            // conn2 must still exist in connections
            assert!(
                manager.connections.get(&conn_id2).is_some(),
                "conn2 must exist in connections map"
            );

            // CRITICAL: conn2 must also be tracked in user_connections
            // If the race occurred, user_connections.remove() deleted conn2's entry
            let has_user_entry = manager.user_connections.get(&user_id).is_some();
            let user_conn_contains_conn2 = manager
                .user_connections
                .get(&user_id)
                .map(|ids| ids.contains(&conn_id2))
                .unwrap_or(false);

            assert!(
                has_user_entry,
                "user_connections entry for user {} must exist (conn2 is still active)",
                user_id
            );
            assert!(
                user_conn_contains_conn2,
                "user_connections must contain conn_id2={} for user {}",
                conn_id2, user_id
            );

            // Clean up
            manager.unregister(conn_id2);
            assert_eq!(manager.connection_count(), 0);
            assert_eq!(manager.user_count(), 0);
        }
    }

    /// Test that high-contention concurrent register/unregister for the SAME user
    /// always leaves consistent state: connection_count == 0, user_count == 0.
    #[test]
    fn test_concurrent_same_user_consistency() {
        use std::thread;

        for _ in 0..50 {
            let manager = ConnectionManager::new();
            let user_id: UserId = 1;

            let handles: Vec<_> = (0..20)
                .map(|j| {
                    let m = manager.clone();
                    thread::spawn(move || {
                        for k in 0..100 {
                            let (conn_id, _) =
                                m.register(user_id, format!("127.0.0.1:{}", j * 1000 + k));
                            // Tiny yield to increase interleaving
                            std::thread::yield_now();
                            m.unregister(conn_id);
                        }
                    })
                })
                .collect();

            for h in handles {
                h.join().unwrap();
            }

            assert_eq!(
                manager.connection_count(),
                0,
                "all connections must be cleaned up"
            );
            // This is the key assertion: user_connections must also be fully cleaned
            assert_eq!(
                manager.user_count(),
                0,
                "user_connections must be empty when all connections are gone"
            );
        }
    }
}
