//! User management with hot-reload and kick-off capability

use arc_swap::ArcSwap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::super::password_to_hex;
use crate::config::User;
use crate::core::{ConnectionManager, UserId};
use crate::logger::log;

/// User manager for handling user hot-reload with kick-off capability
///
/// Uses ArcSwap so the authentication hot path (reads) is completely lock-free.
/// Updates build the new map and compute diffs without holding any lock,
/// then atomically swap the map pointer.
pub struct UserManager {
    /// Current users map: password_hex -> user_id (lock-free reads via ArcSwap)
    users: Arc<ArcSwap<HashMap<[u8; 56], UserId>>>,
    /// Connection manager for kick-off
    connections: ConnectionManager,
}

impl UserManager {
    /// Create a new user manager
    pub fn new(connections: ConnectionManager) -> Self {
        Self {
            users: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            connections,
        }
    }

    /// Get a clone of the current users map
    #[allow(dead_code)]
    pub fn get_users(&self) -> HashMap<[u8; 56], UserId> {
        (**self.users.load()).clone()
    }

    /// Get arc reference to users for Server
    pub fn get_users_arc(&self) -> Arc<ArcSwap<HashMap<[u8; 56], UserId>>> {
        Arc::clone(&self.users)
    }

    /// Initialize with users
    pub fn init(&self, users: &[User]) {
        let mut users_map = HashMap::with_capacity(users.len());

        for user in users {
            let hex = password_to_hex(&user.uuid);
            users_map.insert(hex, user.id);
        }

        self.users.store(Arc::new(users_map));
        log::info!(count = users.len(), "Users initialized");
    }

    /// Update users with hot-reload
    ///
    /// - Add new users
    /// - Remove deleted users and kick their connections
    /// - Detect UUID changes and kick affected connections
    ///
    /// All diff computation and kick operations happen without holding any lock.
    /// Only the final map swap is atomic (nanosecond-level).
    pub fn update(&self, new_users: &[User]) -> (usize, usize, usize, usize) {
        // Snapshot the old map (lock-free load)
        let old_map = self.users.load();

        // Build new map (no lock held)
        let mut new_map: HashMap<[u8; 56], UserId> = HashMap::with_capacity(new_users.len());
        let new_user_ids: HashSet<UserId> = new_users.iter().map(|u| u.id).collect();

        for user in new_users {
            let hex = password_to_hex(&user.uuid);
            new_map.insert(hex, user.id);
        }

        // Compute diff (no lock held)
        let old_user_ids: HashSet<UserId> = old_map.values().copied().collect();

        let added = new_user_ids.difference(&old_user_ids).count();
        let removed = old_user_ids.difference(&new_user_ids).count();
        let mut uuid_changed = 0;
        let mut kicked = 0;

        // Kick removed users (no lock held)
        for user_id in old_user_ids.difference(&new_user_ids) {
            let k = self.connections.kick_user(*user_id);
            kicked += k;
            if k > 0 {
                log::info!(user_id = user_id, kicked = k, "User removed and kicked");
            }
        }

        // Kick users with UUID changes (no lock held)
        for (new_hex, &new_id) in &new_map {
            if old_user_ids.contains(&new_id) {
                // User exists in old map, check if password_hex changed
                if old_map.get(new_hex) != Some(&new_id) {
                    // UUID changed
                    uuid_changed += 1;
                    let k = self.connections.kick_user(new_id);
                    kicked += k;
                    if k > 0 {
                        log::info!(user_id = new_id, kicked = k, "User UUID changed and kicked");
                    }
                }
            }
        }

        let total = new_map.len();

        // Atomic swap — this is the only "write" operation, takes nanoseconds
        self.users.store(Arc::new(new_map));

        if added > 0 || removed > 0 || uuid_changed > 0 {
            log::info!(
                added = added,
                removed = removed,
                uuid_changed = uuid_changed,
                kicked = kicked,
                total = total,
                "Users updated"
            );
        }

        (added, removed, uuid_changed, kicked)
    }

    /// Get user count
    #[allow(dead_code)]
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
        let conn_manager = ConnectionManager::new();
        let user_manager = UserManager::new(conn_manager);
        assert_eq!(user_manager.user_count(), 0);
    }

    #[test]
    fn test_user_manager_init() {
        let conn_manager = ConnectionManager::new();
        let user_manager = UserManager::new(conn_manager);

        let users = vec![create_user(1, "uuid-1"), create_user(2, "uuid-2")];

        user_manager.init(&users);
        assert_eq!(user_manager.user_count(), 2);
    }

    #[test]
    fn test_user_manager_update_add_users() {
        let conn_manager = ConnectionManager::new();
        let user_manager = UserManager::new(conn_manager);

        let initial_users = vec![create_user(1, "uuid-1")];
        user_manager.init(&initial_users);

        let new_users = vec![
            create_user(1, "uuid-1"),
            create_user(2, "uuid-2"),
            create_user(3, "uuid-3"),
        ];

        let (added, removed, uuid_changed, kicked) = user_manager.update(&new_users);
        assert_eq!(added, 2);
        assert_eq!(removed, 0);
        assert_eq!(uuid_changed, 0);
        assert_eq!(kicked, 0);
        assert_eq!(user_manager.user_count(), 3);
    }

    #[test]
    fn test_user_manager_update_remove_users() {
        let conn_manager = ConnectionManager::new();
        let user_manager = UserManager::new(conn_manager);

        let initial_users = vec![
            create_user(1, "uuid-1"),
            create_user(2, "uuid-2"),
            create_user(3, "uuid-3"),
        ];
        user_manager.init(&initial_users);

        let new_users = vec![create_user(1, "uuid-1")];

        let (added, removed, uuid_changed, _kicked) = user_manager.update(&new_users);
        assert_eq!(added, 0);
        assert_eq!(removed, 2);
        assert_eq!(uuid_changed, 0);
        assert_eq!(user_manager.user_count(), 1);
    }

    #[test]
    fn test_user_manager_update_mixed() {
        let conn_manager = ConnectionManager::new();
        let user_manager = UserManager::new(conn_manager);

        let initial_users = vec![create_user(1, "uuid-1"), create_user(2, "uuid-2")];
        user_manager.init(&initial_users);

        let new_users = vec![create_user(2, "uuid-2"), create_user(3, "uuid-3")];

        let (added, removed, uuid_changed, _kicked) = user_manager.update(&new_users);
        assert_eq!(added, 1);
        assert_eq!(removed, 1);
        assert_eq!(uuid_changed, 0);
        assert_eq!(user_manager.user_count(), 2);
    }

    #[test]
    fn test_user_manager_update_uuid_changed() {
        let conn_manager = ConnectionManager::new();

        // Register a connection for user 1
        let (_, _token) = conn_manager.register(1, "127.0.0.1:1234".parse().unwrap());

        let user_manager = UserManager::new(conn_manager);

        let initial_users = vec![create_user(1, "uuid-1"), create_user(2, "uuid-2")];
        user_manager.init(&initial_users);

        // User 1's UUID changed from "uuid-1" to "uuid-1-new"
        let new_users = vec![create_user(1, "uuid-1-new"), create_user(2, "uuid-2")];

        let (added, removed, uuid_changed, kicked) = user_manager.update(&new_users);
        assert_eq!(added, 0);
        assert_eq!(removed, 0);
        assert_eq!(uuid_changed, 1);
        assert_eq!(kicked, 1);
        assert_eq!(user_manager.user_count(), 2);
    }

    #[test]
    fn test_user_manager_get_users_arc() {
        let conn_manager = ConnectionManager::new();
        let user_manager = UserManager::new(conn_manager);

        let users = vec![create_user(1, "uuid-1")];
        user_manager.init(&users);

        let users_arc = user_manager.get_users_arc();
        let users_map = users_arc.load();
        assert_eq!(users_map.len(), 1);
    }

    #[test]
    fn test_user_manager_kick_on_remove() {
        let conn_manager = ConnectionManager::new();

        // Register a connection for user 1
        let (_, _token) = conn_manager.register(1, "127.0.0.1:1234".parse().unwrap());

        let user_manager = UserManager::new(conn_manager);

        let initial_users = vec![create_user(1, "uuid-1")];
        user_manager.init(&initial_users);

        // Remove user 1
        let new_users: Vec<User> = vec![];
        let (_added, removed, _uuid_changed, kicked) = user_manager.update(&new_users);

        assert_eq!(removed, 1);
        assert_eq!(kicked, 1);
    }

    /// Verify that update does not block concurrent reads
    #[test]
    fn test_user_manager_update_does_not_block_reads() {
        let conn_manager = ConnectionManager::new();
        let user_manager = UserManager::new(conn_manager);

        let initial_users = vec![create_user(1, "uuid-1")];
        user_manager.init(&initial_users);

        // Simulate an in-flight read (holds a snapshot)
        let snapshot = user_manager.users.load();
        assert_eq!(snapshot.len(), 1);

        // Update while snapshot is held — this should NOT block
        let new_users = vec![create_user(2, "uuid-2"), create_user(3, "uuid-3")];
        let (added, removed, _, _) = user_manager.update(&new_users);
        assert_eq!(added, 2);
        assert_eq!(removed, 1);

        // Snapshot still sees old data
        assert_eq!(snapshot.len(), 1);

        // New reads see new data
        assert_eq!(user_manager.user_count(), 2);
    }
}
