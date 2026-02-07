//! User management with hot-reload and kick-off capability

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::super::password_to_hex;
use crate::config::User;
use crate::core::{ConnectionManager, UserId};
use crate::logger::log;

/// User manager for handling user hot-reload with kick-off capability
pub struct UserManager {
    /// Current users map: password_hex -> user_id
    users: Arc<RwLock<HashMap<[u8; 56], UserId>>>,
    /// Connection manager for kick-off
    connections: ConnectionManager,
}

impl UserManager {
    /// Create a new user manager
    pub fn new(connections: ConnectionManager) -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            connections,
        }
    }

    /// Get a clone of the current users map
    #[allow(dead_code)]
    pub async fn get_users(&self) -> HashMap<[u8; 56], UserId> {
        self.users.read().await.clone()
    }

    /// Get arc reference to users for Server
    pub fn get_users_arc(&self) -> Arc<RwLock<HashMap<[u8; 56], UserId>>> {
        Arc::clone(&self.users)
    }

    /// Initialize with users
    pub async fn init(&self, users: &[User]) {
        let mut users_map = self.users.write().await;
        users_map.clear();

        for user in users {
            let hex = password_to_hex(&user.uuid);
            users_map.insert(hex, user.id);
        }

        log::info!(count = users.len(), "Users initialized");
    }

    /// Update users with hot-reload
    ///
    /// - Add new users
    /// - Remove deleted users and kick their connections
    /// - Detect UUID changes and kick affected connections
    pub async fn update(&self, new_users: &[User]) -> (usize, usize, usize, usize) {
        let mut users_map = self.users.write().await;

        // Build new map and user_id set
        let mut new_map: HashMap<[u8; 56], UserId> = HashMap::with_capacity(new_users.len());
        let new_user_ids: HashSet<UserId> = new_users.iter().map(|u| u.id).collect();

        for user in new_users {
            let hex = password_to_hex(&user.uuid);
            new_map.insert(hex, user.id);
        }

        // Collect old user_ids from current map
        let old_user_ids: HashSet<UserId> = users_map.values().copied().collect();

        let added = new_user_ids.difference(&old_user_ids).count();
        let removed = old_user_ids.difference(&new_user_ids).count();
        let mut uuid_changed = 0;
        let mut kicked = 0;

        // Kick removed users
        for user_id in old_user_ids.difference(&new_user_ids) {
            let k = self.connections.kick_user(*user_id);
            kicked += k;
            if k > 0 {
                log::info!(user_id = user_id, kicked = k, "User removed and kicked");
            }
        }

        // Kick users with UUID changes
        for (new_hex, &new_id) in &new_map {
            if old_user_ids.contains(&new_id) {
                // User exists in old map, check if password_hex changed
                if users_map.get(new_hex) != Some(&new_id) {
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

        // Replace map
        *users_map = new_map;

        if added > 0 || removed > 0 || uuid_changed > 0 {
            log::info!(
                added = added,
                removed = removed,
                uuid_changed = uuid_changed,
                kicked = kicked,
                total = users_map.len(),
                "Users updated"
            );
        }

        (added, removed, uuid_changed, kicked)
    }

    /// Get user count
    #[allow(dead_code)]
    pub async fn user_count(&self) -> usize {
        self.users.read().await.len()
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

    #[tokio::test]
    async fn test_user_manager_new() {
        let conn_manager = ConnectionManager::new();
        let user_manager = UserManager::new(conn_manager);
        assert_eq!(user_manager.user_count().await, 0);
    }

    #[tokio::test]
    async fn test_user_manager_init() {
        let conn_manager = ConnectionManager::new();
        let user_manager = UserManager::new(conn_manager);

        let users = vec![create_user(1, "uuid-1"), create_user(2, "uuid-2")];

        user_manager.init(&users).await;
        assert_eq!(user_manager.user_count().await, 2);
    }

    #[tokio::test]
    async fn test_user_manager_update_add_users() {
        let conn_manager = ConnectionManager::new();
        let user_manager = UserManager::new(conn_manager);

        let initial_users = vec![create_user(1, "uuid-1")];
        user_manager.init(&initial_users).await;

        let new_users = vec![
            create_user(1, "uuid-1"),
            create_user(2, "uuid-2"),
            create_user(3, "uuid-3"),
        ];

        let (added, removed, uuid_changed, kicked) = user_manager.update(&new_users).await;
        assert_eq!(added, 2);
        assert_eq!(removed, 0);
        assert_eq!(uuid_changed, 0);
        assert_eq!(kicked, 0);
        assert_eq!(user_manager.user_count().await, 3);
    }

    #[tokio::test]
    async fn test_user_manager_update_remove_users() {
        let conn_manager = ConnectionManager::new();
        let user_manager = UserManager::new(conn_manager);

        let initial_users = vec![
            create_user(1, "uuid-1"),
            create_user(2, "uuid-2"),
            create_user(3, "uuid-3"),
        ];
        user_manager.init(&initial_users).await;

        let new_users = vec![create_user(1, "uuid-1")];

        let (added, removed, uuid_changed, _kicked) = user_manager.update(&new_users).await;
        assert_eq!(added, 0);
        assert_eq!(removed, 2);
        assert_eq!(uuid_changed, 0);
        assert_eq!(user_manager.user_count().await, 1);
    }

    #[tokio::test]
    async fn test_user_manager_update_mixed() {
        let conn_manager = ConnectionManager::new();
        let user_manager = UserManager::new(conn_manager);

        let initial_users = vec![create_user(1, "uuid-1"), create_user(2, "uuid-2")];
        user_manager.init(&initial_users).await;

        let new_users = vec![create_user(2, "uuid-2"), create_user(3, "uuid-3")];

        let (added, removed, uuid_changed, _kicked) = user_manager.update(&new_users).await;
        assert_eq!(added, 1);
        assert_eq!(removed, 1);
        assert_eq!(uuid_changed, 0);
        assert_eq!(user_manager.user_count().await, 2);
    }

    #[tokio::test]
    async fn test_user_manager_update_uuid_changed() {
        let conn_manager = ConnectionManager::new();

        // Register a connection for user 1
        let (_, _token) = conn_manager.register(1, "127.0.0.1:1234".to_string());

        let user_manager = UserManager::new(conn_manager);

        let initial_users = vec![create_user(1, "uuid-1"), create_user(2, "uuid-2")];
        user_manager.init(&initial_users).await;

        // User 1's UUID changed from "uuid-1" to "uuid-1-new"
        let new_users = vec![create_user(1, "uuid-1-new"), create_user(2, "uuid-2")];

        let (added, removed, uuid_changed, kicked) = user_manager.update(&new_users).await;
        assert_eq!(added, 0);
        assert_eq!(removed, 0);
        assert_eq!(uuid_changed, 1);
        assert_eq!(kicked, 1);
        assert_eq!(user_manager.user_count().await, 2);
    }

    #[tokio::test]
    async fn test_user_manager_get_users_arc() {
        let conn_manager = ConnectionManager::new();
        let user_manager = UserManager::new(conn_manager);

        let users = vec![create_user(1, "uuid-1")];
        user_manager.init(&users).await;

        let users_arc = user_manager.get_users_arc();
        let users_map = users_arc.read().await;
        assert_eq!(users_map.len(), 1);
    }

    #[tokio::test]
    async fn test_user_manager_kick_on_remove() {
        let conn_manager = ConnectionManager::new();

        // Register a connection for user 1
        let (_, _token) = conn_manager.register(1, "127.0.0.1:1234".to_string());

        let user_manager = UserManager::new(conn_manager);

        let initial_users = vec![create_user(1, "uuid-1")];
        user_manager.init(&initial_users).await;

        // Remove user 1
        let new_users: Vec<User> = vec![];
        let (_added, removed, _uuid_changed, kicked) = user_manager.update(&new_users).await;

        assert_eq!(removed, 1);
        assert_eq!(kicked, 1);
    }
}
