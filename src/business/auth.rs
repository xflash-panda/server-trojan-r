//! API-based authentication implementation

use arc_swap::ArcSwap;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

use crate::core::hooks::Authenticator;
use crate::core::UserId;

/// API-based authenticator that uses a shared user map
///
/// Uses ArcSwap for lock-free reads on the hot authentication path.
/// Updates atomically swap the entire map, so readers never block.
pub struct ApiAuthenticator {
    /// Shared users map: password_hex -> user_id
    users: Arc<ArcSwap<HashMap<[u8; 56], UserId>>>,
}

impl ApiAuthenticator {
    /// Create a new API authenticator with a shared user map
    pub fn new(users: Arc<ArcSwap<HashMap<[u8; 56], UserId>>>) -> Self {
        Self { users }
    }

    /// Get user count
    #[allow(dead_code)]
    pub fn user_count(&self) -> usize {
        self.users.load().len()
    }
}

#[async_trait]
impl Authenticator for ApiAuthenticator {
    async fn authenticate(&self, password: &[u8; 56]) -> Option<UserId> {
        self.users.load().get(password).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_api_authenticator_new() {
        let users = Arc::new(ArcSwap::from_pointee(HashMap::new()));
        let auth = ApiAuthenticator::new(users);
        assert_eq!(auth.user_count(), 0);
    }

    #[tokio::test]
    async fn test_api_authenticator_authenticate_success() {
        let mut map = HashMap::new();
        let password = [b'a'; 56];
        map.insert(password, 42 as UserId);

        let users = Arc::new(ArcSwap::from_pointee(map));
        let auth = ApiAuthenticator::new(users);

        assert_eq!(auth.authenticate(&password).await, Some(42));
    }

    #[tokio::test]
    async fn test_api_authenticator_authenticate_failure() {
        let users = Arc::new(ArcSwap::from_pointee(HashMap::new()));
        let auth = ApiAuthenticator::new(users);

        let password = [b'x'; 56];
        assert_eq!(auth.authenticate(&password).await, None);
    }

    #[tokio::test]
    async fn test_api_authenticator_shared_update() {
        let users = Arc::new(ArcSwap::from_pointee(HashMap::new()));
        let auth = ApiAuthenticator::new(Arc::clone(&users));

        let password = [b'b'; 56];

        // Initially not found
        assert_eq!(auth.authenticate(&password).await, None);

        // Update shared map via atomic swap
        let mut new_map = HashMap::new();
        new_map.insert(password, 100);
        users.store(Arc::new(new_map));

        // Now found
        assert_eq!(auth.authenticate(&password).await, Some(100));
        assert_eq!(auth.user_count(), 1);
    }

    /// Verify that in-flight reads see a consistent snapshot even during updates
    #[test]
    fn test_api_authenticator_snapshot_consistency() {
        let mut map = HashMap::new();
        let pw1 = [b'1'; 56];
        let pw2 = [b'2'; 56];
        map.insert(pw1, 1);
        map.insert(pw2, 2);

        let users = Arc::new(ArcSwap::from_pointee(map));
        let auth = ApiAuthenticator::new(Arc::clone(&users));

        // Take a snapshot (simulates an in-flight read)
        let snapshot = auth.users.load();
        assert_eq!(snapshot.get(&pw1).copied(), Some(1));
        assert_eq!(snapshot.get(&pw2).copied(), Some(2));

        // Swap to a completely different map while snapshot is held
        let mut new_map = HashMap::new();
        new_map.insert(pw1, 100); // pw1 changed
        // pw2 removed
        users.store(Arc::new(new_map));

        // Snapshot still sees old data (consistent read)
        assert_eq!(snapshot.get(&pw1).copied(), Some(1));
        assert_eq!(snapshot.get(&pw2).copied(), Some(2));

        // New reads see new data
        assert_eq!(auth.users.load().get(&pw1).copied(), Some(100));
        assert_eq!(auth.users.load().get(&pw2).copied(), None);
    }
}
