//! API-based authentication implementation

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::core::hooks::Authenticator;
use crate::core::UserId;

/// API-based authenticator that uses a shared user map
pub struct ApiAuthenticator {
    /// Shared users map: password_hex -> user_id
    users: Arc<RwLock<HashMap<[u8; 56], UserId>>>,
}

impl ApiAuthenticator {
    /// Create a new API authenticator with a shared user map
    pub fn new(users: Arc<RwLock<HashMap<[u8; 56], UserId>>>) -> Self {
        Self { users }
    }

    /// Get user count
    #[allow(dead_code)]
    pub async fn user_count(&self) -> usize {
        self.users.read().await.len()
    }
}

#[async_trait]
impl Authenticator for ApiAuthenticator {
    async fn authenticate(&self, password: &[u8; 56]) -> Option<UserId> {
        self.users.read().await.get(password).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_api_authenticator_new() {
        let users = Arc::new(RwLock::new(HashMap::new()));
        let auth = ApiAuthenticator::new(users);
        assert_eq!(auth.user_count().await, 0);
    }

    #[tokio::test]
    async fn test_api_authenticator_authenticate_success() {
        let mut map = HashMap::new();
        let password = [b'a'; 56];
        map.insert(password, 42 as UserId);

        let users = Arc::new(RwLock::new(map));
        let auth = ApiAuthenticator::new(users);

        assert_eq!(auth.authenticate(&password).await, Some(42));
    }

    #[tokio::test]
    async fn test_api_authenticator_authenticate_failure() {
        let users = Arc::new(RwLock::new(HashMap::new()));
        let auth = ApiAuthenticator::new(users);

        let password = [b'x'; 56];
        assert_eq!(auth.authenticate(&password).await, None);
    }

    #[tokio::test]
    async fn test_api_authenticator_shared_update() {
        let users = Arc::new(RwLock::new(HashMap::new()));
        let auth = ApiAuthenticator::new(Arc::clone(&users));

        let password = [b'b'; 56];

        // Initially not found
        assert_eq!(auth.authenticate(&password).await, None);

        // Update shared map
        users.write().await.insert(password, 100);

        // Now found
        assert_eq!(auth.authenticate(&password).await, Some(100));
        assert_eq!(auth.user_count().await, 1);
    }
}
