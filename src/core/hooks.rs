//! Hook traits for extensibility
//!
//! Defines the extension points that allow business logic to be injected into the core proxy.

use crate::core::Address;
use async_trait::async_trait;

/// User ID type used throughout the system.
/// Using i64 for consistency with database and API layer.
pub type UserId = i64;

/// Authenticator trait for user authentication
#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Authenticate user by password hash, returns user_id if successful
    async fn authenticate(&self, password: &[u8; 56]) -> Option<UserId>;
}

/// Statistics collector trait for traffic tracking
pub trait StatsCollector: Send + Sync {
    /// Record a proxy request
    fn record_request(&self, user_id: UserId);
    /// Record upload bytes (client -> remote)
    fn record_upload(&self, user_id: UserId, bytes: u64);
    /// Record download bytes (remote -> client)
    fn record_download(&self, user_id: UserId, bytes: u64);
}

/// Outbound router trait for routing decisions
#[async_trait]
pub trait OutboundRouter: Send + Sync {
    /// Route based on target address, returns the outbound handler
    async fn route(&self, addr: &Address) -> OutboundType;
}

/// Outbound type for routing decisions
#[derive(Debug, Clone)]
pub enum OutboundType {
    /// Direct connection
    Direct,
    /// Reject connection
    Reject,
}

/// Direct router - routes all traffic directly
pub struct DirectRouter;

#[async_trait]
impl OutboundRouter for DirectRouter {
    async fn route(&self, _addr: &Address) -> OutboundType {
        OutboundType::Direct
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_direct_router() {
        let router = DirectRouter;
        let addr = Address::Domain("example.com".to_string(), 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Direct));
    }
}
