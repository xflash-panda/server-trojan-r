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

/// Direct router - routes all traffic directly with optional private IP blocking
pub struct DirectRouter {
    /// Block connections to private/loopback IP addresses
    block_private_ip: bool,
}

impl DirectRouter {
    /// Create a new DirectRouter with private IP blocking enabled (default)
    pub fn new() -> Self {
        Self {
            block_private_ip: true,
        }
    }

    /// Create a new DirectRouter with custom private IP blocking setting
    pub fn with_block_private_ip(block_private_ip: bool) -> Self {
        Self { block_private_ip }
    }
}

impl Default for DirectRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OutboundRouter for DirectRouter {
    async fn route(&self, addr: &Address) -> OutboundType {
        if self.block_private_ip && is_private_address(addr).await {
            return OutboundType::Reject;
        }
        OutboundType::Direct
    }
}

/// Check if an address is private/loopback/link-local
async fn is_private_address(addr: &Address) -> bool {
    use super::ip_filter::{is_private_ipv4, is_private_ipv6};
    use std::net::{Ipv4Addr, Ipv6Addr};

    match addr {
        Address::IPv4(ip, _) => {
            let ipv4 = Ipv4Addr::from(*ip);
            is_private_ipv4(&ipv4)
        }
        Address::IPv6(ip, _) => {
            let ipv6 = Ipv6Addr::from(*ip);
            is_private_ipv6(&ipv6)
        }
        Address::Domain(domain, _) => {
            // Resolve domain and check if it resolves to private IP
            use tokio::net::lookup_host;
            let lookup = format!("{}:0", domain);
            if let Ok(addrs) = lookup_host(&lookup).await {
                for addr in addrs {
                    match addr.ip() {
                        std::net::IpAddr::V4(ipv4) => {
                            if is_private_ipv4(&ipv4) {
                                return true;
                            }
                        }
                        std::net::IpAddr::V6(ipv6) => {
                            if is_private_ipv6(&ipv6) {
                                return true;
                            }
                        }
                    }
                }
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_direct_router_public_domain() {
        let router = DirectRouter::new();
        let addr = Address::Domain("example.com".to_string(), 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Direct));
    }

    #[tokio::test]
    async fn test_direct_router_blocks_loopback() {
        let router = DirectRouter::new();
        let addr = Address::IPv4([127, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Reject));
    }

    #[tokio::test]
    async fn test_direct_router_blocks_private_ip() {
        let router = DirectRouter::new();

        // 10.0.0.0/8
        let addr = Address::IPv4([10, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Reject));

        // 192.168.0.0/16
        let addr = Address::IPv4([192, 168, 1, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Reject));
    }

    #[tokio::test]
    async fn test_direct_router_allows_public_ip() {
        let router = DirectRouter::new();
        let addr = Address::IPv4([8, 8, 8, 8], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Direct));
    }

    #[tokio::test]
    async fn test_direct_router_allows_private_when_disabled() {
        let router = DirectRouter::with_block_private_ip(false);
        let addr = Address::IPv4([127, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Direct));
    }
}
