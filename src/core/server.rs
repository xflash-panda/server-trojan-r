//! Core proxy server implementation
//!
//! The Server struct coordinates all components and handles connections.

use std::sync::Arc;

use super::connection::ConnectionManager;
use super::hooks::{Authenticator, DirectRouter, OutboundRouter, StatsCollector};
use crate::config::ConnConfig;

/// Core proxy server
pub struct Server {
    /// Authenticator for user validation
    pub authenticator: Arc<dyn Authenticator>,
    /// Statistics collector
    pub stats: Arc<dyn StatsCollector>,
    /// Outbound router for traffic routing
    pub router: Arc<dyn OutboundRouter>,
    /// Connection manager
    pub conn_manager: ConnectionManager,
    /// Connection performance configuration
    pub conn_config: ConnConfig,
}

impl Server {
    /// Create a new server builder
    pub fn builder() -> ServerBuilder {
        ServerBuilder::new()
    }
}

/// Builder for constructing a Server
pub struct ServerBuilder {
    authenticator: Option<Arc<dyn Authenticator>>,
    stats: Option<Arc<dyn StatsCollector>>,
    router: Option<Arc<dyn OutboundRouter>>,
    conn_manager: Option<ConnectionManager>,
    conn_config: Option<ConnConfig>,
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerBuilder {
    /// Create a new server builder with default settings
    pub fn new() -> Self {
        Self {
            authenticator: None,
            stats: None,
            router: None,
            conn_manager: None,
            conn_config: None,
        }
    }

    /// Set authenticator
    pub fn authenticator(mut self, auth: Arc<dyn Authenticator>) -> Self {
        self.authenticator = Some(auth);
        self
    }

    /// Set statistics collector
    pub fn stats(mut self, stats: Arc<dyn StatsCollector>) -> Self {
        self.stats = Some(stats);
        self
    }

    /// Set outbound router
    pub fn router(mut self, router: Arc<dyn OutboundRouter>) -> Self {
        self.router = Some(router);
        self
    }

    /// Set connection manager
    pub fn conn_manager(mut self, manager: ConnectionManager) -> Self {
        self.conn_manager = Some(manager);
        self
    }

    /// Set connection configuration
    pub fn conn_config(mut self, config: ConnConfig) -> Self {
        self.conn_config = Some(config);
        self
    }

    /// Build the server
    ///
    /// Panics if authenticator, stats collector or conn_config is not set
    pub fn build(self) -> Server {
        Server {
            authenticator: self.authenticator.expect("authenticator is required"),
            stats: self.stats.expect("stats collector is required"),
            router: self.router.unwrap_or_else(|| Arc::new(DirectRouter::new())),
            conn_manager: self.conn_manager.unwrap_or_default(),
            conn_config: self.conn_config.expect("conn_config is required"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::UserId;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    // Simple test implementations
    struct TestAuthenticator;

    #[async_trait::async_trait]
    impl Authenticator for TestAuthenticator {
        async fn authenticate(&self, _password: &[u8; 56]) -> Option<UserId> {
            Some(1)
        }
    }

    struct TestStatsCollector {
        requests: AtomicU64,
    }

    impl TestStatsCollector {
        fn new() -> Self {
            Self {
                requests: AtomicU64::new(0),
            }
        }
    }

    impl StatsCollector for TestStatsCollector {
        fn record_request(&self, _user_id: UserId) {
            self.requests.fetch_add(1, Ordering::Relaxed);
        }
        fn record_upload(&self, _user_id: UserId, _bytes: u64) {}
        fn record_download(&self, _user_id: UserId, _bytes: u64) {}
    }

    fn test_conn_config() -> ConnConfig {
        ConnConfig {
            idle_timeout: Duration::from_secs(300),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(5),
            tls_handshake_timeout: Duration::from_secs(10),
            buffer_size: 32 * 1024,
            tcp_backlog: 1024,
            tcp_nodelay: true,
        }
    }

    #[test]
    fn test_server_builder() {
        let _server = Server::builder()
            .authenticator(Arc::new(TestAuthenticator))
            .stats(Arc::new(TestStatsCollector::new()))
            .conn_config(test_conn_config())
            .build();
    }

    #[test]
    fn test_server_builder_with_conn_manager() {
        let conn_manager = ConnectionManager::new();
        let _server = Server::builder()
            .authenticator(Arc::new(TestAuthenticator))
            .stats(Arc::new(TestStatsCollector::new()))
            .conn_manager(conn_manager)
            .conn_config(test_conn_config())
            .build();
    }
}
