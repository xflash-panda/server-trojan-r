//! Transport layer abstraction
//!
//! Provides unified interface for different transport protocols:
//! - TCP (plain)
//! - TLS (TCP + TLS)
//! - WebSocket (over TCP or TLS)
//! - gRPC (HTTP/2 over TCP or TLS)

pub mod grpc;
mod tls;
mod ws;

pub use grpc::GrpcConnection;
pub use tls::TlsTransportListener;
pub use ws::WebSocketTransport;

use std::net::SocketAddr;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

/// Unified transport stream trait combining AsyncRead + AsyncWrite + Send + Unpin
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}

/// Unified transport stream type
pub type TransportStream = Pin<Box<dyn AsyncStream>>;

/// Transport type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    /// Plain TCP
    Tcp,
    /// WebSocket over TCP/TLS
    WebSocket,
    /// gRPC (HTTP/2) over TCP/TLS
    Grpc,
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportType::Tcp => write!(f, "tcp"),
            TransportType::WebSocket => write!(f, "ws"),
            TransportType::Grpc => write!(f, "grpc"),
        }
    }
}

/// Connection metadata
#[derive(Debug, Clone)]
pub struct ConnectionMeta {
    /// Client peer address
    pub peer_addr: SocketAddr,
    /// Transport type
    pub transport_type: TransportType,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_type_display() {
        assert_eq!(format!("{}", TransportType::Tcp), "tcp");
        assert_eq!(format!("{}", TransportType::WebSocket), "ws");
        assert_eq!(format!("{}", TransportType::Grpc), "grpc");
    }

    #[test]
    fn test_transport_type_eq() {
        assert_eq!(TransportType::Tcp, TransportType::Tcp);
        assert_ne!(TransportType::Tcp, TransportType::WebSocket);
    }

    #[test]
    fn test_connection_meta_clone() {
        let meta = ConnectionMeta {
            peer_addr: "127.0.0.1:1234".parse().unwrap(),
            transport_type: TransportType::Tcp,
        };
        let cloned = meta.clone();
        assert_eq!(cloned.peer_addr, meta.peer_addr);
        assert_eq!(cloned.transport_type, meta.transport_type);
    }
}
