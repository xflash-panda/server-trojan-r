//! TLS configuration utilities
//!
//! Provides TLS certificate loading for the server.

use rustls::ServerConfig;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

/// TLS transport listener helper (provides TLS config loading)
pub struct TlsTransportListener;

impl TlsTransportListener {
    /// Create TLS config from certificate and key files
    pub fn load_tls_config(
        cert_path: &Path,
        key_path: &Path,
    ) -> std::io::Result<Arc<ServerConfig>> {
        // Load certificates
        let cert_file = File::open(cert_path)?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
            .filter_map(|r| r.ok())
            .collect();

        if certs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "No certificates found in cert file",
            ));
        }

        // Load private key
        let key_file = File::open(key_path)?;
        let mut key_reader = BufReader::new(key_file);
        let key = rustls_pemfile::private_key(&mut key_reader)?.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "No private key found")
        })?;

        // Build TLS config
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Enable TLS session tickets for faster reconnection.
        // Clients that reconnect skip the full handshake, saving ~1 RTT.
        // Keys are automatically rotated by rustls's TicketSwitcher.
        if let Ok(ticketer) = rustls::crypto::ring::Ticketer::new() {
            config.ticketer = ticketer;
        }

        Ok(Arc::new(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_tls_config_invalid_cert() {
        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(b"invalid cert").unwrap();

        let mut key_file = NamedTempFile::new().unwrap();
        key_file.write_all(b"invalid key").unwrap();

        let result = TlsTransportListener::load_tls_config(cert_file.path(), key_file.path());

        assert!(result.is_err());
    }
}
