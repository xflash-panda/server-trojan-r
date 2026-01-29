use anyhow::{anyhow, Result};
use rustls::ServerConfig;
use rustls_pemfile::certs;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

use crate::logger::log;
use crate::TransportMode;

pub fn get_tls_acceptor(
    cert_path: Option<String>,
    key_path: Option<String>,
    transport_mode: TransportMode,
) -> Result<Option<TlsAcceptor>> {
    match (cert_path, key_path) {
        (Some(cert_path_str), Some(key_path_str)) => {
            log::info!(cert = %cert_path_str, key = %key_path_str, "Loading TLS certificates");
            let acceptor =
                load_tls_config_with_transport_mode(&cert_path_str, &key_path_str, transport_mode)?;
            Ok(Some(acceptor))
        }
        _ => Ok(None),
    }
}

fn load_tls_config_with_transport_mode(
    cert_path: &str,
    key_path: &str,
    transport_mode: TransportMode,
) -> Result<TlsAcceptor> {
    let mut config = load_tls_config(cert_path, key_path)?;
    config.alpn_protocols = match transport_mode {
        TransportMode::Grpc | TransportMode::Tcp => {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        }
        TransportMode::WebSocket => {
            vec![b"http/1.1".to_vec()]
        }
    };
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_tls_config(cert_path: &str, key_path: &str) -> Result<ServerConfig> {
    let cert_file = File::open(cert_path)?;
    let mut reader = BufReader::new(cert_file);
    let certs = certs(&mut reader).collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        return Err(anyhow!("No certificates found in {}", cert_path));
    }

    let key_file = File::open(key_path)?;
    let mut reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut reader)?;

    let key = key.ok_or_else(|| anyhow!("No private key found in {}", key_path))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_get_tls_acceptor_none_when_no_paths() {
        let result = get_tls_acceptor(None, None, TransportMode::Tcp);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_get_tls_acceptor_none_when_only_cert() {
        let result = get_tls_acceptor(
            Some("/path/to/cert.pem".to_string()),
            None,
            TransportMode::Tcp,
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_get_tls_acceptor_none_when_only_key() {
        let result = get_tls_acceptor(
            None,
            Some("/path/to/key.pem".to_string()),
            TransportMode::Tcp,
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_get_tls_acceptor_error_on_invalid_cert_path() {
        let result = get_tls_acceptor(
            Some("/nonexistent/cert.pem".to_string()),
            Some("/nonexistent/key.pem".to_string()),
            TransportMode::Tcp,
        );
        assert!(result.is_err());
        let err_msg = result.err().unwrap().to_string();
        assert!(
            err_msg.contains("No such file")
                || err_msg.contains("not found")
                || err_msg.contains("os error")
        );
    }

    #[test]
    fn test_get_tls_acceptor_error_on_empty_cert() {
        let cert_file = NamedTempFile::new().unwrap();
        let key_file = NamedTempFile::new().unwrap();

        let result = get_tls_acceptor(
            Some(cert_file.path().to_string_lossy().to_string()),
            Some(key_file.path().to_string_lossy().to_string()),
            TransportMode::Tcp,
        );
        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("No certificates found"));
    }

    #[test]
    fn test_get_tls_acceptor_error_on_invalid_cert_format() {
        let mut cert_file = NamedTempFile::new().unwrap();
        writeln!(cert_file, "not a valid certificate").unwrap();
        let key_file = NamedTempFile::new().unwrap();

        let result = get_tls_acceptor(
            Some(cert_file.path().to_string_lossy().to_string()),
            Some(key_file.path().to_string_lossy().to_string()),
            TransportMode::Tcp,
        );
        assert!(result.is_err());
    }
}
