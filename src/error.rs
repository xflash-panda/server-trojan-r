use std::io;
use thiserror::Error;

/// Trojan 服务器统一的错误类型
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum TrojanError {
    /// IO 错误
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// 配置错误
    #[error("Configuration error: {0}")]
    Config(String),

    /// 协议解析错误
    #[error("Protocol parse error: {0}")]
    ProtocolParse(String),

    /// 认证错误
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// TLS 错误
    #[error("TLS error: {0}")]
    Tls(String),

    /// 网络连接错误
    #[error("Network connection error: {0}")]
    Connection(String),

    /// 传输层错误
    #[error("Transport error: {0}")]
    Transport(String),

    /// 其他错误
    #[error("{0}")]
    Other(String),
}

/// 结果类型别名
#[allow(dead_code)]
pub type Result<T> = std::result::Result<T, TrojanError>;

impl From<anyhow::Error> for TrojanError {
    fn from(err: anyhow::Error) -> Self {
        TrojanError::Other(err.to_string())
    }
}

impl From<toml::de::Error> for TrojanError {
    fn from(err: toml::de::Error) -> Self {
        TrojanError::Config(format!("TOML parse error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_error_display() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let trojan_err: TrojanError = io_err.into();
        let display = format!("{}", trojan_err);
        assert!(display.contains("IO error"));
        assert!(display.contains("file not found"));
    }

    #[test]
    fn test_config_error_display() {
        let err = TrojanError::Config("invalid port".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Configuration error"));
        assert!(display.contains("invalid port"));
    }

    #[test]
    fn test_protocol_parse_error_display() {
        let err = TrojanError::ProtocolParse("invalid header".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Protocol parse error"));
        assert!(display.contains("invalid header"));
    }

    #[test]
    fn test_authentication_error_display() {
        let err = TrojanError::Authentication("invalid password".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Authentication error"));
        assert!(display.contains("invalid password"));
    }

    #[test]
    fn test_tls_error_display() {
        let err = TrojanError::Tls("certificate expired".to_string());
        let display = format!("{}", err);
        assert!(display.contains("TLS error"));
        assert!(display.contains("certificate expired"));
    }

    #[test]
    fn test_connection_error_display() {
        let err = TrojanError::Connection("connection refused".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Network connection error"));
        assert!(display.contains("connection refused"));
    }

    #[test]
    fn test_transport_error_display() {
        let err = TrojanError::Transport("stream closed".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Transport error"));
        assert!(display.contains("stream closed"));
    }

    #[test]
    fn test_other_error_display() {
        let err = TrojanError::Other("unknown error".to_string());
        let display = format!("{}", err);
        assert!(display.contains("unknown error"));
    }

    #[test]
    fn test_from_anyhow_error() {
        let anyhow_err = anyhow::anyhow!("some anyhow error");
        let trojan_err: TrojanError = anyhow_err.into();
        let display = format!("{}", trojan_err);
        assert!(display.contains("some anyhow error"));
    }

    #[test]
    fn test_error_debug() {
        let err = TrojanError::Config("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Config"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_result_type_alias() {
        fn test_fn() -> Result<i32> {
            Ok(42)
        }
        assert_eq!(test_fn().unwrap(), 42);
    }

    #[test]
    fn test_result_type_alias_error() {
        fn test_fn() -> Result<i32> {
            Err(TrojanError::Other("failed".to_string()))
        }
        assert!(test_fn().is_err());
    }
}
