//! Configuration module for Trojan server
//!
//! This module handles CLI argument parsing with environment variable support.
//! Configuration is fetched from remote panel API, not from local files.

use anyhow::{anyhow, Result};
use clap::Parser;
use std::path::PathBuf;

/// Default intervals in seconds
const DEFAULT_FETCH_USERS_INTERVAL: u64 = 60;
const DEFAULT_REPORT_TRAFFICS_INTERVAL: u64 = 80;
const DEFAULT_HEARTBEAT_INTERVAL: u64 = 180;

/// Default data directory for state persistence (same as server-trojan Go version)
const DEFAULT_DATA_DIR: &str = "/var/lib/trojan-node";

/// CLI arguments for the Trojan server
///
/// Supports environment variables with X_PANDA_TROJAN_ prefix
#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Trojan Server with Remote Panel Integration")]
pub struct CliArgs {
    /// API endpoint URL (required)
    #[arg(long, env = "X_PANDA_TROJAN_API")]
    pub api: String,

    /// API authentication token (required)
    #[arg(long, env = "X_PANDA_TROJAN_TOKEN")]
    pub token: String,

    /// Node ID from the panel (required)
    #[arg(long, env = "X_PANDA_TROJAN_NODE")]
    pub node: i64,

    /// TLS certificate file path (required)
    #[arg(long, env = "X_PANDA_TROJAN_CERT_FILE")]
    pub cert_file: String,

    /// TLS private key file path (required)
    #[arg(long, env = "X_PANDA_TROJAN_KEY_FILE")]
    pub key_file: String,

    /// Interval for fetching users in seconds (default: 60)
    #[arg(long, env = "X_PANDA_TROJAN_FETCH_USERS_INTERVAL", default_value_t = DEFAULT_FETCH_USERS_INTERVAL)]
    pub fetch_users_interval: u64,

    /// Interval for reporting traffic in seconds (default: 80)
    #[arg(long, env = "X_PANDA_TROJAN_REPORT_TRAFFICS_INTERVAL", default_value_t = DEFAULT_REPORT_TRAFFICS_INTERVAL)]
    pub report_traffics_interval: u64,

    /// Interval for sending heartbeat in seconds (default: 180)
    #[arg(long, env = "X_PANDA_TROJAN_HEARTBEAT_INTERVAL", default_value_t = DEFAULT_HEARTBEAT_INTERVAL)]
    pub heartbeat_interval: u64,

    /// Log mode: debug, info, warn, error (default: info)
    #[arg(long, env = "X_PANDA_TROJAN_LOG_MODE", default_value = "info")]
    pub log_mode: String,

    /// Data directory for state persistence (default: /var/lib/trojan-node)
    #[arg(long, env = "X_PANDA_TROJAN_DATA_DIR", default_value = DEFAULT_DATA_DIR)]
    pub data_dir: PathBuf,

    /// Extended configuration file path (ACL config, YAML format)
    #[arg(long, env = "X_PANDA_TROJAN_EXT_CONF_FILE")]
    pub ext_conf_file: Option<PathBuf>,
}

impl CliArgs {
    /// Parse CLI arguments
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Validate the CLI arguments
    pub fn validate(&self) -> Result<()> {
        if self.api.is_empty() {
            return Err(anyhow!("API endpoint URL is required"));
        }
        if self.token.is_empty() {
            return Err(anyhow!("API token is required"));
        }
        if self.node <= 0 {
            return Err(anyhow!("Node ID must be a positive integer"));
        }

        // Validate TLS cert/key - both are required for Trojan protocol
        if self.cert_file.is_empty() {
            return Err(anyhow!("TLS certificate file path is required (--cert-file)"));
        }
        if self.key_file.is_empty() {
            return Err(anyhow!("TLS private key file path is required (--key-file)"));
        }

        // Validate cert file exists
        let cert_path = std::path::Path::new(&self.cert_file);
        if !cert_path.exists() {
            return Err(anyhow!("TLS certificate file not found: {}", self.cert_file));
        }

        // Validate key file exists
        let key_path = std::path::Path::new(&self.key_file);
        if !key_path.exists() {
            return Err(anyhow!("TLS private key file not found: {}", self.key_file));
        }

        // Validate intervals
        if self.fetch_users_interval == 0 {
            return Err(anyhow!("fetch_users_interval must be greater than 0"));
        }
        if self.report_traffics_interval == 0 {
            return Err(anyhow!("report_traffics_interval must be greater than 0"));
        }
        if self.heartbeat_interval == 0 {
            return Err(anyhow!("heartbeat_interval must be greater than 0"));
        }

        // Validate ext_conf_file if provided
        if let Some(ref path) = self.ext_conf_file {
            if !path.exists() {
                return Err(anyhow!("ACL config file not found: {}", path.display()));
            }
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !ext.eq_ignore_ascii_case("yaml") && !ext.eq_ignore_ascii_case("yml") {
                return Err(anyhow!(
                    "Invalid ACL config file format: expected .yaml or .yml extension"
                ));
            }
        }

        Ok(())
    }

    /// Get the state file path for register_id persistence
    pub fn get_state_file_path(&self) -> PathBuf {
        self.data_dir.join(".trojan_state")
    }
}

/// User configuration with id for tracking and uuid for authentication
#[derive(Debug, Clone)]
pub struct User {
    /// User ID for traffic statistics and user management
    pub id: i64,
    /// UUID used for authentication (this is what gets validated as the "password")
    pub uuid: String,
}

impl From<server_r_client::User> for User {
    fn from(u: server_r_client::User) -> Self {
        Self {
            id: u.id,
            uuid: u.uuid,
        }
    }
}

/// Runtime server configuration (built from remote panel config + CLI args)
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Host address to bind
    pub host: String,
    /// Port number
    pub port: u16,
    /// Enable WebSocket mode
    pub enable_ws: bool,
    /// Enable gRPC mode
    pub enable_grpc: bool,
    /// TLS certificate file path
    pub cert: Option<PathBuf>,
    /// TLS private key file path
    pub key: Option<PathBuf>,
    /// ACL config file path
    pub acl_conf_file: Option<PathBuf>,
    /// Data directory for geo data files (default: /var/lib/trojan-node)
    pub data_dir: PathBuf,
}

impl ServerConfig {
    /// Build ServerConfig from remote TrojanConfig and CLI args
    pub fn from_remote(
        remote: &server_r_client::TrojanConfig,
        cli: &CliArgs,
        _users: Vec<User>,
    ) -> Result<Self> {
        // Determine transport mode from remote config
        let network = remote.network.as_deref().unwrap_or("tcp");
        let (enable_ws, enable_grpc) = match network.to_lowercase().as_str() {
            "ws" | "websocket" => (true, false),
            "grpc" => (false, true),
            _ => (false, false),
        };

        // Use CLI cert/key (required)
        let cert = Some(PathBuf::from(&cli.cert_file));
        let key = Some(PathBuf::from(&cli.key_file));

        Ok(Self {
            host: "0.0.0.0".to_string(), // Always bind to all interfaces
            port: remote.server_port,
            enable_ws,
            enable_grpc,
            cert,
            key,
            acl_conf_file: cli.ext_conf_file.clone(),
            data_dir: cli.data_dir.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_cli_args() -> CliArgs {
        CliArgs {
            api: "https://api.example.com".to_string(),
            token: "test-token".to_string(),
            node: 1,
            cert_file: "/path/to/cert.pem".to_string(),
            key_file: "/path/to/key.pem".to_string(),
            fetch_users_interval: 60,
            report_traffics_interval: 80,
            heartbeat_interval: 180,
            log_mode: "info".to_string(),
            data_dir: PathBuf::from(DEFAULT_DATA_DIR),
            ext_conf_file: None,
        }
    }

    fn create_test_cli_args_with_temp_certs() -> (CliArgs, tempfile::TempDir) {
        let temp_dir = tempfile::tempdir().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        // Create dummy cert and key files
        std::fs::write(&cert_path, "dummy cert").unwrap();
        std::fs::write(&key_path, "dummy key").unwrap();

        let cli = CliArgs {
            api: "https://api.example.com".to_string(),
            token: "test-token".to_string(),
            node: 1,
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
            fetch_users_interval: 60,
            report_traffics_interval: 80,
            heartbeat_interval: 180,
            log_mode: "info".to_string(),
            data_dir: PathBuf::from(DEFAULT_DATA_DIR),
            ext_conf_file: None,
        };
        (cli, temp_dir)
    }

    #[test]
    fn test_cli_args_defaults() {
        // Test that default values are correct
        assert_eq!(DEFAULT_FETCH_USERS_INTERVAL, 60);
        assert_eq!(DEFAULT_REPORT_TRAFFICS_INTERVAL, 80);
        assert_eq!(DEFAULT_HEARTBEAT_INTERVAL, 180);
    }

    #[test]
    fn test_cli_args_validate_success() {
        let (cli, _temp_dir) = create_test_cli_args_with_temp_certs();
        assert!(cli.validate().is_ok());
    }

    #[test]
    fn test_cli_args_validate_empty_api() {
        let mut cli = create_test_cli_args();
        cli.api = "".to_string();
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_empty_token() {
        let mut cli = create_test_cli_args();
        cli.token = "".to_string();
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_invalid_node_id() {
        let mut cli = create_test_cli_args();
        cli.node = 0;
        assert!(cli.validate().is_err());

        cli.node = -1;
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_empty_cert() {
        let mut cli = create_test_cli_args();
        cli.cert_file = "".to_string();
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_empty_key() {
        let mut cli = create_test_cli_args();
        cli.key_file = "".to_string();
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_cert_file_not_found() {
        let mut cli = create_test_cli_args();
        cli.cert_file = "/nonexistent/path/cert.pem".to_string();
        cli.key_file = "/nonexistent/path/key.pem".to_string();
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_with_valid_cert_files() {
        let (cli, _temp_dir) = create_test_cli_args_with_temp_certs();
        assert!(cli.validate().is_ok());
    }

    #[test]
    fn test_cli_args_validate_zero_interval() {
        let (mut cli, _temp_dir) = create_test_cli_args_with_temp_certs();
        cli.fetch_users_interval = 0;
        assert!(cli.validate().is_err());

        let (mut cli, _temp_dir) = create_test_cli_args_with_temp_certs();
        cli.report_traffics_interval = 0;
        assert!(cli.validate().is_err());

        let (mut cli, _temp_dir) = create_test_cli_args_with_temp_certs();
        cli.heartbeat_interval = 0;
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_get_state_file_path() {
        let mut cli = create_test_cli_args();
        cli.data_dir = PathBuf::from("/tmp/test-data");
        let state_file = cli.get_state_file_path();
        assert_eq!(state_file, PathBuf::from("/tmp/test-data/.trojan_state"));
    }

    #[test]
    fn test_default_data_dir_value() {
        assert_eq!(DEFAULT_DATA_DIR, "/var/lib/trojan-node");
    }

    #[test]
    fn test_user_from_remote() {
        let remote_user = server_r_client::User {
            id: 42,
            uuid: "test-uuid-123".to_string(),
        };
        let user: User = remote_user.into();
        assert_eq!(user.id, 42);
        assert_eq!(user.uuid, "test-uuid-123");
    }

    #[test]
    fn test_user_clone() {
        let user = User {
            id: 1,
            uuid: "test-uuid".to_string(),
        };
        let cloned = user.clone();
        assert_eq!(cloned.id, user.id);
        assert_eq!(cloned.uuid, user.uuid);
    }

    #[test]
    fn test_server_config_from_remote_tcp() {
        let remote = server_r_client::TrojanConfig {
            id: 1,
            server_port: 443,
            allow_insecure: false,
            server_name: None,
            network: None, // TCP by default
            websocket_config: None,
            grpc_config: None,
        };
        let cli = create_test_cli_args();
        let users = vec![User {
            id: 1,
            uuid: "uuid-1".to_string(),
        }];

        let config = ServerConfig::from_remote(&remote, &cli, users).unwrap();

        assert_eq!(config.port, 443);
        assert!(!config.enable_ws);
        assert!(!config.enable_grpc);
    }

    #[test]
    fn test_server_config_from_remote_websocket() {
        let remote = server_r_client::TrojanConfig {
            id: 1,
            server_port: 443,
            allow_insecure: false,
            server_name: None,
            network: Some("ws".to_string()),
            websocket_config: None,
            grpc_config: None,
        };
        let cli = create_test_cli_args();
        let users = vec![];

        let config = ServerConfig::from_remote(&remote, &cli, users).unwrap();

        assert!(config.enable_ws);
        assert!(!config.enable_grpc);
    }

    #[test]
    fn test_server_config_from_remote_websocket_full() {
        let remote = server_r_client::TrojanConfig {
            id: 1,
            server_port: 443,
            allow_insecure: false,
            server_name: None,
            network: Some("websocket".to_string()),
            websocket_config: None,
            grpc_config: None,
        };
        let cli = create_test_cli_args();
        let users = vec![];

        let config = ServerConfig::from_remote(&remote, &cli, users).unwrap();

        assert!(config.enable_ws);
        assert!(!config.enable_grpc);
    }

    #[test]
    fn test_server_config_from_remote_grpc() {
        let remote = server_r_client::TrojanConfig {
            id: 1,
            server_port: 443,
            allow_insecure: false,
            server_name: None,
            network: Some("grpc".to_string()),
            websocket_config: None,
            grpc_config: None,
        };
        let cli = create_test_cli_args();
        let users = vec![];

        let config = ServerConfig::from_remote(&remote, &cli, users).unwrap();

        assert!(!config.enable_ws);
        assert!(config.enable_grpc);
    }

    #[test]
    fn test_server_config_from_remote_network_case_insensitive() {
        let remote = server_r_client::TrojanConfig {
            id: 1,
            server_port: 443,
            allow_insecure: false,
            server_name: None,
            network: Some("GRPC".to_string()),
            websocket_config: None,
            grpc_config: None,
        };
        let cli = create_test_cli_args();
        let users = vec![];

        let config = ServerConfig::from_remote(&remote, &cli, users).unwrap();

        assert!(config.enable_grpc);
    }

    #[test]
    fn test_server_config_from_remote_with_cert() {
        let remote = server_r_client::TrojanConfig {
            id: 1,
            server_port: 443,
            allow_insecure: false,
            server_name: None,
            network: None,
            websocket_config: None,
            grpc_config: None,
        };
        let cli = create_test_cli_args();
        let users = vec![];

        let config = ServerConfig::from_remote(&remote, &cli, users).unwrap();

        assert_eq!(config.cert, Some(PathBuf::from("/path/to/cert.pem")));
        assert_eq!(config.key, Some(PathBuf::from("/path/to/key.pem")));
    }

    #[test]
    fn test_server_config_from_remote_with_acl_config() {
        let remote = server_r_client::TrojanConfig {
            id: 1,
            server_port: 443,
            allow_insecure: false,
            server_name: None,
            network: None,
            websocket_config: None,
            grpc_config: None,
        };
        let mut cli = create_test_cli_args();
        cli.ext_conf_file = Some(PathBuf::from("/path/to/acl.yaml"));
        let users = vec![];

        let config = ServerConfig::from_remote(&remote, &cli, users).unwrap();

        assert_eq!(
            config.acl_conf_file,
            Some(PathBuf::from("/path/to/acl.yaml"))
        );
    }

    #[test]
    fn test_server_config_host_always_binds_all() {
        let remote = server_r_client::TrojanConfig {
            id: 1,
            server_port: 8080,
            allow_insecure: false,
            server_name: None,
            network: None,
            websocket_config: None,
            grpc_config: None,
        };
        let cli = create_test_cli_args();
        let users = vec![];

        let config = ServerConfig::from_remote(&remote, &cli, users).unwrap();

        assert_eq!(config.host, "0.0.0.0");
    }
}
