use clap::Parser;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Trojan Server")]
pub struct ServerConfig {
    /// Host address
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Port number
    #[arg(long, default_value = "35537")]
    pub port: String,

    /// Password
    #[arg(long, default_value = "")]
    pub password: String,

    /// Enable WebSocket mode
    #[arg(long, default_value_t = false)]
    pub enable_ws: bool,

    /// Enable gRPC mode
    #[arg(long, default_value_t = false)]
    pub enable_grpc: bool,

    /// Enable UDP support
    #[arg(long, default_value_t = true)]
    pub enable_udp: bool,

    /// TLS certificate file path (optional)
    #[arg(long)]
    pub cert: Option<String>,

    /// TLS private key file path (optional)
    #[arg(long)]
    pub key: Option<String>,

    /// Load configuration from TOML file
    #[arg(short = 'c', long)]
    pub config_file: Option<String>,

    /// Generate example configuration file
    #[arg(long)]
    pub generate_config: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long)]
    pub log_level: Option<String>,
}

impl ServerConfig {
    /// 从 TOML 文件或命令行参数加载配置
    pub fn load() -> Result<Self> {
        let mut config = Self::parse();

        // 如果指定了生成配置文件，生成后退出
        if let Some(ref path) = config.generate_config {
            TomlConfig::generate_example(path)?;
            println!("Example configuration file generated at: {}", path);
            std::process::exit(0);
        }

        // 如果指定了配置文件，从文件加载
        if let Some(ref config_path) = config.config_file {
            println!("Loading configuration from: {}", config_path);
            let toml_config = TomlConfig::from_file(config_path)?;

            // 转换成 ServerConfig
            let file_config = toml_config.to_server_config();

            // 只有命令行参数为默认值时才使用文件配置
            if config.host == "127.0.0.1" {
                config.host = file_config.host;
            }
            if config.port == "35537" {
                config.port = file_config.port;
            }
            if config.password.is_empty() {
                config.password = file_config.password;
            }
            if !config.enable_ws {
                config.enable_ws = file_config.enable_ws;
            }
            if !config.enable_grpc {
                config.enable_grpc = file_config.enable_grpc;
            }
            if config.enable_udp {
                config.enable_udp = file_config.enable_udp;
            }
            if config.cert.is_none() {
                config.cert = file_config.cert;
            }
            if config.key.is_none() {
                config.key = file_config.key;
            }
            if config.log_level.is_none() {
                config.log_level = file_config.log_level;
            }
        }

        // 验证密码不为空
        if config.password.is_empty() {
            return Err(anyhow!("Password must be provided either via --password or config file"));
        }

        if config.enable_ws && config.enable_grpc {
            return Err(anyhow!("WebSocket mode and gRPC mode cannot be enabled simultaneously"));
        }

        Ok(config)
    }
}

// =============== TOML 配置部分 ==================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TomlConfig {
    pub server: ServerSettings,
    #[serde(default)]
    pub tls: Option<TlsSettings>,
    #[serde(default)]
    pub log: Option<LogSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    pub host: String,
    pub port: String,
    pub password: String,

    #[serde(default)]
    pub enable_ws: bool,

    #[serde(default)]
    pub enable_grpc: bool,

    #[serde(default = "default_enable_udp")]
    pub enable_udp: bool,
}

const fn default_enable_udp() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSettings {
    pub cert: String,
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSettings {
    /// Log level: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub level: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl TomlConfig {
    /// 从文件加载配置
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: TomlConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// 生成示例配置文件
    pub fn generate_example<P: AsRef<Path>>(path: P) -> Result<()> {
        let example = TomlConfig {
            server: ServerSettings {
                host: "127.0.0.1".to_string(),
                port: "35537".to_string(),
                password: "your_password_here".to_string(),
                enable_ws: true,
                enable_grpc: false,
                enable_udp: true,
            },
            tls: Some(TlsSettings {
                cert: "/path/to/cert.pem".to_string(),
                key: "/path/to/key.pem".to_string(),
            }),
            log: Some(LogSettings {
                level: "info".to_string(),
            }),
        };

        let toml_str = toml::to_string_pretty(&example)?;
        fs::write(path, toml_str)?;
        Ok(())
    }

    /// 转换为 ServerConfig
    pub fn to_server_config(self) -> ServerConfig {
        ServerConfig {
            host: self.server.host,
            port: self.server.port,
            password: self.server.password,
            enable_ws: self.server.enable_ws,
            enable_grpc: self.server.enable_grpc,
            enable_udp: self.server.enable_udp,
            cert: self.tls.as_ref().map(|t| t.cert.clone()),
            key: self.tls.as_ref().map(|t| t.key.clone()),
            config_file: None,
            generate_config: None,
            log_level: self.log.map(|l| l.level),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_toml_config_from_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"
[server]
host = "0.0.0.0"
port = "8080"
password = "test_password"
enable_ws = true
enable_grpc = false
enable_udp = true
"#).unwrap();

        let config = TomlConfig::from_file(file.path()).unwrap();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, "8080");
        assert_eq!(config.server.password, "test_password");
        assert!(config.server.enable_ws);
        assert!(!config.server.enable_grpc);
        assert!(config.server.enable_udp);
    }

    #[test]
    fn test_toml_config_with_tls() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"
[server]
host = "127.0.0.1"
port = "443"
password = "secure_password"

[tls]
cert = "/path/to/cert.pem"
key = "/path/to/key.pem"
"#).unwrap();

        let config = TomlConfig::from_file(file.path()).unwrap();
        assert!(config.tls.is_some());
        let tls = config.tls.unwrap();
        assert_eq!(tls.cert, "/path/to/cert.pem");
        assert_eq!(tls.key, "/path/to/key.pem");
    }

    #[test]
    fn test_toml_config_with_log() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"
[server]
host = "127.0.0.1"
port = "8080"
password = "test"

[log]
level = "debug"
"#).unwrap();

        let config = TomlConfig::from_file(file.path()).unwrap();
        assert!(config.log.is_some());
        assert_eq!(config.log.unwrap().level, "debug");
    }

    #[test]
    fn test_toml_config_default_log_level() {
        let log = LogSettings { level: default_log_level() };
        assert_eq!(log.level, "info");
    }

    #[test]
    fn test_toml_config_default_enable_udp() {
        assert!(default_enable_udp());
    }

    #[test]
    fn test_toml_config_to_server_config() {
        let toml_config = TomlConfig {
            server: ServerSettings {
                host: "0.0.0.0".to_string(),
                port: "8080".to_string(),
                password: "test".to_string(),
                enable_ws: true,
                enable_grpc: false,
                enable_udp: true,
            },
            tls: Some(TlsSettings {
                cert: "/cert.pem".to_string(),
                key: "/key.pem".to_string(),
            }),
            log: Some(LogSettings {
                level: "debug".to_string(),
            }),
        };

        let server_config = toml_config.to_server_config();
        assert_eq!(server_config.host, "0.0.0.0");
        assert_eq!(server_config.port, "8080");
        assert_eq!(server_config.password, "test");
        assert!(server_config.enable_ws);
        assert!(!server_config.enable_grpc);
        assert!(server_config.enable_udp);
        assert_eq!(server_config.cert, Some("/cert.pem".to_string()));
        assert_eq!(server_config.key, Some("/key.pem".to_string()));
        assert_eq!(server_config.log_level, Some("debug".to_string()));
    }

    #[test]
    fn test_toml_config_generate_example() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();
        drop(file);

        TomlConfig::generate_example(&path).unwrap();

        let config = TomlConfig::from_file(&path).unwrap();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, "35537");
        assert!(config.tls.is_some());
        assert!(config.log.is_some());

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_toml_config_invalid_file() {
        let result = TomlConfig::from_file("/nonexistent/path/config.toml");
        assert!(result.is_err());
    }

    #[test]
    fn test_toml_config_invalid_toml() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "this is not valid toml {{{{").unwrap();

        let result = TomlConfig::from_file(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_server_settings_debug() {
        let settings = ServerSettings {
            host: "127.0.0.1".to_string(),
            port: "8080".to_string(),
            password: "secret".to_string(),
            enable_ws: false,
            enable_grpc: false,
            enable_udp: true,
        };
        let debug_str = format!("{:?}", settings);
        assert!(debug_str.contains("127.0.0.1"));
        assert!(debug_str.contains("8080"));
    }
}
