use std::str::FromStr;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt::time::LocalTime, layer::SubscriberExt, util::SubscriberInitExt};

/// Log level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl FromStr for LogLevel {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            _ => Err(()),
        }
    }
}

impl LogLevel {
    pub fn to_level_filter(self) -> LevelFilter {
        match self {
            LogLevel::Trace => LevelFilter::TRACE,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Warn => LevelFilter::WARN,
            LogLevel::Error => LevelFilter::ERROR,
        }
    }
}

#[allow(dead_code)]
fn get_log_level_from_args() -> Option<LogLevel> {
    let args: Vec<String> = std::env::args().collect();

    let log_level_from_cli = args
        .iter()
        .position(|a| a == "--log-level")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| LogLevel::from_str(s).ok());

    if log_level_from_cli.is_some() {
        return log_level_from_cli;
    }

    args.iter()
        .position(|a| a == "--config-file" || a == "-c")
        .and_then(|i| args.get(i + 1))
        .and_then(|config_path| {
            std::fs::read_to_string(config_path)
                .ok()
                .and_then(|content| {
                    toml::from_str::<toml::Value>(&content)
                        .ok()
                        .and_then(|v| v.get("log")?.get("level")?.as_str().map(|s| s.to_string()))
                        .and_then(|s| LogLevel::from_str(&s).ok())
                })
        })
}

/// Time format for log timestamps
const LOG_TIME_FORMAT: &[time::format_description::FormatItem<'static>] = time::macros::format_description!(
    "[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]"
);

/// Initialize logger with log level string
pub fn init_logger(log_level_str: &str) {
    let level = LogLevel::from_str(log_level_str).unwrap_or_default();

    let filter = tracing_subscriber::filter::Targets::new()
        .with_targets(vec![
            ("server_trojan_r", level.to_level_filter()),
            ("server", level.to_level_filter()),
        ])
        .with_default(LevelFilter::INFO);

    let registry = tracing_subscriber::registry();
    registry
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_timer(LocalTime::new(LOG_TIME_FORMAT)),
        )
        .init();
}

pub mod log {
    pub use tracing::{debug, error, info, warn};

    /// Log connection events
    pub fn connection(addr: &str, event: &str) {
        debug!(peer = addr, event = event, "Connection");
    }

    /// Log authentication events
    pub fn authentication(addr: &str, success: bool) {
        if success {
            debug!(peer = addr, "Authentication successful");
        } else {
            warn!(peer = addr, "Authentication failed");
        }
    }

    /// Log transport layer events
    #[allow(dead_code)]
    pub fn transport(transport: &str, event: &str, details: Option<&str>) {
        if let Some(details) = details {
            info!(
                transport = transport,
                event = event,
                details = details,
                "Transport"
            );
        } else {
            info!(transport = transport, event = event, "Transport");
        }
    }

    /// Log protocol parsing events
    #[allow(dead_code)]
    pub fn protocol(event: &str, error: Option<&str>) {
        if let Some(err) = error {
            warn!(event = event, error = err, "Protocol");
        } else {
            debug!(event = event, "Protocol");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_from_str_valid() {
        assert_eq!(LogLevel::from_str("trace"), Ok(LogLevel::Trace));
        assert_eq!(LogLevel::from_str("debug"), Ok(LogLevel::Debug));
        assert_eq!(LogLevel::from_str("info"), Ok(LogLevel::Info));
        assert_eq!(LogLevel::from_str("warn"), Ok(LogLevel::Warn));
        assert_eq!(LogLevel::from_str("error"), Ok(LogLevel::Error));
    }

    #[test]
    fn test_log_level_from_str_case_insensitive() {
        assert_eq!(LogLevel::from_str("TRACE"), Ok(LogLevel::Trace));
        assert_eq!(LogLevel::from_str("Debug"), Ok(LogLevel::Debug));
        assert_eq!(LogLevel::from_str("INFO"), Ok(LogLevel::Info));
        assert_eq!(LogLevel::from_str("WARN"), Ok(LogLevel::Warn));
        assert_eq!(LogLevel::from_str("Error"), Ok(LogLevel::Error));
    }

    #[test]
    fn test_log_level_from_str_invalid() {
        assert!(LogLevel::from_str("invalid").is_err());
        assert!(LogLevel::from_str("").is_err());
        assert!(LogLevel::from_str("warning").is_err());
    }

    #[test]
    fn test_log_level_to_level_filter() {
        assert_eq!(LogLevel::Trace.to_level_filter(), LevelFilter::TRACE);
        assert_eq!(LogLevel::Debug.to_level_filter(), LevelFilter::DEBUG);
        assert_eq!(LogLevel::Info.to_level_filter(), LevelFilter::INFO);
        assert_eq!(LogLevel::Warn.to_level_filter(), LevelFilter::WARN);
        assert_eq!(LogLevel::Error.to_level_filter(), LevelFilter::ERROR);
    }

    #[test]
    fn test_log_level_default() {
        assert_eq!(LogLevel::default(), LogLevel::Info);
    }

    #[test]
    fn test_log_time_format_is_valid() {
        // This test verifies that the compile-time format description is valid
        // by checking it can format a time without panicking
        use time::OffsetDateTime;
        let now = OffsetDateTime::now_utc();
        let formatted = now.format(LOG_TIME_FORMAT);
        assert!(formatted.is_ok());
        let formatted_str = formatted.unwrap();
        // Format: "YY-MM-DD HH:MM:SS"
        assert!(formatted_str.len() >= 17);
    }
}
