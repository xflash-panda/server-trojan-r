//! Background tasks for periodic API operations

use server_r_client::UserTraffic;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::{interval, MissedTickBehavior};

use super::client::ApiManager;
use super::user_manager::UserManager;
use crate::business::stats::ApiStatsCollector;
use crate::logger::log;

/// Format bytes into human-readable string (KB, MB, GB)
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2}KB", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

/// Background task configuration
#[derive(Debug, Clone)]
pub struct TaskConfig {
    /// Interval for fetching users
    pub fetch_users_interval: Duration,
    /// Interval for reporting traffic
    pub report_traffic_interval: Duration,
    /// Interval for sending heartbeat
    pub heartbeat_interval: Duration,
}

impl Default for TaskConfig {
    fn default() -> Self {
        Self {
            fetch_users_interval: Duration::from_secs(60),
            report_traffic_interval: Duration::from_secs(60),
            heartbeat_interval: Duration::from_secs(60),
        }
    }
}

impl TaskConfig {
    /// Create task config from durations
    pub fn new(fetch_users: Duration, report_traffic: Duration, heartbeat: Duration) -> Self {
        Self {
            fetch_users_interval: fetch_users,
            report_traffic_interval: report_traffic,
            heartbeat_interval: heartbeat,
        }
    }
}

/// Background tasks manager
pub struct BackgroundTasks {
    config: TaskConfig,
    api_manager: Arc<ApiManager>,
    user_manager: Arc<UserManager>,
    stats_collector: Arc<ApiStatsCollector>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl BackgroundTasks {
    /// Create a new background tasks manager
    pub fn new(
        config: TaskConfig,
        api_manager: Arc<ApiManager>,
        user_manager: Arc<UserManager>,
        stats_collector: Arc<ApiStatsCollector>,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            config,
            api_manager,
            user_manager,
            stats_collector,
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Start all background tasks
    pub fn start(&self) {
        self.start_fetch_users_task();
        self.start_report_traffic_task();
        self.start_heartbeat_task();
        log::info!("Background tasks started");
    }

    /// Stop all background tasks
    #[allow(dead_code)]
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
        log::info!("Background tasks stopped");
    }

    /// Start the fetch users task
    fn start_fetch_users_task(&self) {
        let api_manager = Arc::clone(&self.api_manager);
        let user_manager = Arc::clone(&self.user_manager);
        let interval_duration = self.config.fetch_users_interval;
        let mut shutdown_rx = self.shutdown_rx.clone();

        tokio::spawn(async move {
            let mut interval = interval(interval_duration);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = fetch_users_once(&api_manager, &user_manager).await {
                            log::debug!(error = %e, "Fetch users tick skipped");
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        log::debug!("Fetch users task shutting down");
                        break;
                    }
                }
            }
        });
    }

    /// Start the report traffic task
    fn start_report_traffic_task(&self) {
        let api_manager = Arc::clone(&self.api_manager);
        let stats_collector = Arc::clone(&self.stats_collector);
        let interval_duration = self.config.report_traffic_interval;
        let mut shutdown_rx = self.shutdown_rx.clone();

        tokio::spawn(async move {
            let mut interval = interval(interval_duration);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = report_traffic_once(&api_manager, &stats_collector).await {
                            log::warn!(error = %e, "Failed to report traffic");
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        log::debug!("Report traffic task shutting down");
                        // Final report before shutdown
                        if let Err(e) = report_traffic_once(&api_manager, &stats_collector).await {
                            log::warn!(error = %e, "Failed to report final traffic");
                        }
                        break;
                    }
                }
            }
        });
    }

    /// Start the heartbeat task
    fn start_heartbeat_task(&self) {
        let api_manager = Arc::clone(&self.api_manager);
        let interval_duration = self.config.heartbeat_interval;
        let mut shutdown_rx = self.shutdown_rx.clone();

        tokio::spawn(async move {
            let mut interval = interval(interval_duration);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        match api_manager.heartbeat().await {
                            Ok(()) => log::info!("Heartbeat sent"),
                            Err(e) => log::warn!(error = %e, "Failed to send heartbeat"),
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        log::debug!("Heartbeat task shutting down");
                        break;
                    }
                }
            }
        });
    }
}

/// Fetch users once and update user manager
async fn fetch_users_once(
    api_manager: &ApiManager,
    user_manager: &UserManager,
) -> anyhow::Result<()> {
    let users = api_manager.fetch_users().await?;
    let total = users.len();
    let (added, removed, kicked) = user_manager.update(&users).await;

    log::info!(
        total = total,
        added = added,
        removed = removed,
        kicked = kicked,
        "Users synchronized"
    );

    Ok(())
}

/// Report traffic once
async fn report_traffic_once(
    api_manager: &ApiManager,
    stats_collector: &ApiStatsCollector,
) -> anyhow::Result<()> {
    let snapshots = stats_collector.reset_all();

    if snapshots.is_empty() {
        return Ok(());
    }

    let traffic_data: Vec<UserTraffic> = snapshots
        .into_iter()
        .filter(|s| s.upload_bytes > 0 || s.download_bytes > 0)
        .map(|s| {
            UserTraffic::with_count(s.user_id, s.upload_bytes, s.download_bytes, s.request_count)
        })
        .collect();

    if traffic_data.is_empty() {
        return Ok(());
    }

    let count = traffic_data.len();
    let total_upload: u64 = traffic_data.iter().map(|t| t.u).sum();
    let total_download: u64 = traffic_data.iter().map(|t| t.d).sum();
    api_manager.submit_traffic(traffic_data).await?;
    log::info!(
        users = count,
        upload = %format_bytes(total_upload),
        download = %format_bytes(total_download),
        "Traffic reported"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_config_default() {
        let config = TaskConfig::default();
        assert_eq!(config.fetch_users_interval, Duration::from_secs(60));
        assert_eq!(config.report_traffic_interval, Duration::from_secs(60));
        assert_eq!(config.heartbeat_interval, Duration::from_secs(60));
    }

    #[test]
    fn test_task_config_new() {
        let config = TaskConfig::new(
            Duration::from_secs(30),
            Duration::from_secs(45),
            Duration::from_secs(120),
        );
        assert_eq!(config.fetch_users_interval, Duration::from_secs(30));
        assert_eq!(config.report_traffic_interval, Duration::from_secs(45));
        assert_eq!(config.heartbeat_interval, Duration::from_secs(120));
    }

    #[test]
    fn test_task_config_clone() {
        let config = TaskConfig::new(
            Duration::from_secs(10),
            Duration::from_secs(20),
            Duration::from_secs(30),
        );
        let cloned = config.clone();
        assert_eq!(cloned.fetch_users_interval, config.fetch_users_interval);
        assert_eq!(
            cloned.report_traffic_interval,
            config.report_traffic_interval
        );
        assert_eq!(cloned.heartbeat_interval, config.heartbeat_interval);
    }
}
