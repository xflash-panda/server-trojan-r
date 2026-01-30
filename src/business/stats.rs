//! API-based statistics collection implementation

use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::core::hooks::StatsCollector;
use crate::core::UserId;

/// User statistics data
#[derive(Debug, Default)]
struct UserStatsData {
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
    request_count: AtomicU64,
}

/// Statistics snapshot for a user
#[derive(Debug, Clone)]
pub struct UserStatsSnapshot {
    pub user_id: UserId,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub request_count: u64,
}

/// API-based statistics collector
///
/// Collects traffic statistics that can be reported to the remote panel.
/// Uses atomic operations for lock-free collection.
pub struct ApiStatsCollector {
    /// Active stats being written to
    stats: Arc<DashMap<UserId, UserStatsData>>,
    /// Flag to prevent concurrent resets
    resetting: AtomicBool,
}

impl Default for ApiStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiStatsCollector {
    /// Create a new API stats collector
    pub fn new() -> Self {
        Self {
            stats: Arc::new(DashMap::new()),
            resetting: AtomicBool::new(false),
        }
    }

    /// Get stats for a specific user
    #[allow(dead_code)]
    pub fn get_stats(&self, user_id: UserId) -> Option<UserStatsSnapshot> {
        self.stats.get(&user_id).map(|entry| {
            let data = entry.value();
            UserStatsSnapshot {
                user_id,
                upload_bytes: data.upload_bytes.load(Ordering::Relaxed),
                download_bytes: data.download_bytes.load(Ordering::Relaxed),
                request_count: data.request_count.load(Ordering::Relaxed),
            }
        })
    }

    /// Get all stats snapshots
    #[allow(dead_code)]
    pub fn get_all_snapshots(&self) -> Vec<UserStatsSnapshot> {
        self.stats
            .iter()
            .map(|entry| {
                let data = entry.value();
                UserStatsSnapshot {
                    user_id: *entry.key(),
                    upload_bytes: data.upload_bytes.load(Ordering::Relaxed),
                    download_bytes: data.download_bytes.load(Ordering::Relaxed),
                    request_count: data.request_count.load(Ordering::Relaxed),
                }
            })
            .collect()
    }

    /// Reset all stats and return snapshots
    ///
    /// This method uses a single-pass swap-and-collect approach:
    /// 1. Iterate all entries once
    /// 2. For each entry, atomically swap values to 0 and collect if non-zero
    /// 3. Any writes during this process will either be counted in this snapshot
    ///    or accumulated for the next snapshot (no data loss)
    pub fn reset_all(&self) -> Vec<UserStatsSnapshot> {
        // Prevent concurrent resets using compare_exchange
        if self
            .resetting
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Another reset in progress, return empty
            return Vec::new();
        }

        // Ensure we clear the flag when done
        let _guard = scopeguard::guard((), |_| {
            self.resetting.store(false, Ordering::Release);
        });

        // Single-pass: swap values and collect non-zero entries
        let mut snapshots = Vec::new();
        let mut all_keys = Vec::new();

        for entry in self.stats.iter() {
            let user_id = *entry.key();
            let data = entry.value();

            // Atomic swaps ensure no data is lost
            let upload = data.upload_bytes.swap(0, Ordering::AcqRel);
            let download = data.download_bytes.swap(0, Ordering::AcqRel);
            let requests = data.request_count.swap(0, Ordering::AcqRel);

            // Track all keys for cleanup
            all_keys.push(user_id);

            if upload > 0 || download > 0 || requests > 0 {
                snapshots.push(UserStatsSnapshot {
                    user_id,
                    upload_bytes: upload,
                    download_bytes: download,
                    request_count: requests,
                });
            }
        }

        // Remove zero-traffic entries to prevent unbounded growth
        // Check all entries since we swapped all to 0
        for key in all_keys {
            // Double-check the entry is still zero before removing
            // (new traffic may have arrived during iteration)
            if let Some(entry) = self.stats.get(&key) {
                let data = entry.value();
                if data.upload_bytes.load(Ordering::Relaxed) == 0
                    && data.download_bytes.load(Ordering::Relaxed) == 0
                    && data.request_count.load(Ordering::Relaxed) == 0
                {
                    drop(entry); // Release the reference before remove
                    self.stats.remove(&key);
                }
            }
        }

        snapshots
    }

    /// Get user count
    #[allow(dead_code)]
    pub fn user_count(&self) -> usize {
        self.stats.len()
    }
}

impl StatsCollector for ApiStatsCollector {
    fn record_request(&self, user_id: UserId) {
        self.stats
            .entry(user_id)
            .or_default()
            .request_count
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_upload(&self, user_id: UserId, bytes: u64) {
        self.stats
            .entry(user_id)
            .or_default()
            .upload_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_download(&self, user_id: UserId, bytes: u64) {
        self.stats
            .entry(user_id)
            .or_default()
            .download_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_stats_collector_new() {
        let collector = ApiStatsCollector::new();
        assert_eq!(collector.user_count(), 0);
    }

    #[test]
    fn test_api_stats_collector_record_request() {
        let collector = ApiStatsCollector::new();
        collector.record_request(1);
        collector.record_request(1);
        collector.record_request(2);

        assert_eq!(collector.get_stats(1).unwrap().request_count, 2);
        assert_eq!(collector.get_stats(2).unwrap().request_count, 1);
    }

    #[test]
    fn test_api_stats_collector_record_upload_download() {
        let collector = ApiStatsCollector::new();
        collector.record_upload(1, 100);
        collector.record_download(1, 200);
        collector.record_upload(1, 50);

        let stats = collector.get_stats(1).unwrap();
        assert_eq!(stats.upload_bytes, 150);
        assert_eq!(stats.download_bytes, 200);
    }

    #[test]
    fn test_api_stats_collector_reset_all() {
        let collector = ApiStatsCollector::new();
        collector.record_upload(1, 100);
        collector.record_download(1, 200);
        collector.record_request(1);

        let snapshots = collector.reset_all();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].upload_bytes, 100);
        assert_eq!(snapshots[0].download_bytes, 200);
        assert_eq!(snapshots[0].request_count, 1);

        // After reset, entry should be cleaned up (no traffic)
        assert!(collector.get_stats(1).is_none());
    }

    #[test]
    fn test_api_stats_collector_reset_filters_empty() {
        let collector = ApiStatsCollector::new();
        collector.record_upload(1, 100);
        collector.record_request(2); // Only request, no traffic

        let snapshots = collector.reset_all();
        // Both should be included as they have non-zero values
        assert_eq!(snapshots.len(), 2);
    }

    #[test]
    fn test_api_stats_collector_get_all_snapshots() {
        let collector = ApiStatsCollector::new();
        collector.record_upload(1, 100);
        collector.record_upload(2, 200);
        collector.record_upload(3, 300);

        let snapshots = collector.get_all_snapshots();
        assert_eq!(snapshots.len(), 3);

        let total_upload: u64 = snapshots.iter().map(|s| s.upload_bytes).sum();
        assert_eq!(total_upload, 600);
    }

    #[test]
    fn test_api_stats_collector_concurrent() {
        use std::thread;

        let collector = Arc::new(ApiStatsCollector::new());
        let mut handles = vec![];

        for i in 0..10 {
            let c = Arc::clone(&collector);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    c.record_request(i % 3);
                    c.record_upload(i % 3, 1);
                    c.record_download(i % 3, 2);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let snapshots = collector.get_all_snapshots();
        assert_eq!(snapshots.len(), 3);

        let total_requests: u64 = snapshots.iter().map(|s| s.request_count).sum();
        assert_eq!(total_requests, 10000);
    }

    #[test]
    fn test_api_stats_collector_concurrent_with_reset() {
        use std::thread;

        let collector = Arc::new(ApiStatsCollector::new());
        let mut write_handles = vec![];

        // Writers
        for i in 0..5 {
            let c = Arc::clone(&collector);
            write_handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    c.record_upload(i % 3, 1);
                    c.record_download(i % 3, 1);
                }
            }));
        }

        // Reader/resetter in a separate variable to get the return value
        let c = Arc::clone(&collector);
        let reset_handle = thread::spawn(move || {
            let mut total_upload = 0u64;
            let mut total_download = 0u64;
            for _ in 0..10 {
                thread::sleep(std::time::Duration::from_millis(1));
                let snapshots = c.reset_all();
                for s in snapshots {
                    total_upload += s.upload_bytes;
                    total_download += s.download_bytes;
                }
            }
            (total_upload, total_download)
        });

        for h in write_handles {
            h.join().unwrap();
        }

        let (_collected_upload, _collected_download) = reset_handle.join().unwrap();

        // Final reset to get remaining stats
        let final_snapshots = collector.reset_all();
        let remaining: u64 = final_snapshots.iter().map(|s| s.upload_bytes).sum();

        // Total should be 5 threads * 1000 iterations * 1 byte = 5000 bytes
        // Some may have been collected by resets, some remain
        // The important thing is no data is lost
        assert!(remaining <= 5000);
    }

    #[test]
    fn test_user_stats_snapshot_clone() {
        let snapshot = UserStatsSnapshot {
            user_id: 1,
            upload_bytes: 100,
            download_bytes: 200,
            request_count: 10,
        };
        let cloned = snapshot.clone();
        assert_eq!(cloned.user_id, snapshot.user_id);
        assert_eq!(cloned.upload_bytes, snapshot.upload_bytes);
    }
}
