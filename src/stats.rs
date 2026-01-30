//! User traffic statistics module
//!
//! Tracks per-user upload/download bytes and proxy request count.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Statistics for a single user
#[derive(Debug, Default)]
pub struct UserStats {
    /// Total bytes uploaded (client -> remote)
    upload_bytes: AtomicU64,
    /// Total bytes downloaded (remote -> client)
    download_bytes: AtomicU64,
    /// Number of proxy requests (not connections, but actual proxy requests)
    request_count: AtomicU64,
}

impl UserStats {
    /// Create a new UserStats instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Add upload bytes
    #[inline]
    pub fn add_upload(&self, bytes: u64) {
        self.upload_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add download bytes
    #[inline]
    pub fn add_download(&self, bytes: u64) {
        self.download_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increment request count
    #[inline]
    pub fn inc_request(&self) {
        self.request_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current upload bytes
    pub fn upload_bytes(&self) -> u64 {
        self.upload_bytes.load(Ordering::Relaxed)
    }

    /// Get current download bytes
    pub fn download_bytes(&self) -> u64 {
        self.download_bytes.load(Ordering::Relaxed)
    }

    /// Get current request count
    pub fn request_count(&self) -> u64 {
        self.request_count.load(Ordering::Relaxed)
    }

    /// Get all stats as a tuple (upload, download, requests)
    pub fn get_all(&self) -> (u64, u64, u64) {
        (
            self.upload_bytes.load(Ordering::Relaxed),
            self.download_bytes.load(Ordering::Relaxed),
            self.request_count.load(Ordering::Relaxed),
        )
    }

    /// Reset all counters and return the previous values
    pub fn reset(&self) -> (u64, u64, u64) {
        let upload = self.upload_bytes.swap(0, Ordering::Relaxed);
        let download = self.download_bytes.swap(0, Ordering::Relaxed);
        let requests = self.request_count.swap(0, Ordering::Relaxed);
        (upload, download, requests)
    }
}

/// Snapshot of user statistics
#[derive(Debug, Clone)]
pub struct UserStatsSnapshot {
    pub user_id: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub request_count: u64,
}

/// Manager for all user statistics
#[derive(Debug, Clone)]
pub struct StatsManager {
    /// Map from user_id to their stats
    users: Arc<DashMap<u64, Arc<UserStats>>>,
}

impl Default for StatsManager {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsManager {
    /// Create a new StatsManager
    pub fn new() -> Self {
        Self {
            users: Arc::new(DashMap::new()),
        }
    }

    /// Get or create stats for a user
    pub fn get_or_create(&self, user_id: u64) -> Arc<UserStats> {
        self.users
            .entry(user_id)
            .or_insert_with(|| Arc::new(UserStats::new()))
            .clone()
    }

    /// Get stats for a user if they exist
    pub fn get(&self, user_id: u64) -> Option<Arc<UserStats>> {
        self.users.get(&user_id).map(|r| r.clone())
    }

    /// Record a proxy request for a user
    #[inline]
    pub fn record_request(&self, user_id: u64) {
        self.get_or_create(user_id).inc_request();
    }

    /// Get snapshot of all users' stats
    pub fn get_all_snapshots(&self) -> Vec<UserStatsSnapshot> {
        self.users
            .iter()
            .map(|entry| {
                let (upload, download, requests) = entry.value().get_all();
                UserStatsSnapshot {
                    user_id: *entry.key(),
                    upload_bytes: upload,
                    download_bytes: download,
                    request_count: requests,
                }
            })
            .collect()
    }

    /// Get snapshot of a single user's stats
    pub fn get_snapshot(&self, user_id: u64) -> Option<UserStatsSnapshot> {
        self.users.get(&user_id).map(|entry| {
            let (upload, download, requests) = entry.value().get_all();
            UserStatsSnapshot {
                user_id,
                upload_bytes: upload,
                download_bytes: download,
                request_count: requests,
            }
        })
    }

    /// Reset all stats for a user and return the previous values
    pub fn reset_user(&self, user_id: u64) -> Option<(u64, u64, u64)> {
        self.users.get(&user_id).map(|entry| entry.value().reset())
    }

    /// Reset all users' stats and return snapshots of previous values
    pub fn reset_all(&self) -> Vec<UserStatsSnapshot> {
        self.users
            .iter()
            .map(|entry| {
                let (upload, download, requests) = entry.value().reset();
                UserStatsSnapshot {
                    user_id: *entry.key(),
                    upload_bytes: upload,
                    download_bytes: download,
                    request_count: requests,
                }
            })
            .collect()
    }

    /// Get the number of tracked users
    pub fn user_count(&self) -> usize {
        self.users.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_stats_new() {
        let stats = UserStats::new();
        assert_eq!(stats.upload_bytes(), 0);
        assert_eq!(stats.download_bytes(), 0);
        assert_eq!(stats.request_count(), 0);
    }

    #[test]
    fn test_user_stats_add_upload() {
        let stats = UserStats::new();
        stats.add_upload(100);
        stats.add_upload(50);
        assert_eq!(stats.upload_bytes(), 150);
    }

    #[test]
    fn test_user_stats_add_download() {
        let stats = UserStats::new();
        stats.add_download(200);
        stats.add_download(100);
        assert_eq!(stats.download_bytes(), 300);
    }

    #[test]
    fn test_user_stats_inc_request() {
        let stats = UserStats::new();
        stats.inc_request();
        stats.inc_request();
        stats.inc_request();
        assert_eq!(stats.request_count(), 3);
    }

    #[test]
    fn test_user_stats_get_all() {
        let stats = UserStats::new();
        stats.add_upload(100);
        stats.add_download(200);
        stats.inc_request();
        let (upload, download, requests) = stats.get_all();
        assert_eq!(upload, 100);
        assert_eq!(download, 200);
        assert_eq!(requests, 1);
    }

    #[test]
    fn test_user_stats_reset() {
        let stats = UserStats::new();
        stats.add_upload(100);
        stats.add_download(200);
        stats.inc_request();

        let (upload, download, requests) = stats.reset();
        assert_eq!(upload, 100);
        assert_eq!(download, 200);
        assert_eq!(requests, 1);

        // After reset, all should be 0
        assert_eq!(stats.upload_bytes(), 0);
        assert_eq!(stats.download_bytes(), 0);
        assert_eq!(stats.request_count(), 0);
    }

    #[test]
    fn test_stats_manager_new() {
        let manager = StatsManager::new();
        assert_eq!(manager.user_count(), 0);
    }

    #[test]
    fn test_stats_manager_get_or_create() {
        let manager = StatsManager::new();
        let stats1 = manager.get_or_create(1);
        let stats2 = manager.get_or_create(1);
        // Should return the same Arc
        assert!(Arc::ptr_eq(&stats1, &stats2));
        assert_eq!(manager.user_count(), 1);
    }

    #[test]
    fn test_stats_manager_record_request() {
        let manager = StatsManager::new();
        manager.record_request(1);
        manager.record_request(1);
        manager.record_request(2);

        let stats1 = manager.get(1).unwrap();
        let stats2 = manager.get(2).unwrap();

        assert_eq!(stats1.request_count(), 2);
        assert_eq!(stats2.request_count(), 1);
    }

    #[test]
    fn test_stats_manager_get_snapshot() {
        let manager = StatsManager::new();
        let stats = manager.get_or_create(42);
        stats.add_upload(1000);
        stats.add_download(2000);
        stats.inc_request();

        let snapshot = manager.get_snapshot(42).unwrap();
        assert_eq!(snapshot.user_id, 42);
        assert_eq!(snapshot.upload_bytes, 1000);
        assert_eq!(snapshot.download_bytes, 2000);
        assert_eq!(snapshot.request_count, 1);
    }

    #[test]
    fn test_stats_manager_get_all_snapshots() {
        let manager = StatsManager::new();

        let stats1 = manager.get_or_create(1);
        stats1.add_upload(100);

        let stats2 = manager.get_or_create(2);
        stats2.add_download(200);

        let snapshots = manager.get_all_snapshots();
        assert_eq!(snapshots.len(), 2);
    }

    #[test]
    fn test_stats_manager_reset_user() {
        let manager = StatsManager::new();
        let stats = manager.get_or_create(1);
        stats.add_upload(100);
        stats.add_download(200);

        let (upload, download, _) = manager.reset_user(1).unwrap();
        assert_eq!(upload, 100);
        assert_eq!(download, 200);

        // After reset
        assert_eq!(stats.upload_bytes(), 0);
        assert_eq!(stats.download_bytes(), 0);
    }

    #[test]
    fn test_stats_manager_reset_all() {
        let manager = StatsManager::new();

        manager.get_or_create(1).add_upload(100);
        manager.get_or_create(2).add_download(200);

        let snapshots = manager.reset_all();
        assert_eq!(snapshots.len(), 2);

        // All should be reset
        assert_eq!(manager.get(1).unwrap().upload_bytes(), 0);
        assert_eq!(manager.get(2).unwrap().download_bytes(), 0);
    }

    #[test]
    fn test_stats_concurrent_updates() {
        use std::thread;

        let manager = StatsManager::new();
        let manager_clone = manager.clone();

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let m = manager_clone.clone();
                thread::spawn(move || {
                    for _ in 0..1000 {
                        m.record_request(i % 3); // 3 different users
                        m.get_or_create(i % 3).add_upload(1);
                        m.get_or_create(i % 3).add_download(2);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let snapshots = manager.get_all_snapshots();
        assert_eq!(snapshots.len(), 3);

        let total_requests: u64 = snapshots.iter().map(|s| s.request_count).sum();
        assert_eq!(total_requests, 10000); // 10 threads * 1000 iterations
    }
}
