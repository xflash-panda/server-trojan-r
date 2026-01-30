use crate::stats::UserStats;
use crate::utils::TimedStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};

/// Result of bidirectional copy with traffic stats
#[derive(Debug, Clone, Copy)]
pub struct CopyResult {
    /// Whether the copy completed normally (true) or timed out (false)
    pub completed: bool,
    /// Bytes sent from client to remote (upload)
    pub upload_bytes: u64,
    /// Bytes sent from remote to client (download)
    pub download_bytes: u64,
}

/// 双向转发，支持空闲超时检测
pub async fn copy_bidirectional_with_idle_timeout<A, B>(
    a: A,
    b: B,
    idle_timeout_secs: u64,
) -> std::io::Result<CopyResult>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    copy_bidirectional_with_stats(a, b, idle_timeout_secs, None).await
}

/// 双向转发，支持空闲超时检测和流量统计
pub async fn copy_bidirectional_with_stats<A, B>(
    a: A,
    b: B,
    idle_timeout_secs: u64,
    user_stats: Option<Arc<UserStats>>,
) -> std::io::Result<CopyResult>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let start_time = Instant::now();
    let last_activity = Arc::new(AtomicU64::new(0));

    let mut stream_a = TimedStream::new(a, start_time, Arc::clone(&last_activity));
    let mut stream_b = TimedStream::new(b, start_time, Arc::clone(&last_activity));

    let copy_task = tokio::io::copy_bidirectional(&mut stream_a, &mut stream_b);

    let timeout_check = async {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        interval.tick().await;
        loop {
            interval.tick().await;
            // Use Acquire ordering to see the latest update from
            // TimedStream writers using Release ordering
            let last_active = last_activity.load(Ordering::Acquire);
            let current_elapsed = start_time.elapsed().as_secs();
            let idle_secs = current_elapsed.saturating_sub(last_active);
            if idle_secs >= idle_timeout_secs {
                return idle_secs;
            }
        }
    };

    tokio::select! {
        result = copy_task => {
            let (a_to_b, b_to_a) = result?;
            // a is client, b is remote
            // a_to_b = client -> remote = upload
            // b_to_a = remote -> client = download
            if let Some(ref stats) = user_stats {
                stats.add_upload(a_to_b);
                stats.add_download(b_to_a);
            }
            Ok(CopyResult {
                completed: true,
                upload_bytes: a_to_b,
                download_bytes: b_to_a,
            })
        }
        _ = timeout_check => {
            Ok(CopyResult {
                completed: false,
                upload_bytes: 0,
                download_bytes: 0,
            })
        }
    }
}
