use crate::utils::TimedStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};

/// 双向转发，支持空闲超时检测
pub async fn copy_bidirectional_with_idle_timeout<A, B>(
    a: A,
    b: B,
    idle_timeout_secs: u64,
) -> std::io::Result<bool>
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
            result?;
            Ok(true)
        }
        _ = timeout_check => {
            Ok(false)
        }
    }
}
