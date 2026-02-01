//! Bidirectional relay with traffic statistics
//!
//! Provides copy_bidirectional with idle timeout detection and optional traffic stats.

use pin_project_lite::pin_project;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Shared traffic counters for tracking bytes during relay
struct TrafficCounters {
    /// Bytes transferred from A to B (upload)
    a_to_b: Arc<AtomicU64>,
    /// Bytes transferred from B to A (download)
    b_to_a: Arc<AtomicU64>,
}

/// Result of bidirectional copy with traffic stats
#[derive(Debug, Clone, Copy)]
pub struct CopyResult {
    /// Bytes transferred from A to B (upload)
    pub a_to_b: u64,
    /// Bytes transferred from B to A (download)
    pub b_to_a: u64,
    /// Whether the copy completed normally (true) or timed out (false)
    pub completed: bool,
}

pin_project! {
    /// A stream wrapper that tracks the last activity time and bytes transferred
    struct TimedStream<S> {
        #[pin]
        inner: S,
        start_time: Instant,
        last_activity: Arc<AtomicU64>,
        // Counter for bytes read from this stream
        read_bytes: Arc<AtomicU64>,
        // Counter for bytes written to this stream
        write_bytes: Arc<AtomicU64>,
    }
}

impl<S> TimedStream<S> {
    fn new(
        inner: S,
        start_time: Instant,
        last_activity: Arc<AtomicU64>,
        read_bytes: Arc<AtomicU64>,
        write_bytes: Arc<AtomicU64>,
    ) -> Self {
        Self {
            inner,
            start_time,
            last_activity,
            read_bytes,
            write_bytes,
        }
    }
}

impl<S: AsyncRead> AsyncRead for TimedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();
        let before_len = buf.filled().len();
        let result = this.inner.poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let bytes_read = buf.filled().len() - before_len;
            if bytes_read > 0 {
                this.last_activity
                    .store(this.start_time.elapsed().as_secs(), Ordering::Release);
                this.read_bytes
                    .fetch_add(bytes_read as u64, Ordering::Relaxed);
            }
        }
        result
    }
}

impl<S: AsyncWrite> AsyncWrite for TimedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        let result = this.inner.poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            if *n > 0 {
                this.last_activity
                    .store(this.start_time.elapsed().as_secs(), Ordering::Release);
                this.write_bytes.fetch_add(*n as u64, Ordering::Relaxed);
            }
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

use super::hooks::{StatsCollector, UserId};

/// Bidirectional copy with idle timeout detection and optional traffic statistics
///
/// - `a`: Client stream
/// - `b`: Remote/outbound stream
/// - `idle_timeout_secs`: Idle timeout in seconds
/// - `stats`: Optional tuple of (user_id, stats_collector) for traffic tracking
///
/// Returns CopyResult with bytes transferred and completion status.
/// Note: Traffic is tracked in real-time, even if the connection times out.
pub async fn copy_bidirectional_with_stats<A, B>(
    a: A,
    b: B,
    idle_timeout_secs: u64,
    stats: Option<(UserId, Arc<dyn StatsCollector>)>,
) -> std::io::Result<CopyResult>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let start_time = Instant::now();
    let last_activity = Arc::new(AtomicU64::new(0));

    // Shared counters to track traffic even during timeout
    // a_to_b: read from A, write to B (upload from client perspective)
    // b_to_a: read from B, write to A (download from client perspective)
    let counters = TrafficCounters {
        a_to_b: Arc::new(AtomicU64::new(0)),
        b_to_a: Arc::new(AtomicU64::new(0)),
    };

    // stream_a reads from client, writes to client
    // When we read from A, that's data going A->B (upload)
    // When we write to A, that's data coming B->A (download)
    let mut stream_a = TimedStream::new(
        a,
        start_time,
        Arc::clone(&last_activity),
        Arc::clone(&counters.a_to_b), // reads from A = upload
        Arc::clone(&counters.b_to_a), // writes to A = download (not used by copy_bidirectional for counting)
    );

    // stream_b reads from remote, writes to remote
    // When we read from B, that's data going B->A (download)
    // When we write to B, that's data coming A->B (upload, not used by copy_bidirectional for counting)
    let mut stream_b = TimedStream::new(
        b,
        start_time,
        Arc::clone(&last_activity),
        Arc::clone(&counters.b_to_a), // reads from B = download
        Arc::clone(&counters.a_to_b), // writes to B = upload (not used by copy_bidirectional for counting)
    );

    let copy_task = tokio::io::copy_bidirectional(&mut stream_a, &mut stream_b);

    let timeout_check = async {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        interval.tick().await;
        loop {
            interval.tick().await;
            let last_active = last_activity.load(Ordering::Acquire);
            let current_elapsed = start_time.elapsed().as_secs();
            let idle_secs = current_elapsed.saturating_sub(last_active);
            if idle_secs >= idle_timeout_secs {
                return idle_secs;
            }
        }
    };

    let result = tokio::select! {
        result = copy_task => {
            let (a_to_b, b_to_a) = result?;
            CopyResult {
                a_to_b,
                b_to_a,
                completed: true,
            }
        }
        _ = timeout_check => {
            // Even on timeout, we have accurate traffic stats from counters
            let a_to_b = counters.a_to_b.load(Ordering::Relaxed);
            let b_to_a = counters.b_to_a.load(Ordering::Relaxed);
            CopyResult {
                a_to_b,
                b_to_a,
                completed: false,
            }
        }
    };

    // Record stats if provided
    if let Some((user_id, collector)) = stats {
        if result.a_to_b > 0 {
            collector.record_upload(user_id, result.a_to_b);
        }
        if result.b_to_a > 0 {
            collector.record_download(user_id, result.b_to_a);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_copy_result_clone() {
        let result = CopyResult {
            a_to_b: 100,
            b_to_a: 200,
            completed: true,
        };
        let cloned = result;
        assert_eq!(cloned.a_to_b, 100);
        assert_eq!(cloned.b_to_a, 200);
        assert!(cloned.completed);
    }

    #[tokio::test]
    async fn test_timed_stream_read_updates_activity() {
        let data = b"hello world";
        let cursor = Cursor::new(data.to_vec());
        let start_time = Instant::now();
        let last_activity = Arc::new(AtomicU64::new(0));
        let read_bytes = Arc::new(AtomicU64::new(0));
        let write_bytes = Arc::new(AtomicU64::new(0));

        let mut stream = TimedStream::new(
            cursor,
            start_time,
            Arc::clone(&last_activity),
            read_bytes.clone(),
            write_bytes,
        );

        let mut buf = [0u8; 5];
        let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
            .await
            .unwrap();

        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");
        assert_eq!(read_bytes.load(Ordering::Relaxed), 5);
    }

    #[tokio::test]
    async fn test_timed_stream_write_updates_activity() {
        let cursor = Cursor::new(Vec::new());
        let start_time = Instant::now();
        let last_activity = Arc::new(AtomicU64::new(0));
        let read_bytes = Arc::new(AtomicU64::new(0));
        let write_bytes = Arc::new(AtomicU64::new(0));

        let mut stream = TimedStream::new(
            cursor,
            start_time,
            Arc::clone(&last_activity),
            read_bytes,
            write_bytes.clone(),
        );

        let n = tokio::io::AsyncWriteExt::write(&mut stream, b"test")
            .await
            .unwrap();
        assert_eq!(n, 4);
        assert_eq!(write_bytes.load(Ordering::Relaxed), 4);
    }

    #[tokio::test]
    async fn test_timed_stream_activity_updates_on_read() {
        let data = b"hello world";
        let cursor = Cursor::new(data.to_vec());
        let start_time = Instant::now();
        let last_activity = Arc::new(AtomicU64::new(0));
        let read_bytes = Arc::new(AtomicU64::new(0));
        let write_bytes = Arc::new(AtomicU64::new(0));

        let mut stream = TimedStream::new(
            cursor,
            start_time,
            Arc::clone(&last_activity),
            read_bytes,
            write_bytes,
        );

        // Initial activity should be 0
        assert_eq!(last_activity.load(Ordering::Acquire), 0);

        // Wait a bit and then read
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let mut buf = [0u8; 5];
        let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
            .await
            .unwrap();

        // Activity should be updated to >= 1
        assert!(last_activity.load(Ordering::Acquire) >= 1);
    }

    #[tokio::test]
    async fn test_timed_stream_flush() {
        let cursor = Cursor::new(Vec::new());
        let start_time = Instant::now();
        let last_activity = Arc::new(AtomicU64::new(0));
        let read_bytes = Arc::new(AtomicU64::new(0));
        let write_bytes = Arc::new(AtomicU64::new(0));

        let mut stream =
            TimedStream::new(cursor, start_time, last_activity, read_bytes, write_bytes);

        // Flush should not panic
        tokio::io::AsyncWriteExt::flush(&mut stream).await.unwrap();
    }

    #[tokio::test]
    async fn test_timed_stream_shutdown() {
        let cursor = Cursor::new(Vec::new());
        let start_time = Instant::now();
        let last_activity = Arc::new(AtomicU64::new(0));
        let read_bytes = Arc::new(AtomicU64::new(0));
        let write_bytes = Arc::new(AtomicU64::new(0));

        let mut stream =
            TimedStream::new(cursor, start_time, last_activity, read_bytes, write_bytes);

        // Shutdown should not panic
        tokio::io::AsyncWriteExt::shutdown(&mut stream)
            .await
            .unwrap();
    }
}
