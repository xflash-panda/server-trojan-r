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
/// - `buffer_size`: Buffer size for each direction of the relay
/// - `stats`: Optional tuple of (user_id, stats_collector) for traffic tracking
///
/// Returns CopyResult with bytes transferred and completion status.
/// Note: Traffic is tracked in real-time, even if the connection times out.
pub async fn copy_bidirectional_with_stats<A, B>(
    a: &mut A,
    b: &mut B,
    idle_timeout_secs: u64,
    buffer_size: usize,
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

    let copy_task = tokio::io::copy_bidirectional_with_sizes(
        &mut stream_a,
        &mut stream_b,
        buffer_size,
        buffer_size,
    );

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

    // Execute relay and capture result (success, timeout, or error)
    let (completed, io_error) = tokio::select! {
        result = copy_task => {
            match result {
                Ok(_) => (true, None),
                Err(e) => (false, Some(e)),
            }
        }
        _ = timeout_check => (false, None)
    };

    // Graceful shutdown when relay didn't complete normally (timeout or error).
    // Ensures WebSocket Close frames, gRPC trailers, and TCP FIN are sent.
    if !completed {
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream_a).await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream_b).await;
    }

    // Always get accurate traffic data from counters (real-time tracked)
    let a_to_b = counters.a_to_b.load(Ordering::Relaxed);
    let b_to_a = counters.b_to_a.load(Ordering::Relaxed);

    // Always record traffic stats - regardless of success, timeout, or error
    if let Some((user_id, collector)) = stats {
        if a_to_b > 0 {
            collector.record_upload(user_id, a_to_b);
        }
        if b_to_a > 0 {
            collector.record_download(user_id, b_to_a);
        }
    }

    // Return result based on execution outcome
    match io_error {
        Some(e) => Err(e),
        None => Ok(CopyResult {
            a_to_b,
            b_to_a,
            completed,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::AtomicBool;

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

    /// Stream wrapper that tracks whether shutdown was called
    struct ShutdownTracker<S> {
        inner: S,
        shutdown_called: Arc<AtomicBool>,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for ShutdownTracker<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for ShutdownTracker<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.shutdown_called.store(true, Ordering::Release);
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// A stream that always returns error on read (simulates broken connection)
    struct AlwaysError;

    impl AsyncRead for AlwaysError {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "test error",
            )))
        }
    }

    impl AsyncWrite for AlwaysError {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "test error",
            )))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Verify that streams are shut down when relay errors out.
    /// This tests the `if !completed` shutdown path added to fix
    /// connections being dropped without proper close frames/FIN.
    #[tokio::test]
    async fn test_shutdown_called_on_relay_error() {
        let client_shutdown = Arc::new(AtomicBool::new(false));
        let remote_shutdown = Arc::new(AtomicBool::new(false));

        let mut client = ShutdownTracker {
            inner: AlwaysError,
            shutdown_called: Arc::clone(&client_shutdown),
        };
        let mut remote = ShutdownTracker {
            inner: Cursor::new(Vec::new()),
            shutdown_called: Arc::clone(&remote_shutdown),
        };

        let result = copy_bidirectional_with_stats(&mut client, &mut remote, 300, 1024, None).await;

        assert!(result.is_err(), "Should return error from broken stream");
        assert!(
            client_shutdown.load(Ordering::Acquire),
            "Client stream should be shut down after error"
        );
        assert!(
            remote_shutdown.load(Ordering::Acquire),
            "Remote stream should be shut down after error"
        );
    }

    /// Verify that the &mut reference pattern allows callers to
    /// access and shutdown streams after relay completes.
    /// This enables handler.rs to call shutdown after cancel_token fires.
    #[tokio::test]
    async fn test_mut_ref_allows_post_relay_shutdown() {
        let data = b"hello";
        let mut client = Cursor::new(data.to_vec());
        let mut remote = Cursor::new(Vec::new());

        let result = copy_bidirectional_with_stats(&mut client, &mut remote, 300, 1024, None)
            .await
            .unwrap();

        assert!(result.completed);
        assert!(result.a_to_b > 0);

        // Key: streams are still accessible after relay (not moved into the future).
        // This enables the caller to call shutdown after cancel or timeout.
        tokio::io::AsyncWriteExt::shutdown(&mut client)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::shutdown(&mut remote)
            .await
            .unwrap();
    }
}
