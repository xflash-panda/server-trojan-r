//! Bidirectional relay with idle timeout, half-close timeout, and traffic statistics
//!
//! Custom poll-based bidirectional copy that replaces tokio's `copy_bidirectional`
//! with support for:
//! - Idle timeout: disconnect if no data flows in either direction
//! - Half-close timeout: after one direction finishes (EOF), give the other
//!   direction a short deadline before closing (like Xray's uplinkOnly/downlinkOnly)
//! - Per-direction traffic byte counting

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::hooks::{StatsCollector, UserId};
use std::sync::Arc;

/// Shutdown timeout — prevents infinite hang when peer is unresponsive.
const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

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

/// Buffer for one direction of a bidirectional copy.
///
/// State machine: Read → Write → Flush → (loop) or EOF → Shutdown → Done
struct DirectionalBuffer {
    buf: Vec<u8>,
    /// Start of unwritten data in buf
    pos: usize,
    /// End of valid data in buf
    cap: usize,
    /// Total bytes written to destination
    amt: u64,
    /// Reader returned EOF
    read_done: bool,
    /// Writer needs flush
    need_flush: bool,
    /// Writer shutdown complete — this direction is fully done
    shutdown_done: bool,
}

impl DirectionalBuffer {
    fn new(buf_size: usize) -> Self {
        Self {
            buf: vec![0u8; buf_size],
            pos: 0,
            cap: 0,
            amt: 0,
            read_done: false,
            need_flush: false,
            shutdown_done: false,
        }
    }

    fn is_done(&self) -> bool {
        self.shutdown_done
    }

    fn bytes_transferred(&self) -> u64 {
        self.amt
    }

    /// Try to make maximum progress on this direction.
    ///
    /// Returns:
    /// - `Poll::Ready(Ok(()))` — direction fully complete (EOF + flush + shutdown)
    /// - `Poll::Ready(Err(e))` — I/O error
    /// - `Poll::Pending` — blocked on I/O, waker registered
    fn poll_copy<R: AsyncRead, W: AsyncWrite>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<()>> {
        if self.shutdown_done {
            return Poll::Ready(Ok(()));
        }

        loop {
            // Step 1: Write buffered data
            while self.pos < self.cap {
                let i = ready!(writer
                    .as_mut()
                    .poll_write(cx, &self.buf[self.pos..self.cap]))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero bytes",
                    )));
                }
                self.pos += i;
                self.amt += i as u64;
                self.need_flush = true;
            }

            // Step 2: Flush after writing
            if self.need_flush {
                ready!(writer.as_mut().poll_flush(cx))?;
                self.need_flush = false;
            }

            // Step 3: If reader hit EOF, shutdown writer
            if self.read_done {
                // Ignore shutdown errors (peer may have already closed)
                let _ = ready!(writer.as_mut().poll_shutdown(cx));
                self.shutdown_done = true;
                return Poll::Ready(Ok(()));
            }

            // Step 4: Read more data
            let mut buf = ReadBuf::new(&mut self.buf);
            ready!(reader.as_mut().poll_read(cx, &mut buf))?;
            let n = buf.filled().len();
            if n == 0 {
                self.read_done = true;
                // Loop back to step 3 for shutdown
            } else {
                self.pos = 0;
                self.cap = n;
                // Loop back to step 1 for writing
            }
        }
    }
}

/// Bidirectional copy with idle timeout, per-direction half-close timeouts, and optional traffic statistics
///
/// - `a`: Client stream
/// - `b`: Remote/outbound stream
/// - `idle_timeout_secs`: Disconnect if no data flows for this many seconds
/// - `uplink_only_secs`: After client EOF (a→b done), wait this long for remote (b→a) to finish (Xray: uplinkOnly=2s)
/// - `downlink_only_secs`: After remote EOF (b→a done), wait this long for client (a→b) to finish (Xray: downlinkOnly=5s)
/// - `buffer_size`: Buffer size for each direction of the relay
/// - `stats`: Optional (user_id, stats_collector) for traffic tracking
pub async fn copy_bidirectional_with_stats<A, B>(
    a: &mut A,
    b: &mut B,
    idle_timeout_secs: u64,
    uplink_only_secs: u64,
    downlink_only_secs: u64,
    buffer_size: usize,
    stats: Option<(UserId, Arc<dyn StatsCollector>)>,
) -> io::Result<CopyResult>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut a_to_b = DirectionalBuffer::new(buffer_size);
    let mut b_to_a = DirectionalBuffer::new(buffer_size);

    // Half-close deadline: set when one direction completes, fires after timeout
    let mut half_close_deadline: Option<Pin<Box<tokio::time::Sleep>>> = None;

    // Idle timeout: single Sleep that resets on every data transfer.
    // Unlike interval(30s), this avoids waking active connections every 30s
    // and fires precisely at idle_timeout instead of ±30s granularity.
    let mut idle_deadline = Box::pin(tokio::time::sleep(tokio::time::Duration::from_secs(
        idle_timeout_secs,
    )));

    let result: io::Result<bool> = std::future::poll_fn(|cx| {
        let bytes_before = a_to_b.bytes_transferred() + b_to_a.bytes_transferred();

        // Poll a→b (upload: read from client, write to remote)
        if !a_to_b.is_done() {
            match a_to_b.poll_copy(cx, Pin::new(&mut *a), Pin::new(&mut *b)) {
                Poll::Ready(Ok(())) => {
                    // Client closed (upload EOF) → use uplinkOnly timeout for remaining download
                    if !b_to_a.is_done() && half_close_deadline.is_none() {
                        half_close_deadline = Some(Box::pin(tokio::time::sleep(
                            tokio::time::Duration::from_secs(uplink_only_secs),
                        )));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }

        // Poll b→a (download: read from remote, write to client)
        if !b_to_a.is_done() {
            match b_to_a.poll_copy(cx, Pin::new(&mut *b), Pin::new(&mut *a)) {
                Poll::Ready(Ok(())) => {
                    // Remote closed (download EOF) → use downlinkOnly timeout for remaining upload
                    if !a_to_b.is_done() && half_close_deadline.is_none() {
                        half_close_deadline = Some(Box::pin(tokio::time::sleep(
                            tokio::time::Duration::from_secs(downlink_only_secs),
                        )));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }

        // Reset idle deadline on data activity
        let bytes_after = a_to_b.bytes_transferred() + b_to_a.bytes_transferred();
        if bytes_after > bytes_before {
            idle_deadline.as_mut().reset(
                tokio::time::Instant::now() + tokio::time::Duration::from_secs(idle_timeout_secs),
            );
        }

        // Both directions done → completed normally
        if a_to_b.is_done() && b_to_a.is_done() {
            return Poll::Ready(Ok(true));
        }

        // Half-close timeout
        if let Some(ref mut sleep) = half_close_deadline {
            if sleep.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok(false));
            }
        }

        // Idle timeout: fires precisely after idle_timeout_secs of inactivity
        if idle_deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Ok(false));
        }

        Poll::Pending
    })
    .await;

    // Collect stats before any cleanup
    let a_to_b_bytes = a_to_b.bytes_transferred();
    let b_to_a_bytes = b_to_a.bytes_transferred();

    let completed = matches!(result, Ok(true));

    // Graceful shutdown for streams that didn't complete normally.
    // Sends WebSocket Close frames, gRPC trailers, or TCP FIN as appropriate.
    if !completed {
        let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, tokio::io::AsyncWriteExt::shutdown(a)).await;
        let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, tokio::io::AsyncWriteExt::shutdown(b)).await;
    }

    // Always record traffic stats — regardless of success, timeout, or error
    if let Some((user_id, collector)) = stats {
        if a_to_b_bytes > 0 {
            collector.record_upload(user_id, a_to_b_bytes);
        }
        if b_to_a_bytes > 0 {
            collector.record_download(user_id, b_to_a_bytes);
        }
    }

    match result {
        Ok(completed) => Ok(CopyResult {
            a_to_b: a_to_b_bytes,
            b_to_a: b_to_a_bytes,
            completed,
        }),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicBool, Ordering};

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
    async fn test_basic_bidirectional_copy() {
        let data = b"hello world";
        let mut client = Cursor::new(data.to_vec());
        let mut remote = Cursor::new(Vec::new());

        let result = copy_bidirectional_with_stats(&mut client, &mut remote, 300, 2, 5, 1024, None)
            .await
            .unwrap();

        assert!(result.completed);
        assert!(result.a_to_b > 0);
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
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for ShutdownTracker<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
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
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "test error",
            )))
        }
    }

    impl AsyncWrite for AlwaysError {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "test error",
            )))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Verify that streams are shut down when relay errors out.
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

        let result =
            copy_bidirectional_with_stats(&mut client, &mut remote, 300, 2, 5, 1024, None).await;

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

    /// A stream that accepts writes but never returns data on read.
    /// Simulates a peer that keeps the connection open without sending EOF.
    struct NeverEofSink;

    impl AsyncRead for NeverEofSink {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            // Never return data or EOF — peer keeps connection open.
            // The half-close timer will wake the task, so no waker needed here.
            Poll::Pending
        }
    }

    impl AsyncWrite for NeverEofSink {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// When client sends EOF first (a→b done), uplink_only timeout should apply.
    /// Uses asymmetric timeouts (1s vs 100s) to verify the correct one fires.
    #[tokio::test(start_paused = true)]
    async fn test_uplink_only_timeout_on_client_eof() {
        let mut client = Cursor::new(b"hello".to_vec()); // Will EOF after data
        let mut remote = NeverEofSink; // Never sends EOF back

        let start = tokio::time::Instant::now();
        let result = copy_bidirectional_with_stats(
            &mut client,
            &mut remote,
            300, // idle timeout (high, won't trigger)
            1,   // uplink_only = 1s (THIS should fire)
            100, // downlink_only = 100s (should NOT fire)
            1024,
            None,
        )
        .await
        .unwrap();

        assert!(!result.completed, "Should timeout, not complete normally");
        assert!(result.a_to_b > 0, "Client data should have been relayed");
        // With paused time, mocked clock should advance to uplink_only (1s)
        let elapsed = start.elapsed();
        assert!(
            elapsed >= tokio::time::Duration::from_secs(1),
            "Should wait at least uplink_only timeout"
        );
        assert!(
            elapsed < tokio::time::Duration::from_secs(10),
            "Should NOT wait for downlink_only (100s), elapsed={:?}",
            elapsed
        );
    }

    /// When remote sends EOF first (b→a done), downlink_only timeout should apply.
    /// Uses asymmetric timeouts (100s vs 1s) to verify the correct one fires.
    #[tokio::test(start_paused = true)]
    async fn test_downlink_only_timeout_on_remote_eof() {
        let mut client = NeverEofSink; // Never sends EOF
        let mut remote = Cursor::new(b"world".to_vec()); // Will EOF after data

        let start = tokio::time::Instant::now();
        let result = copy_bidirectional_with_stats(
            &mut client,
            &mut remote,
            300, // idle timeout (high, won't trigger)
            100, // uplink_only = 100s (should NOT fire)
            1,   // downlink_only = 1s (THIS should fire)
            1024,
            None,
        )
        .await
        .unwrap();

        assert!(!result.completed, "Should timeout, not complete normally");
        assert!(result.b_to_a > 0, "Remote data should have been relayed");
        let elapsed = start.elapsed();
        assert!(
            elapsed >= tokio::time::Duration::from_secs(1),
            "Should wait at least downlink_only timeout"
        );
        assert!(
            elapsed < tokio::time::Duration::from_secs(10),
            "Should NOT wait for uplink_only (100s), elapsed={:?}",
            elapsed
        );
    }

    /// Verify stats are recorded even when relay ends via half-close timeout
    #[tokio::test(start_paused = true)]
    async fn test_stats_recorded_on_half_close_timeout() {
        use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

        struct RecordingCollector {
            upload: AtomicU64,
            download: AtomicU64,
        }
        impl StatsCollector for RecordingCollector {
            fn record_request(&self, _: UserId) {}
            fn record_upload(&self, _: UserId, bytes: u64) {
                self.upload.fetch_add(bytes, AtomicOrdering::Relaxed);
            }
            fn record_download(&self, _: UserId, bytes: u64) {
                self.download.fetch_add(bytes, AtomicOrdering::Relaxed);
            }
        }

        let collector = Arc::new(RecordingCollector {
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
        });

        let mut client = Cursor::new(b"upload-data".to_vec());
        let mut remote = NeverEofSink;

        let result = copy_bidirectional_with_stats(
            &mut client,
            &mut remote,
            300,
            1, // uplink_only = 1s
            5, // downlink_only = 5s
            1024,
            Some((42, Arc::clone(&collector) as Arc<dyn StatsCollector>)),
        )
        .await
        .unwrap();

        assert!(!result.completed);
        assert_eq!(
            collector.upload.load(AtomicOrdering::Relaxed),
            result.a_to_b,
            "Upload stats should match bytes transferred"
        );
    }

    #[test]
    fn test_shutdown_timeout_constant() {
        assert_eq!(SHUTDOWN_TIMEOUT, std::time::Duration::from_secs(5));
    }

    /// Verify that &mut reference pattern allows callers to access and
    /// shutdown streams after relay completes (enables cancel_token pattern).
    #[tokio::test]
    async fn test_mut_ref_allows_post_relay_shutdown() {
        let data = b"hello";
        let mut client = Cursor::new(data.to_vec());
        let mut remote = Cursor::new(Vec::new());

        let result = copy_bidirectional_with_stats(&mut client, &mut remote, 300, 2, 5, 1024, None)
            .await
            .unwrap();

        assert!(result.completed);
        assert!(result.a_to_b > 0);

        // Key: streams are still accessible after relay (not moved into the future).
        tokio::io::AsyncWriteExt::shutdown(&mut client)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::shutdown(&mut remote)
            .await
            .unwrap();
    }
}
