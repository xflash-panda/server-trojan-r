//! gRPC HTTP/2 connection manager
//!
//! Manages HTTP/2 connections and accepts multiple streams,
//! each stream corresponds to an independent Trojan tunnel.

use anyhow::Result;
use bytes::Bytes;
use h2::server;
use http::{Response, StatusCode};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::heartbeat::H2Heartbeat;
use super::transport::{GrpcTransport, MAX_FRAME_SIZE, MAX_SEND_QUEUE_BYTES};

/// Maximum concurrent HTTP/2 streams
const MAX_CONCURRENT_STREAMS: usize = 100;

/// Maximum HTTP/2 header list size
const MAX_HEADER_LIST_SIZE: u32 = 8 * 1024;

/// Initial HTTP/2 stream window size (per stream)
/// Go net/http2 default is 1MB. 8MB was excessive and caused high memory
/// usage under load (100 streams × 8MB = 800MB per H2 connection).
const INITIAL_WINDOW_SIZE: u32 = 1024 * 1024;

/// Initial HTTP/2 connection window size (shared across all streams)
const INITIAL_CONNECTION_WINDOW_SIZE: u32 = 4 * 1024 * 1024;

/// gRPC HTTP/2 connection manager
///
/// Manages an HTTP/2 connection, accepting multiple streams where each
/// stream corresponds to an independent Trojan tunnel.
pub struct GrpcConnection<S> {
    h2_conn: server::Connection<S, Bytes>,
    stream_semaphore: Arc<Semaphore>,
    active_count: Arc<AtomicUsize>,
    /// Expected gRPC path (format: "/${service_name}/Tun")
    expected_path: String,
    /// Buffer size for gRPC message framing
    buffer_size: usize,
}

/// Default gRPC service name (Xray compatible)
const DEFAULT_GRPC_SERVICE_NAME: &str = "GunService";

impl<S> GrpcConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Create a new gRPC connection from an underlying stream with default service name
    #[allow(dead_code)]
    pub async fn new(stream: S) -> io::Result<Self> {
        Self::with_service_name(stream, DEFAULT_GRPC_SERVICE_NAME).await
    }

    /// Create a new gRPC connection with a custom service name
    ///
    /// The expected path will be "/${service_name}/Tun" (v2ray/Xray compatible)
    pub async fn with_service_name(stream: S, service_name: &str) -> io::Result<Self> {
        Self::with_config(stream, service_name, 0).await
    }

    /// Create a new gRPC connection with a custom service name and buffer size
    ///
    /// `buffer_size` controls the gRPC message framing size.
    /// If 0, uses the default (32KB).
    pub async fn with_config(
        stream: S,
        service_name: &str,
        buffer_size: usize,
    ) -> io::Result<Self> {
        let h2_conn = server::Builder::new()
            .max_header_list_size(MAX_HEADER_LIST_SIZE)
            .initial_window_size(INITIAL_WINDOW_SIZE)
            .initial_connection_window_size(INITIAL_CONNECTION_WINDOW_SIZE)
            .max_frame_size(MAX_FRAME_SIZE)
            .max_concurrent_streams(MAX_CONCURRENT_STREAMS as u32)
            .max_send_buffer_size(MAX_SEND_QUEUE_BYTES)
            .handshake(stream)
            .await
            .map_err(|e| io::Error::other(format!("h2 handshake: {}", e)))?;

        let expected_path = format!("/{}/Tun", service_name);

        Ok(Self {
            h2_conn,
            stream_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_STREAMS)),
            active_count: Arc::new(AtomicUsize::new(0)),
            expected_path,
            buffer_size,
        })
    }

    /// Run the connection, calling the handler for each accepted stream
    ///
    /// When the H2 connection closes (error, heartbeat timeout, or graceful),
    /// all spawned handler tasks are cancelled via a shared CancellationToken
    /// to prevent orphaned tasks from holding resources until their idle timeout.
    pub async fn run<F, Fut>(self, handler: F) -> Result<()>
    where
        F: Fn(GrpcTransport) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let mut h2_conn = self.h2_conn;
        let stream_semaphore = self.stream_semaphore;
        let active_count = self.active_count;
        let buffer_size = self.buffer_size;

        // Shared token: cancelled when this H2 connection closes,
        // causing all spawned handler tasks to abort promptly.
        let conn_cancel = CancellationToken::new();

        let mut heartbeat = H2Heartbeat::new(h2_conn.ping_pong());

        let result = loop {
            tokio::select! {
                result = h2_conn.accept() => {
                    match result {
                        Some(Ok((request, mut respond))) => {
                            heartbeat.on_activity();

                            if request.method() != http::Method::POST {
                                let response = Response::builder()
                                    .status(StatusCode::METHOD_NOT_ALLOWED)
                                    .body(())
                                    .unwrap();
                                let _ = respond.send_response(response, true);
                                continue;
                            }

                            let path = request.uri().path();
                            if path != self.expected_path {
                                debug!(path = %path, expected = %self.expected_path, "gRPC path mismatch");
                                let response = Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(())
                                    .unwrap();
                                let _ = respond.send_response(response, true);
                                continue;
                            }

                            let permit = match stream_semaphore.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    let response = Response::builder()
                                        .status(StatusCode::SERVICE_UNAVAILABLE)
                                        .header("grpc-status", "8")
                                        .body(())
                                        .unwrap();
                                    let _ = respond.send_response(response, true);
                                    continue;
                                }
                            };

                            let response = Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/grpc")
                                .header("te", "trailers")
                                .header("grpc-accept-encoding", "identity,deflate,gzip")
                                .body(())
                                .unwrap();

                            let send_stream = match respond.send_response(response, false) {
                                Ok(stream) => stream,
                                Err(e) => {
                                    warn!(error = %e, "Failed to send gRPC response");
                                    drop(permit);
                                    continue;
                                }
                            };

                            let transport = if buffer_size > 0 {
                                GrpcTransport::with_buffer_size(
                                    request.into_body(),
                                    send_stream,
                                    buffer_size,
                                )
                            } else {
                                GrpcTransport::new(
                                    request.into_body(),
                                    send_stream,
                                )
                            };

                            let handler_clone = Arc::clone(&handler);
                            let active_count_clone = Arc::clone(&active_count);
                            let task_cancel = conn_cancel.child_token();
                            active_count_clone.fetch_add(1, Ordering::Relaxed);
                            tokio::spawn(async move {
                                let _permit = permit;
                                let _guard = scopeguard::guard((), |_| {
                                    active_count_clone.fetch_sub(1, Ordering::Relaxed);
                                });
                                tokio::select! {
                                    result = handler_clone(transport) => { let _ = result; }
                                    _ = task_cancel.cancelled() => {
                                        debug!("gRPC stream handler cancelled (connection closed)");
                                    }
                                }
                            });
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "gRPC connection error");
                            break Err(anyhow::anyhow!("gRPC connection error: {}", e));
                        }
                        None => {
                            debug!("gRPC connection closed normally");
                            break Ok(());
                        }
                    }
                }

                result = heartbeat.poll() => {
                    if let Err(e) = result {
                        break Err(anyhow::anyhow!("gRPC {}", e));
                    }
                }
            }
        };

        // Cancel all handler tasks spawned on this H2 connection.
        // Tasks will drop their GrpcTransport, relay buffers, and
        // ConnectionManager registrations via scopeguard.
        conn_cancel.cancel();

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    #[tokio::test]
    async fn test_scopeguard_decrements_on_panic() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        counter.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            let _guard = scopeguard::guard((), |_| {
                counter_clone.fetch_sub(1, Ordering::Relaxed);
            });
            panic!("intentional panic for testing");
        });

        let _ = handle.await;
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_scopeguard_decrements_on_early_return() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        counter.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            let _guard = scopeguard::guard((), |_| {
                counter_clone.fetch_sub(1, Ordering::Relaxed);
            });
        });

        let _ = handle.await;
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_concurrent_counter_operations() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];

        for _ in 0..100 {
            let counter_clone = Arc::clone(&counter);
            handles.push(tokio::spawn(async move {
                counter_clone.fetch_add(1, Ordering::Relaxed);
                let _guard = scopeguard::guard((), |_| {
                    counter_clone.fetch_sub(1, Ordering::Relaxed);
                });
                tokio::task::yield_now().await;
            }));
        }

        for handle in handles {
            let _ = handle.await;
        }

        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    // Compile-time assertions for H2 window size relationships
    const _: () = assert!(INITIAL_WINDOW_SIZE <= INITIAL_CONNECTION_WINDOW_SIZE);
    const _: () = assert!(INITIAL_CONNECTION_WINDOW_SIZE >= INITIAL_WINDOW_SIZE * 2);

    #[test]
    fn test_h2_window_sizes() {
        // Match Go net/http2 defaults (1MB stream, 4MB connection)
        assert_eq!(INITIAL_WINDOW_SIZE, 1024 * 1024);
        assert_eq!(INITIAL_CONNECTION_WINDOW_SIZE, 4 * 1024 * 1024);
    }

    #[test]
    fn test_h2_max_concurrent_streams() {
        // Memory bound: MAX_CONCURRENT_STREAMS × INITIAL_WINDOW_SIZE should be reasonable
        let max_memory_per_conn = MAX_CONCURRENT_STREAMS as u64 * INITIAL_WINDOW_SIZE as u64;
        // With 100 streams × 1MB = 100MB per H2 connection (was 800MB with 8MB windows)
        assert!(
            max_memory_per_conn <= 256 * 1024 * 1024,
            "per-connection memory bound too high: {}MB",
            max_memory_per_conn / (1024 * 1024)
        );
    }

    /// Verify that conn_cancel token cancels spawned handler tasks when
    /// the H2 connection closes, preventing orphaned tasks.
    #[tokio::test]
    async fn test_conn_cancel_token_cancels_handlers() {
        let conn_cancel = CancellationToken::new();
        let task_started = Arc::new(AtomicBool::new(false));
        let task_cancelled = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicUsize::new(0));

        // Simulate spawning a handler task with child_token (same pattern as run())
        let task_cancel = conn_cancel.child_token();
        let started = Arc::clone(&task_started);
        let cancelled = Arc::clone(&task_cancelled);
        let counter_clone = Arc::clone(&counter);
        counter_clone.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            let _guard = scopeguard::guard((), |_| {
                counter_clone.fetch_sub(1, Ordering::Relaxed);
            });
            started.store(true, Ordering::Release);

            tokio::select! {
                // Simulate a long-running handler (e.g. relay with 5min idle timeout)
                _ = tokio::time::sleep(std::time::Duration::from_secs(300)) => {}
                _ = task_cancel.cancelled() => {
                    cancelled.store(true, Ordering::Release);
                }
            }
        });

        // Wait for task to start
        tokio::task::yield_now().await;
        assert!(task_started.load(Ordering::Acquire));
        assert_eq!(counter.load(Ordering::Relaxed), 1);

        // Simulate H2 connection closing → cancel all handlers
        conn_cancel.cancel();

        handle.await.unwrap();

        assert!(
            task_cancelled.load(Ordering::Acquire),
            "Handler task should have been cancelled"
        );
        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "Scopeguard should have decremented counter"
        );
    }

    /// Verify that multiple handler tasks are all cancelled when conn_cancel fires.
    #[tokio::test]
    async fn test_conn_cancel_token_cancels_multiple_handlers() {
        let conn_cancel = CancellationToken::new();
        let active = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];

        for _ in 0..10 {
            let task_cancel = conn_cancel.child_token();
            let active_clone = Arc::clone(&active);
            active_clone.fetch_add(1, Ordering::Relaxed);

            handles.push(tokio::spawn(async move {
                let _guard = scopeguard::guard((), |_| {
                    active_clone.fetch_sub(1, Ordering::Relaxed);
                });
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(300)) => {}
                    _ = task_cancel.cancelled() => {}
                }
            }));
        }

        tokio::task::yield_now().await;
        assert_eq!(active.load(Ordering::Relaxed), 10);

        // Cancel all at once
        conn_cancel.cancel();

        for handle in handles {
            handle.await.unwrap();
        }
        assert_eq!(
            active.load(Ordering::Relaxed),
            0,
            "All handler tasks should have been cleaned up"
        );
    }

    /// Verify that already-completed handlers are not affected by conn_cancel.
    #[tokio::test]
    async fn test_conn_cancel_ignores_completed_handlers() {
        let conn_cancel = CancellationToken::new();
        let counter = Arc::new(AtomicUsize::new(0));

        // Spawn a handler that completes immediately
        let task_cancel = conn_cancel.child_token();
        let counter_clone = Arc::clone(&counter);
        counter_clone.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            let _guard = scopeguard::guard((), |_| {
                counter_clone.fetch_sub(1, Ordering::Relaxed);
            });
            tokio::select! {
                _ = async { /* completes immediately */ } => {}
                _ = task_cancel.cancelled() => {}
            }
        });

        handle.await.unwrap();
        assert_eq!(counter.load(Ordering::Relaxed), 0);

        // Cancel after handler already finished — should be a no-op
        conn_cancel.cancel();
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }
}
