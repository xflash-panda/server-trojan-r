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

        let mut heartbeat = H2Heartbeat::new(h2_conn.ping_pong());

        loop {
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
                            active_count_clone.fetch_add(1, Ordering::Relaxed);
                            tokio::spawn(async move {
                                let _permit = permit;
                                let _guard = scopeguard::guard((), |_| {
                                    active_count_clone.fetch_sub(1, Ordering::Relaxed);
                                });
                                let _ = handler_clone(transport).await;
                            });
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "gRPC connection error");
                            return Err(anyhow::anyhow!("gRPC connection error: {}", e));
                        }
                        None => {
                            debug!("gRPC connection closed normally");
                            break;
                        }
                    }
                }

                result = heartbeat.poll() => {
                    if let Err(e) = result {
                        return Err(anyhow::anyhow!("gRPC {}", e));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

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
}
