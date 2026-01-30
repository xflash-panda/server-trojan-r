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
use super::transport::{GrpcH2cTransport, MAX_FRAME_SIZE, MAX_SEND_QUEUE_BYTES};

/// Maximum concurrent HTTP/2 streams
const MAX_CONCURRENT_STREAMS: usize = 100;

/// Maximum HTTP/2 header list size
const MAX_HEADER_LIST_SIZE: u32 = 8 * 1024;

/// Initial HTTP/2 window size
const INITIAL_WINDOW_SIZE: u32 = 8 * 1024 * 1024;

/// Initial HTTP/2 connection window size
const INITIAL_CONNECTION_WINDOW_SIZE: u32 = 16 * 1024 * 1024;

/// gRPC HTTP/2 连接管理器
///
/// 管理整个 HTTP/2 连接，接受多个流，每个流对应一个独立的 Trojan 隧道
pub struct GrpcH2cConnection<S> {
    h2_conn: server::Connection<S, Bytes>,
    stream_semaphore: Arc<Semaphore>,
    active_count: Arc<AtomicUsize>,
}

/// Helper to spawn a task with panic-safe counter management
///
/// This ensures the counter is decremented even if the task panics
#[inline]
#[allow(dead_code)]
fn spawn_with_counter<F, Fut>(counter: Arc<AtomicUsize>, task: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    counter.fetch_add(1, Ordering::Relaxed);
    tokio::spawn(async move {
        let _guard = scopeguard::guard((), |_| {
            counter.fetch_sub(1, Ordering::Relaxed);
        });
        task().await;
    });
}

impl<S> GrpcH2cConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub async fn new(stream: S) -> io::Result<Self> {
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

        Ok(Self {
            h2_conn,
            stream_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_STREAMS)),
            active_count: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub async fn run<F, Fut>(self, handler: F) -> Result<()>
    where
        F: Fn(GrpcH2cTransport) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let mut h2_conn = self.h2_conn;
        let stream_semaphore = self.stream_semaphore;
        let active_count = self.active_count;

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
                            if !path.ends_with("/Tun") {
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

                            let transport = GrpcH2cTransport::new(
                                request.into_body(),
                                send_stream,
                            );

                            let handler_clone = Arc::clone(&handler);
                            let active_count_clone = Arc::clone(&active_count);
                            active_count_clone.fetch_add(1, Ordering::Relaxed);
                            tokio::spawn(async move {
                                let _permit = permit;
                                // Use a guard to ensure active_count is decremented even on panic
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
    async fn test_spawn_with_counter_normal_completion() {
        let counter = Arc::new(AtomicUsize::new(0));

        spawn_with_counter(Arc::clone(&counter), || async {
            // Normal task completion
        });

        // Wait for task to complete
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_spawn_with_counter_multiple_tasks() {
        let counter = Arc::new(AtomicUsize::new(0));

        for _ in 0..5 {
            spawn_with_counter(Arc::clone(&counter), || async {
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            });
        }

        // Initially all 5 tasks should be running
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        assert!(counter.load(Ordering::Relaxed) > 0);

        // Wait for all tasks to complete
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_scopeguard_decrements_on_panic() {
        // Test that scopeguard pattern correctly decrements counter on panic
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        counter.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            let _guard = scopeguard::guard((), |_| {
                counter_clone.fetch_sub(1, Ordering::Relaxed);
            });
            panic!("intentional panic for testing");
        });

        // Wait for task to panic
        let _ = handle.await;

        // Counter should be decremented even after panic
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
            // Early return without completing the "work"
            return;
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
}
