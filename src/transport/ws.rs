//! WebSocket transport
//!
//! Provides WebSocket transport for Trojan protocol.
//! Uses generic type parameter to work with any AsyncRead + AsyncWrite stream,
//! including both plain TCP and TLS streams.
//!
//! Key design decisions for high-throughput + high-connection-count scenarios:
//! - No intermediate write buffer — data goes directly from relay buffer to WS sink
//! - Backpressure returns Poll::Pending (not Error) so connections survive slow peers
//! - Data stays in copy_bidirectional's buffer when sink is not ready (zero extra copies)

use bytes::Bytes;
use futures_util::{Sink, Stream};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream as TungsteniteStream};

/// WebSocket transport wrapper
///
/// Implements AsyncRead + AsyncWrite to provide a unified stream interface
/// for any underlying transport (TCP, TLS, etc.)
///
/// `TungsteniteStream<S>` is `Unpin` when `S: Unpin` (all fields are owned,
/// no `PhantomPinned`), so we store it directly instead of `Pin<Box<...>>`.
/// This saves one heap allocation per connection and one pointer indirection
/// on every poll_read/poll_write/poll_flush call (the hottest path).
pub struct WebSocketTransport<S> {
    ws_stream: TungsteniteStream<S>,
    read_buffer: Bytes,
    read_pos: usize,
    closed: bool,
    peer_addr: SocketAddr,
}

impl<S> WebSocketTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Create a new WebSocket transport from a WebSocket stream
    pub fn new(ws_stream: TungsteniteStream<S>, peer_addr: SocketAddr) -> Self {
        Self {
            ws_stream,
            read_buffer: Bytes::new(),
            read_pos: 0,
            closed: false,
            peer_addr,
        }
    }
}

impl<S> AsyncRead for WebSocketTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }

        // If buffer has data, consume it first
        if self.read_pos < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;

            if self.read_pos >= self.read_buffer.len() {
                self.read_buffer = Bytes::new();
                self.read_pos = 0;
            }

            return Poll::Ready(Ok(()));
        }

        // Read directly from WebSocket stream
        match Stream::poll_next(Pin::new(&mut self.ws_stream), cx) {
            Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);

                if to_copy < data.len() {
                    // Zero-copy slice
                    self.read_buffer = data.slice(to_copy..);
                    self.read_pos = 0;
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Ok(Message::Close(frame)))) => {
                tracing::info!(
                    peer = %self.peer_addr,
                    close_code = frame.as_ref().map(|f| f.code.into()).unwrap_or(0u16),
                    close_reason = frame.as_ref().map(|f| f.reason.as_ref()).unwrap_or(""),
                    "WS recv Close"
                );
                self.closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => {
                tracing::info!(peer = %self.peer_addr, error = %e, "WS recv error");
                self.closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Ok(_))) => {
                // Skip non-binary messages
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(None) => {
                tracing::info!(peer = %self.peer_addr, "WS stream ended (None)");
                self.closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> AsyncWrite for WebSocketTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WebSocket closed",
            )));
        }

        let me = &mut *self;

        // Check if sink is ready to accept a message
        match Sink::poll_ready(Pin::new(&mut me.ws_stream), cx) {
            Poll::Ready(Ok(())) => {
                // Sink ready — send data directly as a single WS Binary message.
                // No intermediate buffer needed: data comes from copy_bidirectional's
                // 32KB relay buffer and goes straight to tungstenite.
                let data = Bytes::copy_from_slice(buf);
                Sink::start_send(Pin::new(&mut me.ws_stream), Message::Binary(data)).map_err(
                    |_| io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket send error"),
                )?;
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WebSocket error",
            ))),
            Poll::Pending => {
                // Sink not ready — apply backpressure via Pending.
                // Data stays in copy_bidirectional's relay buffer (no copy needed).
                // Waker is already registered by poll_ready above.
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Sink::poll_flush(Pin::new(&mut self.ws_stream), cx)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket flush error"))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            self.closed = true;
            // Send WebSocket Close frame (best-effort, don't block on peer response)
            let me = &mut *self;
            let sent = if let Poll::Ready(Ok(())) = Sink::poll_ready(Pin::new(&mut me.ws_stream), cx) {
                let _ = Sink::start_send(Pin::new(&mut me.ws_stream), Message::Close(None));
                true
            } else {
                false
            };
            tracing::info!(peer = %me.peer_addr, close_sent = sent, "WS shutdown");
        }
        // Don't wait for flush to complete - this avoids hanging on slow peers (realm)
        // during shutdown, which caused connection accumulation in high load scenarios.
        // The Close frame will be sent best-effort, and the connection will be dropped
        // immediately, freeing resources much faster.
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time proof that `WebSocketTransport<S>` is `Unpin` when `S: Unpin`.
    /// This guarantees we can use `Pin::new(&mut ws_stream)` instead of `Box::pin`,
    /// saving one heap allocation per WS connection and one pointer indirection
    /// on every poll_read/poll_write/poll_flush call.
    #[test]
    fn test_websocket_transport_is_unpin() {
        fn assert_unpin<T: Unpin>() {}
        // tokio::io::DuplexStream is a common Unpin stream
        assert_unpin::<WebSocketTransport<tokio::io::DuplexStream>>();
    }

    /// Verify that `WebSocketTransport<S>` implements `Send` when `S: Send`.
    /// Required for `tokio::spawn` in the accept loop.
    #[test]
    fn test_websocket_transport_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<WebSocketTransport<tokio::io::DuplexStream>>();
    }
}
