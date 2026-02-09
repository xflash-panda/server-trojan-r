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
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream as TungsteniteStream};

/// WebSocket transport wrapper
///
/// Implements AsyncRead + AsyncWrite to provide a unified stream interface
/// for any underlying transport (TCP, TLS, etc.)
pub struct WebSocketTransport<S> {
    ws_stream: Pin<Box<TungsteniteStream<S>>>,
    read_buffer: Bytes,
    read_pos: usize,
    closed: bool,
}

impl<S> WebSocketTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Create a new WebSocket transport from a WebSocket stream
    pub fn new(ws_stream: TungsteniteStream<S>) -> Self {
        Self {
            ws_stream: Box::pin(ws_stream),
            read_buffer: Bytes::new(),
            read_pos: 0,
            closed: false,
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
        match Stream::poll_next(self.ws_stream.as_mut(), cx) {
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
            Poll::Ready(Some(Ok(Message::Close(_))) | Some(Err(_))) => {
                self.closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Ok(_))) => {
                // Skip non-binary messages
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(None) => {
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
        match Sink::poll_ready(me.ws_stream.as_mut(), cx) {
            Poll::Ready(Ok(())) => {
                // Sink ready — send data directly as a single WS Binary message.
                // No intermediate buffer needed: data comes from copy_bidirectional's
                // 32KB relay buffer and goes straight to tungstenite.
                let data = Bytes::copy_from_slice(buf);
                Sink::start_send(me.ws_stream.as_mut(), Message::Binary(data)).map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket send error")
                })?;
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
        Sink::poll_flush(self.ws_stream.as_mut(), cx)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket flush error"))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed = true;
        self.as_mut().poll_flush(cx)
    }
}
