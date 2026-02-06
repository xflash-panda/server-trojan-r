//! WebSocket transport
//!
//! Provides WebSocket transport for Trojan protocol.
//! Uses generic type parameter to work with any AsyncRead + AsyncWrite stream,
//! including both plain TCP and TLS streams.

use bytes::Bytes;
use futures_util::{Sink, Stream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream as TungsteniteStream};

/// Initial write buffer capacity (4KB - typical MTU size)
const INITIAL_WRITE_BUFFER_CAPACITY: usize = 4 * 1024;

/// Maximum write buffer size to prevent memory exhaustion (512KB)
const MAX_WRITE_BUFFER_SIZE: usize = 512 * 1024;

/// WebSocket transport wrapper
///
/// Implements AsyncRead + AsyncWrite to provide a unified stream interface
/// for any underlying transport (TCP, TLS, etc.)
pub struct WebSocketTransport<S> {
    ws_stream: Pin<Box<TungsteniteStream<S>>>,
    read_buffer: Bytes,
    read_pos: usize,
    write_buffer: Vec<u8>,
    write_pending: bool,
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
            write_buffer: Vec::with_capacity(INITIAL_WRITE_BUFFER_CAPACITY),
            write_pending: false,
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

        // If there's pending data, try to send it first
        if self.write_pending {
            match Sink::poll_ready(self.ws_stream.as_mut(), cx) {
                Poll::Ready(Ok(())) => {
                    let data = std::mem::take(&mut self.write_buffer);
                    match Sink::start_send(self.ws_stream.as_mut(), Message::Binary(data.into())) {
                        Ok(()) => {
                            self.write_pending = false;
                        }
                        Err(e) => {
                            return Poll::Ready(Err(io::Error::other(format!(
                                "WebSocket send error: {}",
                                e
                            ))));
                        }
                    }
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::other(format!("WebSocket error: {}", e))));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }

        // Check buffer size limit to prevent memory exhaustion
        if self.write_buffer.len() + buf.len() > MAX_WRITE_BUFFER_SIZE {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "WebSocket write buffer exceeded limit",
            )));
        }

        // Add new data to buffer
        self.write_buffer.extend_from_slice(buf);

        // Try to send immediately
        match Sink::poll_ready(self.ws_stream.as_mut(), cx) {
            Poll::Ready(Ok(())) => {
                let data = std::mem::take(&mut self.write_buffer);
                match Sink::start_send(self.ws_stream.as_mut(), Message::Binary(data.into())) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(e) => Poll::Ready(Err(io::Error::other(format!(
                        "WebSocket send error: {}",
                        e
                    )))),
                }
            }
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::other(format!("WebSocket error: {}", e))))
            }
            Poll::Pending => {
                self.write_pending = true;
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Ensure all pending data is sent
        if self.write_pending {
            match Sink::poll_ready(self.ws_stream.as_mut(), cx) {
                Poll::Ready(Ok(())) => {
                    if !self.write_buffer.is_empty() {
                        let data = std::mem::take(&mut self.write_buffer);
                        match Sink::start_send(
                            self.ws_stream.as_mut(),
                            Message::Binary(data.into()),
                        ) {
                            Ok(()) => {
                                self.write_pending = false;
                            }
                            Err(e) => {
                                return Poll::Ready(Err(io::Error::other(format!(
                                    "WebSocket send error: {}",
                                    e
                                ))));
                            }
                        }
                    }
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::other(format!("WebSocket error: {}", e))));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }

        Sink::poll_flush(self.ws_stream.as_mut(), cx)
            .map_err(|e| io::Error::other(format!("WebSocket flush error: {}", e)))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed = true;
        self.as_mut().poll_flush(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_buffer_capacity() {
        assert_eq!(INITIAL_WRITE_BUFFER_CAPACITY, 4 * 1024);
    }

    #[test]
    fn test_max_write_buffer_size() {
        assert_eq!(MAX_WRITE_BUFFER_SIZE, 512 * 1024);
        // Ensure max > initial
        assert!(MAX_WRITE_BUFFER_SIZE > INITIAL_WRITE_BUFFER_CAPACITY);
    }
}
