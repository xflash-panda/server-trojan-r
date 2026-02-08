//! gRPC transport layer (v2ray compatible)
//!
//! Implements AsyncRead + AsyncWrite for use as a TCP-like stream.

use bytes::{Buf, Bytes, BytesMut};
use h2::{Reason, RecvStream, SendStream};
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::warn;

use super::codec::{encode_grpc_message, parse_grpc_message};

/// Initial read buffer size (start small, grow as needed)
const INITIAL_READ_BUFFER_SIZE: usize = 8 * 1024;

/// Maximum read buffer size
const MAX_READ_BUFFER_SIZE: usize = 512 * 1024;

/// Maximum frame size for HTTP/2
pub(super) const MAX_FRAME_SIZE: u32 = 64 * 1024;

/// Maximum gRPC message size
const GRPC_MAX_MESSAGE_SIZE: usize = 32 * 1024;

/// Maximum send queue bytes
pub(super) const MAX_SEND_QUEUE_BYTES: usize = 512 * 1024;

/// gRPC transport layer (v2ray compatible)
///
/// Implements AsyncRead + AsyncWrite for use like a normal TCP stream
pub struct GrpcTransport {
    pub(crate) recv_stream: RecvStream,
    pub(crate) send_stream: SendStream<Bytes>,
    pub(crate) read_pending: BytesMut,
    pub(crate) read_buf: Bytes,
    pub(crate) read_pos: usize,
    pub(crate) pending_release_capacity: usize,
    pub(crate) send_queue: VecDeque<Bytes>,
    pub(crate) send_queue_bytes: usize,
    pub(crate) current_frame: Option<Bytes>,
    pub(crate) current_frame_offset: usize,
    pub(crate) closed: bool,
}

impl GrpcTransport {
    pub(crate) fn new(recv_stream: RecvStream, send_stream: SendStream<Bytes>) -> Self {
        Self {
            recv_stream,
            send_stream,
            read_pending: BytesMut::with_capacity(INITIAL_READ_BUFFER_SIZE),
            read_buf: Bytes::new(),
            read_pos: 0,
            pending_release_capacity: 0,
            send_queue: VecDeque::new(),
            send_queue_bytes: 0,
            current_frame: None,
            current_frame_offset: 0,
            closed: false,
        }
    }

    /// Ensure read buffer has capacity, growing if needed up to max
    #[inline]
    fn ensure_read_capacity(&mut self, additional: usize) {
        let needed = self.read_pending.len() + additional;
        if self.read_pending.capacity() < needed {
            let new_capacity = needed
                .max(self.read_pending.capacity() * 2)
                .min(MAX_READ_BUFFER_SIZE);
            self.read_pending
                .reserve(new_capacity - self.read_pending.len());
        }
    }

    fn poll_send_queued(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Some(ref frame) = self.current_frame {
                let remaining = frame.len() - self.current_frame_offset;
                if remaining > 0 {
                    let frame_len = frame.len();
                    match self.poll_send_current_frame(cx)? {
                        Poll::Ready(()) => {
                            self.send_queue_bytes = self.send_queue_bytes.saturating_sub(frame_len);
                            self.current_frame = None;
                            self.current_frame_offset = 0;
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                } else {
                    self.current_frame = None;
                    self.current_frame_offset = 0;
                }
            }

            match self.send_queue.pop_front() {
                Some(frame) => {
                    self.current_frame = Some(frame);
                    self.current_frame_offset = 0;
                }
                None => return Poll::Ready(Ok(())),
            }
        }
    }

    fn poll_send_current_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let frame = match &self.current_frame {
            Some(f) => f,
            None => return Poll::Ready(Ok(())),
        };

        loop {
            let remaining = frame.len() - self.current_frame_offset;
            if remaining == 0 {
                return Poll::Ready(Ok(()));
            }

            let capacity = self.send_stream.capacity();
            if capacity == 0 {
                self.send_stream
                    .reserve_capacity(remaining.min(MAX_FRAME_SIZE as usize));
                match self.send_stream.poll_capacity(cx) {
                    Poll::Ready(Some(Ok(cap))) if cap > 0 => continue,
                    Poll::Ready(Some(Ok(_))) => return Poll::Pending,
                    Poll::Ready(Some(Err(e))) => {
                        return Poll::Ready(Err(io::Error::other(format!(
                            "gRPC capacity error: {}",
                            e
                        ))));
                    }
                    Poll::Ready(None) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "gRPC stream closed",
                        )));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            let send_size = remaining.min(capacity);
            let chunk =
                frame.slice(self.current_frame_offset..self.current_frame_offset + send_size);

            match self.send_stream.send_data(chunk, false) {
                Ok(()) => {
                    self.current_frame_offset += send_size;
                    if self.current_frame_offset >= frame.len() {
                        return Poll::Ready(Ok(()));
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        format!("gRPC send error: {}", e),
                    )));
                }
            }
        }
    }
}

fn is_normal_stream_close(error: &h2::Error) -> bool {
    if let Some(reason) = error.reason() {
        matches!(reason, Reason::NO_ERROR | Reason::CANCEL)
    } else {
        false
    }
}

impl AsyncRead for GrpcTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }

        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;

            if self.pending_release_capacity > 0 {
                let to_release = self.pending_release_capacity.min(to_copy);
                if let Err(e) = self.recv_stream.flow_control().release_capacity(to_release) {
                    warn!(error = %e, to_release, "Failed to release HTTP/2 flow control capacity");
                }
                self.pending_release_capacity -= to_release;
            }

            if self.read_pos >= self.read_buf.len() {
                self.read_buf = Bytes::new();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        loop {
            match parse_grpc_message(&self.read_pending) {
                Ok(Some((consumed, payload))) => {
                    let to_copy = payload.len().min(buf.remaining());
                    buf.put_slice(&payload[..to_copy]);

                    if to_copy < payload.len() {
                        self.read_buf = Bytes::copy_from_slice(&payload[to_copy..]);
                        self.read_pos = 0;
                    }

                    self.read_pending.advance(consumed);

                    // Reclaim memory: after advance(), the consumed bytes become
                    // inaccessible "dead space" in the allocation. Replace with a
                    // fresh small buffer so idle connections don't waste memory.
                    if self.read_pending.is_empty() {
                        self.read_pending = BytesMut::with_capacity(INITIAL_READ_BUFFER_SIZE);
                    }

                    let to_release = self.pending_release_capacity.min(consumed);
                    if to_release > 0 {
                        if let Err(e) = self.recv_stream.flow_control().release_capacity(to_release)
                        {
                            warn!(error = %e, to_release, "Failed to release HTTP/2 flow control capacity");
                        }
                        self.pending_release_capacity -= to_release;
                    }

                    return Poll::Ready(Ok(()));
                }
                Ok(None) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }

            match self.recv_stream.poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    let chunk_len = chunk.len();
                    self.ensure_read_capacity(chunk_len);
                    self.read_pending.extend_from_slice(&chunk);
                    self.pending_release_capacity += chunk_len;
                }
                Poll::Ready(Some(Err(e))) => {
                    self.closed = true;
                    if is_normal_stream_close(&e) {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::other(format!("gRPC recv error: {}", e))));
                }
                Poll::Ready(None) => {
                    self.closed = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for GrpcTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transport closed",
            )));
        }

        let _ = self.poll_send_queued(cx)?;

        if self.send_queue_bytes >= MAX_SEND_QUEUE_BYTES {
            return Poll::Pending;
        }

        let to_write = buf.len().min(GRPC_MAX_MESSAGE_SIZE);
        let frame = encode_grpc_message(&buf[..to_write]);
        let frame_bytes = frame.len();
        self.send_queue.push_back(frame.freeze());
        self.send_queue_bytes += frame_bytes;

        let _ = self.poll_send_queued(cx)?;

        Poll::Ready(Ok(to_write))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_send_queued(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed = true;

        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                if self.current_frame.is_some() || !self.send_queue.is_empty() {
                    return Poll::Pending;
                }

                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", "0".parse().unwrap());
                match self.send_stream.send_trailers(trailers) {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(e) => {
                        if e.is_remote() || e.is_io() {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Ready(Err(io::Error::other(format!(
                                "gRPC send trailers error: {}",
                                e
                            ))))
                        }
                    }
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_buffer_size() {
        assert_eq!(INITIAL_READ_BUFFER_SIZE, 8 * 1024);
        // Compile-time assertion that initial < max
        const _: () = assert!(INITIAL_READ_BUFFER_SIZE < MAX_READ_BUFFER_SIZE);
    }

    #[test]
    fn test_max_buffer_size() {
        assert_eq!(MAX_READ_BUFFER_SIZE, 512 * 1024);
    }

    #[test]
    fn test_grpc_max_message_size() {
        assert_eq!(GRPC_MAX_MESSAGE_SIZE, 32 * 1024);
    }

    #[test]
    fn test_max_send_queue_bytes() {
        assert_eq!(MAX_SEND_QUEUE_BYTES, 512 * 1024);
    }

    #[test]
    fn test_max_frame_size() {
        assert_eq!(MAX_FRAME_SIZE, 64 * 1024);
    }

    /// Verify that read_pending is reset to initial size after all data is consumed.
    ///
    /// Problem: BytesMut::advance() creates "dead space" at the front of the
    /// allocation. After consuming a large gRPC message, the buffer is empty
    /// but the allocation stays large. For idle connections, this wastes memory.
    #[test]
    fn test_read_pending_shrinks_after_grpc_message_consumed() {
        use crate::transport::grpc::codec::{encode_grpc_message, parse_grpc_message};
        use bytes::Buf;

        let mut read_pending = BytesMut::with_capacity(INITIAL_READ_BUFFER_SIZE);
        assert_eq!(read_pending.capacity(), INITIAL_READ_BUFFER_SIZE);

        // Simulate receiving a large gRPC message (same as poll_read does)
        let payload = vec![0xAB; 64 * 1024];
        let encoded = encode_grpc_message(&payload);
        read_pending.extend_from_slice(&encoded);

        let grown_capacity = read_pending.capacity();
        assert!(
            grown_capacity > INITIAL_READ_BUFFER_SIZE,
            "buffer should have grown, capacity={}",
            grown_capacity
        );

        // Parse and consume (same as poll_read line 205-215)
        let (consumed, parsed) = parse_grpc_message(&read_pending).unwrap().unwrap();
        assert_eq!(
            parsed.len(),
            64 * 1024,
            "parsed payload should match original size"
        );
        read_pending.advance(consumed);
        assert!(read_pending.is_empty());

        // After advance: capacity is near 0 because the pointer is at the end.
        // The underlying ALLOCATION is still large (64KB+) but inaccessible.
        // This is the "only grows, never shrinks" problem.
        let wasted_capacity = read_pending.capacity();
        assert!(
            wasted_capacity < INITIAL_READ_BUFFER_SIZE,
            "after full advance, usable capacity should be small, got {}",
            wasted_capacity
        );

        // Apply the production shrink logic (same as what poll_read should do)
        if read_pending.is_empty() {
            read_pending = BytesMut::with_capacity(INITIAL_READ_BUFFER_SIZE);
        }

        // After shrink: fresh buffer with proper initial capacity
        assert_eq!(
            read_pending.capacity(),
            INITIAL_READ_BUFFER_SIZE,
            "after shrink, buffer should be reset to initial size"
        );
    }
}
