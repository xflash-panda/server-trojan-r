use hex;
use pin_project_lite::pin_project;
use sha2::{Digest, Sha224};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// ========== TimedStream ==========

pin_project! {
    /// A stream wrapper that tracks the last activity time
    ///
    /// Useful for implementing idle timeout detection
    pub struct TimedStream<S> {
        #[pin]
        inner: S,
        start_time: Instant,
        last_activity: Arc<AtomicU64>,
    }
}

impl<S> TimedStream<S> {
    /// Create a new TimedStream
    pub fn new(inner: S, start_time: Instant, last_activity: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            start_time,
            last_activity,
        }
    }

    /// Get a reference to the inner stream
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Get a mutable reference to the inner stream
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consume this wrapper and return the inner stream
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead> AsyncRead for TimedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();
        let result = this.inner.poll_read(cx, buf);
        if matches!(&result, Poll::Ready(Ok(())) if !buf.filled().is_empty()) {
            // Use Release ordering to ensure the timestamp update is visible
            // to timeout checkers using Acquire ordering
            this.last_activity
                .store(this.start_time.elapsed().as_secs(), Ordering::Release);
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
        if matches!(&result, Poll::Ready(Ok(n)) if *n > 0) {
            // Use Release ordering to ensure the timestamp update is visible
            // to timeout checkers using Acquire ordering
            this.last_activity
                .store(this.start_time.elapsed().as_secs(), Ordering::Release);
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

// ========== Password utilities ==========

/// Hash password using SHA224
pub fn hash_password(password: &str) -> [u8; 28] {
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 28];
    hash.copy_from_slice(&result);
    hash
}

// Convert password to hex
pub fn password_to_hex(password: &str) -> [u8; 56] {
    let hash = hash_password(password);
    let hex_string = hex::encode(hash);
    let mut hex_bytes: [u8; 56] = [0u8; 56];
    hex_bytes.copy_from_slice(hex_string.as_bytes());
    hex_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ========== TimedStream tests ==========

    #[tokio::test]
    async fn test_timed_stream_read_updates_activity() {
        let data = b"hello world";
        let cursor = Cursor::new(data.to_vec());
        let start_time = Instant::now();
        let last_activity = Arc::new(AtomicU64::new(0));

        let mut stream = TimedStream::new(cursor, start_time, Arc::clone(&last_activity));

        let mut buf = [0u8; 5];
        let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await.unwrap();

        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");
        // Activity should be updated (though may still be 0 if < 1 second elapsed)
    }

    #[tokio::test]
    async fn test_timed_stream_write_updates_activity() {
        let cursor = Cursor::new(Vec::new());
        let start_time = Instant::now();
        let last_activity = Arc::new(AtomicU64::new(0));

        let mut stream = TimedStream::new(cursor, start_time, Arc::clone(&last_activity));

        let n = tokio::io::AsyncWriteExt::write(&mut stream, b"test").await.unwrap();
        assert_eq!(n, 4);
    }

    #[test]
    fn test_timed_stream_inner_access() {
        let data = vec![1, 2, 3];
        let cursor = Cursor::new(data.clone());
        let start_time = Instant::now();
        let last_activity = Arc::new(AtomicU64::new(0));

        let stream = TimedStream::new(cursor, start_time, last_activity);

        assert_eq!(stream.inner().get_ref(), &data);
    }

    #[test]
    fn test_timed_stream_into_inner() {
        let data = vec![1, 2, 3];
        let cursor = Cursor::new(data.clone());
        let start_time = Instant::now();
        let last_activity = Arc::new(AtomicU64::new(0));

        let stream = TimedStream::new(cursor, start_time, last_activity);
        let recovered = stream.into_inner();

        assert_eq!(recovered.get_ref(), &data);
    }

    // ========== Password tests ==========

    #[test]
    fn test_hash_password_produces_28_bytes() {
        let hash = hash_password("test_password");
        assert_eq!(hash.len(), 28);
    }

    #[test]
    fn test_hash_password_deterministic() {
        let hash1 = hash_password("same_password");
        let hash2 = hash_password("same_password");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_password_different_inputs() {
        let hash1 = hash_password("password1");
        let hash2 = hash_password("password2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_password_empty_string() {
        let hash = hash_password("");
        assert_eq!(hash.len(), 28);
    }

    #[test]
    fn test_password_to_hex_produces_56_bytes() {
        let hex_bytes = password_to_hex("test_password");
        assert_eq!(hex_bytes.len(), 56);
    }

    #[test]
    fn test_password_to_hex_valid_hex_chars() {
        let hex_bytes = password_to_hex("test_password");
        for &byte in &hex_bytes {
            let c = byte as char;
            assert!(c.is_ascii_hexdigit(), "Expected hex digit, got: {}", c);
        }
    }

    #[test]
    fn test_password_to_hex_known_value() {
        // SHA224("password") = d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01
        let hex_bytes = password_to_hex("password");
        let hex_string = std::str::from_utf8(&hex_bytes).unwrap();
        assert_eq!(
            hex_string,
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }

    #[test]
    fn test_password_to_hex_deterministic() {
        let hex1 = password_to_hex("same_password");
        let hex2 = password_to_hex("same_password");
        assert_eq!(hex1, hex2);
    }

    #[test]
    fn test_password_to_hex_unicode() {
        let hex_bytes = password_to_hex("密码");
        assert_eq!(hex_bytes.len(), 56);
        for &byte in &hex_bytes {
            assert!((byte as char).is_ascii_hexdigit());
        }
    }

    // ========== TimedStream concurrency tests ==========

    #[tokio::test]
    async fn test_timed_stream_activity_updates_on_read() {
        let data = b"hello world";
        let cursor = Cursor::new(data.to_vec());
        let start_time = Instant::now();
        let last_activity = Arc::new(AtomicU64::new(0));

        let mut stream = TimedStream::new(cursor, start_time, Arc::clone(&last_activity));

        // Initial activity should be 0
        assert_eq!(last_activity.load(Ordering::Acquire), 0);

        // Wait a bit and then read
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let mut buf = [0u8; 5];
        let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await.unwrap();

        // Activity should be updated to >= 1
        assert!(last_activity.load(Ordering::Acquire) >= 1);
    }

    #[tokio::test]
    async fn test_timed_stream_activity_updates_on_write() {
        let cursor = Cursor::new(Vec::new());
        let start_time = Instant::now();
        let last_activity = Arc::new(AtomicU64::new(0));

        let mut stream = TimedStream::new(cursor, start_time, Arc::clone(&last_activity));

        // Wait a bit and then write
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let _ = tokio::io::AsyncWriteExt::write(&mut stream, b"test").await.unwrap();

        // Activity should be updated to >= 1
        assert!(last_activity.load(Ordering::Acquire) >= 1);
    }

    #[tokio::test]
    async fn test_timed_stream_shared_activity_tracker() {
        // Test that multiple streams can share the same activity tracker
        let data1 = b"hello";
        let data2 = b"world";
        let start_time = Instant::now();
        let last_activity = Arc::new(AtomicU64::new(0));

        let cursor1 = Cursor::new(data1.to_vec());
        let cursor2 = Cursor::new(data2.to_vec());

        let mut stream1 = TimedStream::new(cursor1, start_time, Arc::clone(&last_activity));
        let mut stream2 = TimedStream::new(cursor2, start_time, Arc::clone(&last_activity));

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Read from stream1
        let mut buf = [0u8; 5];
        let _ = tokio::io::AsyncReadExt::read(&mut stream1, &mut buf).await.unwrap();

        let activity_after_stream1 = last_activity.load(Ordering::Acquire);
        assert!(activity_after_stream1 >= 1);

        // Read from stream2 should also update shared activity
        let _ = tokio::io::AsyncReadExt::read(&mut stream2, &mut buf).await.unwrap();

        let activity_after_stream2 = last_activity.load(Ordering::Acquire);
        assert!(activity_after_stream2 >= activity_after_stream1);
    }
}
