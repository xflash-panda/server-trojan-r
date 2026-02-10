//! gRPC message codec
//!
//! Encodes and decodes gRPC frames compatible with v2ray format.

use bytes::{BufMut, Bytes, BytesMut};
use std::io;

/// Parse gRPC message frame (v2ray compatible format)
///
/// Format: 5-byte gRPC header + protobuf header + data
#[allow(dead_code)]
pub fn parse_grpc_message(buf: &BytesMut) -> io::Result<Option<(usize, &[u8])>> {
    if buf.len() < 6 {
        return Ok(None);
    }

    if buf[0] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed gRPC not supported",
        ));
    }

    let grpc_frame_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;

    if buf.len() < 5 + grpc_frame_len {
        return Ok(None);
    }

    if buf[5] != 0x0A {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected protobuf tag: 0x{:02X}, expected 0x0A", buf[5]),
        ));
    }

    let (payload_len_u64, varint_bytes) = decode_varint(&buf[6..])?;
    let payload_len = payload_len_u64 as usize;
    let data_start = 6 + varint_bytes;
    let data_end = data_start + payload_len;

    if data_end > 5 + grpc_frame_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "payload length {} exceeds gRPC frame length {}",
                payload_len, grpc_frame_len
            ),
        ));
    }

    let payload = &buf[data_start..data_end];
    let consumed = 5 + grpc_frame_len;

    Ok(Some((consumed, payload)))
}

/// Zero-copy variant of parse_grpc_message.
///
/// Consumes the gRPC frame from `buf` via `split_to` and returns the payload as
/// a `Bytes` handle that shares the underlying allocation (no memcpy).
/// Also returns the number of bytes consumed (for HTTP/2 flow control).
pub fn parse_grpc_message_zerocopy(buf: &mut BytesMut) -> io::Result<Option<(Bytes, usize)>> {
    if buf.len() < 6 {
        return Ok(None);
    }

    if buf[0] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed gRPC not supported",
        ));
    }

    let grpc_frame_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;

    if buf.len() < 5 + grpc_frame_len {
        return Ok(None);
    }

    if buf[5] != 0x0A {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected protobuf tag: 0x{:02X}, expected 0x0A", buf[5]),
        ));
    }

    let (payload_len_u64, varint_bytes) = decode_varint(&buf[6..])?;
    let payload_len = payload_len_u64 as usize;
    let data_start = 6 + varint_bytes;
    let data_end = data_start + payload_len;

    if data_end > 5 + grpc_frame_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "payload length {} exceeds gRPC frame length {}",
                payload_len, grpc_frame_len
            ),
        ));
    }

    let consumed = 5 + grpc_frame_len;
    // split_to consumes the frame from buf; freeze + slice yields a zero-copy Bytes
    let frame = buf.split_to(consumed).freeze();
    let payload = frame.slice(data_start..data_end);

    Ok(Some((payload, consumed)))
}

/// Encode gRPC message frame (single allocation)
pub fn encode_grpc_message(payload: &[u8]) -> BytesMut {
    let varint_bytes = varint_len(payload.len() as u64);
    let proto_len = 1 + varint_bytes + payload.len(); // tag + varint + payload

    let mut buf = BytesMut::with_capacity(5 + proto_len);
    buf.put_u8(0x00); // not compressed
    buf.put_u32(proto_len as u32); // gRPC frame length
    buf.put_u8(0x0A); // protobuf field 1, wire type 2
    encode_varint(payload.len() as u64, &mut buf);
    buf.extend_from_slice(payload);
    buf
}

fn decode_varint(data: &[u8]) -> io::Result<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0;

    for (i, &byte) in data.iter().enumerate() {
        if i >= 10 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "varint too long",
            ));
        }

        result |= ((byte & 0x7F) as u64) << shift;

        if (byte & 0x80) == 0 {
            return Ok((result, i + 1));
        }

        shift += 7;
    }

    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "incomplete varint",
    ))
}

/// Compute the number of bytes needed to encode a varint
fn varint_len(value: u64) -> usize {
    if value == 0 {
        return 1;
    }
    let bits = 64 - value.leading_zeros() as usize;
    bits.div_ceil(7)
}

fn encode_varint(mut value: u64, buf: &mut BytesMut) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.put_u8(byte);
        if value == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_grpc_message_simple() {
        let payload = b"hello";
        let encoded = encode_grpc_message(payload);

        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[5], 0x0A);
    }

    #[test]
    fn test_encode_grpc_message_empty() {
        let payload = b"";
        let encoded = encode_grpc_message(payload);

        assert_eq!(encoded[0], 0x00);
        let frame_len = u32::from_be_bytes([encoded[1], encoded[2], encoded[3], encoded[4]]);
        assert_eq!(frame_len, 2);
    }

    #[test]
    fn test_parse_grpc_message_simple() {
        let payload = b"test data";
        let encoded = encode_grpc_message(payload);

        let buf = BytesMut::from(&encoded[..]);
        let result = parse_grpc_message(&buf).unwrap();

        assert!(result.is_some());
        let (consumed, parsed_payload) = result.unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn test_parse_grpc_message_incomplete_header() {
        let buf = BytesMut::from(&[0x00, 0x00, 0x00][..]);
        let result = parse_grpc_message(&buf).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = b"The quick brown fox jumps over the lazy dog";
        let encoded = encode_grpc_message(original);
        let buf = BytesMut::from(&encoded[..]);

        let (consumed, decoded) = parse_grpc_message(&buf).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_varint_encoding() {
        let mut buf = BytesMut::new();
        encode_varint(0, &mut buf);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0], 0);

        buf.clear();
        encode_varint(127, &mut buf);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0], 127);

        buf.clear();
        encode_varint(128, &mut buf);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf[0], 0x80);
        assert_eq!(buf[1], 0x01);
    }

    #[test]
    fn test_varint_decoding() {
        let (val, bytes) = decode_varint(&[0]).unwrap();
        assert_eq!(val, 0);
        assert_eq!(bytes, 1);

        let (val, bytes) = decode_varint(&[127]).unwrap();
        assert_eq!(val, 127);
        assert_eq!(bytes, 1);

        let (val, bytes) = decode_varint(&[0x80, 0x01]).unwrap();
        assert_eq!(val, 128);
        assert_eq!(bytes, 2);
    }

    #[test]
    fn test_parse_grpc_message_zerocopy_roundtrip() {
        let payload = b"zero-copy test data";
        let encoded = encode_grpc_message(payload);

        let mut buf = BytesMut::from(&encoded[..]);
        let (parsed_payload, consumed) = parse_grpc_message_zerocopy(&mut buf).unwrap().unwrap();

        assert_eq!(consumed, encoded.len());
        assert_eq!(&parsed_payload[..], &payload[..]);
        // buf should be empty after split_to consumed the frame
        assert!(buf.is_empty());
    }

    #[test]
    fn test_parse_grpc_message_zerocopy_incomplete() {
        let mut buf = BytesMut::from(&[0x00, 0x00, 0x00][..]);
        assert!(parse_grpc_message_zerocopy(&mut buf).unwrap().is_none());
        // buf should be unchanged since nothing was consumed
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn test_varint_roundtrip() {
        for value in [0u64, 1, 127, 128, 255, 256, 16383, 16384, 1000000] {
            let mut buf = BytesMut::new();
            encode_varint(value, &mut buf);
            let (decoded, _) = decode_varint(&buf).unwrap();
            assert_eq!(decoded, value, "Roundtrip failed for {}", value);
        }
    }
}
