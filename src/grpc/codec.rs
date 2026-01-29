use bytes::{BufMut, BytesMut};
use std::io;

/// 解析 gRPC 消息帧（兼容 v2ray 格式）
///
/// 格式：5字节 gRPC 头部 + protobuf 头部 + 数据
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

/// 编码 gRPC 消息帧
pub fn encode_grpc_message(payload: &[u8]) -> BytesMut {
    let mut proto_header = BytesMut::with_capacity(10);
    proto_header.put_u8(0x0A);
    encode_varint(payload.len() as u64, &mut proto_header);

    let grpc_payload_len = (proto_header.len() + payload.len()) as u32;
    let mut buf = BytesMut::with_capacity(5 + proto_header.len() + payload.len());
    buf.put_u8(0x00);
    buf.put_u32(grpc_payload_len);
    buf.extend_from_slice(&proto_header);
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

        // Verify structure
        assert_eq!(encoded[0], 0x00); // Not compressed
                                      // Check protobuf tag
        assert_eq!(encoded[5], 0x0A); // Field 1, wire type 2 (length-delimited)
    }

    #[test]
    fn test_encode_grpc_message_empty() {
        let payload = b"";
        let encoded = encode_grpc_message(payload);

        assert_eq!(encoded[0], 0x00); // Not compressed
                                      // gRPC frame length should be 2 (tag + varint 0)
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
    fn test_parse_grpc_message_incomplete_body() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x00); // Not compressed
        buf.put_u32(100); // Claim 100 bytes
        buf.put_u8(0x0A); // Protobuf tag

        let result = parse_grpc_message(&buf).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_grpc_message_compressed_error() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x01); // Compressed
        buf.put_u32(10);
        buf.extend_from_slice(&[0; 10]);

        let result = parse_grpc_message(&buf);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("compressed"));
    }

    #[test]
    fn test_parse_grpc_message_invalid_tag() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x00); // Not compressed
        buf.put_u32(5); // 5 bytes
        buf.put_u8(0xFF); // Invalid tag
        buf.extend_from_slice(&[0; 4]);

        let result = parse_grpc_message(&buf);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unexpected protobuf tag"));
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
    fn test_encode_decode_roundtrip_large() {
        let original: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let encoded = encode_grpc_message(&original);
        let buf = BytesMut::from(&encoded[..]);

        let (_, decoded) = parse_grpc_message(&buf).unwrap().unwrap();
        assert_eq!(decoded, &original[..]);
    }

    #[test]
    fn test_varint_encoding() {
        // Test small values
        let mut buf = BytesMut::new();
        encode_varint(0, &mut buf);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0], 0);

        buf.clear();
        encode_varint(127, &mut buf);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0], 127);

        // Test values requiring multiple bytes
        buf.clear();
        encode_varint(128, &mut buf);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf[0], 0x80);
        assert_eq!(buf[1], 0x01);

        buf.clear();
        encode_varint(300, &mut buf);
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn test_varint_decoding() {
        // Test single byte
        let (val, bytes) = decode_varint(&[0]).unwrap();
        assert_eq!(val, 0);
        assert_eq!(bytes, 1);

        let (val, bytes) = decode_varint(&[127]).unwrap();
        assert_eq!(val, 127);
        assert_eq!(bytes, 1);

        // Test multi-byte
        let (val, bytes) = decode_varint(&[0x80, 0x01]).unwrap();
        assert_eq!(val, 128);
        assert_eq!(bytes, 2);

        let (val, bytes) = decode_varint(&[0xAC, 0x02]).unwrap();
        assert_eq!(val, 300);
        assert_eq!(bytes, 2);
    }

    #[test]
    fn test_varint_roundtrip() {
        for value in [
            0u64,
            1,
            127,
            128,
            255,
            256,
            16383,
            16384,
            1000000,
            u64::MAX / 2,
        ] {
            let mut buf = BytesMut::new();
            encode_varint(value, &mut buf);
            let (decoded, _) = decode_varint(&buf).unwrap();
            assert_eq!(decoded, value, "Roundtrip failed for {}", value);
        }
    }

    #[test]
    fn test_varint_decode_incomplete() {
        let result = decode_varint(&[0x80]); // Needs more bytes
        assert!(result.is_err());
    }

    #[test]
    fn test_varint_decode_too_long() {
        // More than 10 continuation bytes
        let data = [0x80u8; 11];
        let result = decode_varint(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("varint too long"));
    }

    #[test]
    fn test_parse_multiple_messages() {
        let payload1 = b"first";
        let payload2 = b"second";

        let encoded1 = encode_grpc_message(payload1);
        let encoded2 = encode_grpc_message(payload2);

        let mut buf = BytesMut::new();
        buf.extend_from_slice(&encoded1);
        buf.extend_from_slice(&encoded2);

        // Parse first message
        let (consumed1, decoded1) = parse_grpc_message(&buf).unwrap().unwrap();
        assert_eq!(decoded1, payload1);

        // Advance buffer and parse second
        let _ = buf.split_to(consumed1);
        let (_, decoded2) = parse_grpc_message(&buf).unwrap().unwrap();
        assert_eq!(decoded2, payload2);
    }
}
