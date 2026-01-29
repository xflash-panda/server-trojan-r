use sha2::{Sha224, Digest};
use hex;  

// Hash password using SHA224
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
            assert!(
                c.is_ascii_hexdigit(),
                "Expected hex digit, got: {}",
                c
            );
        }
    }

    #[test]
    fn test_password_to_hex_known_value() {
        // SHA224("password") = d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01
        let hex_bytes = password_to_hex("password");
        let hex_string = std::str::from_utf8(&hex_bytes).unwrap();
        assert_eq!(hex_string, "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01");
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
}
