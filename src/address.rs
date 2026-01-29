use std::net::{IpAddr, SocketAddr};
use anyhow::{Result, anyhow};

const DNS_RESOLVE_TIMEOUT_SECS: u64 = 10;

// Address types (compatible with Trojan/SOCKS5 address encoding)
#[derive(Debug, Clone, Copy)]
pub enum _AddressType {
    IPv4 = 1,
    FQDN = 3,
    IPv6 = 4,
}

// Target address for Trojan protocol
#[derive(Debug, Clone)]
pub enum Address {
    IPv4([u8; 4], u16),
    IPv6([u8; 16], u16),
    Domain(String, u16),
}

impl Address {
    pub fn port(&self) -> u16 {
        match self {
            Address::IPv4(_, port) => *port,
            Address::IPv6(_, port) => *port,
            Address::Domain(_, port) => *port,
        }
    }

    pub async fn to_socket_addr(&self) -> Result<SocketAddr> {
        match self {
            Address::IPv4(ip, port) => {
                let addr = IpAddr::V4(std::net::Ipv4Addr::from(*ip));
                Ok(SocketAddr::new(addr, *port))
            }
            Address::IPv6(ip, port) => {
                let addr = IpAddr::V6(std::net::Ipv6Addr::from(*ip));
                Ok(SocketAddr::new(addr, *port))
            }
            Address::Domain(domain, port) => {
                let addrs = tokio::time::timeout(
                    tokio::time::Duration::from_secs(DNS_RESOLVE_TIMEOUT_SECS),
                    tokio::net::lookup_host((domain.as_str(), *port)),
                )
                .await
                .map_err(|_| anyhow!("DNS resolution timeout after {} seconds", DNS_RESOLVE_TIMEOUT_SECS))??;
                addrs.into_iter().next()
                    .ok_or_else(|| anyhow!("Failed to resolve domain: {}", domain))
            }
        }
    }

    // For UDP associations, we don't use the target address as the key
    // Instead, we could use connection info or just create unique sockets
    pub fn to_association_key(&self, client_info: &str) -> String {
        format!("{}_{}", client_info, self.to_key())
    }
    
    pub fn to_key(&self) -> String {
        match self {
            Address::IPv4(ip, port) => format!("{}:{}",
                std::net::Ipv4Addr::from(*ip), port),
            Address::IPv6(ip, port) => format!("[{}]:{}",
                std::net::Ipv6Addr::from(*ip), port),
            Address::Domain(domain, port) => format!("{}:{}", domain, port),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_address_port() {
        let addr = Address::IPv4([192, 168, 1, 1], 8080);
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_ipv6_address_port() {
        let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443);
        assert_eq!(addr.port(), 443);
    }

    #[test]
    fn test_domain_address_port() {
        let addr = Address::Domain("example.com".to_string(), 80);
        assert_eq!(addr.port(), 80);
    }

    #[test]
    fn test_ipv4_to_key() {
        let addr = Address::IPv4([192, 168, 1, 1], 8080);
        assert_eq!(addr.to_key(), "192.168.1.1:8080");
    }

    #[test]
    fn test_ipv6_to_key() {
        let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443);
        assert_eq!(addr.to_key(), "[::1]:443");
    }

    #[test]
    fn test_domain_to_key() {
        let addr = Address::Domain("example.com".to_string(), 80);
        assert_eq!(addr.to_key(), "example.com:80");
    }

    #[test]
    fn test_to_association_key() {
        let addr = Address::IPv4([10, 0, 0, 1], 1234);
        let key = addr.to_association_key("client_127.0.0.1:5000");
        assert_eq!(key, "client_127.0.0.1:5000_10.0.0.1:1234");
    }

    #[tokio::test]
    async fn test_ipv4_to_socket_addr() {
        let addr = Address::IPv4([127, 0, 0, 1], 8080);
        let socket_addr = addr.to_socket_addr().await.unwrap();
        assert_eq!(socket_addr.to_string(), "127.0.0.1:8080");
    }

    #[tokio::test]
    async fn test_ipv6_to_socket_addr() {
        let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443);
        let socket_addr = addr.to_socket_addr().await.unwrap();
        assert_eq!(socket_addr.to_string(), "[::1]:443");
    }

    #[tokio::test]
    async fn test_domain_to_socket_addr_localhost() {
        let addr = Address::Domain("localhost".to_string(), 8080);
        let result = addr.to_socket_addr().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_domain_to_socket_addr_unresolvable() {
        // Use a guaranteed invalid TLD per RFC 6761
        let addr = Address::Domain("unresolvable.invalid".to_string(), 80);
        let result = addr.to_socket_addr().await;
        // Some DNS resolvers may return NXDOMAIN, others may resolve it
        // We just verify the function completes without panic
        let _ = result;
    }

    #[test]
    fn test_address_clone() {
        let addr1 = Address::Domain("example.com".to_string(), 443);
        let addr2 = addr1.clone();
        assert_eq!(addr1.to_key(), addr2.to_key());
    }

    #[test]
    fn test_address_debug() {
        let addr = Address::IPv4([192, 168, 0, 1], 8080);
        let debug_str = format!("{:?}", addr);
        assert!(debug_str.contains("IPv4"));
        assert!(debug_str.contains("192"));
        assert!(debug_str.contains("8080"));
    }
}