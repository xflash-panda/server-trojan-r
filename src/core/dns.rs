//! DNS resolution for trojan-rs.
//!
//! Single entry point for converting `Address` values into `SocketAddr`s,
//! and for the SSRF private-IP check that needs the resolved address.
//!
//! Backed by `dns_cache_rs::DnsCache`: per-entry TTL, singleflight,
//! negative caching, pluggable resolver. The cache is constructed in
//! `main.rs`, owned by `Server`, and cloned into the routers (cheap —
//! `DnsCache: Clone` over Arc).

use std::io;
use std::net::SocketAddr;

use dns_cache_rs::{DnsCache, DnsError};

use super::Address;

/// Map a `dns_cache_rs::DnsError` to an `io::Error`.
fn dns_error_to_io(err: DnsError) -> io::Error {
    match err {
        DnsError::NotFound(host) => io::Error::new(
            io::ErrorKind::NotFound,
            format!("no addresses found for {host}"),
        ),
        DnsError::Timeout(d) => io::Error::new(
            io::ErrorKind::TimedOut,
            format!("DNS query timeout after {d:?}"),
        ),
        DnsError::InvalidHost(h) => {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid host: {h}"))
        }
        DnsError::Other(e) => io::Error::other(e.to_string()),
    }
}

/// Resolve an `Address` to a single `SocketAddr`.
///
/// IP literals bypass the cache. Domains go through `DnsCache`; the first
/// resolved address is returned.
pub async fn resolve_socket_addr(cache: &DnsCache, addr: &Address) -> io::Result<SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    match addr {
        Address::IPv4(ip, port) => Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*ip)), *port)),
        Address::IPv6(ip, port) => Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(*ip)), *port)),
        Address::Domain(host, port) => {
            let mut it = cache
                .resolve_with_port_iter(host, *port)
                .await
                .map_err(dns_error_to_io)?;
            it.next().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no addresses found for {host}"),
                )
            })
        }
    }
}

/// Check whether an address is private/loopback/link-local. For domain
/// addresses, also returns the first non-private resolved `SocketAddr` so
/// callers can reuse it without a second DNS lookup.
///
/// **Error semantics — preserved from v0.2.31**: any resolver error
/// (NotFound, Timeout, InvalidHost, Other) collapses to `(false, None)`.
pub(crate) async fn check_private_and_resolve(
    cache: &DnsCache,
    addr: &Address,
) -> (bool, Option<SocketAddr>) {
    use super::ip_filter::{is_private_ipv4, is_private_ipv6};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    match addr {
        Address::IPv4(ip, _) => {
            let ipv4 = Ipv4Addr::from(*ip);
            (is_private_ipv4(&ipv4), None)
        }
        Address::IPv6(ip, _) => {
            let ipv6 = Ipv6Addr::from(*ip);
            (is_private_ipv6(&ipv6), None)
        }
        Address::Domain(host, port) => {
            let it = match cache.resolve_with_port_iter(host, *port).await {
                Ok(it) => it,
                Err(_) => return (false, None),
            };
            let mut first_public: Option<SocketAddr> = None;
            for sa in it {
                match sa.ip() {
                    IpAddr::V4(ipv4) if is_private_ipv4(&ipv4) => {
                        return (true, None);
                    }
                    IpAddr::V6(ipv6) if is_private_ipv6(&ipv6) => {
                        return (true, None);
                    }
                    _ => {
                        if first_public.is_none() {
                            first_public = Some(sa);
                        }
                    }
                }
            }
            (false, first_public)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use dns_cache_rs::{DnsCache, MockResolver};

    fn mock_cache() -> (DnsCache, Arc<MockResolver>) {
        let mock = Arc::new(MockResolver::new());
        let cache = DnsCache::builder()
            .resolver_arc(mock.clone() as Arc<dyn dns_cache_rs::Resolver>)
            .build()
            .expect("DnsCache build with MockResolver");
        (cache, mock)
    }

    #[tokio::test]
    async fn resolve_socket_addr_ipv4_literal_bypasses_cache() {
        let (cache, mock) = mock_cache();
        let addr = Address::IPv4([127, 0, 0, 1], 8080);
        let got = resolve_socket_addr(&cache, &addr).await.unwrap();
        assert_eq!(got, "127.0.0.1:8080".parse::<SocketAddr>().unwrap());
        assert_eq!(mock.total_calls(), 0, "IP literal must not hit resolver");
    }

    #[tokio::test]
    async fn resolve_socket_addr_ipv6_literal_bypasses_cache() {
        let (cache, mock) = mock_cache();
        let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443);
        let got = resolve_socket_addr(&cache, &addr).await.unwrap();
        assert_eq!(got.to_string(), "[::1]:443");
        assert_eq!(mock.total_calls(), 0);
    }

    #[tokio::test]
    async fn resolve_socket_addr_domain_returns_first_address_with_port() {
        let (cache, mock) = mock_cache();
        mock.set(
            "example.com",
            Ok(vec![
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            ]),
        );
        let addr = Address::Domain("example.com".into(), 8080);
        let got = resolve_socket_addr(&cache, &addr).await.unwrap();
        assert_eq!(got, "93.184.216.34:8080".parse::<SocketAddr>().unwrap());
        assert_eq!(mock.call_count("example.com"), 1);
    }

    #[tokio::test]
    async fn resolve_socket_addr_domain_not_found_maps_to_io_not_found() {
        let (cache, mock) = mock_cache();
        // MockResolver returns NotFound for any unmapped host.
        let addr = Address::Domain("nx.invalid".into(), 80);
        let err = resolve_socket_addr(&cache, &addr).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(mock.call_count("nx.invalid") >= 1);
    }

    #[tokio::test]
    async fn resolve_socket_addr_domain_timeout_maps_to_io_timedout() {
        let (cache, mock) = mock_cache();
        mock.set(
            "slow.example",
            Err(dns_cache_rs::DnsError::Timeout(
                std::time::Duration::from_millis(50),
            )),
        );
        let addr = Address::Domain("slow.example".into(), 80);
        let err = resolve_socket_addr(&cache, &addr).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn check_private_and_resolve_ipv4_private_literal() {
        let (cache, mock) = mock_cache();
        let addr = Address::IPv4([10, 0, 0, 1], 80);
        let (is_private, resolved) = check_private_and_resolve(&cache, &addr).await;
        assert!(is_private);
        assert!(resolved.is_none());
        assert_eq!(mock.total_calls(), 0);
    }

    #[tokio::test]
    async fn check_private_and_resolve_ipv6_private_literal() {
        let (cache, mock) = mock_cache();
        // ::1 is loopback
        let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 80);
        let (is_private, resolved) = check_private_and_resolve(&cache, &addr).await;
        assert!(is_private);
        assert!(resolved.is_none());
        assert_eq!(mock.total_calls(), 0);
    }

    #[tokio::test]
    async fn check_private_and_resolve_public_ip_literal() {
        let (cache, mock) = mock_cache();
        let addr = Address::IPv4([8, 8, 8, 8], 53);
        let (is_private, resolved) = check_private_and_resolve(&cache, &addr).await;
        assert!(!is_private);
        assert!(
            resolved.is_none(),
            "IP literals never carry a resolved addr"
        );
        assert_eq!(mock.total_calls(), 0);
    }

    #[tokio::test]
    async fn check_private_and_resolve_domain_resolves_to_private() {
        let (cache, mock) = mock_cache();
        mock.set(
            "internal.example",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))]),
        );
        let addr = Address::Domain("internal.example".into(), 443);
        let (is_private, resolved) = check_private_and_resolve(&cache, &addr).await;
        assert!(is_private);
        assert!(resolved.is_none());
    }

    #[tokio::test]
    async fn check_private_and_resolve_domain_resolves_to_public() {
        let (cache, mock) = mock_cache();
        mock.set(
            "example.com",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]),
        );
        let addr = Address::Domain("example.com".into(), 443);
        let (is_private, resolved) = check_private_and_resolve(&cache, &addr).await;
        assert!(!is_private);
        let sa = resolved.expect("public domain must return a resolved addr");
        assert_eq!(sa, "93.184.216.34:443".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn check_private_and_resolve_domain_resolution_failure_returns_false_none() {
        // Regression guard: preserves v0.2.31 behavior of failing open on
        // DNS errors. Tightening this is out of scope for this refactor.
        let (cache, _mock) = mock_cache();
        let addr = Address::Domain("nx.invalid".into(), 80);
        let (is_private, resolved) = check_private_and_resolve(&cache, &addr).await;
        assert!(!is_private);
        assert!(resolved.is_none());
    }

    #[tokio::test]
    async fn resolve_socket_addr_hits_cache_on_second_call() {
        let (cache, mock) = mock_cache();
        mock.set(
            "hit.example",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]),
        );
        let addr = Address::Domain("hit.example".into(), 80);

        resolve_socket_addr(&cache, &addr).await.unwrap();
        resolve_socket_addr(&cache, &addr).await.unwrap();

        assert_eq!(
            mock.call_count("hit.example"),
            1,
            "cache must coalesce the second call"
        );
    }

    #[tokio::test]
    async fn resolve_socket_addr_singleflight_coalesces_concurrent_calls() {
        use futures_util::future::join_all;

        let (cache, mock) = mock_cache();
        mock.set(
            "race.example",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))]),
        );
        // Force concurrent callers to overlap inside the resolver.
        mock.set_delay(Some(std::time::Duration::from_millis(50)));

        let futs: Vec<_> = (0..100)
            .map(|_| {
                let c = cache.clone();
                tokio::spawn(async move {
                    let addr = Address::Domain("race.example".into(), 80);
                    resolve_socket_addr(&c, &addr).await.unwrap();
                })
            })
            .collect();
        join_all(futs).await;

        assert_eq!(
            mock.call_count("race.example"),
            1,
            "singleflight must collapse 100 concurrent misses into one resolver call"
        );
    }

    #[tokio::test]
    async fn resolve_socket_addr_negative_caching_holds_not_found() {
        let (cache, mock) = mock_cache();
        // Unmapped host => NotFound on every direct resolver call.
        let addr = Address::Domain("nx.example".into(), 80);

        let _ = resolve_socket_addr(&cache, &addr).await;
        let _ = resolve_socket_addr(&cache, &addr).await;

        assert_eq!(
            mock.call_count("nx.example"),
            1,
            "negative caching must hold the NotFound result"
        );
    }

    #[tokio::test]
    async fn resolve_socket_addr_refetches_after_positive_ttl_expires() {
        // moka uses std::time::Instant (not tokio's mock clock), so we must use
        // a short real TTL + real sleep. This mirrors the approach used in
        // dns-cache-rs's own `positive_ttl_expires_then_re_resolves` test.
        let mock = std::sync::Arc::new(dns_cache_rs::MockResolver::new());
        mock.set(
            "ttl.example",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3))]),
        );
        let cache = dns_cache_rs::DnsCache::builder()
            .resolver_arc(mock.clone() as std::sync::Arc<dyn dns_cache_rs::Resolver>)
            .ttl(std::time::Duration::from_millis(200))
            .build()
            .expect("DnsCache build with short TTL");
        let addr = Address::Domain("ttl.example".into(), 80);

        resolve_socket_addr(&cache, &addr).await.unwrap();
        assert_eq!(mock.call_count("ttl.example"), 1);

        // Advance past the 200ms TTL with a 400ms margin to absorb CI jitter.
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        resolve_socket_addr(&cache, &addr).await.unwrap();
        assert_eq!(
            mock.call_count("ttl.example"),
            2,
            "after TTL expiry the resolver must be invoked again"
        );
    }

    // --- Migrated from src/core/protocol.rs (test_address_to_socket_addr_*) ---

    #[tokio::test]
    async fn migrated_to_socket_addr_ipv4() {
        let (cache, _) = mock_cache();
        let addr = Address::IPv4([127, 0, 0, 1], 8080);
        let got = resolve_socket_addr(&cache, &addr).await.unwrap();
        assert_eq!(got.to_string(), "127.0.0.1:8080");
    }

    #[tokio::test]
    async fn migrated_to_socket_addr_ipv6() {
        let (cache, _) = mock_cache();
        let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443);
        let got = resolve_socket_addr(&cache, &addr).await.unwrap();
        assert_eq!(got.to_string(), "[::1]:443");
    }

    #[tokio::test]
    async fn migrated_to_socket_addr_domain_resolves() {
        let (cache, mock) = mock_cache();
        mock.set(
            "localhost.test",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]),
        );
        let addr = Address::Domain("localhost.test".into(), 80);
        assert!(resolve_socket_addr(&cache, &addr).await.is_ok());
    }

    #[tokio::test]
    async fn migrated_to_socket_addr_empty_domain_fails() {
        // Pre-refactor: `Address::Domain("", 80).to_socket_addr()` returned Err.
        // dns-cache-rs's normalize step rejects empty hosts → InvalidHost.
        let (cache, _) = mock_cache();
        let addr = Address::Domain(String::new(), 80);
        let err = resolve_socket_addr(&cache, &addr).await.unwrap_err();
        // Either NotFound (no addrs) or InvalidInput (empty host) is acceptable;
        // we just need a hard error like the pre-refactor behavior.
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::InvalidInput
            ),
            "expected NotFound or InvalidInput, got {:?}",
            err.kind()
        );
    }
}
