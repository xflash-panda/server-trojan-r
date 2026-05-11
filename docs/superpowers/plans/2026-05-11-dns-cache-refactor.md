# DNS Cache Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `tokio::net::lookup_host` calls in server-trojan-rs with `dns-cache-rs` v0.2.0, keeping behavior identical and driving the change with TDD using `MockResolver`.

**Architecture:** Introduce a new `src/core/dns.rs` module as the sole DNS entry point. A single `DnsCache` is constructed in `main.rs`, stored on `Server`, and cloned into `DirectRouter` / `AclRouter` (cheap — `DnsCache: Clone` over Arc). `Address::to_socket_addr` and the free function `core::hooks::check_private_and_resolve` are deleted.

**Tech Stack:** Rust 2021, tokio 1.x, `dns-cache-rs` v0.2.0 (moka-backed, singleflight, per-entry TTL), `MockResolver` for tests.

**Spec:** [docs/superpowers/specs/2026-05-11-dns-cache-refactor-design.md](../specs/2026-05-11-dns-cache-refactor-design.md)

**Test baseline (pre-change):** 275 tests (lib 18 + bin 257). Target post-change: ~286 (+19 new DNS-module tests, −8 migrated/deleted tests = net +11).

**Project rules** (`CLAUDE.md`):
- Commit messages in English. **No** `Co-Authored-By: Claude`.
- Before each commit: `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` must pass.

---

## File Structure

**Create:**
- `src/core/dns.rs` — sole DNS entry point. Holds `resolve_socket_addr`, `check_private_and_resolve`, error mapping, and all DNS-related tests (unit + migrated regression).

**Modify:**
- `Cargo.toml` — add `dns-cache-rs` to `[dependencies]` and `[dev-dependencies]` (with `test-utils` feature). Bump version `0.2.31 → 0.2.32`.
- `src/core/mod.rs` — declare `pub mod dns;` (kept `pub` so `acl.rs` and `handler.rs` can use it).
- `src/core/server.rs` — add `pub dns_cache: DnsCache` field + builder method.
- `src/core/hooks.rs` — add `dns_cache` field to `DirectRouter`; route via `core::dns::check_private_and_resolve`; **delete** the free function `check_private_and_resolve` and the `use tokio::net::lookup_host`. Tests using `lookup_host` move to `core/dns.rs`.
- `src/core/protocol.rs` — **delete** `Address::to_socket_addr` and `use tokio::net::lookup_host`. The 4 `test_address_to_socket_addr_*` tests move to `core/dns.rs` (rewritten against `resolve_socket_addr`).
- `src/acl.rs` — add `dns_cache` field to `AclRouter`; route via `core::dns::check_private_and_resolve`.
- `src/handler.rs` — replace `ctx.target.to_socket_addr()` with `core::dns::resolve_socket_addr(&ctx.server.dns_cache, ctx.target)`.
- `src/main.rs` and `src/server_runner.rs` — build one `DnsCache::new()`, clone into router (via `build_router`) and into `Server` (via builder).

**Delete (by edit):**
- `Address::to_socket_addr` in `src/core/protocol.rs`.
- Free function `core::hooks::check_private_and_resolve` in `src/core/hooks.rs`.

---

## Task 1: Add `dns-cache-rs` dependency

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add dep + dev-dep lines and bump version**

Apply this edit. The new dependency block sits alongside the existing `acl-engine-rs` block; the dev-dep goes into `[dev-dependencies]`.

In the `[package]` section change:
```toml
version = "0.2.31"
```
to:
```toml
version = "0.2.32"
```

After the existing line:
```toml
acl-engine-rs = { git = "https://github.com/xflash-panda/acl-engine-rs.git", tag = "v0.4.4", features = ["async"] }
```
add (one line above the `# Panel Integration` comment if present, otherwise just below the acl-engine-rs line):
```toml

# DNS resolution cache (internal library, shared with server-anytls/server-mieru)
dns-cache-rs = { git = "https://github.com/xflash-panda/dns-cache-rs.git", tag = "v0.2.0" }
```

In the `[dev-dependencies]` section after `tempfile = "3.15"`:
```toml
dns-cache-rs = { git = "https://github.com/xflash-panda/dns-cache-rs.git", tag = "v0.2.0", features = ["test-utils"] }
```

- [ ] **Step 2: Confirm dependency resolves**

Run: `cargo check`
Expected: clean build, no compile errors. New `dns-cache-rs` package downloaded into `Cargo.lock`.

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "build: add dns-cache-rs v0.2.0, bump to 0.2.32"
```

---

## Task 2: Create `core::dns` skeleton + first failing test

**Files:**
- Create: `src/core/dns.rs`
- Modify: `src/core/mod.rs`

- [ ] **Step 1: Add `pub mod dns;` declaration**

Edit `src/core/mod.rs`. Change:
```rust
mod connection;
pub mod hooks;
pub mod ip_filter;
mod protocol;
mod relay;
mod server;
```
to:
```rust
mod connection;
pub mod dns;
pub mod hooks;
pub mod ip_filter;
mod protocol;
mod relay;
mod server;
```

- [ ] **Step 2: Create `src/core/dns.rs` with skeleton + first failing test**

```rust
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
        DnsError::InvalidHost(h) => io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid host: {h}"),
        ),
        DnsError::Other(e) => io::Error::new(io::ErrorKind::Other, e.to_string()),
    }
}

/// Resolve an `Address` to a single `SocketAddr`.
///
/// IP literals bypass the cache. Domains go through `DnsCache`; the first
/// resolved address is returned.
pub async fn resolve_socket_addr(
    cache: &DnsCache,
    addr: &Address,
) -> io::Result<SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    match addr {
        Address::IPv4(ip, port) => {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*ip)), *port))
        }
        Address::IPv6(ip, port) => {
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(*ip)), *port))
        }
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
}
```

- [ ] **Step 3: Run the test (RED)**

Run: `cargo test --lib core::dns::tests::resolve_socket_addr_ipv4_literal_bypasses_cache`
Expected: PASS. (The skeleton already implements this case correctly. It's the smoke test that proves the wiring compiles.)

If `cargo test` complains about unused imports or warnings, treat them as failures and fix them before committing.

- [ ] **Step 4: Run full suite to confirm nothing regressed**

Run: `cargo test`
Expected: 275 lib+bin tests pass, plus 1 new test = 276 total.

- [ ] **Step 5: Commit**

```bash
git add src/core/mod.rs src/core/dns.rs
git commit -m "feat(core/dns): add DNS module skeleton with cache-backed resolver

Introduces resolve_socket_addr and check_private_and_resolve as the
single DNS entry point. Backed by dns-cache-rs DnsCache (singleflight,
per-entry TTL, MockResolver for tests). No call sites migrated yet."
```

---

## Task 3: Add unit tests for IP-literal and domain resolution paths

**Files:**
- Modify: `src/core/dns.rs`

- [ ] **Step 1: Append the next four tests to `tests` mod (RED-then-GREEN: skeleton already implements them)**

Place these inside `#[cfg(test)] mod tests { … }`, after the existing test.

```rust
#[tokio::test]
async fn resolve_socket_addr_ipv6_literal_bypasses_cache() {
    let (cache, mock) = mock_cache();
    let addr = Address::IPv6(
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        443,
    );
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
        Err(DnsError::Timeout(std::time::Duration::from_millis(50))),
    );
    let addr = Address::Domain("slow.example".into(), 80);
    let err = resolve_socket_addr(&cache, &addr).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
}
```

- [ ] **Step 2: Run the new tests**

Run: `cargo test --lib core::dns::tests`
Expected: 5 tests pass (the original + 4 new).

- [ ] **Step 3: Run full suite**

Run: `cargo test`
Expected: 279 total. No regressions.

- [ ] **Step 4: Commit**

```bash
git add src/core/dns.rs
git commit -m "test(core/dns): resolve_socket_addr covers IPv4/IPv6/domain/NotFound/Timeout"
```

---

## Task 4: Add `check_private_and_resolve` unit tests

**Files:**
- Modify: `src/core/dns.rs`

- [ ] **Step 1: Append 6 tests for `check_private_and_resolve`**

Append to `#[cfg(test)] mod tests`:

```rust
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
    assert!(resolved.is_none(), "IP literals never carry a resolved addr");
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
```

- [ ] **Step 2: Run new tests**

Run: `cargo test --lib core::dns::tests`
Expected: 11 tests pass (5 prior + 6 new).

- [ ] **Step 3: Run full suite**

Run: `cargo test`
Expected: 285 total. No regressions.

- [ ] **Step 4: Commit**

```bash
git add src/core/dns.rs
git commit -m "test(core/dns): check_private_and_resolve covers IPs, domains, and error fail-open"
```

---

## Task 5: Cache-hit, singleflight, negative-caching, TTL-expiry tests

**Files:**
- Modify: `src/core/dns.rs`

- [ ] **Step 1: Append 4 cache-behavior tests**

Append to `#[cfg(test)] mod tests`:

```rust
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

    let cache = cache;
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

#[tokio::test(start_paused = true)]
async fn resolve_socket_addr_refetches_after_positive_ttl_expires() {
    let (cache, mock) = mock_cache();
    mock.set(
        "ttl.example",
        Ok(vec![IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3))]),
    );
    let addr = Address::Domain("ttl.example".into(), 80);

    resolve_socket_addr(&cache, &addr).await.unwrap();
    assert_eq!(mock.call_count("ttl.example"), 1);

    // Default positive TTL is 120s; advance past it.
    tokio::time::advance(std::time::Duration::from_secs(130)).await;

    resolve_socket_addr(&cache, &addr).await.unwrap();
    assert_eq!(
        mock.call_count("ttl.example"),
        2,
        "after TTL expiry the resolver must be invoked again"
    );
}
```

`futures_util` is already in `Cargo.toml` (line 9); no new dep needed.

- [ ] **Step 2: Run new tests**

Run: `cargo test --lib core::dns::tests`
Expected: 15 tests pass.

- [ ] **Step 3: Run full suite**

Run: `cargo test`
Expected: 289 total. No regressions.

- [ ] **Step 4: Commit**

```bash
git add src/core/dns.rs
git commit -m "test(core/dns): cache hit, singleflight, negative cache, TTL expiry"
```

---

## Task 6: Migrate `Address::to_socket_addr` tests, then delete the method

**Files:**
- Modify: `src/core/protocol.rs`, `src/core/dns.rs`

- [ ] **Step 1: Copy the 4 protocol tests into `core::dns::tests`, rewritten against `resolve_socket_addr`**

Append to `#[cfg(test)] mod tests`:

```rust
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
```

- [ ] **Step 2: Delete `Address::to_socket_addr` and its 4 tests from `src/core/protocol.rs`**

Remove the entire `pub async fn to_socket_addr` (currently lines 177-193 in protocol.rs):

Find this block:
```rust
    /// Resolve to socket address
    pub async fn to_socket_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Address::IPv4(ip, port) => Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*ip)), *port)),
            Address::IPv6(ip, port) => Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(*ip)), *port)),
            Address::Domain(domain, port) => {
                let addr_str = format!("{}:{}", domain, port);
                let mut addrs = lookup_host(&addr_str).await?;
                addrs.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("no addresses found for {}", domain),
                    )
                })
            }
        }
    }
```
…and delete it (including the blank line above and the doc comment).

Also remove the import:
```rust
use tokio::net::lookup_host;
```

Also delete these 4 tests from the `#[cfg(test)] mod tests` block of protocol.rs:
- `test_address_to_socket_addr_ipv4`
- `test_address_to_socket_addr_ipv6`
- `test_address_to_socket_addr_domain`
- `test_address_to_socket_addr_domain_resolution`

(Currently at protocol.rs:592-620.)

- [ ] **Step 3: Update handler.rs to call `core::dns::resolve_socket_addr`**

In `src/handler.rs`, change line 344 inside `handle_direct_connect`:

```rust
    // Fast path: no ACL handler, use simple TcpStream::connect with keepalive/nodelay
    let remote_addr = match resolved {
        Some(addr) => addr,
        None => ctx.target.to_socket_addr().await?,
    };
```
to:
```rust
    // Fast path: no ACL handler, use simple TcpStream::connect with keepalive/nodelay
    let remote_addr = match resolved {
        Some(addr) => addr,
        None => {
            crate::core::dns::resolve_socket_addr(&ctx.server.dns_cache, ctx.target).await?
        }
    };
```

> Note: this references `ctx.server.dns_cache`, which Task 7 adds. Task 6 will NOT compile until Task 7 lands. **Do not commit Task 6 yet** — proceed to Task 7 first, then verify and commit them together at the end of Task 7.

- [ ] **Step 4: Verify (deferred to Task 7)**

Skip running tests at this point — they will fail because `Server.dns_cache` does not yet exist. Move on to Task 7.

---

## Task 7: Thread `DnsCache` through `Server`, `DirectRouter`, `AclRouter`, `main.rs`

**Files:**
- Modify: `src/core/server.rs`, `src/core/hooks.rs`, `src/acl.rs`, `src/server_runner.rs`, `src/main.rs`

- [ ] **Step 1: Add `dns_cache` field to `Server` + builder method**

Edit `src/core/server.rs`.

Add at the top of the `use` block:
```rust
use dns_cache_rs::DnsCache;
```

Change the `Server` struct:
```rust
pub struct Server {
    /// Authenticator for user validation
    pub authenticator: Arc<dyn Authenticator>,
    /// Statistics collector
    pub stats: Arc<dyn StatsCollector>,
    /// Outbound router for traffic routing
    pub router: Arc<dyn OutboundRouter>,
    /// Connection manager
    pub conn_manager: ConnectionManager,
    /// Connection performance configuration
    pub conn_config: ConnConfig,
    /// Shared DNS cache (cloned into routers; cheap — Arc-backed).
    pub dns_cache: DnsCache,
}
```

Change `ServerBuilder`:
```rust
pub struct ServerBuilder {
    authenticator: Option<Arc<dyn Authenticator>>,
    stats: Option<Arc<dyn StatsCollector>>,
    router: Option<Arc<dyn OutboundRouter>>,
    conn_manager: Option<ConnectionManager>,
    conn_config: Option<ConnConfig>,
    dns_cache: Option<DnsCache>,
}
```

Change `ServerBuilder::new`:
```rust
pub fn new() -> Self {
    Self {
        authenticator: None,
        stats: None,
        router: None,
        conn_manager: None,
        conn_config: None,
        dns_cache: None,
    }
}
```

Add a builder method right after `conn_config`:
```rust
    /// Set shared DNS cache (optional; defaults to `DnsCache::new()`).
    pub fn dns_cache(mut self, cache: DnsCache) -> Self {
        self.dns_cache = Some(cache);
        self
    }
```

Change `ServerBuilder::build`:
```rust
pub fn build(self) -> Server {
    let dns_cache = self.dns_cache.unwrap_or_else(DnsCache::new);
    Server {
        authenticator: self.authenticator.expect("authenticator is required"),
        stats: self.stats.expect("stats collector is required"),
        router: self
            .router
            .unwrap_or_else(|| Arc::new(DirectRouter::with_cache(true, dns_cache.clone()))),
        conn_manager: self.conn_manager.unwrap_or_default(),
        conn_config: self.conn_config.expect("conn_config is required"),
        dns_cache,
    }
}
```

The change from `DirectRouter::new()` to `DirectRouter::with_cache(true, dns_cache.clone())` is intentional: when the caller doesn't supply a router we now use the same shared `DnsCache`. The previous `DirectRouter::new()` (which used its own private cache) is fine but we want one cache per process so future invalidations work.

- [ ] **Step 2: Add `dns_cache` field + new constructors to `DirectRouter`**

Edit `src/core/hooks.rs`.

Add to the top of the `use` block (after the existing `use crate::core::Address;`):
```rust
use dns_cache_rs::DnsCache;
```

Change the `DirectRouter` struct:
```rust
pub struct DirectRouter {
    /// Block connections to private/loopback IP addresses
    block_private_ip: bool,
    /// Shared DNS cache (clone of `Server.dns_cache`).
    dns_cache: DnsCache,
}
```

Update `DirectRouter::new`:
```rust
impl DirectRouter {
    /// Create a new DirectRouter with private IP blocking enabled (default)
    /// and a fresh `DnsCache::new()`.
    pub fn new() -> Self {
        Self {
            block_private_ip: true,
            dns_cache: DnsCache::new(),
        }
    }

    /// Create a new DirectRouter with custom private IP blocking setting
    /// and a fresh `DnsCache::new()`.
    pub fn with_block_private_ip(block_private_ip: bool) -> Self {
        Self {
            block_private_ip,
            dns_cache: DnsCache::new(),
        }
    }

    /// Create a new DirectRouter that shares the given DNS cache.
    pub fn with_cache(block_private_ip: bool, dns_cache: DnsCache) -> Self {
        Self {
            block_private_ip,
            dns_cache,
        }
    }
}
```

Change `impl OutboundRouter for DirectRouter` to call the new `core::dns::check_private_and_resolve`:
```rust
#[async_trait]
impl OutboundRouter for DirectRouter {
    async fn route(&self, addr: &Address) -> OutboundType {
        if self.block_private_ip {
            let (is_private, resolved) =
                crate::core::dns::check_private_and_resolve(&self.dns_cache, addr).await;
            if is_private {
                return OutboundType::Reject;
            }
            return OutboundType::Direct {
                resolved,
                handler: None,
            };
        }
        OutboundType::Direct {
            resolved: None,
            handler: None,
        }
    }
}
```

**Delete** the free function `pub(crate) async fn check_private_and_resolve` (currently lines 126-165) and its 4 unit tests at the bottom of `hooks.rs`:
- `test_check_private_and_resolve_ipv4_private`
- `test_check_private_and_resolve_ipv4_public`
- `test_check_private_and_resolve_domain_private`
- `test_check_private_and_resolve_domain_public`

(Equivalent coverage now lives in `core::dns::tests` — see Task 4.)

Leave the `DirectRouter` tests in place (we'll adjust them in Task 8).

- [ ] **Step 3: Add `dns_cache` field + new constructor to `AclRouter`**

Edit `src/acl.rs`.

Add (near other `use`s, after `use async_trait::async_trait;`):
```rust
use dns_cache_rs::DnsCache;
```

Change the `AclRouter` struct:
```rust
pub struct AclRouter {
    engine: AclEngine,
    /// Block connections to private/loopback IP addresses (SSRF protection)
    block_private_ip: bool,
    /// Shared DNS cache (clone of `Server.dns_cache`).
    dns_cache: DnsCache,
}
```

Update the `impl AclRouter` block (currently around line 643):
```rust
impl AclRouter {
    /// Create a new ACL router with custom private IP blocking setting
    /// and a fresh `DnsCache::new()`.
    pub fn with_block_private_ip(engine: AclEngine, block_private_ip: bool) -> Self {
        Self {
            engine,
            block_private_ip,
            dns_cache: DnsCache::new(),
        }
    }

    /// Create a new ACL router that shares the given DNS cache.
    pub fn with_cache(
        engine: AclEngine,
        block_private_ip: bool,
        dns_cache: DnsCache,
    ) -> Self {
        Self {
            engine,
            block_private_ip,
            dns_cache,
        }
    }
}
```

Change `impl OutboundRouter for AclRouter` (currently line 653-674) to use the new DNS module:
```rust
#[async_trait]
impl crate::core::hooks::OutboundRouter for AclRouter {
    async fn route(&self, addr: &crate::core::Address) -> crate::core::hooks::OutboundType {
        let mut resolved_addr: Option<std::net::SocketAddr> = None;

        if self.block_private_ip {
            let (is_private, resolved) =
                crate::core::dns::check_private_and_resolve(&self.dns_cache, addr).await;
            if is_private {
                log::debug!(target = %addr, "Blocked private address");
                return crate::core::hooks::OutboundType::Reject;
            }
            resolved_addr = resolved;
        }

        let host = addr.host();
        let port = addr.port();

        self.route_host_with_resolved(&host, port, resolved_addr)
    }
}
```

- [ ] **Step 4: Update `server_runner::build_router` to accept and thread the cache**

Edit `src/server_runner.rs`.

Add import at top of `use` block:
```rust
use dns_cache_rs::DnsCache;
```

Change the signature of `build_router`:
```rust
pub async fn build_router(
    config: &config::ServerConfig,
    refresh_geodata: bool,
    dns_cache: DnsCache,
) -> Result<Arc<dyn hooks::OutboundRouter>> {
    use crate::acl::AclRouter;

    if let Some(ref acl_path) = config.acl_conf_file {
        // ... existing path validation unchanged ...

        let acl_config = acl::load_acl_config(acl_path).await?;
        let engine =
            acl::AclEngine::new(acl_config, Some(config.data_dir.as_path()), refresh_geodata)
                .await?;

        log::info!(
            acl_file = %acl_path.display(),
            rules = engine.rule_count(),
            block_private_ip = config.block_private_ip,
            refresh_geodata = refresh_geodata,
            "ACL router loaded"
        );

        Ok(Arc::new(AclRouter::with_cache(
            engine,
            config.block_private_ip,
            dns_cache,
        )) as Arc<dyn hooks::OutboundRouter>)
    } else {
        log::info!(
            block_private_ip = config.block_private_ip,
            "No ACL config, using direct connection for all traffic"
        );
        Ok(Arc::new(hooks::DirectRouter::with_cache(
            config.block_private_ip,
            dns_cache,
        )) as Arc<dyn hooks::OutboundRouter>)
    }
}
```

(Keep the path validation block — the `?` arms and `eq_ignore_ascii_case` checks — exactly as they are; only the construction of `AclRouter`/`DirectRouter` changes.)

- [ ] **Step 5: Update `main.rs` to construct the cache and pass clones**

Edit `src/main.rs`.

Find this block (around line 107):
```rust
    // Build router from ACL config
    let router = server_runner::build_router(&server_config, cli.refresh_geodata).await?;
```

Replace with:
```rust
    // Construct the shared DNS cache once. `DnsCache: Clone` over Arc, so all
    // call sites (router, Server) share the same moka-backed storage.
    let dns_cache = dns_cache_rs::DnsCache::new();

    // Build router from ACL config (shares dns_cache).
    let router = server_runner::build_router(
        &server_config,
        cli.refresh_geodata,
        dns_cache.clone(),
    )
    .await?;
```

Find the `Server::builder()` block (around line 150-160):
```rust
    let server = Arc::new(
        Server::builder()
            .authenticator(authenticator)
            .stats(trojan_stats as Arc<dyn core::hooks::StatsCollector>)
            .router(router)
            .conn_manager(conn_manager)
            .conn_config(conn_config)
            .build(),
    );
```

Replace with:
```rust
    let server = Arc::new(
        Server::builder()
            .authenticator(authenticator)
            .stats(trojan_stats as Arc<dyn core::hooks::StatsCollector>)
            .router(router)
            .conn_manager(conn_manager)
            .conn_config(conn_config)
            .dns_cache(dns_cache)
            .build(),
    );
```

- [ ] **Step 6: Run the full suite**

Run: `cargo build`
Expected: clean build, no errors.

Run: `cargo test`
Expected: 286 tests pass (we removed 4 protocol tests + 4 hooks `check_private_and_resolve_*` tests; added 19 new in `core::dns::tests`; net +11 from baseline 275).

If `cargo test` shows failures in the `DirectRouter` or `AclRouter` existing test modules, that's expected — Task 8 fixes them.

- [ ] **Step 7: Format + lint (project requirement)**

Run: `cargo fmt --check`
Expected: no output. If any file is unformatted, run `cargo fmt` and re-run `cargo fmt --check`.

Run: `cargo clippy --all-targets -- -D warnings`
Expected: zero warnings. If clippy flags an unused import (e.g. leftover `use tokio::net::lookup_host` somewhere), remove it.

- [ ] **Step 8: Commit Task 6 + Task 7 together**

```bash
git add src/core/dns.rs src/core/protocol.rs src/core/hooks.rs src/core/server.rs src/acl.rs src/server_runner.rs src/main.rs src/handler.rs
git commit -m "refactor(dns): thread shared DnsCache through Server, routers, handler

Address::to_socket_addr and the free check_private_and_resolve are
replaced by core::dns. Server now owns the DnsCache; DirectRouter,
AclRouter, and the direct-connect fast path in handler.rs share the
same cache. Per-process DNS storage with singleflight, TTL, and
negative caching. Behavior unchanged.

Migrated tests:
- 5 hooks.rs check_private_and_resolve_* tests
- 4 protocol.rs to_socket_addr_* tests
All now run against MockResolver — no network in CI."
```

---

## Task 8: Update / migrate router tests that depend on real DNS

**Files:**
- Modify: `src/core/hooks.rs`, `src/acl.rs`

- [ ] **Step 1: Inspect existing DirectRouter tests in hooks.rs**

Run: `grep -n "test_direct_router\|test_check_private" src/core/hooks.rs`
Expected output (post Task 7 deletes): only the `test_direct_router_*` tests remain (~6 of them).

- [ ] **Step 2: Rewrite the DirectRouter tests to use MockResolver**

In `src/core/hooks.rs`, the existing tests live inside `#[cfg(test)] mod tests`. Add a helper at the top of that mod (or near the start of the existing helpers):

```rust
    use dns_cache_rs::{DnsCache, MockResolver};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    fn mock_cache_with(
        host: &str,
        result: Result<Vec<IpAddr>, dns_cache_rs::DnsError>,
    ) -> DnsCache {
        let mock = Arc::new(MockResolver::new());
        mock.set(host, result);
        DnsCache::builder()
            .resolver_arc(mock as Arc<dyn dns_cache_rs::Resolver>)
            .build()
            .expect("DnsCache build with MockResolver")
    }
```

Rewrite the existing tests:

```rust
    #[tokio::test]
    async fn test_direct_router_public_domain() {
        let cache = mock_cache_with(
            "example.com",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]),
        );
        let router = DirectRouter::with_cache(true, cache);
        let addr = Address::Domain("example.com".to_string(), 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Direct { resolved: Some(_), .. }));
    }

    #[tokio::test]
    async fn test_direct_router_blocks_loopback() {
        let router = DirectRouter::new();
        let addr = Address::IPv4([127, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Reject));
    }

    #[tokio::test]
    async fn test_direct_router_blocks_private_ip() {
        let router = DirectRouter::new();
        let addr = Address::IPv4([10, 0, 0, 1], 80);
        assert!(matches!(router.route(&addr).await, OutboundType::Reject));
        let addr = Address::IPv4([192, 168, 1, 1], 80);
        assert!(matches!(router.route(&addr).await, OutboundType::Reject));
    }

    #[tokio::test]
    async fn test_direct_router_allows_public_ip() {
        let router = DirectRouter::new();
        let addr = Address::IPv4([8, 8, 8, 8], 80);
        let result = router.route(&addr).await;
        assert!(matches!(
            result,
            OutboundType::Direct { resolved: None, handler: None }
        ));
    }

    #[tokio::test]
    async fn test_direct_router_allows_private_when_disabled() {
        let router = DirectRouter::with_block_private_ip(false);
        let addr = Address::IPv4([127, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(
            result,
            OutboundType::Direct { resolved: None, handler: None }
        ));
    }

    #[tokio::test]
    async fn test_direct_router_blocks_domain_resolving_to_private() {
        // Replaces the old network-based "localhost" test. Pinned to a
        // domain that resolves to a private IP via the mock so it runs offline.
        let cache = mock_cache_with(
            "internal.example",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))]),
        );
        let router = DirectRouter::with_cache(true, cache);
        let addr = Address::Domain("internal.example".to_string(), 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Reject));
    }
```

Specifically, **replace** the old `test_direct_router_domain_returns_resolved_addr` (which hit real DNS for `localhost`) with `test_direct_router_blocks_domain_resolving_to_private` above.

- [ ] **Step 3: Inspect existing AclRouter tests**

Run: `grep -n "fn test_" src/acl.rs | head -30`

The tests that construct an `AclRouter::with_block_private_ip(engine, …)` and then call `router.route(&Address::Domain(...))` (e.g. lines 1608, 1615, 1625, 1657, 1676) will currently hit real DNS via `DnsCache::new()` (because we left the existing constructor backed by a real `SystemResolver`).

Add this helper near the top of the `#[cfg(test)] mod tests` block in `src/acl.rs`:

```rust
    use dns_cache_rs::{DnsCache, MockResolver};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    fn mock_cache_with(
        host: &str,
        result: Result<Vec<IpAddr>, dns_cache_rs::DnsError>,
    ) -> DnsCache {
        let mock = Arc::new(MockResolver::new());
        mock.set(host, result);
        DnsCache::builder()
            .resolver_arc(mock as Arc<dyn dns_cache_rs::Resolver>)
            .build()
            .expect("DnsCache build with MockResolver")
    }
```

For each existing test that calls `AclRouter::with_block_private_ip(engine, true)` AND passes a domain address into `router.route(...)`, change the constructor to:

```rust
let router = AclRouter::with_cache(
    engine,
    /* block_private_ip = */ true,
    mock_cache_with("the-domain-the-test-uses.example", Ok(vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))])),
);
```

Use the actual domain string the test passes to `route`. For tests that only test IP-literal addresses or `block_private_ip=false`, leave them as-is (the unused `DnsCache::new()` is harmless).

- [ ] **Step 4: Run the full suite**

Run: `cargo test`
Expected: All tests pass. Total ~286 (baseline 275 + 19 new in core/dns − 8 deleted in protocol/hooks). Router tests are modified in place, not added.

If any test still hits real DNS and fails offline, repeat Step 3 for that test.

- [ ] **Step 5: Format + lint**

Run: `cargo fmt --check`
Expected: no output.

Run: `cargo clippy --all-targets -- -D warnings`
Expected: zero warnings.

- [ ] **Step 6: Commit**

```bash
git add src/core/hooks.rs src/acl.rs
git commit -m "test: migrate DirectRouter/AclRouter tests to MockResolver-backed DnsCache

Pins router behavior tests to deterministic in-process resolution.
Removes the last real-DNS dependency from cargo test."
```

---

## Task 9: Sanity sweep and version bump verification

**Files:**
- Inspect: all `src/**/*.rs`

- [ ] **Step 1: Confirm no stray `lookup_host` remains in `src/`**

Run: `grep -rn "tokio::net::lookup_host\|use tokio::net::lookup_host" src/ --include='*.rs'`
Expected: no output. If any line is printed, remove the import / call.

- [ ] **Step 2: Confirm no caller still references `Address::to_socket_addr`**

Run: `grep -rn "to_socket_addr" src/ --include='*.rs'`
Expected: at most lines under `src/core/dns.rs` doc comments. No call site of the form `addr.to_socket_addr()`.

- [ ] **Step 3: Confirm version was bumped**

Run: `grep '^version' Cargo.toml`
Expected: `version = "0.2.32"`.

- [ ] **Step 4: Run full suite once more, clean**

Run: `cargo clean && cargo test`
Expected: all tests pass.

- [ ] **Step 5: Verify clippy + fmt one last time**

Run: `cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: both pass silently.

- [ ] **Step 6: Final commit (if any clean-ups were needed)**

If steps 1-2 turned up nothing, no commit needed. Otherwise:
```bash
git add -p   # review each hunk
git commit -m "chore(dns): remove stray lookup_host references"
```

- [ ] **Step 7: Show final state**

Run: `git log --oneline -10`
Expected: ~5-7 new commits on top of `dev/master`:
- `build: add dns-cache-rs v0.2.0, bump to 0.2.32`
- `feat(core/dns): add DNS module skeleton with cache-backed resolver`
- `test(core/dns): resolve_socket_addr covers IPv4/IPv6/domain/NotFound/Timeout`
- `test(core/dns): check_private_and_resolve covers IPs, domains, and error fail-open`
- `test(core/dns): cache hit, singleflight, negative cache, TTL expiry`
- `refactor(dns): thread shared DnsCache through Server, routers, handler`
- `test: migrate DirectRouter/AclRouter tests to MockResolver-backed DnsCache`
- (optional) `chore(dns): remove stray lookup_host references`

Run: `git diff --stat dev/master..HEAD`
Expected stat: roughly +600 / -150 lines across the files listed in **File Structure**.

---

## Notes for the executor

- **Order matters between Task 6 and Task 7**: Task 6 makes `handler.rs` reference `ctx.server.dns_cache`, which doesn't exist until Task 7. The plan deliberately defers the Task 6 commit and bundles it with Task 7 (Step 8). Don't `cargo test` between them — it will fail to compile.
- **Time-paused tokio tests**: Task 5's TTL test uses `#[tokio::test(start_paused = true)]` and `tokio::time::advance`. The project already uses this idiom (per `MEMORY.md`); no new harness needed.
- **`futures_util::future::join_all`**: already in `Cargo.toml` (`futures-util = "0.3"`). No new dep.
- **Lints**: project enforces `cargo fmt --check` and `cargo clippy` cleanliness on every commit. The plan runs both before final commits; do the same after any ad-hoc fix.
- **Commit messages**: English. No `Co-Authored-By: Claude` (project rule in `CLAUDE.md`).
- **Don't widen scope**: The spec deliberately keeps `block_private_ip=true + DNS error → fail open` semantics. Task 4's `check_private_and_resolve_domain_resolution_failure_returns_false_none` test pins this. Do not "fix" it as part of this refactor.
