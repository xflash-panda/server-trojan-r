# DNS Cache Refactor Design — server-trojan-rs

**Date**: 2026-05-11
**Branch**: dev/master
**Target version bump**: 0.2.31 → 0.2.32
**Library**: `dns-cache-rs` v0.2.0 (`https://github.com/xflash-panda/dns-cache-rs`)

## Goal

Replace the hand-rolled, uncached DNS lookups in `server-trojan-rs` with the
shared `dns-cache-rs` library, keeping all externally-observable behavior
identical. Drive the change with TDD using `dns-cache-rs`'s `MockResolver`
(feature `test-utils`) so the new tests run offline and deterministically.

## Non-Goals

- No protocol changes, no config-format additions, no CLI changes.
- No change to the SSRF / private-IP-blocking semantics.
- No change to UDP relay's per-session `HashMap` route cache (that is a
  routing cache, not a DNS cache, and lives orthogonally).

## Current State

`server-trojan-rs` v0.2.31 performs DNS resolution through two functions,
neither of which caches results:

| File | Function | Caller(s) |
|---|---|---|
| `src/core/hooks.rs:126` | `check_private_and_resolve(addr) -> (bool, Option<SocketAddr>)` | `DirectRouter::route`, `AclRouter::route` |
| `src/core/protocol.rs:178` | `Address::to_socket_addr() -> io::Result<SocketAddr>` | `handler.rs:344` (direct-connect fast path) |

Both call `tokio::net::lookup_host` directly. Under sustained load every
new connection to a domain target triggers a fresh `getaddrinfo`. Sister
projects `server-anytls-rs` and `server-mieru-rs` already use
`dns-cache-rs` v0.2.0; this refactor brings trojan in line.

### Failure semantics observed today

```rust
let resolved: Vec<SocketAddr> = match lookup_host(&lookup).await {
    Ok(addrs) => addrs.collect(),
    Err(_) => return (false, None),
};
```

Any resolver error → `(is_private = false, resolved = None)`. The caller
then either falls back to a second `lookup_host` in `to_socket_addr`
(which also fails and surfaces as a connect error), or — in the
`block_private_ip=true` path — *allows* the request through. **The
refactor preserves this exactly**; tightening it is out of scope.

## Architecture

A new module `src/core/dns.rs` becomes the **only** DNS entry point in
trojan-rs. `Address::to_socket_addr` is removed. `tokio::net::lookup_host`
disappears from `src/`.

```
                    +--------------------+
                    |  src/core/dns.rs   |
                    | (only DNS entry)   |
                    +--------------------+
                       ^      ^      ^
              hooks.rs |      | acl.rs|
                       |      |      | handler.rs
              +--------+      +------+
              |               |      |
        DirectRouter      AclRouter  Server.dns_cache
            |                 |
            v                 v
        DnsCache ────clone────┘   (all share one moka-backed cache)
            |
            v
        SystemResolver (default)  /  MockResolver (tests)
```

### Ownership

- `core::Server` gains a public field `dns_cache: DnsCache`.
- `main.rs` (or `server_runner.rs`) constructs one `DnsCache::new()` and
  clones it into `Server`, `DirectRouter`, `AclRouter`. `DnsCache: Clone`
  (Arc-backed) so this is cheap and shares storage.
- All routing/handler code accesses DNS via `&DnsCache`; nothing global,
  no thread-locals.

## Public API (`src/core/dns.rs`)

```rust
use dns_cache_rs::DnsCache;
use std::net::SocketAddr;

/// Resolve an `Address` to a single `SocketAddr`, returning the first
/// address from the resolver iterator (IP literals bypass the cache).
pub async fn resolve_socket_addr(
    cache: &DnsCache,
    addr: &Address,
) -> std::io::Result<SocketAddr>;

/// Check whether an address is private/loopback/link-local. For domain
/// addresses, also returns the first **non-private** resolved
/// `SocketAddr` so callers can reuse it without a second DNS lookup.
/// Errors during resolution collapse to `(false, None)` (current
/// trojan-rs semantics — preserved verbatim).
pub(crate) async fn check_private_and_resolve(
    cache: &DnsCache,
    addr: &Address,
) -> (bool, Option<SocketAddr>);
```

### Behavior matrix

| Input | Action | Output |
|---|---|---|
| `Address::IPv4(ip, port)` | none (bypass cache) | `SocketAddr::new(V4(ip), port)` |
| `Address::IPv6(ip, port)` | none (bypass cache) | `SocketAddr::new(V6(ip), port)` |
| `Address::Domain(host, port)` (cache hit) | composed at call site | first SocketAddr |
| `Address::Domain(host, port)` (cache miss → resolve OK) | `cache.resolve_with_port_iter(host, port)` | first SocketAddr |
| `Address::Domain(host, port)` (resolve `NotFound`) | — | `io::Error::NotFound` / `(false, None)` |
| `Address::Domain(host, port)` (resolve `Timeout(d)`) | — | `io::Error::TimedOut` / `(false, None)` |
| `Address::Domain(host, port)` (resolve `InvalidHost`) | — | `io::Error::InvalidInput` / `(false, None)` |
| `Address::Domain(host, port)` (resolve `Other`) | — | `io::Error::Other` / `(false, None)` |

### Error mapping (`DnsError → io::Error`)

Per `dns-cache-rs` v0.2.0 `error.rs`, the actual variants are
`NotFound(String)`, `Timeout(Duration)`, `InvalidHost(String)`, and
`Other(Arc<dyn Error>)`. Mapping:

```rust
DnsError::NotFound(host)    => io::Error::new(NotFound,     format!("no addresses found for {host}"))
DnsError::Timeout(d)        => io::Error::new(TimedOut,     format!("DNS query timeout after {d:?}"))
DnsError::InvalidHost(h)    => io::Error::new(InvalidInput, format!("invalid host: {h}"))
DnsError::Other(e)          => io::Error::new(Other,        e.to_string())
```

`check_private_and_resolve` discards the error variant (matches current
behavior).

## Call-site Migration

| Call site | Before | After |
|---|---|---|
| `core::hooks::DirectRouter::route` | `check_private_and_resolve(addr)` | `core::dns::check_private_and_resolve(&self.dns_cache, addr)` |
| `acl::AclRouter::route` | same | `core::dns::check_private_and_resolve(&self.dns_cache, addr)` |
| `handler::handle_direct_connect` | `ctx.target.to_socket_addr().await?` | `core::dns::resolve_socket_addr(&ctx.server.dns_cache, ctx.target).await?` |

Removed entirely:
- `Address::to_socket_addr` (moved into `core::dns::resolve_socket_addr`).
- `use tokio::net::lookup_host` in `core/protocol.rs` and `core/hooks.rs`.
- Free-function `core::hooks::check_private_and_resolve` (replaced by
  the version in `core::dns`).

## Struct Changes

```rust
// src/core/server.rs (or wherever Server lives)
pub struct Server {
    // ... existing fields ...
    pub dns_cache: dns_cache_rs::DnsCache,
}

// src/core/hooks.rs
pub struct DirectRouter {
    block_private_ip: bool,
    dns_cache: dns_cache_rs::DnsCache,
}

impl DirectRouter {
    pub fn new() -> Self { /* uses DnsCache::new() */ }
    pub fn with_cache(block_private_ip: bool, dns_cache: DnsCache) -> Self { ... }
}

// src/acl.rs
pub struct AclRouter {
    engine: AclEngine,
    block_private_ip: bool,
    dns_cache: dns_cache_rs::DnsCache,
}

impl AclRouter {
    pub fn with_block_private_ip(engine: AclEngine, block_private_ip: bool) -> Self {
        Self { engine, block_private_ip, dns_cache: DnsCache::new() }
    }

    #[cfg(test)]
    fn with_dns_cache(engine: AclEngine, block_private_ip: bool, dns_cache: DnsCache) -> Self;
}
```

Existing callers of `DirectRouter::new()` and
`AclRouter::with_block_private_ip(engine, …)` need no changes — they
silently get a fresh `DnsCache::new()`.

`server_runner.rs` / `main.rs` build one `DnsCache::new()` and pass
clones into all three consumers so they share storage.

## Cargo.toml Changes

```toml
[dependencies]
dns-cache-rs = { git = "https://github.com/xflash-panda/dns-cache-rs.git", tag = "v0.2.0" }

[dev-dependencies]
dns-cache-rs = { git = "https://github.com/xflash-panda/dns-cache-rs.git", tag = "v0.2.0", features = ["test-utils"] }
```

Version bump: `0.2.31 → 0.2.32`.

## Testing — TDD Strategy

All new tests live in `src/core/dns.rs` (`#[cfg(test)] mod tests`) and
use `dns_cache_rs::MockResolver` injected via
`DnsCache::builder().resolver(...).build()`. No production code path
acquires the network.

### Unit tests (`core::dns`)

1. `resolve_socket_addr` — IPv4 literal: returns `SocketAddr`, resolver
   not invoked.
2. `resolve_socket_addr` — IPv6 literal: same.
3. `resolve_socket_addr` — domain → public IP: returns first addr with
   the requested port.
4. `resolve_socket_addr` — domain → `NotFound`: maps to
   `io::ErrorKind::NotFound`.
5. `resolve_socket_addr` — domain → `Timeout(d)`: maps to
   `io::ErrorKind::TimedOut`.
6. `check_private_and_resolve` — IPv4 private literal → `(true, None)`.
7. `check_private_and_resolve` — IPv6 private literal → `(true, None)`.
8. `check_private_and_resolve` — public IP literal → `(false, None)`.
9. `check_private_and_resolve` — domain resolves to private IP →
   `(true, None)`.
10. `check_private_and_resolve` — domain resolves to public IP →
    `(false, Some(addr))`, port matches input.
11. `check_private_and_resolve` — domain resolves to `NotFound`/error
    → `(false, None)` (regression guard for current semantics).
12. Cache hit: two sequential `resolve_socket_addr` calls for the same
    host invoke `MockResolver` exactly once.
13. Singleflight: with `MockResolver::set_delay(Some(50ms))`, 100
    concurrent `resolve_socket_addr` calls for the same host invoke
    `MockResolver` exactly once (`call_count(host) == 1`).
14. Negative caching: after `NotFound`, a second call within
    `negative_ttl` does not re-invoke the resolver.
15. Positive TTL expiry (`#[tokio::test(start_paused = true)]` +
    `tokio::time::advance` past `ttl`): resolver is invoked twice.

### Router-level tests

16. `DirectRouter::with_cache(true, mock_public)` + domain target →
    `Direct { resolved: Some(_), .. }`.
17. `DirectRouter::with_cache(true, mock_private)` + domain target →
    `Reject`.
18. `AclRouter::with_dns_cache(engine, true, mock_public)` + domain
    `direct` rule → `Direct { resolved: Some(_), .. }`.

### Migrated regression tests

The 5 tests in `hooks.rs` (`test_check_private_and_resolve_*`) and the
4 tests in `protocol.rs` (`test_address_to_socket_addr_*`) move to
`core/dns.rs` and switch to `MockResolver` — no network. One networked
smoke remains as `#[ignore]`.

### Time-paused tests

Tests 14 and 15 use `#[tokio::test(start_paused = true)]` + manual
`tokio::time::advance`. Aligns with the project convention recorded in
`MEMORY.md`.

### Test count

Pre-refactor: 275 (lib 18 + bin 257). Post-refactor: approximately
**290+** (net +15 from the matrix above, after counting the migrations
as in-place rewrites).

## Implementation Order (RED → GREEN → REFACTOR)

1. Add `dns-cache-rs` to `Cargo.toml` (dep + dev-dep with `test-utils`).
2. Create empty `src/core/dns.rs`; declare the two `pub`/`pub(crate)`
   fns with `todo!()` bodies; wire `mod dns;` in `core/mod.rs`.
3. Write **all 15 unit tests** in `core/dns.rs` — they fail to compile
   or panic at `todo!()`. (RED)
4. Implement `resolve_socket_addr` and `check_private_and_resolve`. Run
   tests until green. (GREEN)
5. Write router tests 16-18 against the as-yet-unmodified
   `DirectRouter` / `AclRouter` — they fail to compile because the
   constructors don't accept a cache. (RED)
6. Add `dns_cache` field + `with_cache` / `with_dns_cache`
   constructors. (GREEN)
7. Update `Server` to hold `dns_cache`; thread one shared cache from
   `main.rs` / `server_runner.rs`.
8. Migrate `handler::handle_direct_connect` from
   `ctx.target.to_socket_addr()` to
   `core::dns::resolve_socket_addr(&ctx.server.dns_cache, ctx.target)`.
9. Delete `Address::to_socket_addr` and the now-orphan
   `core::hooks::check_private_and_resolve`. Update / migrate their
   tests.
10. `cargo fmt --check` + `cargo clippy --all-targets -- -D warnings` +
    `cargo test`. All 290+ tests green.
11. Bump `version = "0.2.32"` in `Cargo.toml`.
12. Commit with English message, no Claude attribution (per project
    `CLAUDE.md`).

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Behavior drift in error-paths (e.g. private-IP check fails open) | Tests 11 and the migrated regression tests pin the exact current semantics. |
| Cache lifetime / leak via Arc cycles | `DnsCache` is leaf-level (no back-refs to `Server`). Clones share moka storage. |
| Test flakiness from real DNS | All new tests use `MockResolver`. One ignored smoke test for manual runs. |
| Wider blast radius than expected | `Address::to_socket_addr` was only used in 1 production call site + tests. Verified by grep before signing off. |
| `core/protocol.rs` test churn | The 4 `test_address_to_socket_addr_*` tests are mechanically rewritten against `resolve_socket_addr` — same assertions, new entry point. |

## Out of Scope

- Exposing `dns_ttl_secs` / `dns_capacity` / `dns_query_timeout_ms` via
  CLI or YAML. Defaults from `DnsCache::new()` only.
- Switching the underlying resolver (hickory, c-ares). `SystemResolver`
  stays.
- Fail-closed SSRF tightening when DNS resolution errors. Keeps current
  semantics deliberately.
- UDP relay's per-session route `HashMap` — orthogonal, no change.
