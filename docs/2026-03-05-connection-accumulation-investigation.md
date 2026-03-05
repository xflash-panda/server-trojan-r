# Connection Accumulation Investigation

**Date**: 2026-03-05
**Version**: v0.2.15+debug.3
**Status**: Fix deployed — default max_connections=10000 semaphore backpressure, awaiting verification

## Problem

trojan-r vs Xray (same client, same environment, no realm, nftables port forwarding):

| Metric | trojan-r (before restart) | Xray |
|--------|--------------------------|------|
| ESTABLISHED connections | ~49,000 | 2,000-4,000 |
| Memory (RSS) | 11.6GB (71%) | Much lower |
| CPU | 75.8% | Much lower |

## Phase 1: Relay Diagnostics (v0.2.15+debug.1)

Added info-level relay termination logging: termination reason, EOF status, duration.

### Termination distribution (3-minute sample after restart)

| Termination | Count | Percent | Meaning |
|-------------|-------|---------|---------|
| completed | 6,040 | 89% | Both sides EOF, normal close |
| idle_timeout | 714 | 10.5% | Neither side closed within 2 min |
| half_close_timeout | 18 | 0.3% | One side closed, other didn't finish |

### idle_timeout EOF analysis

All 714 idle_timeout connections: **client_eof=false AND remote_eof=false**
— genuine HTTP keep-alive, neither side closed. Correct behavior.

### Connection count after restart

```
Before restart:  49,613 ESTAB (old process, 24h uptime)
After restart:    1,473 ESTAB (new process, ~10min uptime)
```

**97% drop** — no code change, only restart.

### Phase 1 Conclusion

**Relay logic is healthy.** 89% completed normally, EOF detection works. The relay is NOT the problem.

## Phase 2: Recurrence & Pre-Relay Leak (v0.2.15+debug.1)

### Recurrence confirmed

Within 30 minutes of restart, ESTAB climbed back to **42,860** — proving an active leak, not stale state.

### Critical finding: 37k connections stuck before relay

| Metric | Count |
|--------|-------|
| Inbound ESTABLISHED (sport = :36548) | 45,409 |
| Outbound ESTABLISHED (sport != :36548) | 8,263 |
| **Difference (stuck pre-relay)** | **~37,000** |

- Outbound connections only exist for connections that reached the relay phase
- 37k inbound connections have no matching outbound = never reached relay
- All stuck connections have data in kernel buffers (idle: 0) — app isn't reading

## Phase 3: Stage Logging (v0.2.15+debug.2)

Added info-level logging at each pre-relay failure point (TLS, WS, request stages).

### Stage failure distribution (3-minute sample, 45k ESTAB)

| Stage | Count | Percent | Meaning |
|-------|-------|---------|---------|
| `tls` (TLS handshake error) | 1,424 | 80% | TLS EOF — scanners/probes |
| `tls_timeout` (10s timeout) | 329 | 18.5% | TLS handshake hung |
| `request_timeout` (5s timeout) | 24 | 1.3% | Request read hung |
| `ws_timeout` (5s timeout) | 2 | 0.1% | WS handshake hung |
| **Total stage failures** | **1,779** | | |
| **Relay completions** | **3,739** | | |

### Key insight: timeouts fire but can't keep up

- Timeouts ARE working (354 timeout events / 3 min)
- Total processing rate: ~30.6 connections/sec
- But 35k connections are stuck — **spawned as tasks but not yet polled**
- Timeout timer only starts on first poll → unpolled tasks never time out

## Root Cause: Accept Loop Death Spiral

### Mechanism

1. `max_connections = 0` (default) → no semaphore → accept loop has no backpressure
2. `listener.accept()` + `tokio::spawn()` runs as fast as connections arrive
3. At 45k+ spawned tasks, tokio's run queue grows → new tasks wait longer for first poll
4. `tokio::time::timeout()` only creates the timer on first poll
5. Unpolled tasks → timeouts don't start → connections never cleaned up
6. More stuck connections → more tasks → slower polling → **death spiral**

### Evidence

| Evidence | Supports |
|----------|----------|
| Restart drops 49k → 1.5k instantly | Fresh runtime, no task backlog |
| Climbs back to 45k within 30 min | Active leak, not stale connections |
| 35k inbound vs 12k outbound | Connections stuck in pre-relay stages |
| All connections have kernel buffer data | Tasks not being polled (app not reading) |
| 354 timeouts fire / 3 min | Timeouts work but can't consume 35k backlog |
| 75.8% CPU before restart | Runtime saturated |

## Fix: Default max_connections = 10,000 (v0.2.15+debug.3)

### Change

```
- default_value_t = 0           // unlimited, no semaphore
+ default_value_t = 10_000      // semaphore always active
```

### How it works

- Existing semaphore in accept loop now always active with default 10k permits
- When concurrent connections reach 10k, `semaphore.acquire()` blocks accept loop
- TCP SYN queue absorbs incoming connections at kernel level (no reject)
- When tasks complete and release permits, accept resumes
- Prevents task count from reaching death spiral threshold (~45k)

### Why 10,000?

- Xray handles same traffic with 2,000-4,000 connections
- 10k = 2.5-5x headroom over Xray
- At ~235KB per connection: 10k × 235KB = ~2.3GB memory (manageable)
- Well below the ~45k death spiral threshold
- `--max_connections 0` still available for explicitly unlimited

### Diagnostic logs

All debug.1/debug.2 info-level diagnostic logs reverted to debug level.
Info level reserved for business logs only. Use `--log_mode debug` to see diagnostics.

## Verification Commands

```bash
# After deploying debug.3, monitor ESTAB count
watch -n 30 'ss -tan state established sport = :36548 | wc -l'

# Should stabilize at or below 10,000 (not climb to 45k+)
# If it stabilizes at 2,000-4,000 (like Xray), the fix is confirmed

# Check semaphore is active in startup log
journalctl -u strojan-agent --no-pager | grep "Server started" | tail -1
# Should show max_connections=10000
```

## Per-Connection Memory Overhead

| Component | Size |
|-----------|------|
| 2x DirectionalBuffer (32KB each) | 64KB |
| tungstenite write_buffer | 32KB |
| tungstenite max_write_buffer | 64KB |
| TLS state (rustls) | ~50KB |
| Outbound TCP + kernel buffers | ~20KB |
| Tokio task + misc | ~5KB |
| **Total per connection** | **~235KB** |

| Connections | Memory |
|-------------|--------|
| 1,500 | ~350MB |
| 3,000 | ~700MB |
| 10,000 | ~2.3GB |
| 49,000 | ~11.5GB |

## Timeline

| Time | Event |
|------|-------|
| T+0h | Observed 49,613 ESTAB, 11.6GB RSS, 75.8% CPU |
| T+0h | Deployed v0.2.15+debug.1 (relay termination logging) |
| T+0h | Restarted → ESTAB dropped to 1,473 |
| T+0.2h | Relay diagnostics: 89% completed, relay logic healthy |
| T+0.5h | ESTAB climbed back to 42,860 — recurrence confirmed |
| T+1h | Analysis: 37k connections stuck in pre-relay stages |
| T+1h | Deployed v0.2.15+debug.2 (pre-relay stage logging) |
| T+1.5h | Stage data: timeouts work (354/3min) but can't keep up with 35k backlog |
| T+1.5h | Root cause identified: accept loop death spiral (no backpressure) |
| T+2h | Deployed v0.2.15+debug.3 (default max_connections=10000, logs→debug) |
| T+2h | **Awaiting verification** |
