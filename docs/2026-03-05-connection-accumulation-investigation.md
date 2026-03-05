# Connection Accumulation Investigation

**Date**: 2026-03-05
**Version**: v0.2.15+debug.2
**Status**: Active — pre-relay connection leak confirmed, awaiting debug.2 stage diagnostics

## Problem

trojan-r vs Xray (same client, same environment, no realm, nftables port forwarding):

| Metric | trojan-r (before restart) | Xray |
|--------|--------------------------|------|
| ESTABLISHED connections | ~49,000 | 2,000-4,000 |
| Memory (RSS) | 11.6GB (71%) | Much lower |
| CPU | 75.8% | Much lower |

## Phase 1: Relay Diagnostics (v0.2.15+debug.1)

### Termination distribution (3-minute sample after restart)

| Termination | Count | Percent | Meaning |
|-------------|-------|---------|---------|
| completed | 6,040 | 89% | Both sides EOF, normal close |
| idle_timeout | 714 | 10.5% | Neither side closed within 2 min |
| half_close_timeout | 18 | 0.3% | One side closed, other didn't finish |

### idle_timeout EOF analysis

All 714 idle_timeout connections: **client_eof=false AND remote_eof=false**
— genuine HTTP keep-alive, neither side closed. Correct behavior.

### Connection duration distribution

| Duration | Count | Notes |
|----------|-------|-------|
| 0s | 6,280 | Fast request-response |
| 120s | 611 | Full idle timeout (keep-alive) |
| 15s | 359 | Moderate keep-alive |
| 1s | 280 | Short connections |
| 65s | 149 | Various |

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

- Outbound connections only exist for connections that reached the relay phase (connected to target)
- 37k inbound connections have no matching outbound = never reached relay
- These connections are stuck in pre-relay stages: TLS handshake, WS handshake, or request read

### All stuck connections have data in queues

```
ss -tno state established sport = :36548 | awk idle analysis:
idle: 0  → ALL 45,593 connections have pending data
```

No truly idle connections — the kernel has data for them, but the application isn't reading it.

### Pre-relay timeouts should prevent this

| Stage | Timeout | Expected cleanup |
|-------|---------|-----------------|
| TLS handshake | 10s | tokio::time::timeout |
| WS handshake | 5s | tokio::time::timeout |
| Request read | 5s | tokio::time::timeout |
| **Maximum pre-relay lifetime** | **20s** | All stages combined |

With 20s max pre-relay lifetime, at most `connection_rate × 20` connections should be in pre-relay stages. At 100 conn/s, that's 2,000 — not 37,000.

### Root cause hypothesis: Tokio runtime overload (death spiral)

1. Connection leak starts (cause TBD) → task count grows
2. At 45k+ tokio tasks, the runtime can't poll all tasks promptly
3. Timer fires (e.g., TLS 10s timeout) → wakes task → but task sits in run queue
4. By the time task is polled, new connections have arrived → more tasks
5. Timeout result is observed late or task is never polled → connection never cleaned up
6. **Death spiral**: more stuck connections → slower polling → more stuck connections

Evidence:
- Restart instantly fixes the problem (fresh runtime, no task backlog)
- Connections have data in kernel buffers but app isn't reading → tasks not being polled
- CPU was 75.8% before restart → runtime saturated

## Phase 3: Stage Logging (v0.2.15+debug.2)

### Changes deployed

Added info-level logging at each pre-relay failure point:

| Log | Stage label | Trigger |
|-----|-------------|---------|
| TLS handshake error | `stage=tls` | TLS handshake fails |
| TLS handshake timeout | `stage=tls_timeout` | 10s timeout fires |
| WS handshake timeout | `stage=ws_timeout` | 5s timeout fires |
| Request read timeout | `stage=request_timeout` | 5s timeout fires |

### Diagnostic commands (run after debug.2 is live)

```bash
# Stage distribution — WHERE are connections failing?
journalctl -u strojan-agent --no-pager --since "3 min ago" \
  | grep "Connection failed" | grep -oP 'stage=\w+' | sort | uniq -c | sort -rn

# Stage failure rate over time
journalctl -u strojan-agent --no-pager --since "10 min ago" \
  | grep "Connection failed" | grep -oP 'stage=\w+' \
  | awk '{print strftime("%H:%M", systime()), $0}' | sort | uniq -c

# Compare: relay completions vs stage failures
echo "=== Relay completions ===" && \
journalctl -u strojan-agent --no-pager --since "3 min ago" \
  | grep "Relay done" | wc -l && \
echo "=== Stage failures ===" && \
journalctl -u strojan-agent --no-pager --since "3 min ago" \
  | grep "Connection failed" | wc -l

# Current ESTAB count
ss -tan state established sport = :36548 | wc -l
```

### Expected results

| If stage = ... | Meaning | Fix |
|----------------|---------|-----|
| `tls_timeout` dominant | TLS handshakes hanging | Reduce TLS timeout, investigate TLS library |
| `ws_timeout` dominant | WS handshakes hanging after TLS | Reduce WS timeout, investigate tungstenite |
| `request_timeout` dominant | Request reads hanging after WS | Reduce request timeout |
| **No stage logs** | **Timeouts never fire** | **Confirms runtime overload — tasks not polled** |
| Mixed / low counts | Normal failure distribution | Look elsewhere |

**Most likely outcome**: Few or no stage failure logs, confirming that timeouts fire but tasks are never polled (runtime overload hypothesis).

## Proposed Fix: Per-Task Safety Timeout

Wrap the entire `tokio::spawn` task body with a hard timeout:

```rust
tokio::spawn(async move {
    match tokio::time::timeout(safety_duration, handle_connection(...)).await {
        Ok(result) => { /* normal path */ }
        Err(_) => {
            log::warn!(peer = %peer_addr, "Connection killed by safety timeout");
            // drop cleans up TCP + TLS + WS
        }
    }
});
```

**Proposed value**: `idle_timeout + 30s` = **150s** (2.5 minutes)

- Covers all pre-relay stages (20s) + full relay idle timeout (120s) + margin (10s)
- Any connection alive beyond 150s is definitively leaked
- Drop handler cleans up TCP FD, TLS state, WS buffers
- Independent of tokio timer reliability — `select!` on the outer future

**Why not `max_connections`?** User preference: connection limits should be controlled by the system (ulimit/sysctl), not application-level.

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
| 49,000 | ~11.5GB |

## Timeline

| Time | Event |
|------|-------|
| T+0h | Observed 49,613 ESTAB, 11.6GB RSS, 75.8% CPU |
| T+0h | Deployed v0.2.15+debug.1 (relay termination logging) |
| T+0h | Restarted → ESTAB dropped to 1,473 |
| T+0.5h | ESTAB climbed back to 42,860 — recurrence confirmed |
| T+1h | Analysis: 37k connections stuck in pre-relay stages |
| T+1h | Deployed v0.2.15+debug.2 (pre-relay stage logging) |
| T+1h | **Awaiting diagnostic results** |
