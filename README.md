# Server Trojan-R

高性能 Rust 实现的 Trojan 代理服务器节点，

## 特性

- **高性能**: 基于 Rust + Tokio 异步运行时
- **多传输模式**: TCP / WebSocket / gRPC
- **ACL 规则引擎**: 支持 Direct、SOCKS5、HTTP、Reject 出站
- **GeoIP/GeoSite**: 支持 MaxMind MMDB 和 Sing-box 规则格式
- **SSRF 防护**: 默认阻止访问私有/回环地址
- **API 集成**: 自动同步用户、上报流量、心跳保活

## 安装

```bash
# 从源码构建
cargo build --release

# 针对当前 CPU 优化
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

## 使用

### 命令行参数

| 参数 | 环境变量 | 说明 | 默认值 |
|------|----------|------|--------|
| `--api` | `X_PANDA_TROJAN_API` | API 地址 (必需) | - |
| `--token` | `X_PANDA_TROJAN_TOKEN` | API 令牌 (必需) | - |
| `--node` | `X_PANDA_TROJAN_NODE` | 节点 ID (必需) | - |
| `--cert_file` | `X_PANDA_TROJAN_CERT_FILE` | TLS 证书路径 | /root/.cert/server.crt |
| `--key_file` | `X_PANDA_TROJAN_KEY_FILE` | TLS 私钥路径 | /root/.cert/server.key |
| `--fetch_users_interval` | `X_PANDA_TROJAN_FETCH_USERS_INTERVAL` | 用户同步间隔 | 60s |
| `--report_traffics_interval` | `X_PANDA_TROJAN_REPORT_TRAFFICS_INTERVAL` | 流量上报间隔 | 80s |
| `--heartbeat_interval` | `X_PANDA_TROJAN_HEARTBEAT_INTERVAL` | 心跳间隔 | 180s |
| `--api_timeout` | `X_PANDA_TROJAN_API_TIMEOUT` | API 请求超时 | 30s |
| `--log_mode` | `X_PANDA_TROJAN_LOG_MODE` | 日志级别 | info |
| `--data_dir` | `X_PANDA_TROJAN_DATA_DIR` | 数据目录 | /var/lib/trojan-node |
| `--acl_conf_file` | `X_PANDA_TROJAN_ACL_CONF_FILE` | ACL 配置文件 | - |
| `--block_private_ip` | `X_PANDA_TROJAN_BLOCK_PRIVATE_IP` | 阻止私有IP访问 | true |
| `--refresh_geodata` | `X_PANDA_TROJAN_REFRESH_GEODATA` | 启动时刷新 GeoIP/GeoSite 数据 | false |

#### 性能调优参数

| 参数 | 环境变量 | 说明 | 默认值 |
|------|----------|------|--------|
| `--conn_idle_timeout` | `X_PANDA_TROJAN_CONN_IDLE_TIMEOUT` | 连接空闲超时 | 5m |
| `--tcp_connect_timeout` | `X_PANDA_TROJAN_TCP_CONNECT_TIMEOUT` | TCP 连接超时 | 5s |
| `--request_timeout` | `X_PANDA_TROJAN_REQUEST_TIMEOUT` | 请求读取超时 | 5s |
| `--tls_handshake_timeout` | `X_PANDA_TROJAN_TLS_HANDSHAKE_TIMEOUT` | TLS 握手超时 | 10s |
| `--buffer_size` | `X_PANDA_TROJAN_BUFFER_SIZE` | 数据传输缓冲区大小 (字节) | 32768 |
| `--tcp_backlog` | `X_PANDA_TROJAN_TCP_BACKLOG` | TCP 监听积压队列大小 | 1024 |
| `--tcp_nodelay` | `X_PANDA_TROJAN_TCP_NODELAY` | 启用 TCP_NODELAY 降低延迟 | true |

### 启动示例

```bash
# 基本启动 (使用默认证书路径 /root/.cert/server.crt 和 /root/.cert/server.key)
server-trojan \
  --api https://panel.example.com/api \
  --token your_api_token \
  --node 1

# 自定义证书路径
server-trojan \
  --api https://panel.example.com/api \
  --token your_api_token \
  --node 1 \
  --cert_file /etc/ssl/cert.pem \
  --key_file /etc/ssl/key.pem

# 使用环境变量
export X_PANDA_TROJAN_API=https://panel.example.com/api
export X_PANDA_TROJAN_TOKEN=your_api_token
export X_PANDA_TROJAN_NODE=1
server-trojan
```

## ACL 配置

ACL 配置文件使用 YAML 格式：

```yaml
outbounds:
  - name: proxy
    type: socks5
    socks5:
      addr: 127.0.0.1:1080
      allow_udp: true

  - name: block
    type: reject

acl:
  inline:
    # 阻止 QUIC
    - block(all, udp/443)
    # 域名走代理
    - proxy(suffix:google.com)
    - proxy(geosite:netflix)
    # 默认直连
    - direct(all)
```

### 出站类型

| 类型 | 说明 | UDP |
|------|------|-----|
| `direct` | 直连 | 支持 |
| `socks5` | SOCKS5 代理 | 可配置 |
| `http` | HTTP 代理 | 不支持 |
| `reject` | 拒绝 | - |

### 规则语法

```
outbound(matcher, protocol/port)
```

- **matcher**: `all`, `suffix:domain`, `geosite:category`, `geoip:country`
- **protocol/port**: `tcp/80`, `udp/443`，省略则匹配全部

## SSRF 防护

默认阻止以下地址访问：

- IPv4: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`
- IPv6: `::1`, `fc00::/7`, `fe80::/10`

同时检测域名解析结果，防止 DNS 重绑定攻击。

可通过 `--block_private_ip=false` 禁用。

## 协议支持

- TCP 代理 (CONNECT)
- UDP 代理 (UDP ASSOCIATE)
- IPv4 / IPv6
- 域名解析

## 性能优势

相比 Go 实现的代理服务器（如 Xray），本项目具有以下性能优势：

### 核心优化

| 技术 | 说明 |
|------|------|
| **零 GC 暂停** | Rust 无垃圾回收，延迟稳定可预测 |
| **MiMalloc 分配器** | 微软开源的高性能内存分配器，高并发下优于系统 malloc |
| **DashMap 无锁并发** | 分片锁设计，避免连接管理的全局锁竞争 |
| **零拷贝数据转发** | 使用 `Bytes` 类型，协议解析和转发过程无内存拷贝 |
| **原生异步 TLS** | rustls 无需 FFI 调用，握手不阻塞线程池 |

### 预期性能提升

| 并发规模 | 吞吐提升 | 说明 |
|----------|----------|------|
| < 1,000 连接 | 5-10% | 小规模差距不大 |
| 1,000 - 10,000 连接 | 15-25% | 内存分配和 GC 压力差异体现 |
| 10,000+ 连接 | 30-50% | P99 延迟可降低 2-5 倍 |

### 内存效率

- 单连接开销：~4-8 KB（Go 实现通常 8-16 KB）
- 无 GC 导致的周期性内存压力
- 高并发下内存占用更稳定

### 适用场景

性能优势在以下场景更明显：

- **高并发节点**：云服务商的大流量节点
- **低延迟敏感**：游戏加速、实时通信
- **资源受限**：小内存 VPS 环境

## 许可证

MIT
