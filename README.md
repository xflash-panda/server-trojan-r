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
| `--cert_file` | `X_PANDA_TROJAN_CERT_FILE` | TLS 证书路径 (必需) | - |
| `--key_file` | `X_PANDA_TROJAN_KEY_FILE` | TLS 私钥路径 (必需) | - |
| `--fetch_users_interval` | `X_PANDA_TROJAN_FETCH_USERS_INTERVAL` | 用户同步间隔(秒) | 60 |
| `--report_traffics_interval` | `X_PANDA_TROJAN_REPORT_TRAFFICS_INTERVAL` | 流量上报间隔(秒) | 80 |
| `--heartbeat_interval` | `X_PANDA_TROJAN_HEARTBEAT_INTERVAL` | 心跳间隔(秒) | 180 |
| `--log_mode` | `X_PANDA_TROJAN_LOG_MODE` | 日志级别 | info |
| `--data_dir` | `X_PANDA_TROJAN_DATA_DIR` | 数据目录 | /var/lib/trojan-node |
| `--acl_conf_file` | `X_PANDA_TROJAN_ACL_CONF_FILE` | ACL 配置文件 | - |
| `--block_private_ip` | `X_PANDA_TROJAN_BLOCK_PRIVATE_IP` | 阻止私有IP访问 | true |

### 启动示例

```bash
# 基本启动
server \
  --api https://panel.example.com/api \
  --token your_api_token \
  --node 1 \
  --cert_file /etc/ssl/cert.pem \
  --key_file /etc/ssl/key.pem

# 使用环境变量
export X_PANDA_TROJAN_API=https://panel.example.com/api
export X_PANDA_TROJAN_TOKEN=your_api_token
export X_PANDA_TROJAN_NODE=1
export X_PANDA_TROJAN_CERT_FILE=/etc/ssl/cert.pem
export X_PANDA_TROJAN_KEY_FILE=/etc/ssl/key.pem
server
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

## 许可证

MIT
