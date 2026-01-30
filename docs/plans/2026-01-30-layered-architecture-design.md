# Trojan Server 分层架构设计

## 概述

将当前混合在一起的代码重构为分层架构，实现：
- **Core 与业务分离**：核心代理逻辑不依赖具体业务实现
- **传输层抽象**：TCP/WS/gRPC 通过统一接口接入
- **Hook 机制**：通过 trait 对象提供扩展点

## 目录结构

```
src/
├── core/                    # 代理核心
│   ├── mod.rs              # 导出
│   ├── server.rs           # Server 主结构，连接处理循环
│   ├── protocol.rs         # Trojan 协议解析（TrojanRequest, Address）
│   ├── relay.rs            # 双向转发
│   ├── connection.rs       # 连接管理（生命周期、取消）
│   └── hooks.rs            # Hook traits 定义 + 默认实现
│
├── transport/              # 传输层抽象
│   ├── mod.rs              # Transport trait 导出
│   ├── tcp.rs              # TCP Listener
│   ├── ws.rs               # WebSocket Listener
│   ├── grpc/               # gRPC Listener
│   │   ├── mod.rs
│   │   ├── connection.rs
│   │   ├── transport.rs
│   │   ├── codec.rs
│   │   └── heartbeat.rs
│   └── tls.rs              # TLS 包装（可组合到任意 Listener）
│
├── outbound/               # 出站连接
│   ├── mod.rs              # Outbound trait
│   ├── direct.rs           # 直连
│   ├── socks5.rs           # SOCKS5 代理
│   ├── http.rs             # HTTP 代理
│   └── acl.rs              # ACL 路由引擎
│
├── business/               # 业务实现（实现 hooks traits）
│   ├── mod.rs
│   ├── auth.rs             # 用户认证实现
│   ├── stats.rs            # 流量统计实现
│   └── api/                # 远程面板集成
│       ├── mod.rs
│       ├── client.rs       # API 客户端
│       └── tasks.rs        # 后台任务（心跳、上报）
│
├── lib.rs                  # 库导出
├── main.rs                 # 入口（组装各层）
├── config.rs               # 配置
├── error.rs                # 错误类型
└── utils.rs                # 工具函数
```

## Core 层设计

### Hook Traits 定义

```rust
// src/core/hooks.rs

use async_trait::async_trait;

/// 连接上下文，贯穿整个连接生命周期
pub struct ConnectionContext {
    pub conn_id: u64,
    pub peer_addr: SocketAddr,
    pub user_id: Option<u64>,
    pub target: Address,
    pub connected_at: Instant,
}

/// 认证器
#[async_trait]
pub trait Authenticator: Send + Sync {
    /// 验证密码，返回 user_id
    async fn authenticate(&self, password: &[u8; 56]) -> Option<u64>;
}

/// 流量统计收集器
#[async_trait]
pub trait StatsCollector: Send + Sync {
    /// 记录一次请求
    fn record_request(&self, user_id: u64);
    /// 记录上传字节
    fn record_upload(&self, user_id: u64, bytes: u64);
    /// 记录下载字节
    fn record_download(&self, user_id: u64, bytes: u64);
}

/// 连接生命周期钩子
#[async_trait]
pub trait ConnectionHooks: Send + Sync {
    /// 连接建立时调用，返回是否允许
    async fn on_connect(&self, ctx: &ConnectionContext) -> bool { true }
    /// 连接关闭时调用
    async fn on_disconnect(&self, ctx: &ConnectionContext) {}
}

/// 出站路由决策
#[async_trait]
pub trait OutboundRouter: Send + Sync {
    /// 根据目标地址决定出站方式
    async fn route(&self, target: &Address) -> OutboundType;
}

pub enum OutboundType {
    Direct,
    Socks5(SocketAddr),
    Http(SocketAddr),
    Reject,
}
```

### Server 结构

```rust
// src/core/server.rs

/// 核心服务器配置
pub struct ServerConfig {
    pub idle_timeout: Duration,      // 空闲超时，默认 300s
    pub buffer_size: usize,          // 缓冲区大小，默认 32KB
    pub dns_cache_ttl: Duration,     // DNS 缓存时间
    pub dns_rebind_protection: bool, // DNS 重绑定保护
}

/// 代理核心服务器
pub struct Server {
    config: ServerConfig,
    authenticator: Box<dyn Authenticator>,
    stats: Box<dyn StatsCollector>,
    hooks: Box<dyn ConnectionHooks>,
    router: Box<dyn OutboundRouter>,
    conn_manager: ConnectionManager,  // 内置连接管理
}

impl Server {
    /// 构建器模式创建
    pub fn builder() -> ServerBuilder { ... }

    /// 运行服务器
    pub async fn run(self: Arc<Self>, listener: Box<dyn TransportListener>) {
        loop {
            let (stream, meta) = listener.accept().await?;
            let server = Arc::clone(&self);
            tokio::spawn(async move {
                server.handle_connection(stream, meta).await;
            });
        }
    }

    /// 处理单个连接
    async fn handle_connection(&self, stream: TransportStream, meta: ConnectionMeta) {
        // 1. 解析 Trojan 请求
        let request = TrojanRequest::decode(&mut stream).await?;

        // 2. 认证
        let user_id = self.authenticator.authenticate(&request.password).await
            .ok_or("auth failed")?;

        // 3. 构建上下文 & 注册连接
        let ctx = ConnectionContext { ... };
        let cancel_token = self.conn_manager.register(&ctx);

        // 4. 调用连接钩子
        if !self.hooks.on_connect(&ctx).await {
            return;
        }

        // 5. 记录请求
        self.stats.record_request(user_id);

        // 6. 路由决策 & 建立出站
        let outbound_type = self.router.route(&request.addr).await;
        let outbound = self.create_outbound(outbound_type, &request.addr).await?;

        // 7. 双向转发（带统计和取消支持）
        relay(stream, outbound, &ctx, &self.stats, cancel_token).await;

        // 8. 清理
        self.conn_manager.unregister(ctx.conn_id);
        self.hooks.on_disconnect(&ctx).await;
    }

    /// 获取连接管理器（供外部踢人用）
    pub fn connection_manager(&self) -> &ConnectionManager { ... }
}
```

### 默认实现

```rust
// src/core/hooks.rs

/// 内存认证器（密码 -> user_id 映射）
pub struct MemoryAuthenticator {
    users: RwLock<HashMap<[u8; 56], u64>>,
}

impl MemoryAuthenticator {
    pub fn new() -> Self { ... }
    pub async fn add_user(&self, password: &str, user_id: u64) { ... }
    pub async fn remove_user(&self, password: &str) { ... }
}

/// 内存统计收集器
pub struct MemoryStatsCollector {
    stats: DashMap<u64, UserStats>,
}

impl MemoryStatsCollector {
    pub fn new() -> Self { ... }
    pub fn get_stats(&self, user_id: u64) -> Option<UserStats> { ... }
    pub fn reset_and_collect(&self) -> Vec<(u64, UserStats)> { ... }
}

/// 直连路由器（所有流量直连）
pub struct DirectRouter;

/// 空钩子（什么都不做）
pub struct NoopHooks;
```

## Transport 层设计

### 抽象接口

```rust
// src/transport/mod.rs

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

/// 统一的传输流类型
pub type TransportStream = Box<dyn AsyncRead + AsyncWrite + Send + Unpin>;

/// 连接元信息
pub struct ConnectionMeta {
    pub peer_addr: SocketAddr,
    pub transport_type: TransportType,
}

pub enum TransportType {
    Tcp,
    WebSocket,
    Grpc,
}

/// 传输层监听器
#[async_trait]
pub trait TransportListener: Send + Sync {
    /// 接受下一个连接
    async fn accept(&self) -> Result<(TransportStream, ConnectionMeta)>;

    /// 监听地址
    fn local_addr(&self) -> SocketAddr;
}
```

### TLS 组合

```rust
// src/transport/tls.rs

/// TLS 作为包装器，可组合任意 Listener
pub struct TlsListener<L: TransportListener> {
    inner: L,
    acceptor: TlsAcceptor,
}

impl<L: TransportListener> TlsListener<L> {
    pub fn new(inner: L, acceptor: TlsAcceptor) -> Self { ... }
}

#[async_trait]
impl<L: TransportListener> TransportListener for TlsListener<L> {
    async fn accept(&self) -> Result<(TransportStream, ConnectionMeta)> {
        let (stream, meta) = self.inner.accept().await?;
        let tls_stream = self.acceptor.accept(stream).await?;
        Ok((Box::new(tls_stream), meta))
    }
}
```

## 配置与启动

### 配置结构

```rust
// src/config.rs

/// 传输层配置
pub enum TransportConfig {
    Tcp {
        listen: SocketAddr,
    },
    WebSocket {
        listen: SocketAddr,
        path: String,
    },
    Grpc {
        listen: SocketAddr,
        service_name: String,
    },
}

/// TLS 配置（可选）
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// 完整启动配置
pub struct AppConfig {
    pub transport: TransportConfig,
    pub tls: Option<TlsConfig>,
    pub server: ServerConfig,
    pub acl_path: Option<PathBuf>,
    // API 相关配置...
}
```

### 启动流程

```rust
// src/main.rs

async fn main() -> Result<()> {
    let config = AppConfig::from_env()?;

    // 1. 创建传输层 Listener
    let listener = create_listener(&config).await?;

    // 2. 创建业务组件
    let api_client = ApiClient::new(&config.api)?;
    let authenticator = Box::new(ApiAuthenticator::new(api_client.clone()));
    let stats = Box::new(ApiStatsCollector::new(api_client.clone()));
    let router = create_router(&config)?;

    // 3. 组装 Server
    let server = Server::builder()
        .config(config.server)
        .authenticator(authenticator)
        .stats(stats)
        .router(router)
        .build();

    // 4. 启动后台任务
    let tasks = BackgroundTasks::new(api_client, server.connection_manager());
    tasks.start();

    // 5. 运行
    server.run(listener).await
}

/// 根据配置创建对应的 Listener
async fn create_listener(config: &AppConfig) -> Result<Box<dyn TransportListener>> {
    let base_listener: Box<dyn TransportListener> = match &config.transport {
        TransportConfig::Tcp { listen } => {
            Box::new(TcpTransportListener::bind(*listen).await?)
        }
        TransportConfig::WebSocket { listen, path } => {
            Box::new(WsListener::bind(*listen, path.clone()).await?)
        }
        TransportConfig::Grpc { listen, service_name } => {
            Box::new(GrpcListener::bind(*listen, service_name.clone()).await?)
        }
    };

    // 如果有 TLS 配置，包装一层
    if let Some(tls) = &config.tls {
        let acceptor = create_tls_acceptor(tls)?;
        Ok(Box::new(TlsListener::new(base_listener, acceptor)))
    } else {
        Ok(base_listener)
    }
}
```

## 数据流

```
┌─────────────────────────────────────────────────────────────────────┐
│                           main.rs                                    │
│  AppConfig -> create_listener() -> Server::builder().build()        │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     transport/ (Listener)                            │
│  TcpListener / WsListener / GrpcListener  ──┬── TlsListener 包装     │
│                                              │                       │
│  accept() -> (TransportStream, ConnectionMeta)                      │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        core/server.rs                                │
│                                                                      │
│  ┌──────────┐    ┌───────────────┐    ┌──────────────┐              │
│  │ protocol │───>│ authenticator │───>│ conn_manager │              │
│  │ 解析请求  │    │   (Hook)      │    │  注册连接    │              │
│  └──────────┘    └───────────────┘    └──────────────┘              │
│        │                                      │                      │
│        ▼                                      ▼                      │
│  ┌──────────┐    ┌───────────────┐    ┌──────────────┐              │
│  │  router  │───>│   outbound/   │───>│    relay     │              │
│  │  (Hook)  │    │ 建立出站连接   │    │  双向转发    │              │
│  └──────────┘    └───────────────┘    └──────────────┘              │
│                                              │                      │
│                         stats.record_upload/download (Hook)         │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         business/                                    │
│                                                                      │
│  ApiAuthenticator    ApiStatsCollector    BackgroundTasks           │
│       │                     │                    │                   │
│       └─────────────────────┴────────────────────┘                   │
│                             │                                        │
│                        ApiClient ──> 远程面板                        │
└─────────────────────────────────────────────────────────────────────┘
```

## 错误处理

```rust
// src/error.rs

#[derive(Debug, thiserror::Error)]
pub enum Error {
    // 传输层错误
    #[error("transport error: {0}")]
    Transport(#[from] std::io::Error),

    // 协议错误（可恢复，记录日志即可）
    #[error("protocol error: {0}")]
    Protocol(String),

    // 认证失败（正常情况，不需要告警）
    #[error("authentication failed")]
    AuthFailed,

    // 出站连接失败
    #[error("outbound error: {0}")]
    Outbound(String),

    // 配置错误（启动时失败）
    #[error("config error: {0}")]
    Config(String),
}
```

**错误处理策略**：
- 连接级错误只记日志，不影响服务器
- 区分正常拒绝（AuthFailed）和异常情况
- 配置错误在启动时 panic，快速失败

## 使用示例

### 最简单的单机启动

```rust
// 不需要面板，纯本地使用
let server = Server::builder()
    .authenticator(Box::new(MemoryAuthenticator::new()))
    .stats(Box::new(MemoryStatsCollector::new()))
    .router(Box::new(DirectRouter))
    .build();

// 添加用户
server.authenticator().add_user("password123", 1).await;

// TCP 监听
let listener = TcpTransportListener::bind("0.0.0.0:443").await?;
server.run(listener).await;
```

### 完整面板集成启动

```rust
// 当前使用场景
let api = Arc::new(ApiClient::new(config)?);
let auth = ApiAuthenticator::new(api.clone());
let stats = ApiStatsCollector::new(api.clone());
let router = AclRouter::load(config.acl_path)?;

let server = Server::builder()
    .authenticator(Box::new(auth))
    .stats(Box::new(stats))
    .router(Box::new(router))
    .hooks(Box::new(ApiConnectionHooks::new(api.clone())))
    .build();

// WebSocket + TLS
let ws_listener = WsListener::bind("0.0.0.0:443", "/ws").await?;
let tls_listener = TlsListener::new(ws_listener, tls_acceptor);
server.run(Box::new(tls_listener)).await;
```

## 迁移步骤

1. **创建目录结构**：按上述结构创建 `core/`、`transport/`、`outbound/`、`business/` 目录

2. **提取 Core 层**：
   - 将 `TrojanRequest`、`Address` 移到 `core/protocol.rs`
   - 将 `relay` 函数移到 `core/relay.rs`
   - 将 `ConnectionManager` 移到 `core/connection.rs`
   - 创建 `core/hooks.rs` 定义 traits
   - 创建 `core/server.rs` 重构 Server 结构

3. **提取 Transport 层**：
   - 将 `ws.rs` 移到 `transport/ws.rs`
   - 将 `grpc/` 移到 `transport/grpc/`
   - 创建 `transport/tcp.rs`
   - 将 `tls.rs` 移到 `transport/tls.rs`

4. **提取 Outbound 层**：
   - 从 `main.rs` 提取出站连接逻辑
   - 将 `acl.rs` 移到 `outbound/acl.rs`

5. **提取 Business 层**：
   - 将 `stats.rs` 移到 `business/stats.rs`
   - 将 `api.rs` 拆分到 `business/api/`

6. **重构 main.rs**：使用 builder 模式组装各层
