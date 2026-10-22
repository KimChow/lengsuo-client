//! 流量转发服务：本地监听 → 按目标地址选节点 → 走既有出站会话 → 双向转发。
//!
//! ## 转发循环语义（对齐参考）
//!
//! 参考基线：Xray v26.3.27（`d2758a02`）。
//! - `app/proxyman/outbound/handler.go` 的 `Dispatch` → `h.proxy.Process`：
//!   转发循环由各协议的 `Process` 承担（`proxy/trojan/client.go`、
//!   `proxy/shadowsocks/client.go`），参考用 `task.Run(ctx, postRequest,
//!   responseDoneAndCloseWriter)` **并发**跑两个方向，`postRequest` 干净结束
//!   后对上游做写半关闭（`task.Close(link.Writer)`），回程方向继续跑到自己的
//!   EOF。
//! - `common/buf/copy.go` 的 `Copy`：`buf.Size = 8192`（`common/buf/buffer.go`），
//!   读写都是 8 KiB 粒度。
//! - `features/policy/policy.go` 的 `SessionDefault`：`ConnectionIdle = 300s`。
//!
//! 本端的对应关系：
//! - 两个方向**同时**进行，用 `tokio::join!`（**不是** `select!`——`select!` 会在
//!   一侧 EOF 时取消另一侧，回程会被丢掉；`w4-ss-relay-addr` 当年就是这个坑）。
//! - 一侧 EOF ⇒ **半关闭**另一侧写侧（发 FIN），**不等于**立刻断连；两侧都结束
//!   才真正关闭。
//! - 空闲上限：每个单次读/写都受 `idle_timeout` 约束（对齐参考
//!   `CancelAfterInactivity` 的效果：静默超过上限即断连）。
//! - 整体上限：整条连接受 `session_timeout` 约束。
//! - 缓冲：每方向固定 8 KiB（对齐参考 `buf.Size`）。
//!
//! ## fail-closed
//!
//! 任何失败路径都**断开本地连接**，**绝不**回落到直连：
//! - 路由未命中且无默认节点 ⇒ 断开；
//! - 路由规则冲突 ⇒ 断开（冲突在配置加载阶段就已报错，运行期仍防御性拒绝）；
//! - 节点不可达 / 认证被拒 ⇒ 断开；
//! - 协议结构性不可转发（wireguard 的 L3 隧道）⇒ 断开。
//!
//! ## 关停语义（对齐 `lengsuo_shadowsocks::RelayService`）
//!
//! [`Forwarder::shutdown`]：停止接受新连接 + 优雅收尾既有连接（等在途连接
//! 结束），随后监听器关闭、后台任务全部回收。句柄被 drop 时同样让服务停下来，
//! 不留后台监听。

mod config;
mod relay;
// `pub(crate)`：让 `crate::relay_bridge` 能取到 `session::open`，
// 同时不把转发层的内部模块暴露到 crate 之外。
pub(crate) mod session;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::config::NodeConfig;
use crate::route::RouteTable;

pub use config::{load_config, ForwardConfig, LoadedConfig, DEFAULT_LISTEN, DEFAULT_TIMEOUT_SECS};
pub use relay::{RelayError, RelayOutcome};
pub use session::{LiveSession, Opened, OutboundReader, OutboundWriter, SessionError, COPY_BUF};

/// 转发器的错误。Display 不含口令、密钥或明文载荷。
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("监听 {listen} 失败：{reason}")]
    Listen { listen: String, reason: String },
    #[error("转发配置非法：{0}")]
    Config(String),
    #[error("转发任务异常终止")]
    Task,
}

/// 节点池：节点名 → 节点配置。选中的节点必须存在（路由表在配置加载阶段已校验）。
#[derive(Debug, Clone, Default)]
pub struct NodePool {
    nodes: Vec<NodeConfig>,
}

impl NodePool {
    /// 由节点列表构造。
    #[must_use]
    pub fn new(nodes: Vec<NodeConfig>) -> Self {
        Self { nodes }
    }

    /// 按名字取节点。
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&NodeConfig> {
        self.nodes.iter().find(|node| node.name == name)
    }

    /// 节点数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// 已绑定但未启动的转发服务。绑定与运行分开，测试可以先取到真实端口再启动。
pub struct Forwarder {
    listener: TcpListener,
    pool: Arc<NodePool>,
    routes: Arc<RouteTable>,
    config: Arc<ForwardConfig>,
}

impl Forwarder {
    /// 绑定监听地址并校验配置。端口 0 交给内核分配（避免端口抖动）。
    pub async fn bind(
        listen: SocketAddr,
        pool: NodePool,
        routes: RouteTable,
        config: ForwardConfig,
    ) -> Result<Self, ForwardError> {
        config
            .validate()
            .map_err(|err| ForwardError::Config(err.to_string()))?;
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|err| ForwardError::Listen {
                listen: listen.to_string(),
                reason: err.to_string(),
            })?;
        Ok(Self {
            listener,
            pool: Arc::new(pool),
            routes: Arc::new(routes),
            config: Arc::new(config),
        })
    }

    /// 本地监听地址。
    pub fn local_addr(&self) -> Result<SocketAddr, ForwardError> {
        self.listener
            .local_addr()
            .map_err(|err| ForwardError::Listen {
                listen: "listener".to_owned(),
                reason: err.to_string(),
            })
    }

    /// 启动服务并返回停止句柄。
    ///
    /// 句柄被 drop 或调用 [`ForwardHandle::shutdown`] 后：监听器关闭、不再接受
    /// 新连接、既有连接被收尾（等待在途连接结束）、后台任务全部回收。
    pub async fn start(self) -> Result<ForwardHandle, ForwardError> {
        let (stop_tx, stop_rx) = watch::channel(false);
        let listener = self.listener;
        let pool = Arc::clone(&self.pool);
        let routes = Arc::clone(&self.routes);
        let config = Arc::clone(&self.config);
        let join = tokio::task::spawn(async move {
            let mut connections: JoinSet<RelayOutcome> = JoinSet::new();
            let mut stop_rx = stop_rx;
            loop {
                tokio::select! {
                    // 剪枝：已结束的连接任务在这里回收，避免长时间运行下无界增长。
                    Some(_done) = connections.join_next(), if !connections.is_empty() => {}
                    accepted = listener.accept() => {
                        let (stream, peer) = match accepted {
                            Ok(pair) => pair,
                            // 单个 accept 失败（如瞬时 fd 耗尽）不应终止整个服务。
                            Err(_) => continue,
                        };
                        let pool = Arc::clone(&pool);
                        let routes = Arc::clone(&routes);
                        let config = Arc::clone(&config);
                        connections.spawn(async move {
                            relay::handle(stream, peer, pool, routes, config).await
                        });
                    }
                    changed = stop_rx.changed() => {
                        let stopping = changed.is_err() || *stop_rx.borrow();
                        if stopping {
                            break;
                        }
                    }
                }
            }
            // 停止接受新连接后，**等既有连接收尾**（优雅关停）；
            // 超过收尾上限仍未结束的任务被中断（避免无限等待）。
            let grace = config.session_timeout().max(Duration::from_secs(1));
            let deadline = tokio::time::Instant::now() + grace;
            loop {
                match tokio::time::timeout_at(deadline, connections.join_next()).await {
                    // 收尾时限内又完成一条：继续等剩下的。
                    Ok(Some(_outcome)) => {}
                    // 没有在途连接了。
                    Ok(None) => break,
                    // 收尾时限已到：剩下的任务由 `shutdown()` 中断。
                    Err(_) => break,
                }
            }
            connections.shutdown().await;
            Ok(())
        });
        Ok(ForwardHandle {
            stop_tx: Some(stop_tx),
            join: Some(join),
        })
    }
}

/// 服务句柄。**故意不实现 `Debug`**（内部持有配置，可能含凭据）。
pub struct ForwardHandle {
    stop_tx: Option<watch::Sender<bool>>,
    join: Option<tokio::task::JoinHandle<Result<(), ForwardError>>>,
}

impl ForwardHandle {
    /// 请求停止并等待服务任务退出（在途连接收尾完毕）。可重复调用。
    pub async fn shutdown(mut self) -> Result<(), ForwardError> {
        if let Some(sender) = self.stop_tx.take() {
            let _ = sender.send(true);
        }
        let Some(join) = self.join.take() else {
            return Ok(());
        };
        match join.await {
            Ok(result) => result,
            Err(_) => Err(ForwardError::Task),
        }
    }
}

impl Drop for ForwardHandle {
    fn drop(&mut self) {
        // 句柄被丢弃（测试提前失败）时也要让服务停下来，不留后台监听。
        if let Some(sender) = self.stop_tx.take() {
            let _ = sender.send(true);
        }
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}
