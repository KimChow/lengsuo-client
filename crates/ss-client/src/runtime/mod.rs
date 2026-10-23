//! 客户端运行时：配置 → SOCKS5 入站 → 分流 → 出口拼接。
//!
//! 单连接粒度见 [`Runtime::serve_one`]；[`Runtime::run`] 循环接受连接。
//! **注意**：`outbound::Tunnel` 目前是 `!Send`，`run` 暂按顺序处理连接
//! （详见该方法文档与本卡报告），修好后改回每连接一个 `tokio::spawn`。
//!
//! **监听地址**：`ClientConfig` 没有 listen 字段（配置面只声明出口与规则），
//! 故 [`Runtime::new`] 用 SOCKS5 惯例端口 `127.0.0.1:1080`；测试用
//! [`Runtime::with_bind`] 指定 `:0` 取临时端口。
//!
//! **`Route::Reject` 的应答方式**：配置的动作集合只有 `direct` / `proxy`，
//! 路由层目前没有 reject 来源。若将来出现，本实现选择「**直接关闭 + 记日志**」
//! 而不是回 SOCKS5 `0x02`：入站握手完成时已经回过 `0x00` 成功应答（BND 由
//! 上层决定），再补一个应答会违反 RFC 1928「每个请求一个应答」。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use ss_core::target::TargetAddr;

use crate::config::Target as ConfigTarget;
use crate::config::{Action, ClientConfig, OutboundConfig};
use crate::inbound::{Accepted, InboundError, Socks5Config, Socks5Listener};
use crate::outbound::{DialError, Dialer};

/// [`Runtime::new`] 的缺省监听地址（SOCKS5 惯例端口）。
const DEFAULT_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1080);

/// `connect_timeout_ms == 0` 时的文档缺省值（与 `Dialer` 保持一致）。
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 5_000;

/// accept / 握手失败后的退避：入站 API 把两者合并成一个 `Err`，无法区分
/// 是坏握手还是 accept 层硬错误；短退避避免后者空转打满 CPU。
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(20);

/// 运行时错误。
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("inbound error: {0}")]
    Inbound(#[from] InboundError),

    #[error("dial error: {0}")]
    Dial(#[from] DialError),
}

/// 分流结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Direct,
    Proxy,
    Reject,
}

/// 纯函数路由：命中规则取规则动作；否则取 `fallback`；需要解析地址才能
/// 判定的结论**一律走代理**（防 DNS 泄漏）。
#[must_use]
pub fn route(config: &ClientConfig, target: &TargetAddr) -> Route {
    let decision = config.decide(&config_target(target));
    if decision.needs_resolution {
        tracing::debug!(
            target = ?target,
            fallback = config.fallback.as_str(),
            "routing needs address resolution; defaulting to proxy to avoid DNS leak"
        );
        return Route::Proxy;
    }
    match decision.action {
        Action::Direct => Route::Direct,
        Action::Proxy => Route::Proxy,
    }
}

/// 把 SOCKS5 目标映射为配置匹配器使用的目标视图（仅 TCP）。
fn config_target(target: &TargetAddr) -> ConfigTarget<'_> {
    let (domain, ip, port) = match target {
        TargetAddr::Domain(host, port) => (Some(host.as_str()), None, *port),
        TargetAddr::V4(bytes, port) => (None, Some(IpAddr::V4(Ipv4Addr::from(*bytes))), *port),
        TargetAddr::V6(bytes, port) => (None, Some(IpAddr::V6(Ipv6Addr::from(*bytes))), *port),
    };
    ConfigTarget {
        domain,
        ip,
        port,
        network: Some("tcp"),
        process: None,
        protocol: None,
    }
}

/// 客户端运行时：配置 + 入站监听 + 出口拨号器。
pub struct Runtime {
    config: ClientConfig,
    listener: Socks5Listener,
    dialer: Dialer,
}

impl Runtime {
    /// 用缺省监听地址 [`DEFAULT_BIND`] 构造。
    ///
    /// 先构造 [`Dialer`]、后绑定端口：非法 `ss://`（如未知 method）必须
    /// 稳定地报配置错误，而不是被端口占用之类的绑定时序掩盖。
    pub async fn new(config: ClientConfig) -> Result<Self, RuntimeError> {
        Self::with_bind(config, DEFAULT_BIND).await
    }

    /// 指定监听地址（测试用 `127.0.0.1:0` 取临时端口）。
    pub async fn with_bind(config: ClientConfig, bind: SocketAddr) -> Result<Self, RuntimeError> {
        let dialer = Dialer::new(config.outbound.clone())?;
        let listener = Socks5Listener::bind(Socks5Config { bind, auth: None }).await?;
        Ok(Self {
            config,
            listener,
            dialer,
        })
    }

    /// 实际监听地址（`with_bind` 传 0 端口时取回分配到的端口）。
    pub fn local_addr(&self) -> Result<SocketAddr, RuntimeError> {
        Ok(self.listener.local_addr()?)
    }

    /// 接受一个连接并处理到结束。
    ///
    /// 握手 / 拨号 / 中转错误都只记日志，返回 `Ok(())`：这是**单连接**语义，
    /// 调用方不应因为一个坏连接而停掉整体循环。
    pub async fn serve_one(&self) -> Result<(), RuntimeError> {
        match self.listener.accept().await {
            Ok(accepted) => {
                self.handle(accepted).await;
                Ok(())
            }
            Err(err) => {
                tracing::warn!(error = %err, "SOCKS5 accept failed");
                Ok(())
            }
        }
    }

    /// 循环接受连接。
    ///
    /// 本卡边界不允许改 `outbound/`，而 `outbound::Tunnel` 目前是 `!Send`
    /// （`tunnel.rs:26-27` 的两个 boxed future 别名少了 `+ Send`），
    /// `tokio::spawn` 编不过。故这里暂按**顺序**处理连接：
    /// ponytail: 给那两个别名加 `+ Send` 后，把本循环改回
    /// `tokio::spawn(async move { runtime.handle(accepted).await })` 即可。
    /// 详见本卡报告。
    pub async fn run(self) -> Result<(), RuntimeError> {
        loop {
            match self.listener.accept().await {
                Ok(accepted) => self.handle(accepted).await,
                Err(err) => {
                    tracing::warn!(error = %err, "SOCKS5 accept failed");
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                }
            }
        }
    }

    /// 单连接数据面：分流 → 建连 → 拼接。
    async fn handle(&self, accepted: Accepted) {
        let Accepted {
            target,
            client,
            residual,
        } = accepted;

        match route(&self.config, &target) {
            Route::Reject => {
                // 见模块文档：入站已回过 0x00，这里只关闭并记日志。
                tracing::warn!(target = ?target, "route rejected; closing connection");
            }
            Route::Direct => match self.connect_direct(&target).await {
                Ok(mut upstream) => {
                    if !residual.is_empty() {
                        if let Err(err) = upstream.write_all(&residual).await {
                            tracing::warn!(error = %err, "direct: failed to write residual payload");
                            return;
                        }
                    }
                    splice(client, upstream).await;
                }
                Err(err) => tracing::warn!(error = %err, target = ?target, "direct connect failed"),
            },
            // `residual` 作为首批载荷与目标地址写在同一个认证 chunk 里，
            // 不会丢，也不需要再单独写一次。
            Route::Proxy => match self.dialer.connect(&target, &residual).await {
                Ok(upstream) => splice(client, upstream).await,
                Err(err) => tracing::warn!(error = %err, target = ?target, "proxy dial failed"),
            },
        }
    }

    /// 直连：IP 直用；域名先 `lookup_host`（与出口拨号共用同一超时语义）。
    async fn connect_direct(&self, target: &TargetAddr) -> std::io::Result<TcpStream> {
        let wait = connect_timeout(&self.config.outbound);
        let addr = resolve_target(target, wait).await?;
        tokio::time::timeout(wait, TcpStream::connect(addr))
            .await
            .map_err(|_| timed_out("direct connect timed out"))?
    }
}

/// 双向拼接；任一方向结束或出错都返回，两个流在函数返回时一起关闭。
async fn splice<U>(mut client: TcpStream, mut upstream: U)
where
    U: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        Ok((from_client, from_upstream)) => {
            tracing::debug!(from_client, from_upstream, "connection closed");
        }
        Err(err) => tracing::warn!(error = %err, "relay error; closing both sides"),
    }
}

/// 目标 → `SocketAddr`。域名解析限时 `wait`。
async fn resolve_target(target: &TargetAddr, wait: Duration) -> std::io::Result<SocketAddr> {
    match target {
        TargetAddr::V4(bytes, port) => Ok(SocketAddr::from((Ipv4Addr::from(*bytes), *port))),
        TargetAddr::V6(bytes, port) => Ok(SocketAddr::from((Ipv6Addr::from(*bytes), *port))),
        TargetAddr::Domain(host, port) => {
            let resolved =
                tokio::time::timeout(wait, tokio::net::lookup_host((host.as_str(), *port)))
                    .await
                    .map_err(|_| timed_out("dns lookup timed out"))??;
            resolved.into_iter().next().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no address resolved")
            })
        }
    }
}

/// 与 `Dialer::new` 相同的超时归一化：0 视为文档缺省 5000ms。
fn connect_timeout(outbound: &OutboundConfig) -> Duration {
    let ms = if outbound.connect_timeout_ms == 0 {
        DEFAULT_CONNECT_TIMEOUT_MS
    } else {
        outbound.connect_timeout_ms
    };
    Duration::from_millis(ms)
}

fn timed_out(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, message)
}
