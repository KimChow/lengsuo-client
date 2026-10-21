//! Trojan 出口：TLS → 写请求头 → **观察窗负向排除** 判认证完成。
//!
//! 语义来源（只读参考，固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）：
//! Xray `proxy/trojan/client.go` 的 `Process` 里，客户端写完请求头后**从不**读
//! 一个成功状态字节——`getResponse` 直接把连接交给 `buf.NewReader(conn)`
//! 转发；服务端 `proxy/trojan/server.go` 认证失败时的**唯一**表达就是关闭连接。
//! ⇒ trojan 没有成功响应头，「认证完成」只能**负向排除**。
//!
//! 判据（与 `crate::outbound` 模块注释里那条同源，两协议对照写在一起更易读，
//! 这里只补本模块的实现细节）：
//! - 请求头完整写出（`lengsuo_trojan::Session::connect` 返回即已 flush）；
//! - 观察窗内对端关闭（EOF / 读错误）⇒ 判**拒绝**；
//! - 窗内收到数据、或安静到超时 ⇒ 判**未被拒绝**（返回可转发载荷的会话）。
//!
//! 本文件是 `outbound.rs` 的 trojan 拆分件（纯重构，行为不变）：只搬移
//! **trojan 专属**符号；共享设施（`NodeTlsStream` / `resolve` / `tls_client` /
//! `DialError`）仍留在 `crate::outbound`。

use std::net::IpAddr;
use std::time::Duration;

use lengsuo_trojan::session::Session as TrojanSession;
use lengsuo_trojan::{Command as TrojanCommand, Credential as TrojanCredential, Request};
use ss_core::target::TargetAddr;
use tokio::io::ReadHalf;
use tokio::io::WriteHalf;
use tokio::time::timeout;

use crate::config::{Endpoint, NodeConfig};
use crate::outbound::{resolve, tls_client, DialError, NodeTlsStream};

/// trojan dry-run 缺省握手目标（discard 端口），见 `NodeConfig::probe_target`。
///
/// `pub`（不是 `pub(crate)`）：node 级回归用例要直接断言这两个回落值，
/// 免得日后有人改掉落回值却没有任何用例报警。
pub const TROJAN_PROBE_FALLBACK_HOST: &str = "127.0.0.1";
pub const TROJAN_PROBE_FALLBACK_PORT: u16 = 9;

/// trojan 握手错误：`lengsuo_trojan::stream::Error` 的 node 侧别名。
///
/// `DialError` 本身是八协议共用的枚举（只能留在 `crate::outbound`），把**错误
/// 类型**放在本模块是 Rust 允许的最细粒度拆分：`DialError::Trojan` 的
/// `#[from]` 载荷类型在此别名，Display 文案与 `From` 实现均不变。
pub type TrojanError = lengsuo_trojan::stream::Error;

/// trojan 出站会话：握手（写头）已完成，可转发 TCP 载荷。
pub type TrojanOutbound = TrojanSession<ReadHalf<NodeTlsStream>, WriteHalf<NodeTlsStream>>;

/// trojan 出站：TLS → 写请求头 → 观察窗负向排除。
pub async fn dial_trojan(
    config: &NodeConfig,
    wait: Duration,
    observe: Duration,
) -> Result<TrojanOutbound, DialError> {
    let client = tls_client(config, wait)?;
    let addr = resolve(&config.endpoint.host, config.endpoint.port, wait).await?;
    let stream = client.connect(addr).await?;
    let (read, write) = tokio::io::split(stream);
    let credential = TrojanCredential::new(&config.auth.password);
    let probe = config.probe_target.clone().unwrap_or_else(|| Endpoint {
        host: TROJAN_PROBE_FALLBACK_HOST.to_owned(),
        port: TROJAN_PROBE_FALLBACK_PORT,
    });
    let target = match probe.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => TargetAddr::V4(v4.octets(), probe.port),
        Ok(IpAddr::V6(v6)) => TargetAddr::V6(v6.octets(), probe.port),
        Err(_) => TargetAddr::Domain(probe.host, probe.port),
    };
    let request = Request {
        command: TrojanCommand::Tcp,
        target,
    };
    let mut session = TrojanSession::connect(read, write, &request, &credential, wait).await?;
    // 观察窗：对端关闭 = 认证被拒（参考服务端拒绝的唯一表达）；
    // 安静或收到数据 = 未被拒绝，返回可继续转发业务的会话。
    let mut probe = [0u8; 1];
    match timeout(observe, session.read(&mut probe)).await {
        Ok(Ok(0)) => Err(DialError::Rejected(
            "连接被对端关闭（trojan 无响应头）".to_owned(),
        )),
        Ok(Ok(_)) => Ok(session),
        Ok(Err(_)) => Err(DialError::Rejected("连接在观察窗内断开".to_owned())),
        Err(_) => Ok(session),
    }
}
