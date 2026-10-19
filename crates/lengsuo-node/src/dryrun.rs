//! dry-run：加载配置 → 每节点握手到认证完成 → 输出 ok / 失败原因。
//!
//! 不传任何业务载荷：每节点只执行 `outbound::dial`（TLS + 协议认证完成的
//! 可观测判据），拿到连接立刻干净关闭。trojan 的“认证完成”是负向排除
//! （观察窗内未被对端关闭，协议无响应头，见 `outbound` 模块注释）；anytls
/// 是收到 ServerSettings 的正向证据。失败原因一律不含密码或其摘要。
use std::time::Duration;

use crate::config::{NodeConfig, Protocol};
use crate::outbound::{dial, Outbound};

/// 单节点 dry-run 结果。
#[derive(Debug)]
pub struct NodeReport {
    pub name: String,
    pub protocol: Protocol,
    /// None = 握手到认证完成；Some(reason) = 失败原因（脱敏）。
    pub reason: Option<String>,
}

impl NodeReport {
    #[must_use]
    pub fn ok(&self) -> bool {
        self.reason.is_none()
    }
}

/// 逐节点 dry-run。单个节点的失败不影响其余节点；每步都受 `wait` 约束，
/// trojan 的负向观察窗为 `observe`。
pub async fn dry_run(nodes: &[NodeConfig], wait: Duration, observe: Duration) -> Vec<NodeReport> {
    let mut reports = Vec::with_capacity(nodes.len());
    for node in nodes {
        let reason = match dial(node, wait, observe).await {
            Ok(Outbound::Trojan(session)) => {
                // 干净收尾：drain 策略 + 写半关闭；dry-run 不转发任何载荷。
                let _ = session.close().await;
                None
            }
            Ok(Outbound::AnyTls(mut outbound)) => {
                // TLS close_notify 收尾，不发 FIN/SYN 等业务帧。
                use tokio::io::AsyncWriteExt as _;
                let _ = outbound.stream.shutdown().await;
                None
            }
            Ok(Outbound::Vless(mut outbound)) => {
                // 成功响应头已收到；干净关闭 TLS，不发业务载荷。
                use tokio::io::AsyncWriteExt as _;
                let _ = outbound.stream.shutdown().await;
                None
            }
            Ok(Outbound::Vmess(mut outbound)) => {
                // 认证响应头已解开；dry-run 数据帧已送达，TLS 干净收尾。
                use tokio::io::AsyncWriteExt as _;
                let _ = outbound.stream.shutdown().await;
                None
            }
            Ok(Outbound::Shadowsocks(mut outbound)) => {
                // 回程已有认证 chunk；写半关闭干净收尾。
                use tokio::io::AsyncWriteExt as _;
                let _ = outbound.write.shutdown().await;
                None
            }
            Ok(Outbound::Ss2022(mut outbound)) => {
                // 响应流开场已通过归属校验；半关闭收尾。
                use tokio::io::AsyncWriteExt as _;
                let _ = outbound.stream.shutdown().await;
                None
            }
            Ok(Outbound::Hysteria(mut outbound)) => {
                // TCP 承载已被接受；发送侧 FIN 收尾（对齐 interConn.Close）。
                let _ = outbound.stream.finish();
                outbound.stream.stop_read();
                None
            }
            Ok(Outbound::Wireguard(outbound)) => {
                // 握手响应已认证、transport 密钥已派生；UDP 无连接可关。
                // 只做一次脱敏诊断输出，不打印任何密钥字节。
                let _ = outbound.keys.local_index;
                None
            }
            Err(error) => Some(error.to_string()),
        };
        reports.push(NodeReport {
            name: node.name.clone(),
            protocol: node.protocol,
            reason,
        });
    }
    reports
}
