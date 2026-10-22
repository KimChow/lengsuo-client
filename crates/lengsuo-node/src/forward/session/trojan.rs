//! trojan 出站会话：TLS → 写请求头（携带真实目标）→ 裸字节流。
//!
//! **不复用** `outbound::dial` 的 trojan 分支：它用 `probe_target` 且在观察窗里
//! **读掉 1 字节**（负向排除的代价），实时转发会吞掉回程首字节；且
//! `TrojanSession` 把读写两半私有封死，无法在请求方向 EOF 时只半关闭写侧而
//! 保留回程。这里用同一 crate 的 `stream` 原语（协议编码与凭据派生仍全部复用），
//! 与仓内 trojan 服务端中继（`lengsuo_trojan::server::relay`）的裸两半写法一致。
//!
//! 参考：`proxy/trojan/client.go` 的 `Process` —— 写完请求头即把连接交给
//! 转发循环，**不读任何响应头**（trojan 没有响应头）。

use std::time::Duration;

use lengsuo_trojan::stream::send_request;
use lengsuo_trojan::{
    Command as TrojanCommand, Credential as TrojanCredential, Request as TrojanRequest,
};
use ss_core::target::TargetAddr;

use super::{ByteReader, ByteWriter, LiveSession, SessionError};
use crate::config::NodeConfig;
use crate::outbound::connect_tls;

/// 建立 trojan 出站会话并返回可转发的读 / 写两半。
pub(super) async fn open(
    node: &NodeConfig,
    target: &TargetAddr,
    wait: Duration,
) -> Result<LiveSession, SessionError> {
    let stream = connect_tls(node, wait).await?;
    let (read, mut write) = tokio::io::split(stream);
    let credential = TrojanCredential::new(&node.auth.password);
    let request = TrojanRequest {
        command: TrojanCommand::Tcp,
        target: target.clone(),
    };
    // 请求头完整写出并 flush 之后才算会话建立（对齐 trojan 客户端的顺序约束）。
    send_request(&mut write, &request, &credential, wait).await?;
    Ok(LiveSession {
        reader: Box::new(ByteReader::new(read)),
        writer: Box::new(ByteWriter::new(write)),
    })
}
