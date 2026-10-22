//! vless 出站会话：TLS / REALITY / Vision 承载 → 请求头 → **成功响应头**。
//!
//! 复用 `outbound_vless::dial_vless`：它已经完成「写请求头 → 读成功响应头
//! `[0, 0]`」这条主链路（对齐参考 `proxy/vless/outbound/outbound.go` 的
//! `Process`：服务端在**目标连接建立成功之后**才回这两个字节，因此它是
//! 正向证据），之后承载流上的字节就是目标数据。
//!
//! 三种承载（普通 TLS / REALITY / Vision）都实现 `AsyncRead + AsyncWrite`，
//! 所以这里统一 `tokio::io::split` 后用裸字节流的读侧 / 写侧转发——
//! **REALITY 与普通 TLS 是两条不同的 `VlessStream` 变体，但转发语义一致**。
//!
//! 目标地址：`dial_vless` 走 `probe_target(config)` 取本次连接的目标，
//! 因此这里把 `probe_target` 覆盖成**真实目标**（见 `super::probe_config`）。

use std::time::Duration;

use ss_core::target::TargetAddr;

use super::{ByteReader, ByteWriter, LiveSession, SessionError};
use crate::config::NodeConfig;
use crate::outbound_vless::dial_vless;

/// 建立 vless 出站会话并返回可转发的读 / 写两半。
pub(super) async fn open(
    node: &NodeConfig,
    target: &TargetAddr,
    wait: Duration,
) -> Result<LiveSession, SessionError> {
    let outbound = dial_vless(&super::probe_config(node, target), wait).await?;
    let (read, write) = tokio::io::split(outbound.stream);
    Ok(LiveSession {
        reader: Box::new(ByteReader::new(read)),
        writer: Box::new(ByteWriter::new(write)),
    })
}
