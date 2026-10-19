//! VLESS 出口：TLS → 请求头 → **成功响应头** 正向确认。
//!
//! 语义来源（只读参考，固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）：
//! Xray `proxy/vless/outbound/outbound.go` 的 `Process` 里，客户端在写出请求头后
//! 会读服务端响应：`proxy/vless/outbound/outbound.go` 调用
//! `encoding.DecodeResponse`/`ReadOnce`，期望**恰好两个零字节**（
//! `proxy/vless/inbound/inbound.go` 在目标连接建立成功后才写 `[0, 0]`）。
//! 因此 vless 与 trojan 不同：它有明确的**正向**认证完成证据。
//!
//! 本仓 `lengsuo-vless` 的 `stream::receive_response` 正是这两个字节的校验
//! （非 `[0, 0]` 一律 `Err(Unsupported)`），因此这里不需要观察窗。
//!
//! 偏离：uuid → 16 字节凭据直接取 UUID 文本的十六进制字节（`ss_core` 无 UUID
//! 类型，且参考的 ID 在线上就是原始 16 字节）；Vision/flow 不在本卡范围。

use std::time::Duration;

use lengsuo_vless::header::{Command as VlessCommand, Request};
use lengsuo_vless::stream::{receive_response, send_request};
use ss_core::target::TargetAddr;
use tokio::io::AsyncWriteExt as _;

use crate::config::NodeConfig;
use crate::outbound::{connect_tls, probe_target, DialError, NodeTlsStream};

/// vless 出站会话：请求头已写出且成功响应头已收到，可转发 TCP 载荷。
pub struct VlessOutbound {
    /// 已完成握手的 TLS 流（响应头已消费，后续字节即目标数据）。
    pub stream: NodeTlsStream,
    /// dry-run 里使用的目标地址（诊断用，不含凭据）。
    pub target: TargetAddr,
}

/// vless 出站：TLS → 请求头 → 等服务端成功响应头。
pub async fn dial_vless(config: &NodeConfig, wait: Duration) -> Result<VlessOutbound, DialError> {
    let mut stream = connect_tls(config, wait).await?;
    let credential = uuid_bytes(&config.auth.password)?;
    let target = probe_target(config);
    let request = Request {
        command: VlessCommand::Tcp,
        target: target.clone(),
    };
    send_request(&mut stream, &request, &credential, wait).await?;
    // 正向证据：服务端在目标连接建立后才写 [0, 0]；超时/非零字节都是失败。
    receive_response(&mut stream, wait).await?;
    // dry-run 不转发业务载荷，此处只要让请求头确实上线即可。
    stream.flush().await.map_err(lengsuo_tls::Error::from)?;
    Ok(VlessOutbound { stream, target })
}

/// UUID 文本 → 16 字节凭据。形态已在 `config::validate` 校验过；
/// 这里再做一次 fail-closed 解析（配置对象可能被上层直接构造）。
pub(crate) fn uuid_bytes(text: &str) -> Result<[u8; 16], DialError> {
    let compact: String = text.chars().filter(|c| *c != '-').collect();
    if compact.len() != 32 {
        return Err(DialError::Rejected("凭据不是 16 字节 UUID".to_owned()));
    }
    let mut bytes = [0u8; 16];
    for (index, slot) in bytes.iter_mut().enumerate() {
        let pair = &compact[index * 2..index * 2 + 2];
        *slot = u8::from_str_radix(pair, 16)
            .map_err(|_| DialError::Rejected("凭据不是 16 字节 UUID".to_owned()))?;
    }
    Ok(bytes)
}
