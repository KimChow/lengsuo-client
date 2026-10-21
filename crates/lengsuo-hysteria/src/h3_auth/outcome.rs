//! 认证结果与认证期间必须保活的 HTTP/3 单向流。

use super::datagram::SeedFiller;

/// 认证成功后从响应头提取的信息。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthOutcome {
    /// 服务端是否声明支持 UDP datagram（`Hysteria-UDP`）。
    pub udp_enabled: bool,
    /// 服务端 `Hysteria-CC-RX`（解析失败按 0，与 Go 忽略错误一致）。
    pub server_cc_rx: u64,
}

/// 认证期间必须保持打开的 HTTP/3 单向流（控制/QPACK 编码器/解码器，
/// 提前 FIN 等价于连接层错误），由 [`crate::quic::client::HysteriaClient`]
/// 持有到连接结束；`seeds` 是响应 chunk 派生的 UDP 发送种子。
pub struct H3ControlStreams {
    /// 三条流只持有不发 FIN——drop 即 FIN 会被对端判
    /// H3_CLOSED_CRITICAL_STREAM；control/encoder 建立后不再读写。
    #[allow(dead_code)]
    pub(crate) control: quinn::SendStream,
    #[allow(dead_code)]
    pub(crate) qpack_encoder: quinn::SendStream,
    pub(crate) qpack_decoder: quinn::SendStream,
    /// 响应 chunk 派生的发送种子（`pub(super)` = `h3_auth` 模块内可见）。
    pub(super) seeds: Vec<SeedFiller>,
}

impl H3ControlStreams {
    /// 取走全部发送种子（一次性，交给 UDP 层的种子池）。
    pub fn take_seeds(&mut self) -> Vec<SeedFiller> {
        std::mem::take(&mut self.seeds)
    }
}
