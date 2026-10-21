//! Mux 帧的 fail-closed 错误类型（不携带地址/密钥字节）。

/// 帧错误（fail-closed；不携带地址/密钥字节）。
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// 读帧头失败（EOF/超时等）。
    #[error("failed to read mux frame: {0}")]
    Io(String),
    /// `metaLen > 512`（参考 `invalid metalen`）。
    #[error("invalid metalen")]
    MetaTooLong,
    /// 元数据体不足以容纳固定 4 字节 / 声明的可选段。
    #[error("insufficient buffer: {got}")]
    ShortMeta { got: usize },
    /// 未知会话状态。
    #[error("unknown status: {status}")]
    UnknownStatus { status: u8 },
    /// 未知 network 字节。
    #[error("unknown network type: {network}")]
    UnknownNetwork { network: u8 },
    /// 地址段不合法。
    #[error("failed to parse address and port")]
    Address,
    /// 声明的数据长度超过 buf.Size（参考 `packet size too large`）。
    #[error("packet size too large: {size}")]
    PacketTooLarge { size: u16 },
}
