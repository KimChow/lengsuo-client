//! mux 出站原语的错误类型。全部 fail-closed：出错即返回，不产出任何替代数据。

use crate::mux::frame::FrameError;
use crate::mux::worker::AllocateError;

/// mux 出站原语的错误。全部 fail-closed：出错即返回，不产出任何替代数据。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// 帧编解码失败（协议层不合法）。
    #[error("mux: 帧编解码失败：{0}")]
    Frame(#[from] FrameError),
    /// 会话分配失败（并发/累计上限，或会话表已关闭）。
    #[error("mux: 会话分配失败：{0}")]
    Allocate(#[from] AllocateError),
    /// 会话表已关闭，无法登记新会话。
    #[error("mux: 会话表已关闭")]
    SessionTableClosed,
    /// 承载连接开头的 VLESS 响应头非法。
    ///
    /// 参考 `encoding.DecodeResponseHeader`：version 必须等于请求 version（线上为 0）。
    #[error("mux: VLESS 响应头非法：{0}")]
    ResponseHeader(#[from] crate::stream::Error),
    /// 截止时间必须大于零。
    #[error("mux: 截止时间必须大于零")]
    InvalidDeadline,
    /// I/O 超时。
    #[error("mux: I/O 超时")]
    Timeout,
    /// 底层 I/O 失败。
    #[error("mux: 底层 I/O 失败：{0}")]
    Io(#[from] std::io::Error),
}
