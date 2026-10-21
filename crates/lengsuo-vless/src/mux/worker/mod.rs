//! 通用多会话 Mux 工作端（对照 Xray `common/mux/{session,client,server,writer,reader}.go`，
//! 固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）。
//!
//! 本层是**纯逻辑**转写：不持有 socket，输入输出由调用方以 [`AsyncRead`]/[`AsyncWrite`]
//! 注入（参考用 `buf.Reader`/`buf.Writer` 与 `transport.Link`）。会话的上游/下游
//! 数据面（`buf.Copy`）由调用方驱动，本层只负责帧状态机与会话表，因为参考的
//! `transport.Link` 语义（pipe + 中断）与 Rust 侧 relay 需要一一对应而非「等价」。
//!
//! 逐条对齐参考的语义：
//! - `SessionManager::Allocate`：`MaxConcurrency` 按**活跃会话数**、`MaxConnection`
//!   按**累计会话数**限制；`count` 为单调递增的会话 ID 分配器（从 1 起）；
//! - `CloseIfNoSessionAndIdle`：仅当无活跃会话、`checkSize==0` 且 `count` 未变时关闭；
//! - 客户端 `fetchOutput`：KeepAlive/New 只丢数据，Keep/End 按会话表处理，**未知状态
//!   终止整条 Mux 连接**（参考直接 `return`）；
//! - 服务端 `handleStatusNew`：`GlobalID` 非空分支在本卡不实现（XUDP 跨连接恢复
//!   不在范围，见报告「偏离清单」）；会话建立失败即返回错误（会断开整条 Mux 连接）；
//! - 两端 `handleStatusKeep`：会话不存在时回一个 `End` 帧通知对端关闭，并继续丢弃
//!   后续数据；写入下游失败（`buf.IsWriteError`）时关闭该会话并丢弃余下数据；
//! - `Writer`：首帧 `New`、后续 `Keep`、`Close` 发 `End`（`has_error` 时置
//!   `OptionError`）；`transferType==Stream` 时按 8192 分片，Packet 时一帧一包。
//!
//! **目录结构**（拆分自原单文件 `worker.rs` + `worker_tests.rs`，行为逐字节等价）：
//! - [`session`]：会话表 [`SessionManager`] 与分配策略；
//! - [`writer`]：会话方向的数据写入端 [`SessionWriter`]；
//! - [`action`]：帧处理后的下一步动作 [`Action`]；
//! - [`state`]：客户端 / 服务端状态机；
//! - [`tests`]：单元测试（原 `worker_tests.rs`，本仓此前未把它挂进编译单元，
//!   拆分后按原样挂上，断言与用例名逐字未改）。

mod action;
mod session;
mod state;
mod writer;

#[cfg(test)]
mod manager_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod wire_tests;

use std::io::Write;

use crate::mux::frame::FrameError;

pub use action::Action;
pub use session::{AllocateError, SessionManager, SessionState, Strategy};
pub use state::{MuxClient, MuxServer};
pub use writer::{write_closing_end, SessionWriter};

/// 参考 `buf.IsWriteError`：下游已关闭/断管，属于「本会话可独立失败」的写入错误。
#[must_use]
pub fn is_write_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::UnexpectedEof
    )
}

/// 把字节写全；错误文本与拆分前一致。
fn write_all<W: Write>(out: &mut W, bytes: &[u8]) -> Result<(), FrameError> {
    out.write_all(bytes)
        .map_err(|error| FrameError::Io(format!("{:?}", error.kind())))
}
