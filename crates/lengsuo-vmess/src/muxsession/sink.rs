//! Mux 子流的通道抽象：下行 sink 与目标拨号回调。
//!
//! 语义来源：参考 `common/mux/server.go` 的 `dispatcher.Dispatch` 与
//! `buf.Pipe` 端点，固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。

use ss_core::target::TargetAddr;

use crate::muxframe::TargetNetwork;

/// 子流的逻辑方向：本端读（远端写）与本端写（远端读）。
///
/// 参考里这对读写是两个 `buf.Pipe` 端点；本层把它们显式交给调用方，
/// 由调用方接真实网络或内存通道。
pub trait StreamSink {
    /// 把下行载荷交给本端消费者（`s.output`）。
    fn write(&mut self, payload: &[u8]) -> Result<(), String>;
    /// 对端结束该会话（`s.Close(false)` / `s.output` 关闭）。
    fn close_remote(&mut self) -> Result<(), String>;
    /// 本端结束该会话（收到 End 帧，或本地关闭）。
    fn close_local(&mut self) -> Result<(), String>;
}

/// 空实现：只做记账、不转发（用于纯状态机测试）。
#[derive(Debug, Default)]
pub struct DiscardSink;

impl StreamSink for DiscardSink {
    fn write(&mut self, _payload: &[u8]) -> Result<(), String> {
        Ok(())
    }
    fn close_remote(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn close_local(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// 会话建立的回调（服务端方向）：由调用方按目标地址拨号并给出下行通道。
///
/// 对齐参考 `w.dispatcher.Dispatch(ctx, meta.Target)`；本层不实现 dispatcher。
pub trait TargetDialer {
    /// `Dispatch` 失败即放弃该会话（参考 `failed to dispatch request.`）。
    fn dial(
        &mut self,
        target: &TargetAddr,
        network: TargetNetwork,
    ) -> Result<Box<dyn StreamSink>, String>;
    /// 帧级致命错误时的兜底（参考 `closingWriter.Close()` / 断整条 mux 连接）。
    fn abort_all(&mut self) -> Result<(), String>;
}
