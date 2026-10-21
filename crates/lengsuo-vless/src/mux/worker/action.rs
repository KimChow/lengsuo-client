//! 两端状态机：客户端 `fetchOutput` 与服务端 `handleFrame`。
//!
//! 从父模块拆出以保持单文件 ≤400 行（软约束）。语义逐条对齐参考
//! `common/mux/{client,server}.go`（固定 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）。

/// 帧处理后的下一步动作，交调用方执行（数据面归调用方，见模块头）。
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// 无动作。
    None,
    /// 把该会话的后续数据写入其下游；`payload` 为本帧数据段。
    Deliver {
        id: u16,
        payload: Vec<u8>,
        new: bool,
    },
    /// 关闭该会话（对端 End、或本端下发失败）。
    CloseSession { id: u16 },
    /// 通知对端关闭会话（`Keep` 未命中会话时回 `End`）。
    SendEnd { id: u16 },
}
