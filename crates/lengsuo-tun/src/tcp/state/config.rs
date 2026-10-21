//! 单连接状态机的缓冲上限与初始序号种子。

/// 单连接的缓冲上限与初始序号种子。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// 本端接收窗口通告上限（字节）。可用缓冲归零即通告零窗口。
    pub receive_window: u16,
    /// 乱序重排缓冲的段数上限，至少为 1。
    pub reorder_slots: usize,
    /// 本端初始序号种子；见 [`super::Connection::set_iss_seed`] 的非密码学说明。
    pub iss_seed: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            receive_window: 65_535,
            reorder_slots: 4,
            iss_seed: 0,
        }
    }
}
