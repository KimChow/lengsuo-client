//! UDP 会话池的**公共类型**：配置、错误、回程数据报与投递结果。
//!
//! 语义说明见父模块 `crate::udp_pool` 的模块注释（参考 Xray v26.3.27 `d2758a0`）。

use std::time::Duration;

use ss_core::target::TargetAddr;

use super::{DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_ENTRIES};

/// UDP 会话池错误。Display/Debug 不含口令、密钥与载荷明文。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("池配置非法：{0}")]
    InvalidConfig(&'static str),

    #[error("池已关闭")]
    Closed,

    #[error("载荷长度 {0} 超过单包上限")]
    Oversize(usize),

    #[error("目标地址非法：{0}")]
    Address(#[from] ss_core::Error),

    #[error("出站套接字绑定失败：{0}")]
    Bind(#[source] std::io::Error),

    #[error("出站套接字发送失败：{0}")]
    Send(#[source] std::io::Error),

    #[error("目标地址解析失败：{0}")]
    Resolve(#[source] std::io::Error),
}

/// 池配置。`idle_timeout` 与 `max_entries` 必须为正，`payload_limit` 为 0 表示不限。
#[derive(Debug, Clone, Copy)]
pub struct PoolConfig {
    /// 条目空闲回收阈值：最后一次收发后超过此时长即移除条目、释放 socket。
    pub idle_timeout: Duration,
    /// 池条目上界。超限时**淘汰最久未用的条目**（LRU），不拒绝新包。
    pub max_entries: usize,
    /// cone 模式：首包目标固定，后续包自身的目标被忽略（参考语义）。
    pub cone: bool,
    /// 单包载荷上限（转发侧策略），0 表示不限。
    pub payload_limit: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_entries: DEFAULT_MAX_ENTRIES,
            cone: false,
            payload_limit: crate::stream::REFERENCE_MAX_DATAGRAM_PAYLOAD,
        }
    }
}

impl PoolConfig {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.idle_timeout.is_zero() {
            return Err(Error::InvalidConfig("空闲回收阈值必须大于零"));
        }
        if self.max_entries == 0 {
            return Err(Error::InvalidConfig("条目上界必须大于零"));
        }
        Ok(())
    }
}

/// 回程数据报：来源地址与载荷。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    /// 回程地址（出站目标的真实源地址）。
    pub address: TargetAddr,
    /// 回程载荷。
    pub payload: Vec<u8>,
}

/// 一次投递的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dispatch {
    /// 实际发往的目标：cone 模式下为首包固定的目标，否则为该包自带的目标。
    pub target: TargetAddr,
    /// 出站 socket 是否为复用（false 表示本次新建）。
    pub reused: bool,
}
