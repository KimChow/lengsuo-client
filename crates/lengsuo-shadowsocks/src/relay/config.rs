//! 中继服务的**配置形态**（`RelayConfig` / `RelayConfigParts`）。
//!
//! 口令以 `Arc<Vec<u8>>` 共享，避免每个连接复制一份；**从不落日志**。
//! 必填字段用构造器收口并在 [`RelayConfig::validate`] 里检查，可选字段默认关闭。

use std::sync::Arc;
use std::time::Duration;

use ss_core::crypto::CipherSuite;

use super::Error;
use crate::salt_store::SaltStateConfig;

/// 中继服务配置。口令以 `Arc<Vec<u8>>` 共享，避免每个连接复制一份；从不落日志。
pub struct RelayConfig {
    pub suite: CipherSuite,
    password: Arc<Vec<u8>>,
    /// 每次握手与每个方向的 I/O 截止时间（必须大于零）。
    pub idle_timeout: Duration,
    /// 单方向最大载荷字节数（同时充当接口契约与测试断言值）。
    pub max_payload: usize,
    /// 入站 salt 重放窗口：`None` 表示关闭（与参考基线行为一致，见 `crate::replay`）。
    pub replay: Option<(usize, Duration)>,
    /// 入站 salt 记忆池的**持久化状态文件**（参考形态：入站配置里带一个路径）。
    ///
    /// `None` ⇒ **保持现有内存行为不变**（向后兼容：不落盘、不回写）。
    /// `Some(path)` ⇒ 启动时从该文件加载窗口、运行时记录、收尾时回写。
    pub salt_state: Option<SaltStateConfig>,
}
/// 必需字段用构造器收口并在 [`RelayConfig::validate`] 里检查，可选字段默认关闭。
#[derive(Clone, Copy)]
pub struct RelayConfigParts {
    pub suite: CipherSuite,
    pub idle_timeout: Duration,
    pub replay: Option<(usize, Duration)>,
}
impl RelayConfig {
    /// 单方向载荷上限（与参考 `buf.Size` 一致的 64 KiB 量级；仅作接口契约）。
    pub const DEFAULT_MAX_PAYLOAD: usize = 65_536;

    #[must_use]
    pub fn new(parts: RelayConfigParts, password: &[u8]) -> Self {
        Self {
            suite: parts.suite,
            password: Arc::new(password.to_vec()),
            idle_timeout: parts.idle_timeout,
            max_payload: Self::DEFAULT_MAX_PAYLOAD,
            replay: parts.replay,
            salt_state: None,
        }
    }

    /// 挂上入站 salt 记忆池的持久化状态文件（不挂 ⇒ 行为与现状一致）。
    #[must_use]
    pub fn with_salt_state(mut self, state: SaltStateConfig) -> Self {
        self.salt_state = Some(state);
        self
    }

    /// 口令的借用视图（**不复制**；调用方不得落日志）。
    pub(super) fn password(&self) -> &[u8] {
        self.password.as_slice()
    }

    /// 空口令、零截止时间与零容量窗口都在这里拒绝（fail-closed）。
    pub fn validate(&self) -> Result<(), Error> {
        if self.password.is_empty() {
            return Err(Error::Config("口令为空".into()));
        }
        if self.idle_timeout.is_zero() {
            return Err(Error::Config("截止时间必须大于零".into()));
        }
        if self.max_payload == 0 {
            return Err(Error::Config("载荷上限必须大于零".into()));
        }
        match self.replay {
            Some((0, _)) => Err(Error::Config("重放窗口容量必须大于零".into())),
            Some((_, window)) if window.is_zero() => {
                Err(Error::Config("重放窗口时间窗必须大于零".into()))
            }
            _ => Ok(()),
        }
    }
}
