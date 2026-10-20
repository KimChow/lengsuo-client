//! salt 记忆池的**配置形态**（回写策略 / 记忆池配置 / 中继侧入站配置）。
//!
//! 参考形态对齐：固定参考（Xray v26.3.27 / `d2758a02`）把「持久化文件路径」放在
//! **入站配置**里；本文件对应 `SaltStoreConfig`（持有者视角）与 `SaltStateConfig`
//! （中继入站配置视角）。
//!
//! **不实现 `Debug` 的是带口令的两个配置**：`SaltStoreConfig` 与 `SaltStateConfig`
//! 都可能带上一代口令，调试输出会泄漏凭据。

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

/// 状态文件的回写策略。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlushPolicy {
    /// **间隔回写**：记录之后，距上次回写超过该间隔就立刻写盘（写盘频率有上界）。
    /// 连接收尾时也只在间隔已到的情况下写盘；服务停止时总是写。
    Interval(Duration),
    /// **收尾回写**：只在连接收尾与服务停止时写盘。写盘次数最少，但进程被
    /// 强杀时丢失的窗口最大（见 `docs/shadowsocks-status.md` 的偏离清单）。
    OnClose,
}

impl FlushPolicy {
    /// 该策略下，距上次回写 `elapsed` 之后是否应当立刻写盘。
    pub(crate) fn due(&self, elapsed: Option<Duration>) -> bool {
        match self {
            Self::Interval(interval) => elapsed.is_none_or(|spent| spent >= *interval),
            Self::OnClose => false,
        }
    }
}

/// salt 记忆池的运行时配置（参考形态：**入站配置里带一个持久化文件路径**）。
#[derive(Clone)]
pub struct SaltStoreConfig {
    /// 状态文件路径。父目录必须已存在（不自动创建），写权限由运维保证。
    pub path: PathBuf,
    /// 记忆池容量：最多记住多少个 salt（到顶后 FIFO 逐出最旧）。
    pub capacity: usize,
    /// 记忆池时间窗：一个 salt 被记住多久（过期后同 salt 再次出现不再被拒）。
    pub window: Duration,
    /// 回写策略（间隔回写 / 收尾回写）。
    pub flush_policy: FlushPolicy,
    /// 上一代口令（**可选**）：密钥轮换用。加载时同时接受当前口令与上一代口令
    /// 派生的 MAC 密钥；命中上一代即用当前密钥升级重写。
    pub previous_password: Option<Vec<u8>>,
}

impl SaltStoreConfig {
    /// 构造一份配置：容量与时间窗必填，回写策略默认「收尾回写」。
    pub fn new(path: impl Into<PathBuf>, capacity: usize, window: Duration) -> Self {
        Self {
            path: path.into(),
            capacity,
            window,
            flush_policy: FlushPolicy::OnClose,
            previous_password: None,
        }
    }

    /// 设置回写策略。
    #[must_use]
    pub fn with_flush_policy(mut self, policy: FlushPolicy) -> Self {
        self.flush_policy = policy;
        self
    }

    /// 设置上一代口令（密钥轮换）。
    #[must_use]
    pub fn with_previous_password(mut self, password: impl Into<Vec<u8>>) -> Self {
        self.previous_password = Some(password.into());
        self
    }
}

/// **不实现 `Debug`**：含上一代口令，调试输出会泄漏凭据。
impl fmt::Debug for SaltStoreConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SaltStoreConfig")
            .field("path", &self.path)
            .field("capacity", &self.capacity)
            .field("window", &self.window)
            .field("flush_policy", &self.flush_policy)
            .field(
                "previous_password",
                &self.previous_password.as_ref().map(|_| "<已设置>"),
            )
            .finish()
    }
}

/// salt 记忆池的**入站配置**形态（`Path` / `Window` 形态对齐参考的入站配置）。
///
/// 这是中继侧的一层薄封装：真正的持有者是 [`SaltStore`]。
#[derive(Clone)]
pub struct SaltStateConfig {
    /// 状态文件路径（父目录必须已存在；权限要求见 `docs/shadowsocks-status.md`）。
    pub path: PathBuf,
    /// 记忆池时间窗（`None` ⇒ 由中继的重放窗口配置决定）。
    pub window: Option<Duration>,
    /// 回写策略（间隔回写 / 收尾回写）。
    pub flush_policy: FlushPolicy,
    /// 上一代口令（密钥轮换用）。
    pub previous_password: Option<Vec<u8>>,
}

impl SaltStateConfig {
    /// 只指定状态文件路径（窗口与回写策略由中继配置补齐）。
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            window: None,
            flush_policy: FlushPolicy::OnClose,
            previous_password: None,
        }
    }

    /// 覆盖记忆池时间窗。
    #[must_use]
    pub fn with_window(mut self, window: Duration) -> Self {
        self.window = Some(window);
        self
    }

    /// 设置回写策略。
    #[must_use]
    pub fn with_flush_policy(mut self, policy: FlushPolicy) -> Self {
        self.flush_policy = policy;
        self
    }

    /// 设置上一代口令（密钥轮换）。
    #[must_use]
    pub fn with_previous_password(mut self, password: impl Into<Vec<u8>>) -> Self {
        self.previous_password = Some(password.into());
        self
    }
}

/// **不实现 `Debug`**：含上一代口令，调试输出会泄漏凭据。
impl fmt::Debug for SaltStateConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SaltStateConfig")
            .field("path", &self.path)
            .field("window", &self.window)
            .field("flush_policy", &self.flush_policy)
            .field(
                "previous_password",
                &self.previous_password.as_ref().map(|_| "<已设置>"),
            )
            .finish()
    }
}

/// 由中继的「重放窗口（容量, 时间窗）」与 [`SaltStateConfig`] 拼出记忆池配置。
///
/// 容量与时间窗以中继的重放窗口为准（未配置重放窗口时用保守默认值：容量 4096、
/// 时间窗 60 秒）；`SaltStateConfig::window` 可单独覆盖时间窗。
pub(crate) fn store_config(
    replay: Option<(usize, Duration)>,
    state: &SaltStateConfig,
) -> SaltStoreConfig {
    let (capacity, default_window) = replay.unwrap_or((4096, Duration::from_secs(60)));
    let window = state.window.unwrap_or(default_window);
    let mut store = SaltStoreConfig::new(state.path.clone(), capacity, window)
        .with_flush_policy(state.flush_policy);
    if let Some(previous) = &state.previous_password {
        store = store.with_previous_password(previous.clone());
    }
    store
}
