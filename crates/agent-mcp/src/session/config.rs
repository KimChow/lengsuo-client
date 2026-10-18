//! 会话参数。

use std::time::Duration;

use crate::codec::Framing;

use super::MIN_NOTIFY_CAPACITY;

/// 会话参数。
#[derive(Debug, Clone)]
pub(crate) struct SessionConfig {
    pub(crate) framing: Framing,
    pub(crate) max_frame_bytes: usize,
    pub(crate) notify_capacity: usize,
    pub(crate) default_timeout: Duration,
}

impl SessionConfig {
    /// 每请求默认超时（30s）。
    pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

    pub(crate) fn new(
        framing: Framing,
        max_frame_bytes: usize,
        notify_capacity: usize,
        default_timeout: Duration,
    ) -> Self {
        Self {
            framing,
            max_frame_bytes,
            notify_capacity: notify_capacity.max(MIN_NOTIFY_CAPACITY),
            default_timeout,
        }
    }
}
