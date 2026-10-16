//! 规格 §1 数据模型分片：`window`。
//!
//! 统一从 [`crate::model`] 再导出，字段名/数值契约见本目录各文件。
//! 生效时间窗 `active_range`（规格 §1、§2.2）。

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

/// 生效时间窗（闭区间，毫秒时间戳）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActiveRange {
    /// 起始（含）。
    pub start_ms: u64,
    /// 结束（含）。
    pub end_ms: u64,
}

impl ActiveRange {
    /// 构造时间窗；反向区间（`end_ms < start_ms`）是配置错误，直接拒绝。
    pub fn checked_new(start_ms: u64, end_ms: u64) -> Result<Self, ActiveRangeError> {
        if end_ms < start_ms {
            return Err(ActiveRangeError::Inverted { start_ms, end_ms });
        }
        Ok(Self { start_ms, end_ms })
    }

    /// `now_ms` 是否落在闭区间内。
    #[must_use]
    pub const fn contains(&self, now_ms: u64) -> bool {
        now_ms >= self.start_ms && now_ms <= self.end_ms
    }
}

impl Serialize for ActiveRange {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            start_ms: u64,
            end_ms: u64,
        }
        Wire {
            start_ms: self.start_ms,
            end_ms: self.end_ms,
        }
        .serialize(serializer)
    }
}

/// 反序列化时同步校验区间方向：`end_ms < start_ms` 直接报错，
/// 不留到运行期被解释成「永不生效」或「总是生效」。
impl<'de> Deserialize<'de> for ActiveRange {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            start_ms: u64,
            end_ms: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::checked_new(wire.start_ms, wire.end_ms).map_err(de::Error::custom)
    }
}

/// 时间窗构造错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ActiveRangeError {
    /// 结束早于起始。
    #[error("active_range 区间反向：start_ms={start_ms} > end_ms={end_ms}")]
    Inverted {
        /// 起始毫秒。
        start_ms: u64,
        /// 结束毫秒。
        end_ms: u64,
    },
}
