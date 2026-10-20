//! 启动一次浏览器所需的三个**身份类**值：环境、代次、探测预算。
//!
//! 这三者都不是「随便一个数字」：
//! - [`EnvironmentId`] 要能当**目录名**用（每个环境一个用户数据目录）；
//! - [`Generation`] 必须是**正数**且单调（与 lifecycle 的 `RunGeneration` 语义一致）；
//! - [`ProbeBudget`] 必须是**有限**的（起不来时必须明确失败，不能无限等）。

use crate::error::LaunchError;

/// 环境身份：ASCII 标识符，形状与 `lengsuo-browser-profile` 的
/// `environment_id` 一致（字母数字、`-`、`_`，最长 64）。
///
/// 之所以不用 `lengsuo-environment` 的 `EnvironmentId(u64)`：本 crate 要把
/// 身份**写进用户数据目录名**，需要一个人类可读且可校验的串。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EnvironmentId(String);

impl EnvironmentId {
    /// 最长长度，与 `lengsuo-browser-profile` 的 `MAX_IDENTIFIER_LEN` 对齐。
    pub const MAX_LEN: usize = 64;

    /// 构造环境身份；形状非法即拒绝。
    pub fn new(value: impl Into<String>) -> Result<Self, LaunchError> {
        let value = value.into();
        if value.is_empty() {
            return Err(LaunchError::InvalidEnvironment("环境身份为空"));
        }
        if value.chars().count() > Self::MAX_LEN {
            return Err(LaunchError::InvalidEnvironment("环境身份过长"));
        }
        if value.contains("..") || value.contains(['/', '\\', '\0']) {
            return Err(LaunchError::InvalidEnvironment("环境身份含路径片段"));
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(LaunchError::InvalidEnvironment("环境身份含非法字符"));
        }
        Ok(Self(value))
    }

    /// 身份字符串。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 代次：与 `lengsuo-browser-lifecycle` 的 `RunGeneration` 语义一致
/// （单调递增、不可复用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(u64);

impl Generation {
    /// 构造代次。**0 不是合法代次**（与 state crate 的 `generation > 0` 一致）。
    pub fn new(value: u64) -> Result<Self, LaunchError> {
        if value == 0 {
            return Err(LaunchError::Argument("代次必须为正"));
        }
        Ok(Self(value))
    }

    /// 代次数值。
    #[must_use]
    pub fn value(self) -> u64 {
        self.0
    }
}

/// 就绪探测的总预算（毫秒）。
///
/// 探测**必须有**总上限：浏览器起不来时必须明确失败并回收进程，
/// 不得无限等待。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeBudget {
    total_ms: u64,
}

impl ProbeBudget {
    /// 构造预算；0 或超长即拒绝。
    pub fn new(total_ms: u64) -> Result<Self, LaunchError> {
        if total_ms == 0 {
            return Err(LaunchError::Argument("探测预算必须为正"));
        }
        if total_ms > MAX_PROBE_BUDGET_MS {
            return Err(LaunchError::Argument("探测预算超出上限"));
        }
        Ok(Self { total_ms })
    }

    /// 总预算（毫秒）。
    #[must_use]
    pub fn total_ms(self) -> u64 {
        self.total_ms
    }
}

/// 探测预算上限：一天。防止误配导致「永远等」。
pub const MAX_PROBE_BUDGET_MS: u64 = 24 * 60 * 60 * 1000;

#[cfg(test)]
mod tests {
    use super::{EnvironmentId, Generation, ProbeBudget, MAX_PROBE_BUDGET_MS};
    use crate::error::LaunchError;

    #[test]
    fn an_unsafe_environment_id_is_refused() {
        assert!(EnvironmentId::new("").is_err());
        assert!(EnvironmentId::new("a/b").is_err());
        assert!(EnvironmentId::new("a..b").is_err());
        assert!(EnvironmentId::new("a b").is_err());
        assert!(EnvironmentId::new("x".repeat(65)).is_err());
        assert!(EnvironmentId::new("env_a-1").is_ok());
        assert_eq!(EnvironmentId::new("env-a").unwrap().as_str(), "env-a");
    }

    #[test]
    fn a_zero_generation_is_refused() {
        assert_eq!(
            Generation::new(0).unwrap_err(),
            LaunchError::Argument("代次必须为正")
        );
        assert_eq!(Generation::new(7).unwrap().value(), 7);
    }

    #[test]
    fn a_zero_probe_budget_is_refused() {
        assert_eq!(
            ProbeBudget::new(0).unwrap_err(),
            LaunchError::Argument("探测预算必须为正")
        );
        assert!(ProbeBudget::new(MAX_PROBE_BUDGET_MS + 1).is_err());
        assert_eq!(ProbeBudget::new(1_500).unwrap().total_ms(), 1_500);
    }
}
