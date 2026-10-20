//! 凭据材料的安全载体。
//!
//! 代理口令在本 crate 里只以 [`Secret`] 的形式存在：
//! - `Debug` / `Display` **永远**只打印 `***`，日志与 panic 信息因此不可能
//!   带出口令；
//! - 只有显式调用 [`Secret::expose`] 才能拿到明文，调用点因此在代码里一目了然；
//! - `PartialEq` 按明文比较（用于测试断言），但 `Clone` 会被刻意限制在 crate 内。

use std::fmt;

/// 一个不得出现在日志、命令行或错误消息里的字符串。
///
/// 密码、令牌、口令一律用本类型承载。
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// 包装一段明文。
    ///
    /// 空串不是合法凭据，但构造本身不拒绝：校验发生在使用点（见
    /// [`crate::proxy::ProxyCredential::new`]），以便错误分类更准确。
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// 明文内容。**调用点必须谨慎**：结果不得写进命令行、日志或错误消息。
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// 是否为空串。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 长度（字节），用于「凭据形状」校验而不暴露内容。
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn debug_and_display_never_leak_the_value() {
        let secret = Secret::new("hunter2");
        assert_eq!(format!("{secret:?}"), "Secret(***)");
        assert_eq!(format!("{secret}"), "***");
        assert!(!format!("{secret:?}{secret}").contains("hunter2"));
    }

    #[test]
    fn expose_returns_the_plain_value() {
        assert_eq!(Secret::new("hunter2").expose(), "hunter2");
    }

    #[test]
    fn emptiness_is_reported_without_exposing() {
        assert!(Secret::new("").is_empty());
        assert!(!Secret::new("x").is_empty());
        assert_eq!(Secret::new("abcd").len(), 4);
    }
}
