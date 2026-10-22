use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("handshake rejected: {0}")]
    Handshake(String),

    #[error("core protocol error: {0}")]
    Core(#[from] ss_core::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// 配置加载 / 校验失败。
    ///
    /// 消息**只带字段名与形状**，**不回显**口令 / 密钥 / PSK 原文，
    /// 也不回显可能含凭据的 TOML 源行。
    #[error("config error: {0}")]
    Config(#[from] ConfigError),
}

/// 配置错误。
///
/// 变体按「错在哪」分类，便于调用方 fail-closed 地区别处理；
/// 每个变体的消息都刻意**不含**凭据原文。
#[derive(Debug, Error)]
pub enum ConfigError {
    /// 必填项缺失。
    #[error("missing required field `{0}`")]
    Missing(&'static str),

    /// 字段取值非法（消息已脱敏）。
    #[error("invalid `{field}`: {reason}")]
    Invalid { field: &'static str, reason: String },

    /// 动作取值越界（客户端只允许 `direct` / `proxy`）。
    #[error("unsupported action `{value}` in `{field}` (allowed: direct, proxy)")]
    UnsupportedAction { field: &'static str, value: String },

    /// 规则名重复。
    #[error("duplicate rule name `{0}`")]
    DuplicateRule(String),

    /// 配置文件读不到。
    #[error("cannot read config file `{path}`: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },

    /// 配置文本格式错。`reason` **不含源行原文**（源行可能带凭据）。
    #[error("cannot parse config: {reason}")]
    Parse { reason: String },

    /// 配置文件格式错。`reason` **不含源行原文**（源行可能带凭据）。
    #[error("cannot parse config file `{path}`: {reason}")]
    ParseFile { path: String, reason: String },
}

impl Error {
    /// 构造配置错误。
    ///
    /// 历史调用点（`policy.rs`）以自由文本构造错误；该入口把自由文本收进
    /// [`ConfigError::Invalid`]，保证错误类型仍然可判别、且不回显凭据。
    #[must_use]
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(ConfigError::Invalid {
            field: "config",
            reason: message.into(),
        })
    }
}

pub type Result<T> = std::result::Result<T, Error>;
