//! 工具层错误：只携带可回传给模型的安全信息，不含凭据。

/// 执行/抓取失败的统一错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecError {
    /// 该平台或配置不支持此 shell；值为稳定说明文本。
    #[error("不支持: {0}")]
    Unsupported(&'static str),
    /// 超时且已无可用输出。
    ///
    /// `run` 的正常返回也带 `timed_out` 标记；此变体只用于「连已有输出都拿不到」
    /// 的极端情况，保持与冻结 API 的一致性。
    #[error("执行超时")]
    Timeout,
    /// 非 2xx 响应。
    #[error("HTTP {code}: {url}")]
    HttpStatus {
        /// HTTP 状态码。
        code: u16,
        /// 重定向后的最终 URL。
        url: String,
    },
    /// URL 不合法，或 scheme 不在 http/https 之内。
    #[error("URL 不可用: {0}")]
    InvalidUrl(String),
    /// 进程或网络 IO 失败；文本不含凭据。
    #[error("IO 失败: {0}")]
    Io(String),
    /// JSON/HTML 解析失败。
    #[error("解析失败: {0}")]
    Json(String),
}

impl From<std::io::Error> for ExecError {
    fn from(e: std::io::Error) -> Self {
        ExecError::Io(e.to_string())
    }
}
