//! 每个环境一套的代理出口配置。
//!
//! 浏览器侧的代理约定是 Chromium 公开的命令行约定：
//! `--proxy-server="http=host:port;https=host:port;socks5=socks5://host:port"`
//! 与 `--proxy-bypass-list="..."`。参考实现缺失时以此为准，并在
//! `docs/browser-launch-status.md` 写明依据。
//!
//! **凭据不进命令行**：`ProxyConfig` 渲染出来的 `--proxy-server` 值里
//! **只有端点，没有 userinfo**。上游口令由 [`ProxyCredential`] 承载，只能经
//! 环境变量或凭据文件交给**代理侧车**（见 [`crate::credential`]）。

use crate::error::ProxyError;
use crate::secret::Secret;

/// 代理协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyScheme {
    /// HTTP 代理（同时也是 Chromium 的默认 scheme）。
    Http,
    /// HTTPS 代理（到代理的连接本身走 TLS）。
    Https,
    /// SOCKS4 代理。
    Socks4,
    /// SOCKS5 代理。
    Socks5,
}

impl ProxyScheme {
    /// Chromium `--proxy-server` 的键名。
    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Socks4 => "socks4",
            Self::Socks5 => "socks5",
        }
    }

    /// 该 scheme 在 `--proxy-server` 里是否需要 `scheme://` 前缀。
    ///
    /// Chromium 只对 SOCKS 要求显式前缀；HTTP/HTTPS 走裸 `host:port`。
    #[must_use]
    pub fn needs_uri_prefix(self) -> bool {
        matches!(self, Self::Socks4 | Self::Socks5)
    }
}

/// 一个代理端点（**不含任何凭据**）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEndpoint {
    scheme: ProxyScheme,
    host: String,
    port: u16,
}

impl ProxyEndpoint {
    /// 构造端点；主机名非法或端口为 0 时拒绝。
    pub fn new(
        scheme: ProxyScheme,
        host: impl Into<String>,
        port: u16,
    ) -> Result<Self, ProxyError> {
        let host = host.into();
        if !is_valid_host(&host) {
            return Err(ProxyError::InvalidHost);
        }
        if port == 0 {
            return Err(ProxyError::InvalidPort);
        }
        Ok(Self { scheme, host, port })
    }

    /// 该端点的协议。
    #[must_use]
    pub fn scheme(&self) -> ProxyScheme {
        self.scheme
    }

    /// 主机名。
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// 端口。
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// 渲染成 `--proxy-server` 里该 scheme 的取值。
    #[must_use]
    pub fn render(&self) -> String {
        if self.scheme.needs_uri_prefix() {
            format!("{}://{}:{}", self.scheme.key(), self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// 上游代理的认证凭据。
///
/// **绝不**出现在命令行、日志或错误消息里；`Debug`/`Display` 恒为 `***`。
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyCredential {
    username: Secret,
    password: Secret,
}

impl ProxyCredential {
    /// 构造凭据；任一为空即拒绝（半截凭据会让代理返回 407 并被误判为网络故障）。
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, ProxyError> {
        let username = Secret::new(username.into());
        let password = Secret::new(password.into());
        if username.is_empty() || password.is_empty() {
            return Err(ProxyError::EmptyCredential);
        }
        Ok(Self { username, password })
    }

    /// 用户名（明文）。调用点必须谨慎。
    #[must_use]
    pub fn username(&self) -> &str {
        self.username.expose()
    }

    /// 口令（明文）。调用点必须谨慎。
    #[must_use]
    pub fn password(&self) -> &str {
        self.password.expose()
    }
}

impl std::fmt::Debug for ProxyCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProxyCredential(***)")
    }
}

/// 一个环境的代理出口配置。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProxyConfig {
    endpoints: Vec<ProxyEndpoint>,
    credential: Option<ProxyCredential>,
    bypass: Vec<String>,
}

impl ProxyConfig {
    /// 空配置（**没有端点**，渲染时必然失败 ⇒ 不会产出裸连）。
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// 追加一个端点；同一 scheme 重复即拒绝（后写覆盖先写会让出口不确定）。
    pub fn with_endpoint(
        mut self,
        scheme: ProxyScheme,
        host: impl Into<String>,
        port: u16,
    ) -> Result<Self, ProxyError> {
        let endpoint = ProxyEndpoint::new(scheme, host, port)?;
        if self.endpoints.iter().any(|e| e.scheme == scheme) {
            return Err(ProxyError::DuplicateScheme);
        }
        self.endpoints.push(endpoint);
        Ok(self)
    }

    /// 挂上上游认证凭据。
    pub fn with_credential(mut self, credential: ProxyCredential) -> Self {
        self.credential = Some(credential);
        self
    }

    /// 设置绕过列表（Chromium `--proxy-bypass-list`）。
    pub fn with_bypass<I, S>(mut self, entries: I) -> Result<Self, ProxyError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut list = Vec::new();
        for entry in entries {
            let entry = entry.into();
            if entry.is_empty() || entry.contains([';', '\n', '\r', ' ']) {
                return Err(ProxyError::InvalidBypass);
            }
            list.push(entry);
        }
        self.bypass = list;
        Ok(self)
    }

    /// 端点列表。
    #[must_use]
    pub fn endpoints(&self) -> &[ProxyEndpoint] {
        &self.endpoints
    }

    /// 上游凭据（若有）。
    #[must_use]
    pub fn credential(&self) -> Option<&ProxyCredential> {
        self.credential.as_ref()
    }

    /// 绕过列表。
    #[must_use]
    pub fn bypass(&self) -> &[String] {
        &self.bypass
    }

    /// 是否有端点。空配置**不允许**启动。
    #[must_use]
    pub fn has_endpoint(&self) -> bool {
        !self.endpoints.is_empty()
    }

    /// 渲染成 `--proxy-server` 的取值。
    ///
    /// 结果里**只有端点**：没有 userinfo、没有口令。
    pub fn chromium_server_value(&self) -> Result<String, ProxyError> {
        if self.endpoints.is_empty() {
            return Err(ProxyError::NoEndpoint);
        }
        let parts: Vec<String> = self
            .endpoints
            .iter()
            .map(|e| format!("{}={}", e.scheme().key(), e.render()))
            .collect();
        Ok(parts.join(";"))
    }

    /// 渲染成 `--proxy-bypass-list` 的取值；没有绕过项时返回 `None`。
    #[must_use]
    pub fn chromium_bypass_value(&self) -> Option<String> {
        if self.bypass.is_empty() {
            None
        } else {
            Some(self.bypass.join(";"))
        }
    }
}

/// 主机名形状：ASCII 字母数字、点、下划线、连字符，且不含 `@` `/` `:` 空白。
fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 255 {
        return false;
    }
    host.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::{ProxyConfig, ProxyCredential, ProxyScheme};
    use crate::error::ProxyError;

    fn config() -> ProxyConfig {
        ProxyConfig::empty()
            .with_endpoint(ProxyScheme::Http, "127.0.0.1", 8080)
            .expect("valid endpoint")
    }

    #[test]
    fn an_empty_config_has_no_endpoint_and_never_renders() {
        let empty = ProxyConfig::empty();
        assert!(!empty.has_endpoint());
        assert_eq!(empty.chromium_server_value(), Err(ProxyError::NoEndpoint));
    }

    #[test]
    fn a_single_http_endpoint_renders_as_a_chromium_scheme_mapping() {
        assert_eq!(
            config().chromium_server_value().unwrap(),
            "http=127.0.0.1:8080"
        );
    }

    #[test]
    fn socks_endpoints_carry_their_scheme_prefix() {
        let cfg = config()
            .with_endpoint(ProxyScheme::Socks5, "10.0.0.1", 1080)
            .unwrap()
            .with_endpoint(ProxyScheme::Https, "10.0.0.2", 8443)
            .unwrap();
        assert_eq!(
            cfg.chromium_server_value().unwrap(),
            "http=127.0.0.1:8080;socks5=socks5://10.0.0.1:1080;https=10.0.0.2:8443"
        );
    }

    #[test]
    fn a_duplicate_scheme_is_refused() {
        let err = config()
            .with_endpoint(ProxyScheme::Http, "127.0.0.2", 8081)
            .unwrap_err();
        assert_eq!(err, ProxyError::DuplicateScheme);
    }

    #[test]
    fn an_invalid_host_or_port_is_refused() {
        assert_eq!(
            ProxyConfig::empty()
                .with_endpoint(ProxyScheme::Http, "bad host", 8080)
                .unwrap_err(),
            ProxyError::InvalidHost
        );
        assert_eq!(
            ProxyConfig::empty()
                .with_endpoint(ProxyScheme::Http, "host", 0)
                .unwrap_err(),
            ProxyError::InvalidPort
        );
    }

    #[test]
    fn a_half_credential_is_refused() {
        assert_eq!(
            ProxyCredential::new("", "pw").unwrap_err(),
            ProxyError::EmptyCredential
        );
        assert_eq!(
            ProxyCredential::new("user", "").unwrap_err(),
            ProxyError::EmptyCredential
        );
    }

    #[test]
    fn the_rendered_value_never_contains_the_credential() {
        let credential = ProxyCredential::new("alice", "s3cr3t-pw").unwrap();
        let cfg = config().with_credential(credential);
        let rendered = cfg.chromium_server_value().unwrap();
        assert!(!rendered.contains("alice"));
        assert!(!rendered.contains("s3cr3t-pw"));
    }

    #[test]
    fn the_credential_debug_form_is_redacted() {
        let credential = ProxyCredential::new("alice", "s3cr3t-pw").unwrap();
        assert_eq!(format!("{credential:?}"), "ProxyCredential(***)");
    }

    #[test]
    fn a_bypass_entry_with_a_separator_is_refused() {
        assert_eq!(
            ProxyConfig::empty().with_bypass(vec!["a;b"]).unwrap_err(),
            ProxyError::InvalidBypass
        );
    }
}
