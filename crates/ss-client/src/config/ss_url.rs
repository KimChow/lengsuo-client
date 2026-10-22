//! `ss://` URL 的解析与校验。
//!
//! 形式：`ss://<method>:<password>@<host>:<port>[#<remark>]`。
//!
//! - 口令里可以出现 `:` 与 `/`（口令与 `@` 之间用**最后一个** `@` 切分）；
//! - `#` 之后是备注，忽略；
//! - 加密名必须是 `ss_core` 支持的套件名（`CipherSuite::from_name`，
//!   大小写敏感），否则**加载期**就拒绝 —— 免得连不上时才发现用错了加密名。
//!
//! 错误消息**只说形状**，**不回显口令**（fail-closed 且不泄漏）。

use ss_core::crypto::CipherSuite;

use crate::error::{ConfigError, Error, Result};

/// `ss://` URL 的最小结构。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SsUrl<'a> {
    /// 加密套件名。
    pub method: &'a str,
    /// 出口服务器地址（域名或 IP，IPv6 带方括号）。
    pub host: &'a str,
    /// 出口服务器端口。
    pub port: u16,
}

/// 解析并校验 `ss://` URL。
pub(crate) fn parse_ss_url(raw: &str) -> Result<SsUrl<'_>> {
    let trimmed = raw.trim();
    let Some(rest) = trimmed.strip_prefix("ss://") else {
        return Err(invalid("outbound.ss_url", "must start with `ss://`"));
    };
    // 备注（`#` 之后）不参与解析。
    let rest = rest.split('#').next().unwrap_or("");
    let Some((method, tail)) = rest.split_once(':') else {
        return Err(invalid(
            "outbound.ss_url",
            "must be `ss://<method>:<password>@<host>:<port>`",
        ));
    };
    if method.is_empty() {
        return Err(invalid(
            "outbound.ss_url",
            "encryption method must not be empty",
        ));
    }
    if CipherSuite::from_name(method).is_none() {
        return Err(invalid(
            "outbound.ss_url",
            "unsupported encryption method for this client",
        ));
    }
    // 口令里可能有裸 `@`：用**最后一个** `@` 切分。
    let Some((secret, host_part)) = tail.rsplit_once('@') else {
        return Err(invalid("outbound.ss_url", "missing credentials"));
    };
    if secret.is_empty() {
        return Err(invalid("outbound.ss_url", "password must not be empty"));
    }
    let Some((host, port_text)) = host_part.rsplit_once(':') else {
        return Err(invalid("outbound.ss_url", "missing port"));
    };
    if host.is_empty() {
        return Err(invalid("outbound.ss_url", "host must not be empty"));
    }
    let port: u16 = port_text
        .parse()
        .map_err(|_| invalid("outbound.ss_url", "port must be an integer in 1..=65535"))?;
    if port == 0 {
        return Err(invalid(
            "outbound.ss_url",
            "port must be an integer in 1..=65535",
        ));
    }
    Ok(SsUrl { method, host, port })
}

/// 校验 `ss://` URL（只判形状，不回显口令）。
pub(crate) fn validate_ss_url(raw: &str) -> Result<()> {
    parse_ss_url(raw).map(|_| ())
}

/// 形状错误：只说形状，不回显取值（取值可能是口令）。
fn invalid(field: &'static str, reason: &str) -> Error {
    ConfigError::Invalid {
        field,
        reason: reason.to_owned(),
    }
    .into()
}
