//! 存储错误：所有变体只携带非敏感元信息（静态结构标签、版本号、IO 分类）。
//!
//! 硬规则：错误的 `Display`、`Debug`、`source()` 都不得包含明文、口令、密钥、派生密钥、
//! nonce、salt、密文字节或作用域目标 id。构造时只传入 [`crate::RefId`] 之类的脱敏类型。
//! [`StoreError::Io`] 特意**不**接入 `source()`，并自行实现 `Debug`：系统 IO 错误文本
//! 含存储文件完整路径（可能带用户名），属于用户数据，不得随诊断输出外流，
//! 只保留 [`std::io::ErrorKind`] 供调用点分支（例如“文件不存在 → 空库”）。

use std::fmt;

use crate::reference::REDACTED;

/// 存储层统一错误。
///
/// 不实现 `Clone`/`PartialEq`：`Io` 变体持有 `std::io::Error`（两者皆不可），
/// 而错误比较应在上层用 [`StoreError::code`] 或 `matches!` 针对变体进行。
#[derive(thiserror::Error)]
pub enum StoreError {
    /// 引用不存在。
    #[error("凭据引用不存在")]
    NotFound,
    /// 引用已过期（达到 `expires_at_ms` 即过期，不宽限）。
    #[error("凭据引用已过期")]
    Expired,
    /// 引用作用域与记录（或请求）作用域不一致：跨作用域访问被拒，不返回明文。
    #[error("凭据作用域不匹配，拒绝跨作用域访问")]
    ScopeMismatch,
    /// 引用非法（例如作用域目标为空），拒绝读写。
    #[error("凭据引用非法，已拒绝")]
    InvalidReference,
    /// 口令校验失败（verifier 认证不通过）。只说明结果，不含任何密钥材料。
    #[error("口令错误或密文完整性校验失败")]
    WrongPassphrase,
    /// 记录认证失败：密文或其绑定元数据被篡改，或记录被搬移到其它文件。
    #[error("密文认证失败：记录被篡改或不属于本存储")]
    RecordAuthentication,
    /// 容器结构非法：magic 不符、截断、长度域不自洽、尾部多余字节。
    /// 携带的是静态结构标签，不回显任何文件内容。
    #[error("凭据存储文件结构非法（{0}）")]
    MalformedContainer(&'static str),
    /// 存储 schema 版本不识别：fail-closed 拒绝读取，不尝试解密。
    #[error("不识别的存储 schema 版本: found={found} expected={expected}")]
    UnsupportedVersion {
        /// 文件中声明的 schema 版本。
        found: u32,
        /// 本实现支持的 schema 版本。
        expected: u32,
    },
    /// 底层 IO 错误。字段不进 `Display`/`source()`，`Debug` 只呈现分类，
    /// 但保留原错误供 [`StoreError::io_kind`] 判定（调用点据此区分“不存在”与“读不了”）。
    #[error("凭据存储文件读写失败")]
    Io(std::io::Error),
}

impl StoreError {
    /// 容器结构非法的构造别名（保持调用点可读）。
    pub const fn malformed(what: &'static str) -> Self {
        StoreError::MalformedContainer(what)
    }

    /// 稳定短码，便于上层映射错误码（不含敏感信息）。
    pub const fn code(&self) -> &'static str {
        match self {
            StoreError::NotFound => "not_found",
            StoreError::Expired => "expired",
            StoreError::ScopeMismatch => "scope_mismatch",
            StoreError::InvalidReference => "invalid_reference",
            StoreError::WrongPassphrase => "wrong_passphrase",
            StoreError::RecordAuthentication => "record_authentication",
            StoreError::MalformedContainer(_) => "malformed_container",
            StoreError::UnsupportedVersion { .. } => "unsupported_version",
            StoreError::Io(_) => "io",
        }
    }

    /// IO 分类；非 IO 变体返回 `None`。调用点据此区分
    /// [`std::io::ErrorKind::NotFound`]（文件不存在 → 空库）与其它 IO 失败（必须上抛）。
    pub fn io_kind(&self) -> Option<std::io::ErrorKind> {
        match self {
            StoreError::Io(err) => Some(err.kind()),
            _ => None,
        }
    }
}

impl From<std::io::Error> for StoreError {
    fn from(value: std::io::Error) -> Self {
        StoreError::Io(value)
    }
}

/// 手工 `Debug`：与 `Display` 同样脱敏，`Io` 只打印分类而不透出路径/系统消息。
impl fmt::Debug for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::NotFound => f.write_str("NotFound"),
            StoreError::Expired => f.write_str("Expired"),
            StoreError::ScopeMismatch => f.write_str("ScopeMismatch"),
            StoreError::InvalidReference => f.write_str("InvalidReference"),
            StoreError::WrongPassphrase => f.write_str("WrongPassphrase"),
            StoreError::RecordAuthentication => f.write_str("RecordAuthentication"),
            StoreError::MalformedContainer(what) => write!(f, "MalformedContainer({what:?})"),
            StoreError::UnsupportedVersion { found, expected } => write!(
                f,
                "UnsupportedVersion {{ found: {found}, expected: {expected} }}"
            ),
            StoreError::Io(err) => write!(f, "Io({REDACTED}, kind={:?})", err.kind()),
        }
    }
}
