//! 明文凭据缓冲：内部 `Zeroizing`，离开作用域自动清零；展示面恒为掩码。

use std::fmt;
use std::ops::Deref;

use zeroize::Zeroizing;

/// 明文凭据（口令、token、Cookie 等）字节缓冲。
///
/// 约定：
/// - 只允许短生命周期持有；`put`/`get` 返回后尽快 drop 以触发清零。
/// - `Debug`/`Display` 恒输出固定掩码，不打印字节，也不暴露长度。
/// - 禁止把内部字节以 `&'static`、克隆副本或格式化参数形式写入日志与错误信息。
pub struct Plaintext(Zeroizing<Vec<u8>>);

impl Plaintext {
    /// 由字节构造（缓冲区随即受 `Zeroizing` 保护）。
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(bytes.into()))
    }

    /// 由已受 `Zeroizing` 保护的缓冲构造（不再产生额外副本）。
    pub(crate) fn from_zeroizing(inner: Zeroizing<Vec<u8>>) -> Self {
        Self(inner)
    }

    /// 由 UTF-8 字符串构造（与 [`Plaintext::to_utf8`] 对称；刻意不叫 `from_str`，
    /// 以免与 `std::str::FromStr::from_str` 混淆——本构造永不解析、永不失败）。
    pub fn from_utf8_str(value: &str) -> Self {
        Self::new(value.as_bytes().to_vec())
    }

    /// 借用明文字节。
    ///
    /// 敏感访问器：调用方不得把这些字节写入日志、错误信息或明文元数据；
    /// 仅用于加密前输入或协议组装。
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// 取回受 `Zeroizing` 保护的缓冲区所有权。
    pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.0
    }

    /// 尝试按 UTF-8 解码。
    ///
    /// 敏感返回：调用方不得把返回值写入日志或错误信息。
    pub fn to_utf8(&self) -> Option<String> {
        std::str::from_utf8(self.0.as_slice())
            .map(ToString::to_string)
            .ok()
    }

    /// 与另一缓冲逐字节比较（用于口令自检等场景）。
    pub fn eq_plaintext(&self, other: &Plaintext) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }

    /// 是否空缓冲。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 字节数。
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Clone for Plaintext {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Deref for Plaintext {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl From<&str> for Plaintext {
    fn from(value: &str) -> Self {
        Self::from_utf8_str(value)
    }
}

impl From<String> for Plaintext {
    fn from(value: String) -> Self {
        Self::new(value.into_bytes())
    }
}

impl From<Vec<u8>> for Plaintext {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Plaintext(<redacted>)")
    }
}

impl fmt::Display for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}
