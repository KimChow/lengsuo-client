//! **扩展 ID 严格值校验**与本扩展的固定属性（契约 §5.0）。
//!
//! # 与 [`crate::origin::parse_extension_id`] 的分工
//!
//! | 层 | 做什么 | 模块 |
//! |---|---|---|
//! | 格式 | 恰好 32 字符、落在字母表 `a`–`p` | [`crate::origin`]（W3b-1） |
//! | 值 | **等于** `ejlmmjamfpkoopjachjhcbdjlddknhok` | 本模块 |
//!
//! ⛔ **格式校验不能代替值校验**：`fjlmmjamfpkoopjachjhcbdjlddknhok` 格式完全合法，
//! 但不是我们的扩展。反之值比较也**不**先跑格式校验 —— 值不等就是
//! [`NotOurExtension`]，与 ID 长短、字符集无关，错误变体因此可区分。
//!
//! # 大小写
//!
//! Chromium 的 `crx_file::id_util::IdIsValid` 先 `ToLowerASCII` 再比，产出的 ID
//! 恒为小写；本模块照此**大小写不敏感**比较（见 [`strict_eq`]）。
//!
//! # 本扩展的属性（契约 §5.0）
//!
//! - `EXTENSION_ID`：`ejlmmjamfpkoopjachjhcbdjlddknhok`；
//! - `EXTENSION_ORIGIN`：`chrome-extension://<ID>/`（Chromium 的规范形状，带尾斜杠）。
//!
//! ⛔ 本模块**不改 ID 值、不改派生算法**（`SHA256(公钥 DER)` 前 16 字节 → hex →
//! 每位映射 `'a'+值`）。`tests/vectors/native-host-io-v1.json` 的
//! `derived_bytes_hex` 把它钉住。

use crate::error::{IdFormatError, OriginError};
use crate::origin::parse_extension_id;
use crate::origin::EXTENSION_ID_LEN;

/// 本扩展（credential）的扩展 ID（契约 §5.0，32 字符 `a`–`p`）。
pub const EXTENSION_ID: &str = "ejlmmjamfpkoopjachjhcbdjlddknhok";

/// 本扩展的 origin：`chrome-extension://ejlmmjamfpkoopjachjhcbdjlddknhok/`
/// （Chromium 传给宿主进程 `argv[1]` 的规范形状，带尾斜杠）。
pub const EXTENSION_ORIGIN: &str = "chrome-extension://ejlmmjamfpkoopjachjhcbdjlddknhok/";

/// 严格值比较：`id` 是否**就是**本扩展（大小写不敏感）。
///
/// ⛔ 只比**值**：返回 `false` 不代表格式合法与否，调用方不要拿它当格式校验。
#[must_use]
pub fn strict_eq(id: &str) -> bool {
    id.eq_ignore_ascii_case(EXTENSION_ID)
}

/// 解析 origin 并做**严格值校验**：返回扩展 ID（保持原大小写）。
///
/// 顺序：先走 [`parse_extension_id`] 的形状 + 格式校验，再做值比较。
/// 两步分开 ⇒ 调用方能从错误变体区分「形状/格式坏」与「格式对但不是我们」。
///
/// # Errors
/// - 形状不对 ⇒ [`OriginError::NotExtensionOrigin`]。
/// - 格式不对（长度 / 字母表）⇒ [`OriginError::InvalidExtensionId`]。
/// - 格式合法但值不等于 [`EXTENSION_ID`] ⇒ [`OriginError::NotOurExtension`]。
pub fn require_our_extension(origin: &str) -> Result<&str, OriginError> {
    let id = parse_extension_id(origin)?;
    if !strict_eq(id) {
        return Err(OriginError::NotOurExtension {
            got: id.to_owned(),
            expected: EXTENSION_ID,
        });
    }
    Ok(id)
}

/// 校验一个**裸扩展 ID**（不是 origin）：格式 + 严格值。
///
/// 与 [`require_our_extension`] 的区别：这里**不做**尾斜杠剥离，
/// 所以 `ejlmmjamfpkoopjachjhcbdjlddknhok/` 会因越界字符 `/` 被拒。
///
/// # Errors
/// - 长度不是 32 或含 `a`–`p` 之外的字符 ⇒ [`OriginError::InvalidExtensionId`]。
/// - 格式合法但值不等于 [`EXTENSION_ID`] ⇒ [`OriginError::NotOurExtension`]。
pub fn require_our_id(id: &str) -> Result<(), OriginError> {
    for ch in id.chars() {
        if !matches!(ch, 'a'..='p' | 'A'..='P') {
            return Err(OriginError::InvalidExtensionId {
                id: id.to_owned(),
                reason: IdFormatError::Char { char: ch },
            });
        }
    }
    if id.len() != EXTENSION_ID_LEN {
        return Err(OriginError::InvalidExtensionId {
            id: id.to_owned(),
            reason: IdFormatError::Length { actual: id.len() },
        });
    }
    if !strict_eq(id) {
        return Err(OriginError::NotOurExtension {
            got: id.to_owned(),
            expected: EXTENSION_ID,
        });
    }
    Ok(())
}
