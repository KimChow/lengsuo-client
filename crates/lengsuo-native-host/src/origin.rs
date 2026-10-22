//! 来源（origin）解析：从 Chromium 传给宿主进程的 `argv[1]` 里取出扩展 ID。
//!
//! # Chromium 怎么把来源交给宿主
//!
//! Chromium 启动宿主进程时，**第一个位置参数就是来源 origin**：
//! `launch_context.cc` 里 `command_line.AppendArg(origin.spec())`，
//! 且注释写明「origin 必须是第一个参数」。
//!
//! origin 由 `native_message_process_host.cc` 拼成：
//! `GURL(std::string(kExtensionScheme) + "://" + source_extension_id_)`
//! ⇒ 形状是 `chrome-extension://<扩展ID>`（规范化后带尾斜杠，见下）。
//!
//! # 本模块只做「解析 + 格式校验」
//!
//! ⛔ **不校验「这个 ID 是不是我们的」**：准入是 Chromium 拿宿主清单里的
//! `allowed_origins` 判的（`native_messaging_host_manifest.cc`），
//! 不该由宿主进程重复判断。
//!
//! ⛔ **不硬编码任何扩展 ID**。
//!
//! # 扩展 ID 的格式
//!
//! 照 Chromium 的 `crx_file::id_util::IdIsValid`：恰好 32 个字符，
//! 落在字母表 `a`–`p`。该检查**大小写不敏感**（Chromium 先
//! `ToLowerASCII` 再比），本卡照此语义实现。
//!
//! # 形状
//!
//! Chromium 实际传过来的规范形式是 **`chrome-extension://<扩展ID>/`（带尾斜杠）**：
//! - `native_message_process_host.cc` 用
//!   `GURL(std::string(kExtensionScheme) + "://" + source_extension_id_)` 造 origin；
//! - `chrome-extension` 登记在 `kChromeStandardURLSchemes`
//!   （`chrome/common/chrome_content_client.cc`，`SCHEME_WITH_HOST`）
//!   ⇒ 是**标准 scheme**；
//! - 标准 scheme 的空路径在 `url/url_canon_path.cc` `DoPath` 里会被补成 `/`
//!   （"canonical path is a slash for special URLs"）⇒ `spec()` 带尾斜杠。
//!
//! 因此本模块接受两种形式：`chrome-extension://<扩展ID>` 与
//! `chrome-extension://<扩展ID>/`。不带尾斜杠的那种是**防御性接受**
//! （万一日后 `chrome-extension` 不再被登记为标准 scheme，空路径就会保持为空）。
//! 其余任何形状（路径 / 查询 / 片段 / 空主机 / 端口 / 用户信息）一律拒绝。

use crate::error::{IdFormatError, OriginError};

/// Chromium 传给宿主进程的 origin 前缀。
pub const EXTENSION_SCHEME_PREFIX: &str = "chrome-extension://";

/// 扩展 ID 的长度：32 个字符。
///
/// Chromium 的 `crx_file::id_util::kIdSize` 是 16，`IdIsValid` 要求
/// `id.size() == kIdSize * 2` ⇒ 32。
pub const EXTENSION_ID_LEN: usize = 32;

/// 解析 Chromium 传入的 origin，取出扩展 ID。
///
/// 接受的形状：
/// - `chrome-extension://<扩展ID>/`（Chromium 的规范形式）
/// - `chrome-extension://<扩展ID>`（防御性接受）
///
/// # Errors
/// - origin 不是 `chrome-extension://` 形状 ⇒ `OriginError::NotExtensionOrigin`。
/// - 扩展 ID 长度不是 32，或含字母表 `a`–`p` 之外的字符 ⇒
///   `OriginError::InvalidExtensionId`。
pub fn parse_extension_id(origin: &str) -> Result<&str, OriginError> {
    let Some(rest) = origin.strip_prefix(EXTENSION_SCHEME_PREFIX) else {
        return Err(OriginError::NotExtensionOrigin(origin.to_owned()));
    };
    // 允许一个结尾的 `/`；其余任何路径 / 查询 / 片段一律拒绝。
    let id = rest.strip_suffix('/').unwrap_or(rest);
    if id.is_empty() || id.contains(['/', '?', '#']) {
        return Err(OriginError::NotExtensionOrigin(origin.to_owned()));
    }
    validate_id(id)?;
    Ok(id)
}

/// 校验扩展 ID 的格式（照 Chromium 的 `crx_file::id_util::IdIsValid`）。
fn validate_id(id: &str) -> Result<(), OriginError> {
    // 先查字母表：越界字符比长度更能定位问题
    // （例如 `chrome-extension://<32位ID>:123` 的越界字符是 `:`）。
    for ch in id.chars() {
        // `IdIsValid` 先 `ToLowerASCII` 再比 ⇒ 大小写不敏感。
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
    Ok(())
}
