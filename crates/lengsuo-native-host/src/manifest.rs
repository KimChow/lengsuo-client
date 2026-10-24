//! Host manifest 渲染（Chromium `native_messaging_host_manifest.cc` 的解析器读的形状）。
//!
//! # 输出（冻结）
//!
//! ```json
//! {"name":"lengsuo.credential","description":"<description>","type":"stdio","path":"<绝对路径>","allowed_origins":["chrome-extension://ejlmmjamfpkoopjachjhcbdjlddknhok/"]}
//! ```
//!
//! 字段顺序固定为 `name` → `description` → `type` → `path` → `allowed_origins`，
//! 无空白、无尾换行。
//!
//! # 为什么是这五个字段（不是我方契约，是 Chromium 的解析器）
//!
//! `native_messaging_host_manifest.cc` 的 `NativeMessagingHostManifest::Parse`
//! 逐个**必需**字段：
//!
//! - `name`（`:78`）：缺失或不合 `IsValidName` ⇒ `"Invalid value for name."`；
//! - `description`（`:85`）：缺失或**空串** ⇒ `"Invalid value for description."`；
//! - `type`（`:92-94`）：缺失或不等于字面量 `"stdio"` ⇒ `"Invalid value for type."`
//!   （`stdio` 是唯一支持的类型）；
//! - `path`（`:100`）：缺失或解析成空路径 ⇒ `"Invalid value for path."`；
//! - `allowed_origins`：缺失 ⇒ 拒绝（本模块只放本扩展一项）。
//!
//! 少任何一个字段，这份 JSON 都**必被拒** ⇒ 管道建不起来。
//!
//! # 为什么没有 `key`
//!
//! host manifest **没有** `key` 字段（解析器不读它）。契约 §5.0 里带公钥的 `key`
//! 属于**扩展清单**（安装期材料），与本模块渲染的 host manifest 是两份不同的文件
//! ⇒ 公钥不进本模块、也不进本仓源码。
//!
//! # 谁给 `path`
//!
//! `path` 是**宿主可执行文件**的绝对路径，由调用方给。本 crate 目前没有 `[[bin]]`，
//! 宿主可执行目标与它在内核包里的位置是**后续卡**的事 ⇒ 本模块不猜、不发明目录布局。
//!
//! # 转义
//!
//! `description` / `path` / `origin` 里的 `"`、`\` 与控制字符**一律转义**（不拒绝）：
//! Windows 的绝对路径天然含 `\`，拒绝它就等于 Windows 上无法渲染。转义后仍是合法
//! JSON，解析回来逐字节等于原文。
//!
//! ⛔ **纯函数、不写文件**：落盘与注册属于 [`crate::register`]。

use crate::extension::EXTENSION_ORIGIN;

/// Host 名（契约 §6）。
pub const HOST_NAME: &str = "lengsuo.credential";

/// Chromium 唯一支持的 host 类型字面量（`native_messaging_host_manifest.cc:92-94`）。
pub const HOST_TYPE_STDIO: &str = "stdio";

/// 落点平台：决定「绝对路径」的判据（渲染期校验）与注册位置（[`crate::register`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// POSIX（Linux / macOS）：绝对路径以 `/` 开头。
    Posix,
    /// Windows：绝对路径 = 盘符 + 分隔符（`C:\` / `C:/`），或 UNC（`\\server\share`）。
    Windows,
}

/// 判定 `path` 是否是该平台意义上的**绝对路径**（纯函数、无 IO、无 `cfg` 分平台）。
///
/// 判据逐条对齐 Chromium 的 `base::FilePath::IsAbsolute`（`file_path.cc` 的
/// `IsPathAbsolute`，`launch_context_win.cc:200-205` 用的就是它）：
///
/// - POSIX：首个字符是分隔符 `/`；
/// - Windows（分隔符 `\/` 都认）：
///   - **盘符分支**：`X:` 后面**紧跟**分隔符（`C:\x` / `C:/x`；`C:`、`C:x` 不算）；
///   - **双前导分隔符**：前两个字符都是分隔符（`\\server\share`、`//x`、`/\x` 都算；
///     单个前导分隔符 `\x` 不算 —— Chromium 同样不算）。
///
/// ⛔ 平台由**入参**决定，不读 `cfg!(windows)` ⇒ 两个平台的分支都能在 Linux 上被测。
#[must_use]
pub fn is_absolute_path(path: &str, platform: Platform) -> bool {
    fn is_sep(b: u8) -> bool {
        b == b'\\' || b == b'/'
    }
    match platform {
        Platform::Posix => path.starts_with('/'),
        Platform::Windows => {
            let bytes = path.as_bytes();
            if bytes.len() > 2
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && is_sep(bytes[2])
            {
                return true;
            }
            bytes.len() > 1 && is_sep(bytes[0]) && is_sep(bytes[1])
        }
    }
}

/// 渲染失败（⛔ 不 panic、⛔ 不返回半成品字符串）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    /// `path` 为空串。
    #[error("宿主可执行路径为空：拒绝渲染 host manifest")]
    EmptyPath,

    /// `path` 不是该平台意义上的绝对路径。
    #[error("宿主可执行路径 {path:?} 不是 {platform:?} 平台意义上的绝对路径：拒绝渲染")]
    NotAbsolutePath {
        /// 调用方给的路径原文。
        path: String,
        /// 判定所用的平台。
        platform: Platform,
    },

    /// `description` 为空串（解析器 `:85` 同样拒绝空描述）。
    #[error("description 为空：拒绝渲染 host manifest")]
    EmptyDescription,
}

/// 渲染 host manifest 的 JSON 文本（无尾换行）。
///
/// `host_path` = 宿主可执行文件的**绝对路径**（`path` 字段）；`description` = 描述；
/// `platform` = 路径绝对性判定所用的平台。
///
/// ⛔ `name` 恒为 [`HOST_NAME`]、`type` 恒为 [`HOST_TYPE_STDIO`]、
/// `allowed_origins` 恒只含 [`EXTENSION_ORIGIN`] 一项 ——
/// 三者都**不做入参**：让调用方能改就等于能产出一份「不是本扩展」的 manifest。
///
/// # Errors
/// - `host_path` 空 ⇒ [`ManifestError::EmptyPath`]；
/// - `host_path` 非绝对 ⇒ [`ManifestError::NotAbsolutePath`]；
/// - `description` 空 ⇒ [`ManifestError::EmptyDescription`]。
pub fn render_host_manifest(
    host_path: &str,
    description: &str,
    platform: Platform,
) -> Result<String, ManifestError> {
    if host_path.is_empty() {
        return Err(ManifestError::EmptyPath);
    }
    if !is_absolute_path(host_path, platform) {
        return Err(ManifestError::NotAbsolutePath {
            path: host_path.to_owned(),
            platform,
        });
    }
    if description.is_empty() {
        return Err(ManifestError::EmptyDescription);
    }

    let mut out = String::with_capacity(256);
    out.push_str("{\"name\":\"");
    escape_json_into(&mut out, HOST_NAME);
    out.push_str("\",\"description\":\"");
    escape_json_into(&mut out, description);
    out.push_str("\",\"type\":\"");
    escape_json_into(&mut out, HOST_TYPE_STDIO);
    out.push_str("\",\"path\":\"");
    escape_json_into(&mut out, host_path);
    out.push_str("\",\"allowed_origins\":[\"");
    escape_json_into(&mut out, EXTENSION_ORIGIN);
    out.push_str("\"]}");
    Ok(out)
}

/// 把 `raw` 按 JSON 字符串字面量规则转义后追加到 `out`（本模块需要的最小集）：
/// `"` → `\"`、`\` → `\\`、C0 控制字符（`< 0x20`）→ `\u00XX`；其余原样。
fn escape_json_into(out: &mut String, raw: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for ch in raw.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let v = c as usize;
                out.push_str("\\u00");
                out.push(HEX[(v >> 4) & 0xf] as char);
                out.push(HEX[v & 0xf] as char);
            }
            c => out.push(c),
        }
    }
}
