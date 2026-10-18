//! 规格 §2.5「URL 匹配」边界：通配符编译语义、scheme 归一化、大小写敏感。
//!
//! 本 crate 冻结的匹配语言（不依赖正则库：编译一次，匹配期只借用输入）：
//! - 比较面只有 **host + path**：scheme 归一化后丢弃，query/fragment 剥离；
//! - `*`：段内通配 —— host 区内不跨 `.`，path 区内不跨 `/`，至少吃掉一个字符；
//!   例外：host 段整体只写 `*` 或 `**` 时表示「任意主机」（可跨标签）；
//! - `**`：跨段通配 —— host 区内跨 `.` 且至少一个标签，path 区内跨 `/` 且允许零段；
//!   `**` 必须独占一段，禁止 `a**b` 这类混合写法；
//! - 纯通配模式（`*`、`**`、`*/**`、`**/**`）即「所有网页」模式；
//! - `?`：段内单字符；`{n}`/`{n..m}`/`{n..}` 只在路径尾部限定剩余段数（上界必须有界）；
//! - 其余字符一律字面量（无转义语言）；大小写敏感；百分号转义只校验合法性、不解码。

// 自原 pattern_wildcard.rs 原样搬移；仅可见性提升为 pub 供各主题文件取用。
pub use policy_engine::pattern::{
    more_specific, CompileError, NormalizedUrl, Pattern, Specificity,
};

pub const HTTPS: &str = "https:";
pub const HTTP: &str = "http:";

/// 组装带 scheme 的完整 URL；规则文本与 URL 数据刻意分开写，读起来更贴近配置。
pub fn url(host_path: &str) -> String {
    format!("{}//{}", HTTPS, host_path)
}

pub fn parse(raw: &str) -> NormalizedUrl {
    NormalizedUrl::parse(raw).unwrap_or_else(|e| panic!("URL {raw:?} 应能归一化，实际失败：{e}"))
}

pub fn compile(pattern: &str) -> Pattern {
    Pattern::compile(pattern).unwrap_or_else(|e| panic!("模式 {pattern:?} 应能编译：{e}"))
}

pub fn compile_fail(pattern: &str) -> CompileError {
    Pattern::compile(pattern)
        .err()
        .unwrap_or_else(|| panic!("模式 {pattern:?} 必须编译失败"))
}

/// 模式 + host/path 的命中判定。
pub fn hit(pattern: &str, host_path: &str) -> bool {
    hit_raw(pattern, &url(host_path))
}

/// 原样 URL（含非法写法）的命中判定，用于测试拒绝路径。
pub fn hit_raw(pattern: &str, raw: &str) -> bool {
    let compiled = compile(pattern);
    match NormalizedUrl::parse(raw) {
        Ok(normalized) => compiled.is_match(&normalized),
        Err(e) => panic!("URL {raw:?} 应能归一化，实际失败：{e}"),
    }
}
