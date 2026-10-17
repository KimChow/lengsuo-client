//! 统一错误类型（规格：`SkillsError` 三变体）。

use std::path::PathBuf;

/// Skills 加载/解析错误。
///
/// 解析与扫描一律 fail-closed：任一技能非法即整次 `load()` 失败，
/// 不回退到「跳过坏文件继续加载」。
#[derive(Debug, thiserror::Error)]
pub enum SkillsError {
    /// 技能目录或 `SKILL.md` 不存在。
    #[error("技能文件不存在: SKILL.md")]
    NotFound,

    /// `SKILL.md` 内容或元数据非法（front-matter、name 规则、正文、大小）。
    #[error("SKILL.md 格式非法 {path:?}: {reason}")]
    Malformed { path: PathBuf, reason: String },

    /// 文件系统访问失败。
    #[error("IO 失败 {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}
