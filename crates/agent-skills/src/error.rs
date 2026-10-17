//! 统一错误类型（规格：`SkillsError` 三变体 + 安全入口 `AccessError`）。

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

/// 安全入口（`SkillCatalog`）的拒绝原因。
///
/// 全部为显式拒绝，不静默降级、不返回部分结果；底层解析/扫描故障经
/// `Skills` 变体透出，保持 `SkillsError` 既有语义。
#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    /// 底层解析/扫描失败（fail-closed）。
    #[error(transparent)]
    Skills(SkillsError),

    /// 技能不在任何已授权根目录内（含经 symlink/`..` 逃逸到授权边界之外）。
    ///
    /// 边界判定用 canonical 路径，因此链接指向边界外时以「越界」显式失败，
    /// 而不是把边界外内容当成技能返回。
    #[error("SKILL.md 越出已授权目录边界: {path:?}")]
    OutsideAuthorizedRoot { path: PathBuf },

    /// 授权根目录无法确定边界（不存在或无法 canonicalize）。
    #[error("授权技能根目录不可用 {path:?}: {source}")]
    Boundary {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// 该名字在已授权目录内没有对应技能（含大小写不匹配）。
    #[error("技能不存在: SKILL.md")]
    NotFound,

    /// 技能已被禁用（宿主禁用名单或 `disabled` 标记）：不可见且不可加载。
    #[error("技能已禁用: {name}")]
    Disabled { name: String },

    /// 调用来源不被允许（`disable-model-invocation` / `user-invocable`）。
    #[error("技能 {name} 不允许{origin}调用")]
    NotInvocable {
        name: String,
        /// 被拒的调用来源：`模型` 或 `用户`。
        origin: &'static str,
    },
}

impl From<SkillsError> for AccessError {
    fn from(source: SkillsError) -> Self {
        Self::Skills(source)
    }
}
