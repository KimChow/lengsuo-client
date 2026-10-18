//! agent-skills：目录式技能注册表与 `SKILL.md` 解析。
//!
//! 规格源：worktree 根 `SKILLS-SPEC.md`（本卡唯一规格源，冻结）。
//! 职责边界：fs 域、同步 IO、无 unsafe、不依赖 tokio。
//!
//! 概念对照 参考客户端 的 Skill 工具：技能 = 提示词包，按目录管理，
//! 以 `skillName` 取到 `Skill.body` 后由调用方整段注入 system 消息。
//! 本 crate 只负责「发现 + 解析 + 优先级」，不做注入、不做宿主授权判定、
//! 不缓存会话状态（哪些技能对某会话可见属上层职责）。
//!
//! 两条互不干扰的入口：
//! - `SkillRegistry`/`parse_skill_md`：既有语义，按目录扫描并返回含全文的 `Skill`。
//! - `SkillCatalog`：面向宿主的安全入口，常驻目录（`list()`）只含 name/description/
//!   path 标识与 `SkillPolicy` 限制元数据，正文必须经显式 `load()` 返回；加载前
//!   校验授权目录边界（canonicalize，防 symlink 越界）、禁用面与调用来源，
//!   `allowed-tools` 只与宿主已授权工具集求交集（不扩大授权）。
//!
//! ```no_run
//! use std::path::PathBuf;
//!
//! use agent_skills::{SkillRegistry, SkillsError};
//!
//! fn main() -> Result<(), SkillsError> {
//!     // 站点级默认在前、用户级覆盖在后：同名技能后者生效。
//!     let registry = SkillRegistry::with_dirs(vec![
//!         PathBuf::from("/etc/lengsuo/skills"),
//!         PathBuf::from("/home/me/.lengsuo/skills"),
//!     ]);
//!     if let Some(skill) = registry.find("pdf-forms")? {
//!         // 注入即全文：不裁剪、不改写。
//!         println!("{}", skill.body);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! 按需加载的安全入口（常驻只留元数据，正文显式加载才返回）：
//!
//! ```no_run
//! use std::collections::BTreeSet;
//! use std::path::PathBuf;
//!
//! use agent_skills::{InvocationSource, SkillCatalog};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 已授权根目录 + 宿主禁用名单；路径先 canonicalize，越界即显式失败。
//!     let catalog = SkillCatalog::new(
//!         vec![PathBuf::from("/home/me/.lengsuo/skills")],
//!         vec!["实验技能".to_string()],
//!     )?;
//!     // 常驻目录：只有 name/description/path 与限制元数据，不含正文。
//!     for summary in catalog.list()? {
//!         println!("{}: {}", summary.name, summary.description);
//!     }
//!     // 正文只在显式 load 时返回；生效工具集是技能声明 ∩ 宿主授权的交集。
//!     let host: BTreeSet<String> = ["Read".to_string()].into_iter().collect();
//!     let loaded = catalog.load("pdf-forms", InvocationSource::User, &host)?;
//!     println!("{} 字，工具 {:?}", loaded.body.len(), loaded.effective_tools);
//!     Ok(())
//! }
//! ```

pub mod catalog;
pub mod error;
pub mod parse;
pub mod policy;
pub mod registry;
pub mod skill;

pub use catalog::{LoadedSkill, SkillCatalog, SkillSummary};
pub use error::{AccessError, SkillsError};
pub use parse::{parse_skill_md, parse_skill_with_policy, MAX_SKILL_BYTES, SKILL_FILE};
pub use policy::{InvocationSource, SkillPolicy};
pub use registry::SkillRegistry;
pub use skill::Skill;
