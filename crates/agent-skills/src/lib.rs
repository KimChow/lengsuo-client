//! agent-skills：目录式技能注册表与 `SKILL.md` 解析。
//!
//! 规格源：worktree 根 `SKILLS-SPEC.md`（本卡唯一规格源，冻结）。
//! 职责边界：fs 域、同步 IO、无 unsafe、不依赖 tokio。
//!
//! 概念对照 参照平台 的 Skill 工具：技能 = 提示词包，按目录管理，
//! 以 `skillName` 取到 `Skill.body` 后由调用方整段注入 system 消息。
//! 本 crate 只负责「发现 + 解析 + 优先级」，不做注入、不做权限判断、
//! 不缓存会话状态（哪些技能对某会话可见属上层职责）。
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

pub mod error;
pub mod parse;
pub mod registry;
pub mod skill;

pub use error::SkillsError;
pub use parse::{parse_skill_md, MAX_SKILL_BYTES, SKILL_FILE};
pub use registry::SkillRegistry;
pub use skill::Skill;
