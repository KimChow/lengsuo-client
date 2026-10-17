//! 已安装技能的按需加载安全入口：常驻目录只含元数据，正文只在显式 `load()` 返回。
//!
//! 三道门（全部 fail-closed，不静默降级、不返回部分结果）：
//! 1. **授权目录边界**：根目录与 `SKILL.md` 都先 canonicalize，再判定是否落在边界内。
//!    因此指向边界外的符号链接（目录或文件）、以及带 `..` 的注册路径，都不能把边界外
//!    内容当成技能返回；根目录本身不可用时以 `Boundary` 显式失败。
//! 2. **禁用**：宿主禁用名单与 `disabled` 标记一律「不可见且不可加载」——直接点名
//!    加载同样被拒（`Disabled`），不给「只是列表里藏起来」的绕过面。
//! 3. **调用来源**：`disable-model-invocation: true` 只允许用户显式触发；
//!    `user-invocable: false` 不允许用户菜单触发。不符来源即 `NotInvocable`。
//!
//! 工具集：`load()` 只返回技能声明与宿主已授权工具集的**交集**（见 `SkillPolicy`），
//! 技能自报内容永远不可能扩大宿主授权；无法可靠解析的限制字段降级为空工具集，
//! 绝不按「无限工具」处理。
//!
//! 本模块不实现安装、下载、市场或内容扫描，也不做提示词注入。

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::error::AccessError;
use crate::parse::{parse_skill_with_policy, SKILL_FILE};
use crate::policy::{InvocationSource, SkillPolicy};
use crate::registry::first_level_skill_dirs;
use crate::skill::Skill;

/// 常驻目录里的一条技能元数据（**不含正文**）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillSummary {
    /// 技能名（查找唯一键，大小写敏感）。
    pub name: String,
    /// 一句话描述。
    pub description: String,
    /// canonical 后的 `SKILL.md` 路径（标识与诊断定位用）。
    pub path: PathBuf,
    /// 限制元数据（allowed-tools / 调用来源门 / 禁用标记 / 降级记录）。
    pub policy: SkillPolicy,
}

/// 一次显式加载的结果：正文全文 + 生效工具集。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedSkill {
    /// 技能名。
    pub name: String,
    /// 一句话描述。
    pub description: String,
    /// 提示词正文全文：只在显式 `load()` 的结果里出现，不裁剪、不改写。
    pub body: String,
    /// canonical 后的 `SKILL.md` 路径。
    pub path: PathBuf,
    /// 生效工具集（技能声明 ∩ 宿主授权，升序）。
    pub effective_tools: Vec<String>,
    /// 该技能的常驻元数据（供上层对照展示）。
    pub summary: SkillSummary,
}

/// 已安装技能的常驻目录 + 按需加载入口。
///
/// 与 `SkillRegistry` 共用扫描与覆盖语义（后注册者优先、按 name 合并、坏文件
/// fail-closed），在此之上叠加边界、禁用与调用来源三道门。
#[derive(Debug, Clone, Default)]
pub struct SkillCatalog {
    roots: Vec<PathBuf>,
    disabled: BTreeSet<String>,
}

impl SkillCatalog {
    /// 用已授权技能根目录与禁用名单构造入口。
    ///
    /// `dirs` 按注册顺序（后注册者优先）；每项立即 canonicalize，任一不可用即
    /// `Boundary` 失败（配置写错不静默当空目录）。`disabled` 按 name 精确匹配。
    pub fn new(dirs: Vec<PathBuf>, disabled: Vec<String>) -> Result<Self, AccessError> {
        let mut roots = Vec::with_capacity(dirs.len());
        for dir in &dirs {
            roots.push(canonical_root(dir)?);
        }
        Ok(Self {
            roots,
            disabled: disabled.into_iter().collect(),
        })
    }

    /// 已授权的 canonical 根目录（边界判定基准）。
    pub fn authorized_roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// 常驻目录：可见技能的元数据（name/description/path + 限制），按 name 升序。
    ///
    /// 返回类型里没有正文字段，因此把结果整段展示或常驻上下文都不会带出全文。
    /// 可见性只按禁用门收窄；调用来源门在 `load()` 判定（由宿主按来源过滤是上层职责）。
    pub fn list(&self) -> Result<Vec<SkillSummary>, AccessError> {
        Ok(self
            .scan()?
            .into_iter()
            .filter(|(name, (_, policy))| !self.is_disabled(name, policy))
            .map(|(_, (skill, policy))| SkillSummary {
                name: skill.name,
                description: skill.description,
                path: skill.path,
                policy,
            })
            .collect())
    }

    /// 按需加载正文：显式指定名字与调用来源，并给出宿主已授权工具集。
    pub fn load(
        &self,
        name: &str,
        source: InvocationSource,
        host_tools: &BTreeSet<String>,
    ) -> Result<LoadedSkill, AccessError> {
        let merged = self.scan()?;
        let Some((skill, policy)) = merged.get(name) else {
            return Err(AccessError::NotFound);
        };
        if self.is_disabled(name, policy) {
            return Err(AccessError::Disabled {
                name: name.to_string(),
            });
        }
        if !policy.allows(source) {
            return Err(AccessError::NotInvocable {
                name: name.to_string(),
                origin: source_label(source),
            });
        }
        let summary = SkillSummary {
            name: skill.name.clone(),
            description: skill.description.clone(),
            path: skill.path.clone(),
            policy: policy.clone(),
        };
        Ok(LoadedSkill {
            body: skill.body.clone(),
            effective_tools: policy.effective_tools(host_tools),
            name: summary.name.clone(),
            description: summary.description.clone(),
            path: summary.path.clone(),
            summary,
        })
    }

    /// 扫描各授权根目录，返回按 name 合并后的（技能, 限制）；后者覆盖前者。
    ///
    /// 每次调用重新扫描（v0 无缓存、无 watcher），与 `SkillRegistry::find` 一致。
    /// 任一技能非法或越出授权边界即整次失败（fail-closed）。
    fn scan(&self) -> Result<BTreeMap<String, (Skill, SkillPolicy)>, AccessError> {
        let mut merged: BTreeMap<String, (Skill, SkillPolicy)> = BTreeMap::new();
        for root in &self.roots {
            for dir in first_level_skill_dirs(root)? {
                let skill_md = dir.join(SKILL_FILE);
                let canonical_md =
                    skill_md
                        .canonicalize()
                        .map_err(|source| AccessError::Boundary {
                            path: skill_md.clone(),
                            source,
                        })?;
                if !self.is_authorized(&canonical_md) {
                    return Err(AccessError::OutsideAuthorizedRoot { path: skill_md });
                }
                // 用 canonical 的技能目录解析：落库的 path 即边界内的真实路径。
                let skill_dir = canonical_md
                    .parent()
                    .map_or_else(|| dir.clone(), |parent| parent.to_path_buf());
                let (skill, policy) = parse_skill_with_policy(&skill_dir)?;
                merged.insert(skill.name.clone(), (skill, policy));
            }
        }
        Ok(merged)
    }

    /// 禁用判定：宿主禁用名单（按 name）或 `disabled` 标记（含不可靠值降级）。
    fn is_disabled(&self, name: &str, policy: &SkillPolicy) -> bool {
        self.disabled.contains(name) || policy.disabled
    }

    /// `SKILL.md` 的 canonical 路径是否落在某个授权根内。
    ///
    /// 只认「授权根 / 技能目录 / SKILL.md」这一层结构：技能目录的父目录必须正好
    /// 等于某个授权根，因此符号链接把内容指到根外时判定为越界；链接回指同根内则
    /// 仍在边界内（并按 canonical 路径自然去重）。
    fn is_authorized(&self, canonical_md: &Path) -> bool {
        let Some(skill_dir) = canonical_md.parent() else {
            return false;
        };
        let Some(skill_parent) = skill_dir.parent() else {
            return false;
        };
        self.roots.iter().any(|root| root == skill_parent)
    }
}

/// canonicalize 授权根：不存在或无法解析 ⇒ `Boundary`（不静默当空目录）。
fn canonical_root(dir: &Path) -> Result<PathBuf, AccessError> {
    dir.canonicalize().map_err(|source| AccessError::Boundary {
        path: dir.to_path_buf(),
        source,
    })
}

/// 错误信息里的来源表述（不把英文枚举名漏进用户可见文案）。
fn source_label(source: InvocationSource) -> &'static str {
    match source {
        InvocationSource::User => "用户",
        InvocationSource::Model => "模型",
    }
}
