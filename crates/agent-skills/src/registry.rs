//! 技能注册表：有序目录 + 同名覆盖优先级。
//!
//! 语义对照 参照平台 的 Skill 工具：上层拿到 `Skill.body` 后整段注入 system
//! 消息，因此 `body` 必须是文件全文（仅去掉 front-matter），不做任何裁剪。

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::SkillsError;
use crate::parse::{parse_skill_md, SKILL_FILE};
use crate::skill::Skill;

/// 目录式技能注册表。
///
/// `dirs` 有序：**后注册者优先**（同名的后来目录覆盖先前目录），以支持
/// 「站点级默认 + 用户级覆盖」的分层配置。
#[derive(Debug, Clone, Default)]
pub struct SkillRegistry {
    dirs: Vec<PathBuf>,
}

impl SkillRegistry {
    /// 以给定顺序注册技能根目录。
    pub fn with_dirs(dirs: Vec<PathBuf>) -> Self {
        Self { dirs }
    }

    /// 已注册目录（按注册顺序）。
    pub fn dirs(&self) -> &[PathBuf] {
        &self.dirs
    }

    /// 扫描各根目录的**一级子目录**中的 `SKILL.md`，按名去重后返回。
    ///
    /// 同名技能只保留优先级最高的一份；结果按 name 升序（同输入同输出，可
    /// 确定性比对）。任一技能非法即整体失败（fail-closed），不静默跳过坏文件。
    pub fn load(&self) -> Result<Vec<Skill>, SkillsError> {
        // 插入顺序即优先级：先注册目录、目录内先扫描的名字，都会被后来者覆盖。
        let mut merged: BTreeMap<String, Skill> = BTreeMap::new();
        for root in &self.dirs {
            for dir in first_level_skill_dirs(root)? {
                let skill = parse_skill_md(&dir)?;
                merged.insert(skill.name.clone(), skill);
            }
        }
        Ok(merged.into_values().collect())
    }

    /// 按名查找（大小写敏感）。未命中返回 `Ok(None)`，由调用方决定「技能不存在」
    /// 的对外表述；IO/格式问题仍以 `Err` 上抛。
    pub fn find(&self, name: &str) -> Result<Option<Skill>, SkillsError> {
        Ok(self.load()?.into_iter().find(|skill| skill.name == name))
    }
}

/// 列出根目录下的一级技能目录（含 `SKILL.md` 的子目录），按路径升序。
///
/// 忽略隐藏项（`.` 前缀）、非目录与顶层散落文件；无 `SKILL.md` 的子目录不算技能。
/// 排序使同目录内的同名覆盖次序可预期。根目录不存在返回 `NotFound`
/// （配置写错不静默当空目录）；其它访问故障（权限、路径类型不符）以 `Io` 上抛。
fn first_level_skill_dirs(root: &Path) -> Result<Vec<PathBuf>, SkillsError> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(SkillsError::NotFound)
        }
        Err(source) => {
            return Err(SkillsError::Io {
                path: root.to_path_buf(),
                source,
            })
        }
    };
    for entry in entries {
        let entry = entry.map_err(|source| SkillsError::Io {
            path: root.to_path_buf(),
            source,
        })?;
        let file_name = entry.file_name();
        if file_name.to_string_lossy().starts_with('.') {
            continue;
        }
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if path.join(SKILL_FILE).is_file() {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}
