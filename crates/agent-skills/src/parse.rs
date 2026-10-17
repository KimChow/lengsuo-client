//! `SKILL.md` 解析：front-matter（YAML 简式 key: value）+ 正文。
//!
//! 只解析规格要求的 name/description，不引入 YAML 依赖；未知 key 与 `#` 注释忽略。

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::error::SkillsError;
use crate::policy::SkillPolicy;
use crate::skill::Skill;

/// 技能入口文件名（目录式管理的固定约定）。
pub const SKILL_FILE: &str = "SKILL.md";

/// `SKILL.md` 大小硬上限：32 KiB。
pub const MAX_SKILL_BYTES: u64 = 32 * 1024;

/// name 长度上限（`[a-z0-9-]{1,64}`）。
const MAX_NAME_LEN: usize = 64;

/// front-matter 分隔行。
const DELIMITER: &str = "---";

/// 大小上限的 KiB 表述（错误信息用）。
const MAX_SKILL_KIB: u64 = MAX_SKILL_BYTES / 1024;

/// front-matter 拆分结果。
enum FrontMatter<'a> {
    /// 文件不以 `---` 行开头。
    Absent,
    /// 以 `---` 行开头但找不到收尾 `---` 行。
    Unclosed,
    /// 成功拆分：元数据段 + 正文段。
    Present { meta: &'a str, body: &'a str },
}

/// 解析一个技能目录下的 `SKILL.md`。
///
/// 有 front-matter ⇒ 取其 `name`/`description`（front-matter 优先于目录名）；
/// 无 front-matter ⇒ `name` 取目录名、`description` 为空。
///
/// 本函数只返回 `Skill`（既有语义不变）；限制元数据（`allowed-tools` 等）走
/// [`parse_skill_with_policy`]。
pub fn parse_skill_md(dir: &Path) -> Result<Skill, SkillsError> {
    Ok(parse_impl(dir)?.0)
}

/// 解析 `SKILL.md`，同时返回 [`Skill`] 与其限制元数据。
///
/// 解析规则与 [`parse_skill_md`] 逐字一致（同一实现），额外带出 [`SkillPolicy`]；
/// 无 front-matter ⇒ 默认（未声明限制）策略。
pub fn parse_skill_with_policy(dir: &Path) -> Result<(Skill, SkillPolicy), SkillsError> {
    parse_impl(dir)
}

/// 实际解析：返回（技能, 限制元数据）。
fn parse_impl(dir: &Path) -> Result<(Skill, SkillPolicy), SkillsError> {
    let path = dir.join(SKILL_FILE);
    // 先查大小再读内容：超限文件不整份读进内存。
    let size = match fs::metadata(&path) {
        Ok(size) => size,
        // 目录或文件不存在 ⇒ NotFound（技能本身缺失，不是访问故障）。
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(SkillsError::NotFound)
        }
        Err(source) => return Err(SkillsError::Io { path, source }),
    };
    if !size.is_file() {
        return Err(SkillsError::NotFound);
    }
    if size.len() > MAX_SKILL_BYTES {
        return Err(malformed(
            &path,
            format!(
                "文件超过 {MAX_SKILL_KIB} KiB 上限（实际 {} 字节）",
                size.len()
            ),
        ));
    }
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        // read_to_string 对非 UTF-8 报 InvalidData：属内容问题，按格式非法处理。
        Err(source) if source.kind() == std::io::ErrorKind::InvalidData => {
            return Err(malformed(&path, "文件不是合法 UTF-8 文本".to_string()))
        }
        Err(source) => return Err(SkillsError::Io { path, source }),
    };

    let (meta, body) = match split_front_matter(&text) {
        FrontMatter::Absent => (None, text.as_str()),
        FrontMatter::Unclosed => {
            return Err(malformed(
                &path,
                "front-matter 缺少收尾的 --- 分隔行".to_string(),
            ))
        }
        FrontMatter::Present { meta, body } => (Some(meta), body),
    };
    let body = body.trim().to_string();
    if body.is_empty() {
        return Err(malformed(&path, "正文（body）为空".to_string()));
    }

    let fields = match meta {
        Some(meta) => Some(parse_fields(meta, &path)?),
        None => None,
    };
    // front-matter 与目录名冲突时以 front-matter 为准。
    let name = match &fields {
        Some(fields) => match fields.get("name") {
            // 已写 front-matter 却缺 name：name 是查找唯一键，必须显式合法。
            Some(value) => value.clone(),
            None => return Err(malformed(&path, "front-matter 缺少 name 声明".to_string())),
        },
        None => dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
    };
    check_name(&name, &path)?;
    let description = fields
        .as_ref()
        .and_then(|fields| fields.get("description"))
        .cloned()
        .unwrap_or_default();
    // 限制元数据：无 front-matter ⇒ 默认（未声明）策略。
    let policy = match &fields {
        Some(fields) => SkillPolicy::from_fields(fields),
        None => SkillPolicy::default(),
    };

    Ok((
        Skill {
            name,
            description,
            body,
            path,
        },
        policy,
    ))
}

/// 拆出 front-matter 元数据段与正文段（兼容 LF/CRLF）。
fn split_front_matter(text: &str) -> FrontMatter<'_> {
    let mut lines = text.split_inclusive('\n');
    let Some(first) = lines.next() else {
        return FrontMatter::Absent;
    };
    if first.trim_end_matches(['\r', '\n']).trim() != DELIMITER {
        return FrontMatter::Absent;
    }
    // cursor 停在当前行末尾；命中收尾分隔行时，元数据段到此为止，正文跳过整行开始。
    let mut cursor = first.len();
    for line in lines {
        let content = line.trim_end_matches(['\r', '\n']);
        if content.trim() == DELIMITER {
            return FrontMatter::Present {
                meta: &text[first.len()..cursor],
                body: &text[cursor + line.len()..],
            };
        }
        cursor += line.len();
    }
    FrontMatter::Unclosed
}

/// 解析 front-matter 的 `key: value` 行；未知 key 与注释忽略，非 `key: value` 行非法。
fn parse_fields(meta: &str, path: &Path) -> Result<BTreeMap<String, String>, SkillsError> {
    let mut out = BTreeMap::new();
    for line in meta.split('\n') {
        let trimmed = line.trim_end_matches('\r').trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once(':') else {
            return Err(malformed(
                path,
                format!("front-matter 行不是 key: value: {trimmed:?}"),
            ));
        };
        let key = key.trim();
        if key.is_empty() {
            return Err(malformed(path, "front-matter 行缺少 key".to_string()));
        }
        out.insert(key.to_string(), unquote(value.trim()).to_string());
    }
    Ok(out)
}

/// 去掉成对的简单引号（`"…"` / `'…'`）；不实现 YAML 转义。
fn unquote(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[0] == bytes[bytes.len() - 1]
    {
        return &value[1..value.len() - 1];
    }
    value
}

/// 校验 name 规则 `[a-z0-9-]{1,64}`（大小写敏感，不做归一）。
fn check_name(name: &str, path: &Path) -> Result<(), SkillsError> {
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if ok {
        return Ok(());
    }
    Err(malformed(
        path,
        format!("name 不合法: {name:?}（规则 [a-z0-9-]{{{MAX_NAME_LEN}}})"),
    ))
}

fn malformed(path: &Path, reason: String) -> SkillsError {
    SkillsError::Malformed {
        path: path.to_path_buf(),
        reason,
    }
}
