//! `Skill` 数据结构（规格：name/description/body/path）。

use std::path::PathBuf;

/// 一个技能 = 一个提示词包（对照 参考客户端 的 Skill 工具）。
///
/// `body` 是 `SKILL.md` 去掉 front-matter 后的正文全文；调用方把它整段注入
/// system 消息，本 crate 不做截断、改写或压缩。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skill {
    /// 技能名，满足 `[a-z0-9-]{1,64}`；查找的唯一键（大小写敏感）。
    pub name: String,
    /// 一句话描述，供上层列目录/展示；可为空。
    pub description: String,
    /// 提示词正文全文（注入模型的内容）。
    pub body: String,
    /// `SKILL.md` 的路径，供诊断与日志定位。
    pub path: PathBuf,
}
