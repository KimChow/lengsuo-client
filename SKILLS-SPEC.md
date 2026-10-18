你是 lengsuo-client 的 Skills 系统工程师。工作目录：/home/ubuntu/lengsuo-client-dev/wt-agent-skills（分支 agent/c-skills，基于 origin/main）。必读：AGENTS.md。

对照物：参考客户端 的 Skill 工具（skillName → 读 SKILL.md 全文注入 system 消息；技能=提示词包；目录式管理）。规格（本卡唯一规格源，冻结）：

新 crate `crates/agent-skills`（fs 域，同步 IO）：
```rust
pub struct Skill { pub name: String, pub description: String, pub body: String, pub path: PathBuf }
pub struct SkillRegistry { dirs: Vec<PathBuf> }   // 有序：后注册者优先（同名覆盖）
impl SkillRegistry {
    pub fn with_dirs(dirs: Vec<PathBuf>) -> Self;
    pub fn load(&self) -> Result<Vec<Skill>, SkillsError>;         // 扫描各目录一级子目录的 SKILL.md
    pub fn find(&self, name: &str) -> Result<Option<Skill>, SkillsError>;  // 加载后查找（大小写敏感）
}
pub fn parse_skill_md(dir: &Path) -> Result<Skill, SkillsError>;   // front-matter：--- 包裹的 name/description（YAML 简式 key: value），正文 = body；无 front-matter ⇒ name=目录名、description 空
pub enum SkillsError { NotFound, Malformed { path: PathBuf, reason: String }, Io { path: PathBuf, source: std::io::Error } }
```
约束：SKILL.md ≤32KB（超限 Malformed）；name 规则 `[a-z0-9-]{1,64}`（front-matter 与目录名冲突时以 front-matter 为准并 Malformed 拒绝重名文件内声明缺失）；body 非空。
TDD：解析（有/无 front-matter、超限、坏 name）、多目录同名覆盖优先级、NotFound、body 注入即返回全文。
依赖仅 thiserror/serde（如需）。完成定义：test/clippy(-D warnings)/fmt 全绿（仅本 crate）。git 提交（中文），不 push；根 Cargo.toml 加 members。写 result.md。≤700/400；no unsafe。
