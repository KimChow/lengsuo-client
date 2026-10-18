你是 lengsuo-client 的提示词引擎工程师。工作目录：/home/ubuntu/lengsuo-client-dev/wt-agent-prompts（分支 agent/c-prompts，基于 origin/main）。必读：AGENTS.md。

对照物：参考客户端 提示词系统（模式模板 × 变量注入；quick/ask/plan/craft/expert 五模式；plan 复用 craft 模板 + 门禁片段）。规格（本卡唯一规格源，冻结）：

新 crate `crates/agent-prompts`（纯域，无 IO）：
```rust
pub enum PromptMode { Quick, Ask, Plan, Craft, Expert }
pub struct PromptVars { pub ai_name: String, pub user_name: String, pub soul: String,
                        pub workspace: String, pub date: String, pub user_rules: String,
                        pub memory_digest: String }   // memory_digest=三层记忆组装文本（可为空）
pub struct PromptTemplate { mode: PromptMode, segments: Vec<Segment> }  // Segment::Text(String) | Var(&'static str) | Gate
pub struct Composer;
impl Composer {
    pub fn build(mode: PromptMode, vars: &PromptVars) -> String;   // 模式模板 + 变量替换 + 硬规则段
    pub fn plan_gate() -> &'static str;   // plan 门禁片段（EnterPlanMode/ExitPlanMode 语义：批准前禁止写操作承诺）
}
```
模板内容（v0 冻结要点，按模式递增能力面）：
- 公共头：身份（ai_name/user_name/soul）+ 日期 + 工作区 + 记忆摘要。
- 硬规则（全模式）：「不得声称读过/写过/搜过未实际发生的操作」。
- quick：无工具说明 + 明确告知只答不操作；ask：只读工具白名单说明；craft：全工具说明；plan=craft 模板+plan_gate()；expert=craft+专家协作段。
- userRules 非空时追加为「用户自定义规则」段。
- 输出确定性：同输入同输出（无时间戳注入）。
TDD：五模式快照式断言（关键子串存在/不存在）、变量替换正确、plan 含 gate 且 craft 段完整、userRules 追加、确定性（两次 build 相等）、空 memory_digest 不留空洞标记。
依赖仅 thiserror（可不依赖）。完成定义：test/clippy/fmt 全绿（仅本 crate）。git 提交（中文），不 push；根 Cargo.toml 加 members。写 result.md。≤700/400；no unsafe。
