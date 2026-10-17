# agent-prompts 提示词引擎状态

纯域 crate `crates/agent-prompts`：模式模板 × 变量注入，无 IO、无依赖、不取系统时钟。
规格源为 worktree 根 `PROMPTS-SPEC.md`（v0 冻结要点）。

## 接口

```text
Composer::build(mode, vars) -> String     模式模板 + 变量替换 + 硬规则段
Composer::plan_gate() -> &'static str     plan 门禁片段
PromptMode   quick | ask | plan | craft | expert
PromptVars   ai_name / user_name / soul / workspace / date / user_rules / memory_digest
PromptTemplate { mode, segments }          Segment::Text | Var(&'static str) | Gate
```

`PromptVars` 全部由调用方提供，`date` 也由调用方注入，因此同输入必得同输出。
`memory_digest`（三层记忆组装文本）与 `user_rules` 为空或纯空白时整段省略，不留空洞标题。

## 能力面

- 公共头：身份（ai_name/user_name）+ 人格设定（soul）+ 日期 + 工作区 + 记忆摘要。
- 硬规则（全模式）：不得声称读过/写过/搜过未实际发生的操作；不虚构路径、命令、输出与结果。
- quick：声明不启用任何工具，只答不操作；ask：只读工具白名单说明；craft：全工具说明。
- plan = craft 模板 + 规划门禁段（批准前禁止承诺或发起写操作）；expert = craft 模板 + 专家协作段。

## 验证

`cargo test -p agent-prompts`：24 项测试通过（`tests/modes.rs` 五模式能力面与快照 11 项、
`tests/vars.rs` 变量注入/可省略段/确定性/模板 API 12 项、lib.rs 用法 doctest 1 项），
覆盖关键子串存在与不存在、
无残留占位符、plan 含门禁且 craft 段与 craft 逐字一致、userRules 追加、
两次 build 相等、空 memory_digest 不留空洞标题，以及 quick 完整输出快照。
clippy `-D warnings` 与 `cargo fmt --check` 在本 crate 全绿；最长文件 225 行（低于 400 软目标）。

## 未做

模板文本未与 WorkBuddy 逐字对照，只对照其「模式 × 变量」结构与五模式划分；
真实模型接入、模板外置（文件/数据库）与多语言仍待后续；提示词不是权限边界，
工具的实际可用性由 `agent-core` 权限门强制，隐私不依赖本 crate 措辞保障。
