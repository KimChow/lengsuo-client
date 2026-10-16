# 结果：agent-prompts 提示词引擎（卡 C · 分支 agent/c-prompts）

## 交付

新增纯域 crate `crates/agent-prompts`（无依赖、无 IO、不取时钟、无 unsafe），已加入根
`Cargo.toml` members；`Cargo.lock` 仅新增本 crate 条目。

| 文件 | 行数 | 职责 |
|---|---|---|
| `crates/agent-prompts/src/lib.rs` | 34 | 门面、重导出与用法 doctest |
| `crates/agent-prompts/src/model.rs` | 176 | `PromptMode` / `PromptVars` / `PromptTemplate` / `Segment` + 渲染与替换 |
| `crates/agent-prompts/src/template.rs` | 104 | v0 冻结模板文本与段序列 |
| `crates/agent-prompts/src/compose.rs` | 22 | `Composer::build` / `Composer::plan_gate` |
| `crates/agent-prompts/tests/modes.rs` | 225 | 五模式能力面与完整快照 |
| `crates/agent-prompts/tests/vars.rs` | 178 | 变量注入、可省略段、确定性、公开模板 API |
| `crates/agent-prompts/tests/common/mod.rs` | 97 | 共享夹具与结构守卫 |
| `docs/agent-prompts-status.md` | 38 | 接口、能力面、验证与未做事项 |

接口与卡面规格一致：`Composer::build(mode, vars) -> String`、`Composer::plan_gate() -> &'static str`、
`Segment::Text(String) | Var(&'static str) | Gate`、`PromptTemplate { mode, segments }`
（构造与访问器公开，段序列可直接用于宿主自有模板）。依赖为空——`thiserror` 按「可不依赖」省掉。

## 模板结构（v0）

公共头（模式标题行 + 身份 ai_name/user_name + 人格设定 soul + 日期 + 工作区 + 记忆摘要）
→ 模式能力段 → 门禁段（仅 plan）→ 硬规则 → 用户自定义规则（非空时追加）。

- quick：声明不启用任何工具，只答不操作；ask：只读工具白名单；craft：全工具说明。
- plan：复用 craft 能力段原文，其后插入规划门禁段（批准前不得承诺/发起写操作）。
- expert：复用 craft 能力段原文，追加专家协作段。
- 硬规则首条为冻结要点「不得声称读过/写过/搜过未实际发生的操作」，其余三条为同向收紧。
- `memory_digest` / `user_rules` 为空或纯空白时整段省略，不留空洞标题或连续空行。
- 变量单遍替换：注入值中的 `{{...}}` 不被二次扫描；`date` 由调用方注入，无时间戳来源。

## TDD 与验证

先写断言并把渲染桩为空串，得到红：`15 failed; 5 passed`（失败项覆盖公共头、硬规则、
四模式能力面、用户规则、变量替换、快照）。实现后本 crate 全绿：

```text
cargo test -p agent-prompts        24 passed / 0 failed（modes 11 + vars 12 + lib doctest 1）
cargo clippy -p agent-prompts --all-targets -- -D warnings   无输出，退出码 0
cargo fmt -p agent-prompts -- --check                        无输出，退出码 0
python3 scripts/check_line_limit.py                          289 文件，硬上限失败 0
```

断言要点：五模式关键子串存在/不存在（quick 不含任何工具名与「权限门」，ask 不含写类工具名）；
plan 去掉门禁段并与模式标题归一后与 craft 逐字相等（craft 段完整复用，非另写一份）；
门禁段位置在 craft 段之后、硬规则之前；两次 `build` 相等；只改 `date` 时差异局限在该行；
`snapshot_quick_minimal_vars` 为 quick 全空可选变量的逐字快照。
测试运行使用隔离 target 目录，未触碰既有构建锁。

范围按卡面「仅本 crate」：`cargo fmt --all -- --check` 在 `crates/ss-core/tests/golden.rs:122`
仍有基线既有的格式差异（本卡未改该文件，不顺手混入无关格式化提交）。

## 决策与偏离

- 规格只冻结结构、必含/必不含要点与「无时间戳」，措辞未逐字固定；据此自主设计中文模板文本，
  未与 WorkBuddy 原文对照（本地无该文本），只对照其「模式 × 变量」结构与五模式划分。
- 硬规则从 1 条扩到 4 条（不虚构路径/命令/输出/结果、工具结果按实际陈述、不假装成功），
  与「未实际发生的操作不得声称」同向，不放宽任何能力面。
- craft/ask 的能力段写了具体工具名（fs.list、fs.read、shell.exec 等），与 `agent-core`
  权限门测试里的工具命名保持一致；提示词不是权限边界，实际可用性仍由运行时权限门强制。
- `soul` 也做成可省略槽位（空则不出「人格设定」行）；规格未要求，但可避免空白设定留下孤标题。
- 模板为静态构造，不外置文件、不做多语言、不接真实模型——这些在状态文档「未做」中显式记录。

## 文档

`docs/agent-prompts-status.md` 记录接口、能力面、验证结果与未做事项；`PROMPTS-SPEC.md`
（本卡唯一规格源）随代码入库以保留出处。README 的 crate 表只列 ss-client/ss-core，
本次不改动既有表格布局（智能体族 crate 状态统一在 docs 下）。

## 提交

分支 `agent/c-prompts`，中文提交，未 push。
