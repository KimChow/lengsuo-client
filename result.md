# 任务系统卡（crates/agent-tasks）交付报告

## 结论

新 crate `crates/agent-tasks` 已按 `TASKS-SPEC.md`（冻结规格）实现并验证通过：
纯域逻辑、无 tokio/无 IO、`#![forbid(unsafe_code)]`。本 crate 门禁全绿。

## 门禁证据（隔离 target：`../target-track-tasks`）

| 门禁 | 命令 | 结果 |
|---|---|---|
| 行数 | `python3 scripts/check_line_limit.py` | Checked 290 files; hard-limit failures: 0（本 crate 最大文件 203 行，全部 < 400 软目标） |
| fmt | `cargo fmt -p agent-tasks -- --check` | 通过 |
| clippy | `cargo clippy -p agent-tasks --all-targets --locked -- -D warnings` | 零告警 |
| test | `cargo test -p agent-tasks --locked` | 27 项全绿（board 12 / state_machine 7 / json_contract 5 / errors 3），doc-test 0 |
| unsafe | `grep -rn unsafe crates/agent-tasks --include=*.rs` | 仅 `#![forbid(unsafe_code)]` 本身 |

未运行 workspace 级 test/clippy：本 worktree 有并行任务线在改其他 crate，且 AGENTS.md
禁止并发占用同一 target；卡片完成定义为「仅本 crate」。根 `Cargo.toml` 加 members 一行后
`-p agent-tasks` 的解析/编译/锁定均正常，间接证明 workspace 清单有效。

## TDD 记录

1. 红：先交付测试套件与 `todo!("red")` 骨架，`cargo test -p agent-tasks` →
   **20 failed / 2 passed**（通过的 2 项是纯 `TaskStatus` 枚举断言，其余入口全部 panic `not yet implemented: red`）。
2. 绿：填充实现后 27 项全绿（红阶段用例逐字保留，只按 400 行软目标拆分为四文件 + `tests/support/`）。

覆盖点与规格要求一一对应：

- **状态机全迁移矩阵**：`transition_matrix_covers_every_pair` 遍历 4×4=16 组，
  并断言计数恰好为合法 3、同状态幂等 4、非法 9；非法迁移同时验证状态未被改动。
  注：规格文字写「合法 4 条」，但同一行冻结的迁移式（Pending→InProgress→Done/Cancelled）
  只有 3 条边，测试按迁移式（唯一权威）钉为 3，并把计数写进断言以防漂移。
- **终态**：`done`/`cancelled` 对三个非自身状态一律 `InvalidTransition{from,to}`。
- **同状态幂等**：返回当前任务、`updated_at_ms` 不刷新（注入冻结时钟验证）。
- **subject 空/非空**：create 拒绝 `""`/空格/制表/换行/NBSP；非空原样存储不裁剪；
  `update_text` 空白 subject 拒绝且校验先于写入（不部分更新）。
- **list 排序**：按 `created_at_ms` 升序（注入自增时钟逐毫秒）；同毫秒按 `id` 升序且重复调用顺序一致；
  会话隔离（未知会话空列表）。
- **JSON 字段名冻结**：keys 恰为 7 个冻结名；`status` 为小写词（`in_progress` 下划线）；
  id/session_id 为字符串 UUID，时间戳为非负整数；`Task` 自身 serde 字段名同集。
- **NotFound**：`get`/`update_status`/`update_text`/`to_json` 全入口。
- **错误类型**：Display 文案、`InvalidTransition` 携带 from/to、可比可克隆（供上层网关映射 code）。

## 设计选择（超出/细化规格之处，均为可讨论项）

- `TaskBoard::with_clock(NowMs)`：AGENTS.md 要求固定时钟的确定性用例，故把时钟做成注入点；
  生产入口 `new()` 仍走系统 Unix 毫秒，语义与规格一致。
- 依赖含 `serde_json`：`to_json` 返回 `serde_json::Value`，无法只用 serde/thiserror/uuid。
- `update_text` 只在字段实际变化时刷新 `updated_at_ms`；`None` 视为该字段不变。
- `to_json` 失败路径映射 `TaskError::Json(String)`（规格指定 String 载荷，非 `#[from]`）。
- WorkBuddy「≥3 步任务才提示 AI 使用」属工具/提示层，本 crate 不内置提示策略，
  只提供 `list_by_session` 等事实；已在 crate README 显式记录归属。
- 文件拆分：`src/{lib,task,error,board}.rs`、`tests/{state_machine,board,json_contract,errors}.rs`
  + `tests/support/mod.rs`（沿用 `lengsuo-browser-lifecycle` 的 support 约定）。

## 文档

- 新增 `crates/agent-tasks/README.md`：接口与兼容范围（冻结点）、状态机图、JSON 契约、
  时钟注入、≥3 步归属、依赖边界、验证状态与「未实现/未验收」清单。
- 未改 `docs/network-development.md`（网络轨道任务文件，与本卡无关）、未改根 `README.md`
  （其 crate 表只列 ss-client/ss-core，网络与智能体 crate 未逐项登记）。
- `TASKS-SPEC.md` 是外部投喂的卡片输入，保持未跟踪，未纳入功能提交。

## 未做（明确标注，非遗漏）

- 不 push；未建 PR。
- 未接入 `agent-core` 会话事件流与 `agent-gateway` 的 `task:*` 动作（跨轨集成，需主理人调度）。
- 无落盘/重启恢复；无并发原语（`&mut self` 由调用方串行化）。

## 复现命令

```text
cargo test -p agent-tasks --locked
cargo clippy -p agent-tasks --all-targets --locked -- -D warnings
cargo fmt -p agent-tasks -- --check
python3 scripts/check_line_limit.py
```
