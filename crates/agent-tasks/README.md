# agent-tasks

会话内任务看板，对照 参考客户端 的 task 工具族（`TaskCreate/TaskGet/TaskUpdate/TaskList`）。
纯域逻辑：不依赖 tokio，不做任何 IO，不落盘；持久化与会话存储由上层
（`agent-core` 运行时 / `agent-gateway` 工具接入）负责。规格源：worktree 根 `TASKS-SPEC.md`。

## 接口与兼容范围（冻结点）

```text
Task      { id, session_id, subject, description, status, created_at_ms, updated_at_ms }
TaskStatus: pending | in_progress | done | cancelled
TaskError : NotFound | InvalidTransition{from,to} | EmptySubject | Json(String)
```

- `create(session_id, subject, description)`：`subject` 去空白后不得为空，否则 `EmptySubject`；
  初始状态 `pending`，`created_at_ms == updated_at_ms`。校验先于写入，失败不留痕迹、不部分更新。
- `get(id)` / `to_json(id)`：未知 id 一律 `NotFound`。
- `update_status(id, to)`：同状态**幂等**返回当前任务且不刷新 `updated_at_ms`；
  非法迁移返回 `InvalidTransition{from,to}` 且不改变状态。
- `update_text(id, subject, description)`：给出的 `subject` 不得为空白；`None` 表示该字段不变；
  字段值无变化时不刷新 `updated_at_ms`；状态不受影响。
- `list_by_session(session_id)`：按 `created_at_ms` 升序；同毫秒再按 `id` 升序，
  因此多次调用顺序完全一致（不随哈希表抖动）。未知会话返回空列表，会话之间互不可见。

状态机（唯一合法路径，终态不可出）：

```text
pending -> in_progress -> done
                     \-> cancelled
```

`pending` 不能直达 `done`/`cancelled`；`done`/`cancelled` 为终态。

## JSON 契约

`to_json` 输出字段名固定为
`id / session_id / subject / description / status / created_at_ms / updated_at_ms`，
其中 `id`、`session_id` 为字符串形式 UUID，时间戳为整数毫秒，`status` 为上述小写词
（`in_progress` 用下划线）。该契约由 `tests/json_contract.rs` 钉住，轨道 E（GPUI 壳）
与网关 `task:*` 动作直接依赖，改动即破坏兼容。

## 时间与可测性

`TaskBoard::new()` 使用系统 Unix 毫秒时钟；`TaskBoard::with_clock(fn() -> u64)` 注入时钟，
供固定时间戳的确定性用例使用（测试不依赖墙钟，避免时序抖动）。

## ≥3 步提示

参考客户端 基线为「≥3 步任务才提示 AI 使用任务系统」。该判断属于工具层/提示词层，
本 crate 只提供任务事实（`list_by_session` 计数等），不内置提示策略。

## 依赖与边界

依赖仅 `serde`、`serde_json`、`thiserror`、`uuid`（`Json(String)` 变体与 `serde_json::Value`
返回值决定必须使用 serde_json）。全 crate `#![forbid(unsafe_code)]`。
不含权限判断、事件推送、会话存储与模型提示，这些归属其他 crate。

## 验证状态

- 已验证：状态机 4×4 全迁移矩阵（合法 3、幂等 4、非法 9）、subject 空/非空、
  文本更新的部分与幂等语义、`NotFound` 全入口、`list` 排序与会话隔离与同毫秒稳定顺序、
  JSON 字段名与 `status` 小写词、`Task`/`TaskStatus` serde 往返、系统时钟入口可用性。
- 未验证/未实现：与 `agent-core` 会话事件流的集成、网关 `task:*` 动作、任务落盘与重启恢复、
  并发（本 crate 无同步原语，`&mut self` 由调用方串行化）。

```text
cargo test -p agent-tasks --locked
cargo clippy -p agent-tasks --all-targets --locked -- -D warnings
cargo fmt -p agent-tasks -- --check
```
