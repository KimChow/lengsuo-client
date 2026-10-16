# 轨道 D/E 开工说明 —— 智能体运行时与 GPUI 壳（M1 竖切）

> **性质**：本文是轨道 D（智能体运行时）与轨道 E（GPUI 壳）开工的接口说明与任务分工，执行「新模块先说明接口、兼容范围和测试计划」门禁；用户已拍板开工（2026-10-16，见 [v1-scope-freeze](v1-scope-freeze.md) 变更记录）。
> **工作仓**：`lengsuo-client`（GitHub 公开）；1.47 研究机隔离 worktree 开发，各自分支，**不直接 push main**。
> **规则**：单文件 700 硬 / 400 软；TDD 先失败再实现；基线不绿不得合并；功能完成后同批次更新文档；生产网络代码无 unsafe；GPL/AGPL/SSPL 不进依赖。
> **行为基线**：[参照平台行为基线](reference-platform-agent-baseline.md)；存储拍板 N9（不用 SQLite）；权限 deny-by-default。

## 1. Crate 划分（lengsuo-client workspace 新成员）

| crate | 职责 | 依赖 | 轨道 |
|---|---|---|---|
| `agent-core` | 会话/任务模型、事件日志、工具注册表、权限门、模式系统（纯域逻辑，无 IO 框架依赖） | 仅 serde/thiserror/uuid 等基础库 | D |
| `agent-gateway` | 本地网关：HTTP+WS on `127.0.0.1`、token 鉴权、`域:动作` RPC 路由、事件订阅推送 | agent-core + axum/tokio | D |
| `lengsuo-shell` | GPUI 桌面壳骨架：导航、会话视图、环境管理视图；只走网关客户端 | agent-gateway 的 client 端（同 crate 内 `client` 模块）+ gpui | E |

- **与既有模块解耦**：不 import/不修改 `ss-*`（网络面归轨道 A，已有独立工作树）；浏览器工具经 trait 占位（`BrowserTool` 接口留空实现），C/D 对接时再接。
- 依赖方向：`lengsuo-shell → agent-gateway → agent-core`；agent-core 不得依赖 tokio（用 async-trait 或回调抽象，网关层才碰运行时）。

## 2. 本地网关协议 v0（冻结点，两轨共同遵守）

- 监听：`127.0.0.1` **随机端口** + 握手文件 `%LOCALAPPDATA%/lengsuo/gateway.json`（`{port, pid, token}`，文件 ACL 限当前用户）；token 启动时生成，**退出即失效**。
- RPC：单入口 `POST /rpc`，body `{action: "<域>:<动作>", payload}`；信封 `{code, msg, data}`（`code==0` 成功；404 未注册动作、403 鉴权拒绝、408 超时；其余按 server-contract 错误码段）。默认 30s 超时。
- 事件：`GET /events`（WebSocket）；事件名 `thinking / text / tool_use / tool_result / approval_request / files / done`（参照平台基线 §5）+ `session_update`；一行一个 JSON。
- v0 动作面：`session:list/create/get/send/stop`、`approval:respond`、`config:get/set`、`tool:list`、`sys:ping`。其余动作 404，不预留半成品。
- 鉴权：所有请求头 `X-Gateway-Token`；失败 403；登录态/租户隔离键随 payload（v0 单用户本地，字段预留）。

## 3. 会话与事件 schema v0（F7 定稿初版）

```text
Session { id: uuid, title, workspace_root, mode: quick|ask|plan|craft|expert,
          permission_mode: readonly|full, env_binding: Option<env_id>,   // 环境绑定预留
          isolation: {user_id, tenant_id, env_id?},                       // 隔离键（product-direction §3）
          messages: [Message], created_at_ms, updated_at_ms, status: running|idle|done|failed }
Message { role: user|assistant|tool_call|tool_result, content, tool?: {name, args_ref?, result_ref?, ms}, ts_ms }
Event  { seq, session_id, kind, payload, ts_ms }   // seq 会话内单调递增（N12 分页回溯锚点）
```

- 大结果/附件**不进** `content`（存引用 `result_ref` + 按需取用）——防分页回溯被大输出打爆（参照平台基线 §5 警告项）。
- 消息四类与崩溃恢复语义照 参照平台基线（历史重放不重跑工具）。

## 4. 权限门 v0（运行时强制）

- 三态 ask/auto/deny；**默认 deny**，显式配置才放行（收紧 参照平台 默认矩阵）。
- 工具白名单按模式切换（quick 无工具仍有硬规则占位）；敏感动作表（`rm -rf`/强推/格式化等正则）强制 ask，不可配置跳过。
- 审批事件 `approval_request` 挂起等待 `approval:respond`，带超时（默认 120s → deny）。
- 凭据只以 `cred_ref` 出现在工具参数；任何工具输出先过脱敏过滤器（密码/token 正则族）再进事件流。

## 5. 存储 v0（N9 落地第一步）

- 热态：进程内并发 map（会话/任务索引）；一切 UI 读取走内存，不做同步磁盘 IO。
- 持久：`EventLog` trait + **JSONL 追加实现**（`events-<session>.jsonl`，按行追加 + seq 校验）+ 启动回放；**fjall 实现后置**（trait 已隔离，spike 过许可与基准后替换，接口不变）。
- 迁移：`schema_version` 文件头自第一天。

## 6. 测试计划（每 crate 必测，先失败再实现）

- `agent-core`：会话 CRUD 往返、事件 seq 单调与回放一致、权限门 deny-by-default（未配置即拒）、敏感动作强制 ask、工具白名单按模式、脱敏过滤器命中、EventLog 断行/乱序容错。
- `agent-gateway`：临时端口起服 + RPC roundtrip、404/403/超时、WS 事件订阅顺序、握手文件生成与 token 校验、并发 50 会话发送不阻塞（N9 卡顿教训的回归锚）。
- `lengsuo-shell`：编译 + 启动冒烟（无头环境跳过渲染断言）；网关客户端对 mock 的 roundtrip。
- 异步测试全部带超时；同一 worktree 的 `CARGO_TARGET_DIR` 独立，禁止并发共用 target。

## 7. 分工卡

**卡 A（agent/track-d-runtime）**：`agent-core` + `agent-gateway` 全部域逻辑与测试；交付 = 两 crate 编译绿 + clippy `-D warnings` + 上述测试全绿 + 分支提交记录。**不做**：GPUI、真实 LLM 接入（Provider trait 空实现 + echo provider 用于测试）、fjall 实体集成。
**卡 B（agent/track-e-shell）**：`lengsuo-shell` GPUI 骨架 + 网关客户端 + mock 数据三视图（会话/任务/环境占位）；交付 = 编译绿 + 冒烟测试 + 分支提交。**不做**：改 agent-core/gateway 的协议（发现协议缺口 → 记录到分支内 `PROTOCOL-NOTES.md`，不改代码等 A 轨合流）。

## 8. 集成与收据

- 分支 `agent/track-d-runtime`、`agent/track-e-shell`，基于 `origin/main`；各自独立目录与 target；**不修改别人的工作树**；push 到各自分支（不碰 main）。
- 收据：`reviews/live.json` / `exit.json` / `result.md`（命令、退出码、测试摘要）；主理人复核后合流。
- 每完成一块更新本文档「集成状态」；代码与文档不一致视为未完成（AGENTS 规则）。

## 9. 集成状态

| 项 | 状态 |
|---|---|
| 卡 A 会话启动 | 2026-10-16，1.47 `/home/ubuntu/lengsuo-client-dev/wt-agent-runtime` |
| 卡 B 会话启动 | 2026-10-16，1.47 `/home/ubuntu/lengsuo-client-dev/wt-gpui-shell` |
| 网关协议 v0 | 本文 §2–§5 即初版冻结；变更走本文变更记录 |

## 变更记录

| 日期 | 变更 |
|---|---|
| 2026-10-16 | 初版：crate 划分、网关协议 v0、schema v0（F7 初版定稿）、权限门、存储抽象、测试计划、分工卡；M1 双会话在 1.47 启动 |
