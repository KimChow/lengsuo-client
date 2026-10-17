# lengsuo-shell 网关客户端回环验收（2026-10-17）

## 本卡范围

把 `crates/lengsuo-shell/tests/support/mod.rs` 里已存在但无人调用的 mock 本地网关接上
`GatewayClient`，在**真实 127.0.0.1 socket** 上完成 AGENT-KICKOFF.md §6 要求的
「网关客户端对 mock 的 roundtrip」。不改协议、不动 GPUI、不引入新依赖、不碰其他 crate。

## 交付内容

| 文件 | 测试数 | 覆盖 |
|---|---|---|
| `tests/gateway_roundtrip.rs` | 9 | `POST /rpc`：成功信封 + `X-Gateway-Token` 上线、请求体 `{action,payload}` 形态、HTTP 403 → `Unauthorized`、信封 404 → `ActionNotFound` 与裸 404 → `Http` 的区分、信封 408 / 裸 408 / 网关挂起 → `Timeout`、业务码 1042 / 非 JSON 200 / 裸 500、非法动作名联网前拒绝、端口无监听 → `Transport`、token 不入 `Debug` 与错误文本 |
| `tests/gateway_events.rs` | 8 | `GET /events`：5 帧按序交付且 `seq`/`kind` 不串位、`tool_result/files/session_update` 载荷透传、未知 `kind` → `UnknownKind`（不静默丢）、非法帧 → `Malformed` 且摘要不回显帧内容、静默网关 → 单帧 `Timeout`、网关主动关断 → `Closed`、WS 握手 token 不符 → `Transport` 且不泄 token、无监听 → `Transport` |
| `tests/gateway_handshake.rs` | 3 | `gateway.json` → `127.0.0.1:port` + 默认 30s 超时的完整 roundtrip；缺失 / JSON 非法 / `port:0` / 空 token / 缺字段全部 fail-closed 且错误文本不含 token；`GatewayClient::connect` 文件缺失不回退任何地址 |
| `src/gateway/rpc.rs` | 9（原有，未改） | 信封映射单元测试，全部保留 |

mock 侧改动（仅 `tests/support/mod.rs`）：
- 修正 `event_json` 的签名语法错误（原文件 `session: &str) kind: &str` 无法编译，此前无人调用所以一直没暴露）。
- 补 `SocketAddr` 类型标注（tokio `bind` 的 `parse()` 在测试 crate 里推断不出类型）。
- `EventsBehaviour` 新增 `close_after_frames`，推完帧后由服务端发 WS Close，用于验收 `EventError::Closed`；原有「保持连接直到对端关闭」的路径不变。

## 红灯复现与修复（唯一实现改动）

`tests/gateway_roundtrip.rs::rpc_timeout_arrives_from_envelope_408_raw_408_and_a_hang`
第一次运行时失败：

```text
客户端等待超时应映射 Timeout, 实际 Transport(Io(Custom { kind: TimedOut, error: "gateway rpc timeout" }))
```

原因：`GatewayClient::rpc` 外层 `tokio::time::timeout` 与 `http::request` 内层用的是
**同一个** `timeout` 值，内层先触发并把超时包成 `io::ErrorKind::TimedOut` 的
`RpcError::Transport`，于是「网关慢/无响应」被误报成「连接坏了」。协议 §2 把 408/超时
列为独立网关语义，壳层要能区分超时与传输故障（两者的 UI 处置不同），因此这是缺陷。

修复：`src/gateway/rpc.rs::roundtrip` 增加 `map_timeout`，把 `HttpError::Io` 且
`kind() == TimedOut` 归一为 `RpcError::Timeout`，其余 IO 仍走 `Transport`。未改协议、
未改默认 30s、未改 `http` 模块的字节层语义。

## 实测结果

命令均从 worktree 根发起，`CARGO_TARGET_DIR` 指向本卡独立目录
`../target-shell-roundtrip`，经 `continue-20261017/bin/cargo` 的 flock 包装器执行：

```text
cargo test   -p lengsuo-shell --locked --offline   29 passed / 0 failed（连跑 3 次一致）
  src 单元测试 9 + gateway_events 8 + gateway_handshake 3 + gateway_roundtrip 9
cargo clippy -p lengsuo-shell --all-targets --locked --offline -- -D warnings   Finished，无警告
cargo fmt    -p lengsuo-shell -- --check   通过
python scripts/check_line_limit.py   Checked 411 files; hard-limit failures: 0
```

行数（400 软 / 700 硬）：`gateway_roundtrip.rs` 347、`gateway_events.rs` 269、
`gateway_handshake.rs` 113、`tests/support/mod.rs` 376、`src/gateway/rpc.rs` 320。
`check_line_limit.py` 的 4 条 WARN 均属其他 crate 的既有文件，本卡文件无 WARN。

## 明确未做（不声称已具备）

- 未起真实 `agent-gateway` 服务端：以上只证明**客户端 ↔ mock** 的有限回环语义，
  不证明与真实网关服务端互通；服务端并发 50 会话、握手文件 ACL、事件分页回溯等仍未验收。
- 未做 GPUI 渲染（阶段二 `ui` feature 范围）。
- 未覆盖 WS 断线后的重连与 `seq` 续传（协议里尚未定型，留待服务端实现后一并验收）。
- 未跑 workspace 级门禁：同一 workspace 有多条并行任务线，按项目约定只保本 crate 全绿。
