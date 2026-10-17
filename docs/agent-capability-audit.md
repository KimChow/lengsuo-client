# Agent 能力核验矩阵（只读核验，2026-10-17）

> **性质**：对已合并 agent 模块的**能力核验**，不是新实现记录。本卡只改本文；未改任何代码或其他文档。
> **基线**：分支 `codex/continue-capability-audit`，HEAD `eb02d93888c0fe537f002f1157c55eedbff0e851`（工作树核验前后均干净）。
> **方法**：逐 crate 跑现有测试（`cargo test -p <crate> --locked --offline`，经 PATH 上的 flock cargo 包装器，`jobs=1`），代码走查核对公共入口与运行时连接，文档声明与代码逐条对照。
> **不在范围**：agent-gateway 服务端、GPUI 实体界面、运行时记忆接线（另有三张任务卡在进行），本卡不重复开发、不实现新范围。

## 1. 三层区分（本文统一口径）

- **库测试通过**：crate 自身 `cargo test -p` 退出 0，且断言覆盖所声称的语义。
- **运行时已接入**：域逻辑被工作区内**另一个 crate** 在自己的 Cargo.toml 里引用并在代码中调用。
- **UI 可用**：存在可执行的界面路径（GPUI 渲染或二进制入口 `[[bin]]`/`main.rs`）。

本次核验的 agent 模块内**没有 `[[bin]]` 或 `main.rs`**。因此本次核验的所有 agent crate 均为「无 UI 可用」。

## 2. 依赖接线事实（决定性证据）

```text
agent-core      -> agent-memory                （唯一的 agent 跨模块边）
agent-gateway   -> agent-core
lengsuo-shell   -> tokio/serde/tokio-tungstenite（不依赖 agent-core / agent-gateway）
agent-mcp / agent-skills / agent-prompts / agent-tasks /
credential-ref / policy-engine
                -> 无 agent 侧依赖，且无任何 crate 依赖它们（孤儿）
```

`grep -rl <name> --include=Cargo.toml crates/` 对 agent-mcp / agent-skills / agent-prompts /
agent-tasks / credential-ref / policy-engine **六个 crate 的命中只有其自身 manifest**。
即：除 `agent-memory`（被 agent-core 引用）与 `agent-core`（被 gateway 引用，但 gateway 实现为空）外，
六个模块既不被运行时引用，也不互相引用。

`use agent_mcp|agent_skills|agent_prompts|agent_tasks|credential_ref|policy_engine`
在全工作区 `*.rs` 的命中**只出现在各 crate 自身的 `tests/` 与文档示例**，没有任何生产调用点。

## 3. 核验矩阵

| crate | 实测 passed/ignored（退出码） | 公共入口 | 运行时已接入 | UI 可用 | 状态判定 |
|---|---|---|---|---|---|
| `agent-core` | 40 / 0（0）；lib 单测 0，测试全在 `tests/`（memory_integration 7、permission 9、redact 6、replay 11、schema 7） | `Runtime`/`RuntimeBuilder`、`PermissionGate`、`JsonlEventLog`、`Redactor`、`ToolRegistry`、`Provider`（仅 Echo + 占位） | 部分：仅 `agent-memory`；`agent-gateway` 声明依赖但 lib 为空 | 否 | **待验收**（域逻辑最完整，但宿主链未闭合） |
| `agent-gateway` | **0 / 0**（0） | `src/lib.rs` = 1 字节（单个换行），**无任何公共 API** | 否 | 否 | **缺实现**（§2 协议 v0、`/rpc`、`/events`、token 鉴权、握手文件全部未落地；历史收门的「已完成」说法不成立） |
| `policy-engine` | 32 / 0（0）（lib 单测 0；pattern_wildcard 20、spec_model 12） | `model::{PolicySpec,RuleItem,Action,Actions,PolicyMode,Targets,ActiveRange,…}`、`pattern::{Pattern,NormalizedUrl,Specificity,more_specific}` | 否 | 否 | **缺实现**（只有数据模型 + URL 通配匹配原语，**没有判定器**；详见 §4.1） |
| `credential-ref` | 62 / 0（0）（lib 单测 18 含 container_tests；contract 10、file_store 18、memory_store 13、write_race 2、zz_stress 1） | `CredentialRef/RefId/Scope/ScopeKind`、`SecretStore`、`MemoryStore`、`FileStore`、`Plaintext`、`KdfParams` | 否 | 否 | **库测试通过 + 一处必改缺陷**（§4.2 探针输出）；AAD 与 fail-closed 声称**成立**（§5） |
| `agent-mcp` | 18 / 0（0）**全部是 wire/mcp 两个模块的 serde 单测**（`protocol/mcp.rs` 7、`protocol/wire.rs` 11）；`tests/` 无 `.rs` | `McpClient`、`ClientConfig`、`Framing`、`StdioServerCommand`、协议类型、`NotificationReceiver` | 否 | 否 | **待验收/未验证**（stdio 传输、并发、超时、poisoned、子进程回收**零测试**；§4.3） |
| `agent-tasks` | 27 / 0（0）（lib 单测 0；board 12、state_machine 7、json_contract 5、errors 3） | `TaskBoard`、`Task`、`TaskStatus`、`TaskError`、`NowMs`；`to_json/list_by_session` | 否（上层「会话存储与工具接入」不存在） | 否 | **库测试通过 / 未接线**；规格文件缺失（§4.4） |
| `agent-skills` | 26 / 0（0）（lib 单测 0；parse 16、registry 9、+1 doctest） | `SkillRegistry::{with_dirs,load,find}`、`parse_skill_md`、`Skill`、`MAX_SKILL_BYTES` | 否：**无人注入** | 否 | **库测试通过 / 未接线**（§4.5：注入授权与脱敏在 crate 外且宿主未实现） |
| `agent-prompts` | 24 / 0（0）（modes 11、vars 12、+1 doctest；lib 单测 0） | `Composer::{build,plan_gate}`、`PromptMode/PromptVars/PromptTemplate/Segment` | 否 | 否 | **库测试通过 / 未接线**（`Runtime` 不调用 Composer，`memory_digest` 算了也没进任何提示词；§4.6） |
| `agent-memory` | 31 / 0（0）（daily_tests 14、engine_tests 17；lib 单测 0） | `MemoryEngine`、`MemoryBundle`、`append_daily/read_daily_tail/clear_daily`、`MemoryPaths`、`Identity`、容量常量 | **是**（agent-core 引用） | 否 | **已接入，但注入链未闭合**：digest 进 `Session.memory_digest` 后无消费者；写入脱敏靠调用方自觉（§4.7） |
| `lengsuo-shell` | 9 / 0（0）**仅 `gateway/rpc.rs` 的信封映射单测** | `GatewayClient`、RPC 信封/`action` 白名单、`GatewayHandshake`、事件流、五个视图状态类型 | 否（不依赖 gateway） | 否（无 gpui；`ui` feature 为空占位） | **待验收**：§6 要求的「网关客户端对 mock 的 roundtrip」**未执行**，mock 支持模块无人引用（§4.8） |

合计（agent 线）：**269 passed / 0 failed / 0 ignored，全部命令退出码 0**。
本次单 crate 命令未执行 doctest 之外的重复计数；doctest 命中 2 个（prompts、skills）。
工作区层面：20 个 ignored 用例全部在**网络线**（vless/trojan/ss2022/shadowsocks/anytls 的 xray 互通与 Windows TUN 设备），与本卡的 agent 模块无关，agent 侧 ignored 为 **0**。

## 4. 缺陷与最小可复现步骤

以下均为**核验发现**，本卡未修复。复现命令统一在 worktree 根、经 PATH 包装器执行。

### 4.1 policy-engine 没有判定器（文档承诺 > 代码事实）— 高

`src/lib.rs` 声称「没有任何策略命中、策略取不到、生效时间窗不在窗内 ⇒ 一律拒绝并在
`Decision::reasons` 标明 fail-closed 原因」；POLICY-SPEC §2.1 定义
`EvaluateRequest{url,action,now_ms,targets_ctx}` → `Decision{allowed,matched_rule,reasons}`。
代码中**不存在** `EvaluateRequest`、`Decision`、任何 `evaluate` 入口；
`Actions::enabled`、`ActiveRange::contains`、`Pattern::is_match`、`more_specific` 在 crate 内部也**没有任何调用点**，
即优先级（SpecialCase > 白 > 黑）、白覆盖通配、时间窗、`is_log`、7 操作判定全部未实现。

结论：**策略未真实接入，且连「可被接入的判定 API」都还没有**。「deny-by-default 策略引擎已完成」不能对外说。

最小复现：

```sh
grep -rn -E 'EvaluateRequest|struct Decision|fn evaluate' crates/policy-engine/   # 仅文档注释命中，无定义；退出码 1
cargo test -p policy-engine --locked --offline                                    # 退出 0，32 passed —— 通过的是模型与通配单测，不含判定语义
```

待办（需新卡）：实现 `evaluate(&PolicySpec, EvaluateRequest) -> Decision` + fail-closed + 优先级 + 操作/时间窗，按 SPEC §3 补四类模式各 ≥2 例。

### 4.2 credential-ref 遗留调试探针（违反 §3 日志边界）— 高

`crates/credential-ref/src/file.rs:223-233`（`read_records`）对每次容器解码无条件 `eprintln!`，
输出字节数、`{:?}` 错误值与**凭据库完整文件路径**。由 `eb02d938` 引入（`git log -- crates/credential-ref/src/file.rs`）。

实际输出（真实运行，非推断）：

```text
[probe] decode ok bytes=206 records=1
[probe] decode err bytes=204 err=WrongPassphrase file=/tmp/lengsuo-credential-ref-tests/tamper-header-2613074-14/creds.bin
```

不含明文/口令/salt/密文（错误类型 `StoreError` 的 Display 本身是掩码的），因此不是凭据泄露；
但它（a）是无条件 stderr 噪声，（b）把用户凭据库路径打进日志，（c）位于库代码而非测试，
与 AGENTS.md §3「日志不得输出…」及「移除调试打印」的既有基线相冲突，也与 `container.rs` 手工 `Debug`
刻意不呈现字节的取向相反。

最小复现：

```sh
cargo test -p credential-ref --test file_store --locked --offline -- --nocapture
# 退出 0（18 passed），stderr 出现上面的 [probe] 行
```

待办：删除该 `eprintln!` 块（或降为 `tracing` debug 且不带路径）。一行级修复 + 现有断言不变。

### 4.3 agent-mcp 的关键语义零测试 — 高

`crates/agent-mcp/tests/` 只有一个 **未被任何 Rust 测试引用的** `fixtures/mcp_fixture_server.py`
（`grep -rn mcp_fixture_server crates/` 只命中该文件自身的用法注释）。
18 个通过用例全在 `src/protocol/{mcp,wire}.rs` 做 JSON 形状往返。
`transport.rs`（spawn、`kill_on_drop`、stderr null）、`client.rs`（握手、翻页、`shutdown`/`exit`、grace 强杀）、
`session.rs` 与 `session/{read,reader,notify,state}.rs`（id 关联、并发复用、超时 → `poisoned`、`fail_all`、
慢订阅者滞后丢弃）**没有一个测试**。

即：lib.rs 文档里「超时后会话标记 poisoned，后续请求 fail-closed」「单连接并发复用」
属于**未被验证的声明**。MCP stdio 异常/超时路径按本卡要求专项核验的结论是：**代码有实现形状，无测试证据，不能验收**。

最小复现：

```sh
cargo test -p agent-mcp --locked --offline                # 退出 0，18 passed，且只列出 unittests + doctest 两行（无 tests/ 目标）
grep -rn 'mcp_fixture_server' crates/                     # 无引用
```

待办：用现成 fixture 补 stdio 集成测试——握手、并发 20 请求 id 不错配、请求超时 → `is_poisoned()` 且后续请求立即失败、
对端 EOF/子进程被杀 → 在途请求失败、`shutdown` 后无孤儿进程、`lsp` 与 `line` 两种分帧、超长帧拒绝。需要 dev-dependency（现有仅 `tokio` rt/test-util）。

### 4.4 agent-tasks 规格文件不在仓内 — 中

`src/lib.rs` 写「规格源：worktree 根 `TASKS-SPEC.md`（字段名、方法签名与状态机均冻结）」，
根目录只有 AGENT-KICKOFF/MEMORY/POLICY/PROMPTS/SKILLS-SPEC.md，**没有 TASKS-SPEC.md**（`ls TASKS-SPEC.md` 退出 1）。
状态机与 `to_json` 字段契约的用例在，但**可核对的权威规格缺失**，冻结声明无法验证。

待办：把规格正文落仓（或改指真实来源），否则「契约已冻结」表述应降级。

### 4.5 Skills 注入与授权：边界正确，但授权链只存在于文档 — 中

crate 侧事实（正确）：`SkillRegistry::load/find` 只「发现 + 解析 + 同名后覆盖」，
`Skill.body` 是**去 front-matter 的全文**，crate **不做注入、不做权限判断、不判会话可见性**（lib.rs 明示）。
fail-closed 已测：坏文件整体失败、根目录不存在 `NotFound`、32 KiB 上限、name 字符集。

缺口：
1. **谁对哪个会话可见、经谁授权注入**没有实现——因为没有宿主调用 `find()`（§2）。AGENTS.md §6
   「智能体仅访问获授权的资料」「工具权限由运行时强制检查，文档不能扩大授权」目前对本 crate 无落点。
2. **技能正文 = 未信任内容**。一旦宿主把 `body` 整段拼进 system 消息，`SKILL.md` 作者即获得 system 位写入权，
   可覆盖 §4.6 的模式硬规则文案；宿主侧必须（a）对 body 过 `Redactor`，（b）不允许其影响工具白名单/审批，
   并在事件流标记来源。当前**无任何防护实现或测试**。

待办：定义注入授权点（会话可见集 + 用户显式启用），并补「技能正文含伪指令/含凭据样式串」用例。

### 4.6 agent-prompts 与权限分离：提示词有门禁语，运行时没有配套接线 — 中

事实：`Composer::build(mode, vars)` 纯函数、无 IO、无时钟；模板含
「每个工具调用都必须真实发起，由运行时权限门裁决；被拒绝或待确认时不得假装已执行」，
`plan_gate()` 明确「批准之前不得承诺…发起写入、删除、命令执行、外部网络或浏览器动作」。

问题（提示词 vs 权限分离的角度）：
1. **提示词是唯一的门禁表达**，真正的强制点 `PermissionGate::check`（deny-by-default、敏感动作强制 ask）
   在 agent-core 内**没有任何调用方**（无宿主）。也就是说：门禁只有「模型自觉」这一半被接上了，
   「运行时强制」那一半在 gateway 为空的情况下**无从生效**。
2. `PromptVars.memory_digest` 字段存在，但没有任何代码把 agent-core 算好的 digest 交 `Composer` 使用
   （agent-core 不依赖 agent-prompts）。跨会话记忆的「默认关 → 开启后注入」路径**只在测试里闭合**，产品链断裂。
3. 提示词不区分「未信任工具输出」与用户/技能文本，宿主若把 `tool_result` 原文塞回 `user_rules`
   等变量位，即构成间接提示注入通路——需在宿主侧限制变量来源，本 crate 未提供任何标记或转义工具。

待办：gateway/宿主接线时以 `Composer` 为唯一 system 生成入口，并在同一提交里给出「提示词声明 ask 而 gate 判 deny」的一致性用例。

### 4.7 agent-tasks/agent-memory：唯一真实接入的一条链，仍有半截

`Runtime` 的接入事实：`memory_enabled` **默认 false**（config.rs），开启时 `create_session` 调
`MemoryPaths::new(workdir/.lengsuo, workspace_root)` → `MemoryEngine` 组 digest 存入 `Session.memory_digest`；
失败发 `memory_compose_failed` 事件且不阻断（与集成文档声明一致，memory_integration 7 例覆盖）。
`execute_memory_tool` 暴露 `memory.append_daily/set_user/set_project/identity.set_soul`，成功后发 `memory_update`。

缺口：
- `Provider::next_steps(session_id, user_text)` **不收 system 提示词、不收历史消息**，digest 除存入结构体
  与 `Session::summary` 里透出外**无任何消费者** ⇒ 「会话 memoryDigest 注入」在运行语义上未闭合。
- `execute_memory_tool` 的文档注释写「权限门放行后由宿主调用」，但函数内部**不做 check**，
  仓内也没有宿主调用它 ⇒ 该前置条件当前由**约定而非代码**保证。
- 写入路径（`append_daily`/`set_*`）不落脱敏：crate 与 MEMORY-SPEC 都把脱敏推给调用方，
  而 `execute_memory_tool` 直接透传 `args` 文本 ⇒ 「凭据绝不入内」目前只是文档意图。

待办（属记忆任务卡范围，本卡不实现）：digest → provider 输入通道；执行体内部强制 check；写前过 `Redactor`。

### 4.8 lengsuo-shell：§6 的 mock roundtrip 未执行 — 高

`tests/support/mod.rs` 是一份完整的 mock 本地网关（RPC 信封、原始状态码、挂起不回答驱动超时、
WS 推送、握手文件、token 记录），文件头写明「覆盖 AGENT-KICKOFF §6 对 lengsuo-shell 的要求：网关客户端对 mock 的 roundtrip」，
并带 `#![allow(dead_code)]`。但：

```sh
ls crates/lengsuo-shell/tests/          # 只有 support/ 一个目录，无测试目标文件
grep -rn 'mod support' crates/lengsuo-shell   # 无命中
cargo test -p lengsuo-shell --locked --offline  # 退出 0，仅 9 passed，全部在 src/gateway/rpc.rs
```

⇒ `GatewayHandshake` 读文件与 token 驻留、`http.rs` 真实收发、`events.rs` WS 订阅顺序、
三个视图状态机的聚合/错误路径**零测试**；「无头环境跳过渲染断言」是允许的，
但连**纯逻辑的客户端 roundtrip 也没有**。UI 可用性：无（无 gpui 依赖，`ui = []` 空 feature）。

待办：补 `tests/rpc_roundtrip.rs`/`tests/events.rs`/`tests/handshake.rs` 使用现有 mock（无需新依赖）。

### 4.9 agent-core 运行时执行链自身缺口（属 gateway 任务卡的邻接面，仅记录不实现）— 中

- `run_turn` 把 `ProviderStep::ToolCall` **只发成 `tool_use` 事件，不执行工具、不查 gate、不发起审批**；
  `check_tool`/`respond_approval`/`wait_approval` 是公开入口但无仓内调用者，`ToolRegistry` 也**没有任何内置工具执行体**。
  ⇒ 「工具使用受控凭据引用」「审批挂起等待 approval:respond」缺 **编排器**：把 check → 审批 → 执行 →
  `record_tool_result` 串起来并强制 deny 的那段代码不存在。
- `blobs::CredentialResolver::resolve` 的桩实现固定返回「凭据库未接入」——与 §2 一致：
  `credential-ref` 从未被接入，工具参数里的 `cred_ref` 无法解析成真值。这是**有意的 fail-closed 桩**，不是漏洞，
  但对外不能称为「凭据引用化已可用」。
- `agent-core`/`agent-gateway`/`agent-memory`/`agent-prompts`/`agent-skills` 无 `#![forbid(unsafe_code)]`
  （其余模块有）。全仓 agent 代码当前 `unsafe` 出现次数为 0，属一致性缺口而非现实漏洞。

## 5. 本卡核验项的逐条结论（凭据/超时/授权/状态机/策略）

| 核验点 | 结论 |
|---|---|
| MCP stdio 异常与超时 | 代码存在 `tokio::time::timeout_at` + `poison` + `fail_all` + `EXIT_GRACE` 强杀 + `kill_on_drop`，语义为 fail-closed；**零测试证据**（§4.3），不验收。 |
| Skills 注入授权 | crate 明确不做注入/授权（边界正确）；**宿主授权点未实现**，未信任正文直入 system 的风险无人拦截（§4.5）。 |
| 提示词与权限分离 | 提示词只做声明，`PermissionGate` 判定与提示词**互不影响、互不引用**（gate 不依赖 prompts crate）——分离方向正确；但强制点无宿主调用（§4.6/§4.9），实际未生效。 |
| 任务状态机 | `Pending→InProgress→{Done,Cancelled}`，终态不可出，同状态幂等；7+12+5+3 例覆盖，含 JSON 字段名契约。**唯一缺陷是规格文件缺失**（§4.4）。 |
| 凭据只引用 | `CredentialRef` 只承载元数据且 `Debug/Display` 恒掩码；明文只在 `Plaintext`（`Zeroizing`）内短暂存在；`cred_ref` 在 agent-core 是**字符串引用**，解析桩 fail-closed。**已核实成立（库级）**，但未接入任何工具执行路径。 |
| AES-GCM 头部 AAD 绑定 | **核实成立**：记录 AAD = 完整 header 字节 ‖ `index u32`（`record_aad`）；verifier AAD = `magic..verifier_len` 前缀；每次写重新生成 salt 与新 nonce，`flush_locked` 全程持锁。已有用例覆盖：篡改记录字节 / 篡改元数据长度 / 记录搬到另一文件 / 未知 schema 版本拒绝解密 / 头部截断 / `container_exposes_no_plaintext_or_metadata` / `every_truncated_prefix_fails_closed`。**顺序值得肯定**：`decode_container` 先认证 verifier（头部全字节被 AAD 绑定）再判版本门，故版本字段被篡改不会绕过认证。 |
| 策略是否真实接入 | **未接入，且判定 API 缺失**（§4.1）。 |

## 6. 与既有文档的一致性核对

| 文档声明 | 核验结果 |
|---|---|
| `docs/agent-integration-status.md`：workspace `cargo test` 122 组、733 passed / 0 failed / 20 ignored | 与本卡 agent 子集不冲突（269 passed / 0 ignored 全部退出 0）；ignored 20 例确认为网络线 xray/Windows 用例，**不构成 agent 验收**。 |
| 同上：「M2 包含…会话 memoryDigest 注入、四个记忆工具执行体与 memory_update 事件」 | 代码属实（§4.7），但**「注入」到模型输入未闭合**（digest 无消费者）。文档若被读成「记忆已进对话」则不一致。 |
| 同上：「已实现的模块包括 agent-core/gateway…」 | **不一致**：`agent-gateway` lib 为 1 字节空文件、0 测试、0 API。 |
| `agent-core` 内 `execute_memory_tool` 注释「权限门放行后由宿主调用」 | 无宿主、无内部 check ⇒ 条件性声明当前不成立（§4.7）。 |
| `credential-ref` lib.rs「错误信息与 Debug 不含明文、口令、salt 或密文」 | 成立；但 §4.2 的探针输出与「日志不含敏感值」的精神冲突（含路径与错误类型）。 |

## 7. 下一批窄卡建议（按优先级，每张都限定单 crate 与可验证退出标准）

1. **C-01 修复 credential-ref 调试探针**（最小卡）：删除 `file.rs` 两处 `eprintln!`；
   现有 62 例断言不变，验收 = `cargo test -p credential-ref --locked --offline` 退出 0 且 `-- --nocapture` 无 `[probe]` 行。
2. **C-02 policy-engine 判定器**：新增 `evaluate` + `EvaluateRequest`/`Decision`，实现 SPEC §2.1–2.7 优先级/操作/时间窗/`is_log`，
   按 §3 补齐四类模式与 fail-closed 用例（先红灯）；只改 `policy-engine`，不接宿主。
3. **C-03 MCP stdio 集成测试**：以现有 `mcp_fixture_server.py` 为子进程夹具补 §4.3 用例（超时→poisoned、并发 id 不错配、
   EOF、无孤儿进程、两种分帧、超长帧）；只改 `agent-mcp/tests`（+dev-dependencies 需求见 §8）。
4. **C-04 shell roundtrip 测试**：把已存在的 `tests/support` mock 接上三个测试目标；只改 `lengsuo-shell/tests`。
5. **C-05 编排器（gateway 卡的邻接）**：在 `agent-core` 内实现 `check → approval → 执行 → record_tool_result` 强制链，
   并为「gate deny 而提示词声明 ask」加一致性用例。**不得与三张在途 gateway/GPUI/记忆卡重叠**，需主理人划定边界后再开。
6. **C-06 规格与状态归位**：补 `TASKS-SPEC.md` 入仓；给缺 `#![forbid(unsafe_code)]` 的四个 crate 补齐；
   把 `agent-integration-status.md` 中 gateway 的「已实现」改为「未实现/在途」。

**明确不在本卡范围、不得顺带实现**：真实 LLM/provider（仅 Echo + 占位，已标规划）、GPUI 实体界面、
定时自动化、终端 sidecar、插件扩展、浏览器工具（`BrowserTool` 仅 trait 占位）、fjall 存储实现、
HTTP/SSE 传输与 MCP resources/prompts 面。以上均仍是**规划/未实现**。

## 8. 依赖与命令记录

| 命令（worktree 根执行） | 退出码 | 实测 passed / ignored |
|---|---|---|
| `cargo test -p agent-core --locked --offline` | 0 | 40 / 0 |
| `cargo test -p agent-gateway --locked --offline` | 0 | 0 / 0 |
| `cargo test -p agent-mcp --locked --offline` | 0 | 18 / 0 |
| `cargo test -p agent-memory --locked --offline` | 0 | 31 / 0 |
| `cargo test -p agent-prompts --locked --offline` | 0 | 24 / 0（含 1 doctest） |
| `cargo test -p agent-skills --locked --offline` | 0 | 26 / 0（含 1 doctest） |
| `cargo test -p agent-tasks --locked --offline` | 0 | 27 / 0 |
| `cargo test -p credential-ref --locked --offline` | 0 | 62 / 0（zz_stress 单例约 42s） |
| `cargo test -p policy-engine --locked --offline` | 0 | 32 / 0 |
| `cargo test -p lengsuo-shell --locked --offline` | 0 | 9 / 0 |
| `cargo test -p credential-ref --test file_store -- --nocapture` | 0 | 18 / 0，复现 §4.2 探针输出 |
| `python3 scripts/check_line_limit.py` | 0 | 390 文件，硬失败 0（WARN 为 >400 软目标项） |
| `cargo tree -p agent-core --offline --locked` | 0 | 确认 agent-core 只依赖 agent-memory |

- 全程使用 `CARGO_TARGET_DIR=/home/ubuntu/lengsuo-client-dev/continue-20261017/target-capability-audit`，
  经 PATH 上的 `flock` cargo 包装器串行执行，`jobs=1`，`--offline` 命中既有依赖缓存，**无网络失败**。
- 未修改根 `Cargo.toml`/`Cargo.lock`。若 C-03 需要新 dev-dependency（例如为 fixture 客户端补 `tokio` 的 `process`/`test-util`
  之外的项），须另行走依赖需求记录，本卡未试验任何依赖变更。
- 未执行 `--workspace` 门禁（依项目记忆：本任务线只跑 `-p` 相关 crate）。
- 本卡唯一写入文件：`docs/agent-capability-audit.md`。
