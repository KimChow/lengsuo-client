# Agent 集成状态（2026-10-17）

## 本批范围

初验基线 main：`12ca596501aabfb78025c8d0b99dd07eb2166370`。
交付接入最新 main：`b6611a5d96ff2ac23d67019375d1034c99cfc92d`（VMess 地址修复）。
来源：`agent/integration-batch2` / `f16bd6ab42a56273bfc216a3ab0b424ea9a40512`。
以单个集成提交引入最终源码；不引入来源分支中的 Cargo 缓存、构建产物和临时探针历史。
保留 main 最新 golden 向量、nonce 与 CRC 断言，不回退网络线修复。

已入仓的模块包括 agent-core/gateway、policy-engine、credential-ref、agent-mcp、
agent-skills、agent-prompts、agent-tasks、agent-memory，以及 lengsuo-shell 的纯逻辑骨架。
M2 包含默认关闭的 memoryEnabled、会话 memoryDigest 注入、四个记忆工具执行体与 memory_update 事件。
记忆注入失败告警但不阻断会话；工具执行体测试不代表所有宿主调用链权限验收完成。

## 集成整理与验证

首轮行数检查复现 runtime.rs 728 行、session.rs 753 行、container.rs 704 行超限。
按职责拆出运行时构造器、MCP 读循环、凭据容器测试，保留现有测试断言。
超过 400 行的现存运行时及会话状态协调模块暂保留，避免本次扩大状态机重构；
所有文件仍须通过 700 行硬门禁。部分集成测试超过软目标，以完整场景组织，后续按场景拆分。
新增忽略规则防止再次跟踪隔离 target、Cargo 缓存与本机 .cargo 配置。

研究机 47 使用独立 target `/home/ubuntu/lengsuo-client-dev/target-verified-20261017`。
执行行数、编译 profile、fmt、clippy（all-targets，deny warnings）、locked workspace test/build。
Cargo 使用 --offline，仅使用已有依赖缓存；不提交机器镜像配置。
验证结果（以下命令均退出 0）：

| 检查 | 结果 |
|---|---|
| `python3 scripts/check_line_limit.py` | 387 文件，硬上限失败 0 |
| `python3 scripts/verify_build_profiles.py` | dev/release/test 通过 |
| `cargo fmt --all -- --check` | 通过 |
| `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` | 通过 |
| `cargo test --workspace --locked --offline` | 122 组结果，733 passed / 0 failed / 20 ignored |
| `cargo build --workspace --locked --offline` | 通过 |

20 个 ignored 用例未由本次默认测试命令执行，不能算作真实参考端或平台验收通过。
原始日志位于研究机 `/home/ubuntu/lengsuo-client-dev/verify-{lines,fmt,clippy,tests,build}.log`。
依赖 manifest 的本地辅助抽查不代替完整许可证审计；未缓存的平台包尚未核验。

## 未完成范围

- GPUI 实体界面未实现，shell 的 ui feature 仍为占位。
- 定时自动化、终端 sidecar、插件扩展不在本次验收范围。
- 本次 Linux 工作区测试不代表 Windows 平台、浏览器 TUN 或八协议完整互通通过。
- 许可证检查尚无自动化覆盖，本次不宣称已由 CI 审核。

VMess 最新 main 更新不改 agent 模块；接入后补跑 VMess 测试、全工作区 clippy/build 与静态门禁。

## 实际能力复核（2026-10-17）

此前全绿仅说明已有测试通过，不能作为全部功能交付的证据。
agent-gateway 当前无服务端实现；policy-engine 缺完整判定器；MCP 缺 stdio 集成验收；
Skills/Prompts/Tasks/MCP/凭据/策略未接入运行时。详见 [能力核验矩阵](agent-capability-audit.md)。
记忆路径与落盘脱敏新增回归测试已复现缺陷，修复验收前不得宣称记忆安全路径完整。

## 后续修复进展

记忆安全回归与凭据stderr输出修复已提交；网关现有RPC/WS实现在7项真实回环测试通过后接入。
网关Unix握手权限已测，Windows ACL未实现；仅Echo provider，不宣称真实模型或工具编排完成。
历史能力核验矩阵描述eb02d938基线，最新网关实现见agent-gateway-status.md。

本批安全修复与真实网关/壳客户端联调集成后，workspace完整门禁再次通过：
行数/profile/fmt/clippy/test/build均exit 0；测试合计780 passed / 0 failed / 23 ignored。
日志agent-next-final-{lines,clippy,tests,build}.log位于研究机仓外，不入库。
