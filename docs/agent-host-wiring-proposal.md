# Agent宿主接线说明（未实施，待依据既有基线修订）

## 原因与范围

六个基础库已存在但无人调用；仅补库测试不能形成智能体运行链。
AGENTS要求新模块先说明接口、兼容范围和测试计划，确认后实现。
本提案新增agent-host宿主模块，负责把已有库接起来；不包含真实远程LLM、终端sidecar、定时自动化、
浏览器实际执行、服务端权限/计费/节点池。平台权威判定仍在私有仓。

## 接口与依赖

- agent-host依赖agent-core、agent-prompts、agent-skills、agent-tasks、agent-mcp、credential-ref、policy-engine。
  agent-core保持同步域接口，不引入tokio或依赖宿主。
- HostConfig固定身份/租户/环境和获授权workspace，技能目录/MCP服务由宿主显式注册，默认均空。
- ContextProvider.next(TurnContext)返回文本或ToolCall步骤；TurnContext含会话ID、脱敏历史、
  Composer产出的系统提示词、已授权Skills正文、memoryDigest、可见工具元数据，不含凭据值。
  先提供Echo/测试适配器，未配置真实模型时明确Unsupported，不静默回退。
- ToolExecutor.execute(ExecutionContext, ToolCall)为异步、有界入口；参数只含凭据引用。
  必须经过check_tool→若Ask等待审批→获准后执行→脱敏→record_tool_result。
  Deny/超时/停会话均不得执行；审批绑定会话和工具调用，不可跨隔离范围复用。
- 内置执行适配仅覆盖既有记忆、任务板与显式注册MCP工具；不新增shell命令执行或浏览器副作用。
- 凭据只在受控执行适配器内按Scope解析，回填结果与错误先脱敏，凭据值不进Provider/事件/日志。
- PolicyEvaluator只用于已定义URL操作本地限制；不取代服务端授权。策略缺失/失败按fail-closed。
- GatewayBackend兼容适配：现有GatewayHandle::start(Runtime,...)继续可用；新增宿主适配入口，
  沿用已冻结RPC/WS wire格式，session:send委托宿主有界回合。旧库调用方无需迁移。

## 验收与门禁

先失败用例：capture Provider必须实际收到Composer/Skills/memory；未授权技能/MCP不出现；
工具deny不执行、ask批准后只执行一次、审批超时与停止均不执行；
跨用户/租户/环境/会话不串任务、记忆、凭据或事件；大输出仅引用，假秘密不进Provider与持久日志；
真实Python MCP通过宿主调用并记录tool_result，失败不自动重试有副作用工具；
真实GatewayClient→GatewayBackend→宿主→工具→WS端到端用例，所有IO有限timeout。

默认关闭跨会话记忆及外部工具；限制回合最大步骤/单步超时/输出大小；整数计量。
保留已有269+新增测试，不用mock替代声称真实的链路。
每个功能一commit、代码文档测试一致；700硬400软、全workspace门禁与SHA核对继续执行。

本提案待用户确认后实施；与当前网关/记忆/策略/MCP/shell修复相互独立。

## 2026-10-17 文档复核结论

用户要求先核查wb。已在PC07/09/10/18/19/21/22找到明确行为依据，且私有仓N5/N7/N8已采纳。
因此本提案不作为新架构决策，不据此直接新增agent-host crate；后续回到既有core/gateway分层细化。
Skills常驻仅metadata，正文经Skill按需加载；MCP配置保存不自动启动，需显式Trust并支持server/tool双层开关。
具体来源与取舍统一见私有仓docs/workbuddy-agent-baseline.md §10，不复制为第二份权威规格。
本文件不表示用户已批准新增公共接口或模块，也不表示上述接线已经实现。
