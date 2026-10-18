# 参考端 资产 · 提示词体系架构（分层组装 / 模板矩阵 / 片段 / 风格 / 变量）

> 来源：参考端 pc-devguide 07《提示词系统》§2-§7、18《Agent运行时深挖》§13、21《工具宇宙与Fragments全文收编》§5-§6。
> 体例：忠实转写（含原文英文段落逐字照录），除 参考端文档记载外不加任何内容。

## 1. 分层组装模型（07 册 §2）

```
最终 system prompt =
  主模板（模式 × 变体选 1 个 .tpl）          # prompts/templates/
+ 模式行为片段（agent-loop/tool-use/…）      # interactionmode/*/fragments/
+ prompt-common 共享片段（A2A/记忆/企微路由） # {% include %} 组装
+ 风格层（7 选 1）                           # style/*.md
+ 身份注入（user-context-identity.tpl）
+ 模式提醒（ask/craft-mode-reminder.tpl）+ system-reminder（工具结果回填容器）
```

引擎 **nunjucks**；模板里大量 `{% if IsWindows %}`/`{% if IsOversea %}`/`workMode` 条件分支靠它。

## 2. 每轮请求的完整组装顺序（18 册 §13）

```
system = 主模板(模式×变体)                      # section 顺序见本文件 §3
       + prompt-common 共享片段（A2A/记忆/企微路由，{% include %}）
       + <identity_context>（user-context-identity.tpl）
       + <tone_and_style>（风格层，MUST adopt，"风格只影响怎么说不影响说什么，
          准确性优先级高于风格"）
       + <user_custom_instructions>（userRules，"除非与安全规则冲突必须遵守"）
       + <product_identity>（"You are {{productName}}, a powerful AI assistant."）
messages = [system] + session.messages(含工具消息) + user
运行时追加：<craft_mode>/<ask_mode> 提醒 + <system-reminder>(工具结果/用户消息内注入)
```

每轮消息流（07 册 §7）：

```ts
messages = [
  { role: 'system', content: renderedSystemPrompt },   // §1 拼装产物
  ...session.messages,                                  // 历史（含工具消息）
  { role: 'user', content: userInput }
]
// 上下文管理：超过 api.contextWindowSize 80% 时折叠最老 20% 轮次
// 简单版：直接丢老轮次 + 插"早期对话已折叠"摘要；LLM 摘要版后置
```

## 3. 模板矩阵（07 册 §3，磁盘实证 11 个主模板）

| 模板 | 大小 | 用途 |
|---|---|---|
| ref-client-prompt.tpl | 31KB | 通用主模板（craft"普通"场景回落到这里） |
| ref-client-ask-prompt.tpl / -code- / -coding- | 10.7/10.7/8.8KB | ask 三变体（按话题类型选） |
| ref-client-craft-code- / -coding- / -design-prompt.tpl | 33.3/32.3/26.1KB | craft 三变体 |
| ref-client-expert-prompt.tpl / -code- / -coding- | 32.7/33.1/32.1KB | expert 三变体 |
| ref-client-quick-prompt.tpl | **525B** | quick 极简模板（全文见 system-prompt-quick.md） |
| ~~ref-client-craft-prompt.tpl~~ | — | **不存在（幽灵行）**：craft 只有 code/coding/design 三变体 |
| plan | **无专属模板** | 复用 craft + plan fragments 组装——**plan 不是另一种人格，是 craft 人格 + 门禁片段** |

**模式 × 变体选择规则 R07-1**：workMode 决定模板族；变体（普通/编程/设计）按会话话题类型选；productFeatures.* 开关裁剪段落（同一套模板服务多品牌/多功能组合）。

## 4. craft 模板 28 个 section 骨架（07 册 §3.1，grep 实证）

```
<user_query> <content_policy> <personal_files_safety> <windows_command_safety>
<regional_conventions> <working_modes> <agent_loop> <result_presentation>
<sharing_files> <final_answer_instructions> <automations> <tool_use>
<file_id> <doc_url> <instructions_for_visualizer> <user_info>
<visualizer_examples> <task_management> <example> <asking_questions>
<user-prompt-submit-hook> <tool_usage_policy> <system-reminder> <agent_mail>
<agent_skills> <available_skills> <expert_management> <mcp_configuration>
<response_language> <binary_context>
```

## 5. 模式行为片段清单（07 册 §3.3）

| 模式 | 片段（大小） | 内容 |
|---|---|---|
| craft(8) | agent-loop 1.2KB / tool-use 1.6KB / interaction 654B / current-mode 0B / task-management 848B / result-presentation 3.9KB / plugin-recommendation 4.3KB / browser-computer-use 899B | 完整行为面 |
| plan(5) | agent-loop / interaction(+Enter/ExitPlanMode 门禁) / task-management 2.3KB / result-presentation / tool-use | |
| expert(6) | agent-loop / current-mode / interaction / result-presentation / task-management / tool-use | |
| ask(6) | agent-loop(空) / current-mode / interaction / mode-behavior / result-presentation / tool-use | |
| quick(2) | current-mode / interaction | |

补充实证（21 册 §5）：
- ask/mode-behavior.md 除行为段外还有**第二层 system_reminder**（原文）：
  > "The user is in ask mode; only read-only tools are available. If write/edit/terminal tools are required, let them know they should switch to Agent mode."
  与 18 册 craft/ask-mode-reminder 形成三处只读冗余（fragment×2 + reminder×1）。
- **expert/fragments/current-mode.md 全文只有一行注释**：`{# {{ PluginAgentPrompt }} #}`——**专家模式的人格是纯变量注入点**，current-mode 片段是空壳。
- plan/fragments/current-mode.md 也是**空文件**——plan 的差异全部由"craft 工具集 + Enter/ExitPlanMode + plan 专属 task-management（1040B，比 craft 版多两个示例）"承载。

## 6. 模式提醒原文（18 册 §13，切换时追加）

- craft：
  > You are now in Agent mode. Continue with the task in the new mode, you can edit files freely...
- ask：
  > Ask mode is active... You MUST NOT make any edits, run any non-readonly tools (including changing configs or making commits)... **This supersedes any other instructions you have received**（包括此前收到的编辑指令）

ask 的只读约束**压倒一切先前指令**。

## 7. prompt-common 共享片段（跨模式公共层，category:"template" 插件）

07 册 §3.4 记载 4 个，21 册 §6 实证实为 **10 片段**：

| 片段 | 大小 | 机制（07 册原文要点） |
|---|---|---|
| agent-to-agent.md | 0.8KB | **A2A 协作协议**：先 `A2AGetAgentCard` 取目标能力卡（identifier 从 `<available_A2A_agents>` 原文复制），再 `A2ASendMessage` 委派；**委派消息必须自带完整上下文/目标/约束/预期产出**（目标代理看不到当前会话）；`A2AGetTask` 查进度、`A2ACancelTask` 终止；此路禁用 Agent 工具/ToolSearch |
| memory-context.md | 0.1KB | 三记忆变量注入点 |
| wecom-routing.md | 5.5KB | **企微双通道路由**（防模型按关键词乱路由）：聊天域只走 A2A 聊天代理，其余走 wecomcli-* 技能；**清单现场解析禁止凭记忆**；`AGENT_NOT_FOUND` = "你传的值是猜的"，重试用真实列表值绝不降级 |
| ref-client-memory-system.md | 3.7KB | 三层记忆提示词（30 天蒸馏）；`{% if LocalSkillsMemoryEnabled %}` 包裹 |

21 册 §6 新增 6 个企微/频道路由片段：`wecom-account-routing / wecom-chat-unavailable / wecom-cli-routing / wecom-connector-off / wecom-unified-connector-off / ref-client-channel-prompts`——企微路由的**全状态处理**。

**ref-client-memory-system.md 补充细节**（21 册 §6）：
- Layer 1 云画像**缓存在 `{{ClientUserMemoryDir}}/memory/`**，本地改动会被下次会话覆盖（"Do NOT modify locally"）；
- `conversation_search` **对当前会话零访问**——查询必须自包含（描述要找什么+时间范围背景）；触发例句原文（"我们之前讨论的 XX 方法是什么来着？"）；**不得用于查通用偏好**（那是画像的职责）；
- Layer 2 用户级：`{{ClientUserMemoryDir}}/MEMORY.md`，**用 Edit 工具原地更新**（非追加），4000 字符/会话上限，存"精确的强制规则"。

## 8. 七种语言风格（07 册 §4，style/*.md，与模式正交可热切换）

straightforward 直白（结论先行）/ friendly 友好 / professional 专业 / efficient 高效（bullet）/ sarcastic 嘚瑟（彩蛋）/ socratic 苏格拉底（启发提问）/ creative 创意（比喻）。经 `ToneStyleContent` 变量拼在 system 末尾，各 ~2KB。

## 9. 变量表（07 册 §5，nunjucks 注入，实测全集）

| 变量组 | 变量 | 来源 |
|---|---|---|
| 产品 | productName / dataFolderName / modelName | product config |
| 模式 | workMode / ResponseLanguage / BinaryContext / IsWindows / IsOversea / IsPersonalEdition | 运行时 |
| 功能开关 | productFeatures.{DisableMultimodalGeneration, BrowserUse, ComputerUse} / ExpertManagementEnabled | feature-flag |
| 记忆 | WorkingMemoryContent / UserLocalMemoryContent / UserMemoryContent / ClientMemoryA_1-3 / ClientMemoryB_1 | 三层记忆 |
| 身份 | SoulContent / IdentityContent / UserContent / BootstrapContent / ToneStyleContent / UserCustomPrompt / PluginAgentPrompt / subAgentPrompt / industryModeSystemPromptAppend | identity 域 |
| 展示 | ToolResultPresentationPrompt / ArtifactDirectoryPath | 会话 |

条件段实录（structure.json）：`workMode == "ask"`、`not IsOversea`、`IsWindows`、`IsPersonalEdition`、`ExpertManagementEnabled`、`'中文' in ResponseLanguage`、`not productFeatures.DisableMultimodalGeneration`、`WorkingMemoryContent or UserLocalMemoryContent or UserMemoryContent` 等。

## 10. 边界与错误（07 册 §8）

| 场景 | 行为 |
|---|---|
| 变量缺失 | nunjucks 渲染空串；关键身份变量缺失走 onboarding 分支（WorkspaceIdentityMode == 'onboarding'） |
| 模板文件缺失 | 按模式回落表（craft 普通 → ref-client-prompt.tpl） |
| 技能描述膨胀 | 只注入 name+description，正文按需 Skill 工具读 |
| 风格切换 | 热切换即时生效（ToneStyleContent 重渲染） |

## 11. 身份注入运行时（18 册 §13）

`WorkspaceIdentityMode` 两分支：
- **onboarding**："BOOTSTRAP.md 是你的出生证明"，只在对话有空间时（闲聊/问候/闲置）遵循；用户在干正事就别提身份问题；**边学边更新 SOUL/IDENTITY/USER.md，学完删 BOOTSTRAP.md**；保持对话自然；
- **常态**：SOUL.md 存在则扮演其人格与语气；与最近注入的身份/用户档案保持一致；**改了 SOUL.md 要告诉用户**；
- 四文件全文按 `## SOUL.md / Path: {{SoulPath}}` 格式注入；空/缺失显式标 `(empty or missing)`。

## 12. browser-computer-use 片段（21 册 §7）

`browser-computer-use.md`（`{% if productFeatures.BrowserUse === true %}` 包裹）：
- 定位 Beta："只在任务真的需要 UI 操作且无更简单办法时考虑"；
- 浏览器控制的实现是 **`ref-client-browser-use` Skill**（不是内置工具）；
- 关闭时引导：**设置 > Agent > 浏览器控制** + Chrome/Edge/QQ 浏览器的 参考客户端 扩展。
