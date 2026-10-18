# wb 资产 · LLM 工具描述原文（Bash schema / Agent / TaskOutput / Minimal how-to / 斜杠命令）

> 来源：wb pc-devguide 22《Bash工具完整规格与权限链》§1/§4-§5、19《Agent会话运行时与工具面深挖》§7、24《模式指令全文与内置MCP全表》§1、18《Agent运行时深挖》§5。
> 体例：忠实转写；英文原文逐字照录于引用块，中文要点为出处册原文的表格式收录。除 wb 文档记载外不加任何内容。
> 诚实边界（22 册文首）：lite 变体的 `command` 字段描述是精简版（"The command to execute"）；**完整版长描述在 5.7.7 的 `lazy-headless/` 121 个 chunk 里，随旧安装包已消失**。标准工具描述如需完整原文，需另取得全量版安装包。

## 1. Bash 工具 Zod schema（22 册 §1，描述原文逐字段）

其他工具与之同构（class + Zod schema + needsApproval + execute）。

| 字段 | 描述原文（要点） |
|---|---|
| command | "The command to execute"（REPL 形态追加 REPL 用法后缀） |
| timeout | 可选毫秒；**上限被 `BASH_MAX_TIMEOUT_MS`（env / settings.env）钳制**；具体默认/上限值"见工具描述中本会话生效值"——即运行时动态注入 |
| description | **写规则原文**：主动语态、清晰简短；**禁用 "complex"/"risk" 这类词**；简单命令（git/npm/标准 CLI）5-10 词：`ls → "List files in current directory"`、`git status → "Show working tree status"`、`npm install → "Install package dependencies"`；难解析命令（管道/生僻 flag）写清楚做了什么：`find . -name "*.tmp" -exec rm {} \; → "Find and delete all .tmp files recursively"`、`git reset --hard origin/main → "Discard all local changes and match remote main"`、`curl -s url \| jq '.data[]' → "Fetch JSON from URL and extract data array elements"`；**语言必须跟随系统提示词的 `<response_language>` 或用户输入语言（大概率中文）** |
| run_in_background | true = 后台运行，**用 BashOutput 读输出**（BashOutput 是独立工具） |
| dangerouslyDisableSandbox | **只在确信命令必须在沙箱外运行且预期用户会批准时才设**；设 true 后工具向用户要显式同意——批准则以**无沙箱隔离**执行，用户仍可拒绝；**绝不预防性设置**。仅两种场景：①此前沙箱尝试因策略失败（结果里有 `SANDBOX PERMISSION DENIED`）；②任务语义上无法沙箱化（装系统包、改工作区外文件） |

## 2. Agent / TaskOutput 描述原文（19 册 §7，headless bundle，给模型看的真实字符串）

**Agent 工具**（多代理派发）：

> Launch a detached worker using the same live Agent catalog as normal Agent calls. **Prefer a specialized subtype and set name to distinguish parallel roles. Do not call Grep or Read in the same turn as Agent.** After \<task-notification\>, call TaskOutput once to read the full report. **Failed or cancelled workers are not live; spawn again with a different type or prompt.**

**TaskOutput 工具**：

> Read a worker report, including mid-run output when the user asks for progress. **On the coordinator, block is forced false.** Do not tight-loop while waiting. After the notification, call this once to read the full report. \<summary\> is a short headline, not the body. **A still-running snapshot is valid progress — do not refuse. Do not spawn another worker to recover truncated text.** Failed/cancelled workers are not live — you may spawn again.

**规则 A19-6（派发纪律，全部强制）**：同一轮禁 Grep/Read（先派发再观察）；通知后 TaskOutput **只调一次**；协调者上 block 强制 false（不阻塞等）；运行中快照算有效进度不得拒绝；截断文本不许再开 worker 补捞；失败 worker 不算存活，换 type/prompt 重开。

关联（18 册 §11.2）：**Agent 工具**描述实证 "Launch a detached worker to handle a complex task autonomously"——分离 worker 自主跑复杂任务。

## 3. Minimal 模式工具 how-to（22 册 §4，REPL 形态专用，原文）

| 工具 | 描述 |
|---|---|
| Bash | "Run a shell command. **No Read/Write/Glob/Grep; inspect with cat, sed, or rg. Use r.stdout — do not parse `Command:` labels. Do not call Read.**" |
| Edit | "Edit a file by replacing old_string with new_string. **Minimal mode has no Read tool: do not try to Read first. Inspect the file with Bash before editing** if you need current contents. **To create a new file, pass an empty old_string.**" |
| SpeakInChannel | "Channel talk. `await SpeakInChannel({ content })`. **Not MessageColleague.**"（频道发言与私信是两个工具，别混） |

**规则 A22-3**：Minimal/REPL 形态下**工具的调用方式都变成 REPL 代码**（`await Xxx({...})`），工具描述里写明返回值取法（r.stdout）与禁用项——同一工具在 REPL/native 两种形态有两套描述。

## 4. CLI 五模式 appendInstructions 全文（24 册 §1）

### 4.1 ptc（PTC / Code Mode，582B）

> # PTC / Code Mode
> REPL is the only tool you can call directly. Every worker tool (files, shell, search, web, media, MCP resources, sub-agents, tasks) lives inside the REPL sandbox; calling one outside REPL fails as an unknown tool.
> If the user asks what tools you have, answer directly: REPL is the only direct tool; inside REPL the full session catalog is available. **Use REPL.describeTool / REPL.searchTools only when you need details, not to answer "what tools exist".**
> If the user asks what skills you have, answer from the Skill documentation already in the REPL…

REPL 工具环境（`await Bash({...})` / `tools.*` SDK，hG 工具描述原文）：

> **Do NOT import node:fs / node:path / node:child_process / npm packages inside REPL; they are unavailable.**

——REPL 是封顶沙盒，无 Node 标准库。

### 4.2 minimal（Minimal Code Mode）

> # Minimal Code Mode
> REPL is the only tool you can call directly; inside it **Bash, Edit, and Skill** exist.
> Other native tool names — Read, Write, Glob, Grep, PowerShell, SendMessage, MessageColleague, SpeakInChannel, web, plan, sub-agents — **are unavailable both outside and inside REPL, and MCP is not available in Minimal.** Do not call them; when project rules or skills mention them, use Bash or Edit equivalents instead.
> If the user asks what tools you have, answer directly: REPL, and inside REPL Bash, Edit, and Skill. Do not probe with Read/Glob/Grep.

工具数组实证：`p=["REPL"]`、`h=["Bash","Edit","Skill"]`；多代理变体 `S=[...h,"Agent","TaskOutput","TaskStop","InterruptAgent","ListAgents","InspectSelf","AskUserQuestion","SendUserMessage"]`。

### 4.3 create（Creator / Agent authoring，1084B）

> # Agent authoring
> You are in creation mode: help the user design and write custom agents as Markdown files.
> If the user asks what tools you have, answer directly: this mode has the same full Standard toolset as the cli mode, plus agent-authoring guidance. **Do not probe for a tool list.**
> Default write location is **user-level**: `~/.codebuddy/agents/<name>.md`（全机所有项目）。项目级 `.codebuddy/agents/<name>.md` 仅当用户要求提交/共享给仓库时使用。
> 文件名必须等于 frontmatter `name`；`name` 是新的小写连字符 id（如 code-reviewer）。**NEVER edit or delete shipped product agents（cli, ptc, minimal, create, multitask, Explore 等 built-ins）——改内置模式要复制成新文件再改副本。**
> 写完 `mainAgent: true` 的文件后告知用户：新会话（或刷新后）出现在 Agent presets 选择器；若只要 subagent，省略 mainAgent 并说明可用 @agent 调用而非模式。

自定义 agent frontmatter 样例（原文）：`mainAgent: true` + `tools: Read, Grep, Glob, Bash`——**自定义 agent 就是"一个 md 文件 + frontmatter 工具白名单"**。

### 4.4 multitask（Multitask coordinator，1299B，全文见 mode_instructions_full.md）

核心条款（24 册摘要）：默认不自己搜索/编辑（禁 Bash/Skill/Edit/Write）；**同波次 Grep/Read+Agent 时 Grep/Read 被拒**；调查/改码必须选子代理 subtype；`ListAgents 列的是活 worker（locks ∩ TaskManager）不是目录`；**被问有什么工具只准报十件**：Agent, TaskOutput, TaskStop, InterruptAgent, ListAgents, InspectSelf, AskUserQuestion, SendUserMessage, Grep, Read。

19 册 §9 的 multitask 描述（原文）：

> **Coordinator: spawn background Agents. Do not search or edit yourself. Grep/Read only when this wave has no Agent. No Edit/Bash/Skill.** 要进度就调一次 TaskOutput 报快照。\<task-notification\> 后调一次 TaskOutput 拿完整报告。Do not tight-loop. Failed workers may be re-dispatched.

**规则 A19-8**：`multitask` 协调者模式**自我剥夺了 Edit/Bash/Skill**（只留派发与 TaskOutput）——"协调者不干活"在**工具层强制**。

### 4.5 跨模式通用片段（24 册 §1.5）

- **MEMORY.md 截断注记**（R 常量，原文）：
  > `[MEMORY.md truncated to the ${t} — read the full file with the Read tool if needed]`
  ——记忆注入超限时插入此占位；
- **worker 工具 how-to 表**（P 常量，原文要点）：
  - `Agent: "Auto-creates team. Returns { taskId } or throws. Need description + prompt."`
  - `TaskOutput: "…running is not done. Use block:false."`
  - `MessageColleague: "Room colleagues. await MessageColleague({ action, recipient, content })."`

## 5. CLI 五模式总表（19 册 §9，headless 实证全量）

| 模式名 | 显示名 | 描述（原文） | 工具面 |
|---|---|---|---|
| `cli` | Standard / **标准模式** | "Full coding agent: files, commands, search, skills."（功能完整的编码 Agent：改文件、跑命令、检索代码） | 全量 |
| `ptc` | PTC (Code Mode) | "Standard tools via REPL / Code Mode."——worker 工具经 REPL，模型把步骤组合成**一个程序**执行 | 目录工具集走 REPL |
| `minimal` | Minimal | "REPL only (Bash, Edit, Skill)."——REPL 内只有 Bash/Edit/Skill，**无 MCP、无 Read/Write/Glob/Grep/搜索/plan/子代理**，查文件用 Bash | 极简 |
| `create` | Creator | "Standard tools plus writing custom agents."——含在 `~/.codebuddy/agents` 下写用户级自定义 agent 的引导 | 全量 + 创作引导 |
| `multitask` | Multitask | **协调者覆盖层**（描述原文见 §4.4） | 协调者专用集 |

- **内置子代理固定名**：`explore` / `plan` / `general-purpose` / `statusline-setup`；
- 默认命令集：`init / compact / statusline / insights`。

## 6. 侧通道：提示词改写专家（19 册 §10）

`llm:enhancePrompt`——独立的**提示词改写专家**：系统提示词原文：

> You are a Prompt Engineering Expert specializing in improving user prompts for a development code assistant…

即用户的模糊输入可先经此 side-channel 改写再进主 loop【触发时机为出处册推断：输入增强/改写按钮】。

## 7. A2A 工具族描述机制（18 册 §11.1）

- 工具族：`A2AGetAgentCard` / `A2ASendMessage` / `A2AGetTask` / `A2ACancelTask`（A2AGetTask 与 Send/Cancel 同一描述渲染）；
- **动态工具描述**：`<available_A2A_agents>` 列表**每项以 `[id]` 前缀**，调用时把该 id 作为 `agent_id` 传给 Send/Get/Cancel；`renderCard` 把 `{agent_id, ...agentCard}` JSON 化渲染；`ToolManager` 监听 `onAgentsChanged`——代理清单变化即**刷新 A2AGetAgentCard 的缓存描述**（`invalidateCachedToolDescription`）；
- 代理清单不可用时 `<available_A2A_agents>` 保持空（不报错降级）。
