# wb 资产 · 工具全集目录（模式工具清单 / 工具宇宙 78 项 / 内置 MCP 54 工具）

> 来源：wb pc-devguide 05《交互模式与Agent运行时》§2/§4、21《工具宇宙与Fragments全文收编》§1-§2、24《模式指令全文与内置MCP全表》§2。
> 体例：忠实转写（表格照录出处册，工具名/大小写保持原文）；除 wb 文档记载外不加任何内容。
> 口径注意：05 册记 craft 30 件为旧口径；21 册从原始安装包修正为 craft **40** / plan **42**，两口径并存记录于此。

## 1. 模式矩阵与工具面（05 册 §2，实测 interactionmode 配置）

**模式 = 工具白名单 + 提示词模板 + 硬规则，三层同时切换**（原版实测结论）。

| 模式 | 可用工具 | 定位 | 行为片段 |
|---|---|---|---|
| quick | **无（tools: []）** | 纯对话 | current-mode（硬规则清单）+ interaction |
| ask | Read、WebFetch、WebSearch、Glob、Grep（5 只读） | 问答/读码分析 | mode-behavior + result-presentation |
| plan | craft 全部 + EnterPlanMode/ExitPlanMode | 先方案后执行 | agent-loop/tool-use/task-management/result-presentation/interaction |
| craft | 30 个全量（21 册修正为 40） | 全自动执行到完成 | agent-loop/tool-use/interaction/task-management/result-presentation/plugin-recommendation/browser-computer-use（8 片段最全） |
| expert | plan 工具集 | 专家人格协同 | 同 craft 换人格（PluginAgentPrompt 注入） |

三个原版细节（05 册 §2）：① quick 无工具**但仍有硬规则**（双保险）；② plan 没有专属模板，复用 craft + 门禁片段；③ EnterPlanMode/ExitPlanMode 是两个**真工具**（门禁）。

## 2. 真实模式工具清单（21 册 §1，interaction.md frontmatter 原文）

frontmatter 即"模式=工具白名单"的机器可读载体（`name/description/tools[]`），加载器直接读它。

| 模式 | 工具清单 |
|---|---|
| craft（40） | Read Write Edit Glob Grep Bash PowerShell TaskCreate TaskGet TaskUpdate TaskList TaskStop TaskOutput WebFetch WebSearch Skill AskUserQuestion **Defer(LSP) Defer(ImageGen) Defer(VideoGen) Defer(AudioTranscribe)** Agent **Defer(TeamCreate) Defer(TeamDelete)** SendMessage **A2AGetAgentCard A2ASendMessage A2AGetTask A2ACancelTask** ToolSearch DeferExecuteTool widget_guidelines show_widget present_files **Defer(LibraryUpload)** automation_update Defer(conversation_search) Defer(reference-platform_sites_deploy) ListMcpResources ReadMcpResource |
| plan（42） | = craft + **EnterPlanMode ExitPlanMode** |
| expert（6 片段） | 同 craft 工具集（interaction.md 同表） |
| ask | agent-loop(空) / current-mode / interaction / mode-behavior / result-presentation / tool-use |
| quick | current-mode / interaction |

**新发现工具**（21 册，此前所有文档未记录）：`Defer(AudioTranscribe)`（音频转写）、`Defer(LibraryUpload)`（资料库上传）；**A2A 四件是一等工具**（不经 ToolSearch）。

**craft 白名单机器形态**（24 册 §2，split(".") 串）：

```
Read.Write.Edit.Glob.Grep.Bash.PowerShell.AskUserQuestion.TaskCreate.TaskGet.TaskUpdate.TaskList.TaskStop.TaskOutput.Skill.LSP.Agent.SendMessage.ToolSearch.DeferExecuteTool.EnterPlanMode.ExitPlanMode.present_files.widget_guidelines.show_widget.TeamCreate.TeamDelete.StructuredOutput
```

（29 直呼工具 + Defer 系 + MCP 挂载 = 21 册的 40）

## 3. 30 个工具全集：名称与用途（05 册 §4）

| 工具 | 做什么 |
|---|---|
| Read / Write / Edit / Glob / Grep | 文件读写搜（底层走 file: 通道层，06 册） |
| Bash / PowerShell | shell（Windows Git Bash / pwsh） |
| TaskCreate/Get/Update/List + TaskStop/TaskOutput | 任务清单（右侧面板） |
| WebFetch / WebSearch | 抓网页/搜索 |
| Skill | 加载技能（SKILL.md 注入） |
| AskUserQuestion | 结构化提问（2–4 选项） |
| present_files | 交付文件 + 打开预览 |
| ListMcpResources / ReadMcpResource | MCP 资源 |
| Defer(LSP) | 代码智能（定义/引用/诊断） |
| Defer(ImageGen/VideoGen) | 文生图/视频 |
| Agent / SendMessage / Defer(TeamCreate/Delete) | 子代理/多代理团队 |
| ToolSearch / DeferExecuteTool | 延迟工具发现与调用 |
| widget_guidelines / show_widget | 内联可视化（SVG/HTML/图表，diagram/mockup/interactive/chart/art 五类） |
| automation_update | 一次性/周期自动化（rrule） |
| Defer(conversation_search) | 搜历史会话 |
| Defer(reference-platform_sites_deploy) | 一键发布 |

**Defer 模式 R05-2（token 优化核心，05 册 §4）**：不常驻上下文的工具先 `ToolSearch` 发现再 `DeferExecuteTool` 调用；MCP 侧同构（defer_loading）。

## 4. 工具宇宙 78 项（21 册 §2，渲染层状态映射全表，asar 实证）

`model_streaming.<Tool> => "正在准备<动作>"` 的完整映射（即每个工具在 UI 上的"人话"），按域分组：

- **文件域(14)**：Read/Write/Edit/**MultiEdit**/NotebookEdit/NotebookRead/Glob/Grep/**LS**/Bash/**BashOutput**/**KillShell**/PowerShell/LSP
- **代理域(10)**：Agent/TaskCreate/TaskGet/TaskUpdate/TaskList/TaskStop/TaskOutput/SendMessage/**TeamCreate/TeamDelete**/TodoWrite/**DelegateTool**
- **规划域(4)**：EnterPlanMode/ExitPlanMode/**EnterWorktree/LeaveWorktree**（worktree 有独立工具！）
- **Web 域(5)**：WebFetch/WebSearch/conversation_search/**preview_url/open_result_view**
- **媒体域(4)**：ImageGen/**ImageEdit**/**ComputerUse**/StructuredOutput
- **技能域(4)**：Skill/**SkillManage**/**SlashCommand**/**SaveMemory**（记忆有专用写工具！）
- **定时域(3)**：**CronCreate/CronDelete/CronList**（cron 三件套是一等工具，与 automation_update 并存）
- **IM 域(2)**：**WeChatReply/WeComReply**（微信/企微回复是 agent 工具）
- **ardot 设计台(17)**：ardot_{apply_variables,batch_edit,batch_read,capture_layout,capture_screenshot,create_design,export_nodes,fetch_editor_state,fetch_file_info,fetch_guidelines,fetch_style_guide,fetch_style_guide_tags,fetch_variables,locate_available_space,open_design,save_tokens,scan_exportable_resources,upload_images}
- **杂项(9)**：connect_cloud_service/deliver_attachments/automation_update/ToolSearch/DeferExecuteTool/show_widget/widget_guidelines/read_me/edits/file/notebook

**规则 A21-1**：fragments 的 per-mode 白名单是"可见子集"，78 表是"全宇宙"——ardot/WeChat/Cron 等由插件与特定模式启用。复刻时状态映射表就是**工具→人话标题**的权威来源。

## 5. 内置 MCP 服务器全表（24 册 §2，REFERENCE_PLATFORM_BUNDLED_MCP_SERVERS，6 服务器 54 工具）

| 服务器 | 工具（全量） |
|---|---|
| **connector-proxy**（18） | connect_cloud_service, connect_open_platform, reference-platform_sites_deploy, reference-platform_sites_unpublish, reference-platform_cloud_service, reference-platform_update_app_preview_entry, search_and_install_skills, skill_management, domain_search, automation_update, conversation_search, pick_location, **agent_mail_upload_attachment, agent_mail_download_attachment**, search_plugins, suggest_plugin_install, list_installed_plugins, uninstall_plugin, reconnect_plugin |
| **miora**（8） | miora_write_canvas, miora_open_canvas, miora_text_to_image, miora_edit_image, miora_text_to_video, miora_frame_to_video, miora_reference_to_video, miora_query_task |
| **sheetagent**（9） | resolve_local_excel, get_cell_ranges, set_cell_range, read_table, run_command, search_data, calculate_single_formula, calculate_formulas, fill_formula |
| **weixinpay**（4） | weixinpay_register, weixinpay_feedback, weixinpay_retry_pay, weixinpay_pay |
| **ardot**（19） | create_design, open_design, fetch_editor_state, fetch_guidelines, fetch_style_guide_tags, fetch_style_guide, **get_available_fonts**, batch_edit, batch_read, locate_available_space, capture_screenshot, capture_layout, fetch_variables, apply_variables, export_nodes, upload_images, scan_exportable_resources, save_tokens, **export_to_code** |
| **netdrive**（0） | 空占位 |

**规则 A24-1**（24 册 §2）：`knownMcpToolIds` 的 id 格式是 `mcp:<server>:<tool>`（工具管控按此寻址）；`builtin:<tool>` 是内置工具 id；**别名机制** `builtin:read_me → builtin:widget_guidelines`（历史名重定向）。

## 6. file: 底层通道层（06 册 §2，工具的能力层实现要点）

| 通道 | 上层工具 | 实现要点 |
|---|---|---|
| file:read / file:readChunked | Read | 全文读有上限（~4MB）；分块读**按行对齐**（不切断逻辑行），默认 ~2000 行/次 |
| file:write | Write | **覆盖前需已读旧内容**（协议防呆：防覆盖 AI 不知道的内容） |
| file:writeBatch | 多文件编辑 | **组内失败整体回滚**，防半成品 |
| file:remove | 删除 | **进回收站**（shell.trashItem），不直删 |
| file:rename | 移动 | 跨盘自动退化为复制+删除 |
| file:listDir / file:search | Glob/Grep | 大目录分页；搜索限量返回+总数提示 |
| file:exists / file:getInfo / file:makeDir | 前置校验 | makeDir 幂等（已存在不报错）；getInfo 只取元信息 |
| file:upload | 产物上传 | P1 接 myFiles 网盘；大文件分片+进度事件 |

**workspace 闸 R06-1**（06 册 §2）：所有文件类工具先过 `workspace:checkAccess(subject, path)`——resolve 后必须落在当前工作区根内。

## 7. 工具管控与安全侧（06 册 §3）

| 功能 | 通道 | 行为 |
|---|---|---|
| 审计日志 | queryAuditLog / exportAuditLog / clearAuditLog | **每次工具调用可审计、可导出** |
| 敏感操作审批 | requestSensitiveApproval / cancelSensitiveApproval | 命中规则的操作**挂起等人批（fail-closed）** |
| 工具管控 | getToolControlState / updateToolControl | **按工具名禁用**——禁用后智能体侧该工具直接消失 |

敏感审批状态机（06 册 §5）：

```
工具调用 → 敏感规则匹配
  ├─ 未命中 → autoApprovalSettings 判定 → 自动执行
  └─ 命中 → requestSensitiveApproval → PENDING（挂起，UI 弹窗）
              ├─ 批准 → 执行 → 审计日志记录（含审批人）
              └─ 拒绝/cancelSensitiveApproval → denied → AI 停止该操作并说明
```

分级建议（原版取舍）：读=自动、改=自动（默认矩阵全自动）、**删/强推/公网/支付=审批**。

## 8. 边界与错误（05 册 §8 + 06 册 §6，工具面相关行）

| 场景 | 行为 |
|---|---|
| ask 模式写文件 | 工具白名单拒绝 + 提示切模式（双层） |
| 敏感命令被拒 | AI 收到 denied 并向用户说明，不重试 |
| 越界路径 | workspace 校验拒绝 |
| 覆盖未读文件 | file:write 拒绝（要求先 Read） |
| writeBatch 中途失败 | 整组回滚 |
| 删除 | 进回收站可恢复 |
| 禁用工具后调用 | 智能体侧工具消失（不是调用时报错） |
