# wb 资产 · Agent Loop 与权限链摘要（9 步 loop 两版并存 / 8-Phase 权限链 / plan 门禁）

> 来源：wb pc-devguide 18《Agent运行时深挖》§4、21《工具宇宙与Fragments全文收编》§3、05《交互模式与Agent运行时》§3/§5-§6、22《Bash工具完整规格与权限链》§2-§3、06《工具系统与安全中心》§5、19《Agent会话运行时与工具面深挖》§9。
> 体例：摘要资产——条目与规则编号沿用出处册原文；除 wb 文档记载外不加任何内容。

## 1. Agent Loop：两版并存（fragment 8 步 vs 模板内联 9 步）

21 册修正记录：真实 agent loop fragment 为 **8 步**、craft-code 模板内联为 **9 步**（两版并存）。
18 册修正记录：series/03 曾记 8 步；模板实证为 **9 步**（第 7/8/9 步拆分）。

### 1.1 fragment 版 8 步（05 册 §3，craft/plan/expert 共用 agent-loop.md 693B）

```
1. Analyze context     理解意图与当前状态
2. Think               推理：更新计划/推进阶段/选择动作
3. Select tool         选下一个工具
4. Execute action      沙箱环境执行
5. Receive observation 工具结果追加进上下文
6. Iterate loop        迭代直至完成（maxSteps 熔断）
7. Present outcome     present_files 交付 —— 硬性要求
8. Final answer        按 final_answer_instructions 写最终回复
```

### 1.2 模板内联版 9 步（18 册 §4，craft 模板 `<agent_loop>` 全文翻译对照）

1. **Analyze context**：基于上下文理解用户意图与当前状态；
2. **Think**：推理是否更新计划/推进阶段/采取具体动作；
3. **Select tool**：按计划与状态选下一个 function calling 工具；
4. **Execute action**：选中工具在沙箱环境作为 action 执行；
5. **Receive observation**：action 结果作为新 observation 追加进上下文；
6. **Iterate loop**：耐心重复直至任务完全完成；
7. **IMPORTANT: Present outcome**：经消息发送结果，并按 `<result_presentation>`/`<sharing_files>` 调 present_files。**你传给 present_files 的文件就是交付给用户的文件（含小程序等其他客户端）——不需要任何单独的交付工具调用**；
8. **IMPORTANT: File transfer from computer**：用户要求从电脑传文件（桌面/下载/任意本地目录）时，**必须提醒用户开启小程序连接设置里的"产物回传到小程序"开关**。present_files 只能交付工作区内文件；工作区外文件需先开此开关；
9. **IMPORTANT: Final answer**：最终可见回复必须遵循 `<final_answer_instructions>`——直接回答请求，并把被折叠/隐藏的中间工具调用、observation、进度消息中的重要结果**向前携带**。

**三条 IMPORTANT 都是强制级**（18 册 §4）：7 是交付硬性要求（06 册框架层 `forcePresentFiles` 兜底）；8 是跨端文件边界；9 是"折叠 UI 下的完整性"要求。

### 1.3 两版关系结论（21 册 §3）

- 模板内联版是在 7 与 Final answer 之间插入"**8=File transfer from computer**"；
- 结论：模板内联是**变体特化**（craft-code 面向"交付文件"场景）；fragment 是共用基线；
- 复刻建议（出处册原话）：以 fragment 8 步为基座，按变体注入特化步。

### 1.4 两条硬性要求 R05-1（05 册 §3）

① 第 7 步强制——"任务完成必须 present_files，不得空手结束回合"（提示词写 + 框架层兜底校验 `forcePresentFiles`）；
② 最终回复**不得向用户提具体工具名**（"AI 在干活"，不是"AI 在调 API"）。

## 2. 8-Phase 权限链（22 册 §2，BashTool.needsApproval 全逻辑）

```js
needsApproval(session, input, ctx):
  1. validateRuntimeInput(input)         → 通过则无需审批（返回 false）
  2. checkBashSecurityWindows(command)   → behavior === "block" ⇒ 需要审批
     （Windows 专属命令安检：危险命令模式拦截）
  3. sandboxPermissionGateway.shouldUseSandboxPath(command)
     → 沙箱路径生效 ⇒【跳过 8-Phase 权限检查】日志: `[BashTool] sandbox path active, skipping 8-Phase permission check | cmd="${cmd.slice(0,80)}"`
  4. shouldAutoApproveInSandbox(command, permissionMode)
     → 沙箱内自动批准 ⇒ 日志 `Auto-approved sandboxed command`
  5. 都不命中 → 标准 needsApproval 管线（8-Phase 检查，按 permissionModeSubject）
```

**规则 A22-1（沙箱优先原则）**：命令能进沙箱就**整条跳过人工审批**（沙箱即安全边界）；只有出沙箱（dangerouslyDisableSandbox / 语义上不能沙箱化）才走人工确认链。这解释了自动批准矩阵为什么默认全自动——**真正的安全边界是沙箱，不是弹窗**。

**规则 A22-2**：`checkBashSecurityWindows` 是**独立于沙箱的第二层 Windows 命令安检**（behavior=block 直接要求审批）。

Bash 执行层语义（22 册 §3，要点）：
- **PTY 选择**：`shouldUsePty = options.usePty ?? (!print && !(交互式 && acp))`——print 模式/ACP 会话默认非 PTY；
- **输出发布**：terminalPublisher.publishOutput(sessionId, terminalId, chunk)——前台与后台命令共用终端发布服务；
- **后台命令**：`publishBackgroundOutput`；被杀时注入 `[Background command killed: <reason>]` 注记；
- **自动分类器输入**：`toAutoClassifierInput` 返回 command 字符串——命令会被送去自动分类（权限分级/审计用）。

## 3. plan 门禁与工具授权状态机（05 册 §5）

```
会话权限模式：readonly ⇄ full（storage:updateSessionPermissionMode，每会话独立）

plan 模式门禁：
  ENTERED_PLAN ──AI 写工具调用──► 拒绝（仅 ExitPlanMode 可出）
      │ ExitPlanMode（附完整方案）──用户批准──► EXECUTING
      └──用户拒绝──► 继续 plan（可迭代方案）

工具调用授权流：
  call → 模式白名单? → 敏感正则? →(命中) askUser(approval_request 事件,挂起)
       →(未命中) autoApprovalSettings 判定 → execute
```

门禁是**运行时机制**不只是提示词（18 册 §11.3）：plan 态下写工具调用在工具层被拒（05 册状态机），ExitPlanMode 携带完整方案请求用户批准。

**/plan 斜杠命令与 plan 文件持久化**（22 册 §5，规则 A22-4）：**plan 是一个真实文件**（planStorageService 管理）——EnterPlanMode 后方案落盘，`/plan` 命令随时读取当前方案；与 19 册会话运行时的 `planSnapshot` 字段互为表里：快照在内存、文件在磁盘。**plan 跨轮次不丢的机制就是文件持久化**。未进 plan 模式时调用提示："No plan file found. Enter plan mode first with EnterPlanMode tool."

## 4. 敏感审批状态机（06 册 §5）

```
工具调用 → 敏感规则匹配
  ├─ 未命中 → autoApprovalSettings 判定 → 自动执行
  └─ 命中 → requestSensitiveApproval → PENDING（挂起，UI 弹窗）
              ├─ 批准 → 执行 → 审计日志记录（含审批人）
              └─ 拒绝/cancelSensitiveApproval → denied → AI 停止该操作并说明
```

## 5. 自动批准矩阵（05 册 §6，实测 CodeBuddy.settings.autoApprovalSettings）

```ts
const DEFAULT_APPROVAL = {
  enabled: true,
  actions: { readFiles: true, editFiles: true, executeCommands: true,
             useBrowser: true, useMcp: true,
             openWebViewInVSCode: true, openMarkDownInVSCode: true },
  maxRequests: -1,           // 不限次数
  enableNotifications: false
}
```

**取舍 R05-4**："默认信任 + 高危审批"比"全部弹窗"体验好一个量级（被真实产品验证）。敏感正则参考：`rm -rf|del /s`、`git push --force`、`format|mkfs`——命中即推 `approval_request` 事件挂起等人批；拒绝后工具返回 denied 且 **AI 停止重试同一操作**。

## 6. 循环边界（05 册 §8）

| 场景 | 行为 |
|---|---|
| maxSteps 熔断 | >30 步强制停止并汇报进度，不死循环 |
| ask 模式写文件 | 工具白名单拒绝 + 提示切模式（双层） |
| 敏感命令被拒 | AI 收到 denied 并向用户说明，不重试 |
| 30s 无响应 | 超时提示，不无限转圈 |
