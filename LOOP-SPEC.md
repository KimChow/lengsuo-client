你是 lengsuo-client 的 agent loop 工程师（波次 1 卡 3/6）。工作目录：/home/ubuntu/lengsuo-client-dev/wt-loop（分支 agent/w1-loop，基于 origin/agent/integration-batch2——不是 main）。必读：AGENTS.md、AGENT-KICKOFF.md（§2 网关协议、§3 会话模型）。

对照物：参考客户端 agent loop 8 步 + 五模式（模式=工具白名单+模板+硬规则三层同切；EnterPlanMode/ExitPlanMode 是真门禁工具；maxSteps 熔断）。规格（本卡唯一规格源，冻结）：

改 `crates/agent-core`（新增 mode.rs + loop.rs；不改既有公共 API 语义，只加）：
```rust
pub enum PromptMode { Quick, Ask, Plan, Craft, Expert }   // 若 schema 已有 Mode 则复用并补 Expert
pub struct ModePolicy { pub tools: BTreeSet<String>, pub template: &'static str }
pub fn mode_policy(mode: PromptMode) -> ModePolicy;
// Quick: 空（仅 chat）；Ask: 只读白名单 {fs.read, fs.glob, fs.search, web.fetch, web.search, task.list, skill.use};
// Plan: craft 集合 - 全部写/执行 + {plan.enter, plan.exit}; Craft: 全集; Expert: Craft + {plan.enter, plan.exit}

pub struct LoopLimits { pub max_steps: usize /*默认 30*/ }
pub struct LoopOutcome { pub status: LoopStatus, pub steps: usize, pub final_text: String }
pub enum LoopStatus { Completed, MaxStepsReached, Denied { tool: String }, Aborted }

// ToolExecutor 由宿主实现（本卡定义 trait；真实工具接 agent-tools 在合并期做）：
pub trait ToolExecutor { fn execute(&self, name: &str, args: &serde_json::Value) -> Result<serde_json::Value, String>; }
pub trait ChatProvider { fn chat(&self, msgs: &[serde_json::Value], tools: &[serde_json::Value]) -> Result<ChatTurn, String>; }
pub struct ChatTurn { pub text: String, pub tool_calls: Vec<ToolCall> }  // ToolCall{id,name,args}
pub struct PlanGate { pub active: bool, pub approved: bool }

pub struct AgentLoop<'a> { /* provider, executor, mode, limits, plan_gate, emit: &dyn Fn(Event) */ }
impl AgentLoop<'_> {
    pub fn new(...) -> Self;                                   // emit 回调逐事件上报（thinking/text/tool_use/tool_result/done）
    pub fn run(&mut self, user_input: &str) -> Result<LoopOutcome, String>;
}
```
loop 语义（8 步对应）：①理解（Quick/Ask 无工具）②chat 流式文本③选工具（模式白名单过滤；白名单外直接 denied 结果回填消息，不执行）④权限门调用方已做（本层不管）⑤执行→结果回填⑥观察回传⑦完成必须 present 交付物（无 tool_calls 即完成；Craft/Expert 若从未调用任何写工具且任务文本含"创建/写入/修改"意图 ⇒ 追加一次提醒轮，最多 1 次）⑧最终回复。Plan 模式：进入即 PlanGate{active:true}，除 plan.exit 外写类工具拒绝；plan.exit(args.approved=true) 才切 Craft 继续，approved=false ⇒ Aborted。maxSteps 熔断 ⇒ MaxStepsReached。
硬规则文案（全模式）追加：「不得声称读过/写过/搜过未实际发生的操作」。
TDD：用 Mock provider（脚本化轮次）覆盖——五模式白名单过滤、Plan 进出门禁两分支、maxSteps 熔断、工具拒绝回填不中断、Quick 空工具、交付物提醒轮最多一次、事件顺序。EchoProvider 已有，Mock 另写。
完成定义：cargo test/clippy(-D warnings)/fmt 全绿（agent-core+agent-memory+agent-gateway 三包不回归）。git 提交（中文），不 push。写 result.md。≤700/400；no unsafe。
