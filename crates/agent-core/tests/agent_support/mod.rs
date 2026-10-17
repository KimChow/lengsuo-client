//! Agent loop 测试共享辅助：脚本化 Mock provider、Mock executor、事件采集与断言小工具。
//!
//! `EchoProvider` 只能单轮回显，多轮白名单/门禁/熔断断言需要脚本化回合，故另写本 Mock。
//! 各 `tests/agent_loop_*.rs` 以 `mod agent_support;` 引入（未用项允许 dead_code）。

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::VecDeque;

use serde_json::{json, Value};
use uuid::Uuid;

use agent_core::schema::{Event, EventKind, Mode};
use agent_core::{
    AgentLoop, ChatProvider, ChatTurn, LoopLimits, LoopOutcome, PlanGate, ToolCall, ToolExecutor,
};

// ---------------- Mock provider ----------------

/// 脚本化回合的 Mock：按队列出回合，并记录每次看到的工具面与消息历史。
pub struct MockProvider {
    turns: RefCell<VecDeque<ChatTurn>>,
    seen_tools: RefCell<Vec<Vec<String>>>,
    seen_msgs: RefCell<Vec<Vec<Value>>>,
}

impl MockProvider {
    pub fn new(turns: Vec<ChatTurn>) -> Self {
        Self {
            turns: RefCell::new(turns.into()),
            seen_tools: RefCell::new(Vec::new()),
            seen_msgs: RefCell::new(Vec::new()),
        }
    }

    /// 每回合看到的工具名列表（顺序同回合）。
    pub fn tool_names(&self) -> Vec<Vec<String>> {
        self.seen_tools.borrow().clone()
    }

    /// 第 n 回合（0 起）看到的消息历史副本。
    pub fn msgs_at(&self, n: usize) -> Vec<Value> {
        self.seen_msgs.borrow()[n].clone()
    }

    /// provider 被调用次数（= 消耗回合数）。
    pub fn chat_calls(&self) -> usize {
        self.seen_tools.borrow().len()
    }
}

impl ChatProvider for MockProvider {
    fn chat(&self, msgs: &[Value], tools: &[Value]) -> Result<ChatTurn, String> {
        self.seen_msgs.borrow_mut().push(msgs.to_vec());
        self.seen_tools.borrow_mut().push(
            tools
                .iter()
                .filter_map(|t| t.get("name").and_then(Value::as_str).map(String::from))
                .collect(),
        );
        self.turns
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| "mock 脚本已耗尽".to_string())
    }
}

/// 一个回合：文本 + 工具请求（id 依次为 c0、c1…）。
pub fn turn(text: &str, calls: Vec<(&str, Value)>) -> ChatTurn {
    ChatTurn {
        text: text.to_string(),
        tool_calls: calls
            .into_iter()
            .enumerate()
            .map(|(i, (name, args))| ToolCall {
                id: format!("c{i}"),
                name: name.to_string(),
                args,
            })
            .collect(),
    }
}

/// 单个工具请求的参数表（配合 [`turn`]）。
pub fn call(name: &str, args: Value) -> Vec<(&str, Value)> {
    vec![(name, args)]
}

/// 直接构造工具请求列表（跳过 [`turn`] 的文本行）。
pub fn raw_calls(name: &str, args: Value) -> Vec<ToolCall> {
    vec![ToolCall {
        id: "c0".to_string(),
        name: name.to_string(),
        args,
    }]
}

// ---------------- Mock executor ----------------

/// 记录被实际执行的工具；`fs.write` 返回固定结果，`shell.exec` 可模拟失败。
#[derive(Default)]
pub struct MockExecutor {
    executed: RefCell<Vec<String>>,
}

impl MockExecutor {
    /// 实际执行过的工具名（按顺序）。
    pub fn executed(&self) -> Vec<String> {
        self.executed.borrow().clone()
    }
}

impl ToolExecutor for MockExecutor {
    fn execute(&self, name: &str, args: &Value) -> Result<Value, String> {
        self.executed.borrow_mut().push(name.to_string());
        match name {
            "shell.exec" if args.get("command").and_then(Value::as_str) == Some("boom") => {
                Err("命令执行失败".to_string())
            }
            "fs.write" => Ok(json!({"path": args["path"], "bytes": 12})),
            _ => Ok(json!({"ok": true, "tool": name})),
        }
    }
}

// ---------------- 事件采集 ----------------

#[derive(Default)]
pub struct Recorder {
    events: RefCell<Vec<Event>>,
}

impl Recorder {
    pub fn push(&self, ev: Event) {
        self.events.borrow_mut().push(ev);
    }

    /// 采集到的事件本体（seq 由 run 内的记账分配，供直接断言）。
    pub fn events(&self) -> Vec<Event> {
        self.events.borrow().clone()
    }

    /// 事件 kind 的判别名序列，供逐位断言。
    pub fn kinds(&self) -> Vec<String> {
        self.events()
            .iter()
            .map(|ev| format!("{:?}", ev.kind))
            .collect()
    }

    /// `(kind, payload)` 列表。
    pub fn snapshot(&self) -> Vec<(String, Value)> {
        self.events
            .borrow()
            .iter()
            .map(|e| (e.kind.clone(), e.payload.clone()))
            .collect()
    }

    pub fn seqs(&self) -> Vec<u64> {
        self.events.borrow().iter().map(|e| e.seq).collect()
    }

    pub fn len(&self) -> usize {
        self.events.borrow().len()
    }
}

/// 一次 run 的观测面：结果、事件快照（kind + payload）、seq 序列。
pub type RunReport = (LoopOutcome, Vec<(String, Value)>, Vec<u64>);

/// 组装 loop 并跑一个任务：emit 回调按引用收集事件。
pub fn run_loop(
    mode: Mode,
    provider: &dyn ChatProvider,
    executor: &dyn ToolExecutor,
    limits: LoopLimits,
    gate: PlanGate,
    input: &str,
) -> Result<RunReport, String> {
    let rec = Recorder::default();
    let emit = |ev: Event| rec.push(ev);
    let mut agent = AgentLoop::new(provider, executor, mode, limits, gate, &emit)
        .session_id(Uuid::nil())
        .seq_base(0);
    let outcome = agent.run(input)?;
    Ok((outcome, rec.snapshot(), rec.seqs()))
}

/// 默认熔断配置（max_steps = 30）。
pub fn default_limits() -> LoopLimits {
    LoopLimits::default()
}

/// 事件快照的 kind 序列。
pub fn kinds(events: &[(String, Value)]) -> Vec<&str> {
    events.iter().map(|(k, _)| k.as_str()).collect()
}

/// [`EventKind`] 列表对应的字符串序列（与 [`kinds`] 对比用）。
pub fn kinds_of(kinds: &[EventKind]) -> Vec<&'static str> {
    kinds.iter().map(|k| k.as_str()).collect()
}

/// 取指定 kind 的第一条 payload。
pub fn first_payload(events: &[(String, Value)], kind: EventKind) -> Value {
    events
        .iter()
        .find(|(k, _)| k == kind.as_str())
        .unwrap_or_else(|| panic!("缺少 {} 事件", kind.as_str()))
        .1
        .clone()
}

/// 取指定 kind 的全部 payload。
pub fn payloads(events: &[(String, Value)], kind: EventKind) -> Vec<Value> {
    events
        .iter()
        .filter(|(k, _)| k == kind.as_str())
        .map(|(_, p)| p.clone())
        .collect()
}
