//! 回合上下文组装（provider-context 卡）：Composer × 记忆 × 历史 × 本轮输入。
//!
//! Runtime 发起回合时不再只把用户输入送给 Provider，而是构造 [`TurnContext`]：
//! - `system_prompt`：`agent_prompts::Composer::build(模式, 变量)`，变量含身份层
//!   （AI 名/用户称呼/人格，agent-memory 身份层不受跨会话记忆开关限制）、工作区、
//!   确定性日期文本、以及**已启用**时的记忆摘要；
//! - `history`：会话已有消息（时间序），本轮输入在其后单独作为 `user_text`；
//! - `memory_digest`：`memory.enabled` 关闭时为 `None`，Composer 不留空段。
//!
//! 隐私（AGENTS §6）：进入上下文的任何文本先过脱敏器；凭据不进模型输入。

use super::*;
use agent_prompts::{Composer, PromptMode, PromptVars};

/// 历史消息进上下文前的字符上限（防单条大输出顶爆模型输入；大结果走 result_ref）。
const HISTORY_MESSAGE_CHARS: usize = 2000;

impl Runtime {
    /// 构造本轮上下文。`history` 是本轮输入推入之前的历史快照。
    pub(crate) fn build_turn_context(
        &self,
        session: &Session,
        history: &[Message],
        user_text: &str,
    ) -> TurnContext {
        let digest = self.turn_memory_digest(session);
        let vars = self.prompt_vars(session, digest.as_deref());
        let system_prompt = Composer::build(prompt_mode(session.mode), &vars);
        TurnContext {
            session_id: session.id,
            mode: session.mode,
            system_prompt,
            memory_digest: digest,
            history: narrow_history(history),
            user_text: self.redact(user_text),
        }
    }

    /// 本轮记忆摘要：仅在 `memory.enabled` 时给出（关闭 ⇒ `None`，Composer 不留空段）。
    ///
    /// 会话上的摘要缺失时（建会话时 compose 失败、或重启回放后的会话）在回合内
    /// 重新组装一次；仍失败则本次不带记忆并继续跑回合，不影响既有事件语义。
    fn turn_memory_digest(&self, session: &Session) -> Option<String> {
        let enabled = self
            .config
            .lock()
            .map(|c| c.memory_enabled)
            .unwrap_or_default();
        if !enabled {
            return None;
        }
        if let Some(digest) = &session.memory_digest {
            return Some(self.redact(digest));
        }
        self.compose_memory_digest(&session.workspace_root)
            .ok()
            .map(|digest| self.redact(&digest))
    }

    /// 模板变量：身份层 + 工作区 + 日期 + 用户规则（v0 空）+ 已启用记忆摘要。
    fn prompt_vars(&self, session: &Session, digest: Option<&str>) -> PromptVars {
        let identity = self.read_identity(&session.workspace_root);
        PromptVars {
            ai_name: self.redact(&identity.ai_name),
            user_name: self.redact(&identity.user_name),
            soul: self.redact(&identity.soul),
            workspace: self.redact(&session.workspace_root),
            date: date_text(),
            user_rules: String::new(),
            memory_digest: digest.unwrap_or_default().to_string(),
        }
    }

    /// 身份层读取（失败回退默认值：身份属产品人格，不阻断回合）。
    fn read_identity(&self, workspace_root: &str) -> agent_memory::Identity {
        use agent_memory::{MemoryEngine, MemoryPaths};
        let paths = MemoryPaths::new(self.workdir.join(".lengsuo"), workspace_root);
        MemoryEngine::new(paths, false)
            .read_identity()
            .unwrap_or_default()
    }
}

/// 会话模式 → 提示词模式（两侧枚举一一对应，不引入跨 crate 依赖方向变化）。
fn prompt_mode(mode: Mode) -> PromptMode {
    match mode {
        Mode::Quick => PromptMode::Quick,
        Mode::Ask => PromptMode::Ask,
        Mode::Plan => PromptMode::Plan,
        Mode::Craft => PromptMode::Craft,
        Mode::Expert => PromptMode::Expert,
    }
}

/// 历史进上下文：逐条收窄并脱敏，保持时间序与角色不变。
fn narrow_history(messages: &[Message]) -> Vec<Message> {
    let mut history = messages.to_vec();
    for message in &mut history {
        message.content = narrow(&redact_static(&message.content), HISTORY_MESSAGE_CHARS);
    }
    history
}

/// 无 Runtime 句柄处的脱敏（历史收窄用同一 v0 规则集）。
fn redact_static(text: &str) -> String {
    Redactor::default_v0().redact_str(text)
}

/// 确定性日期文本（本地日期；不引入时刻，保证同一天内同输入同输出）。
fn date_text() -> String {
    chrono::Local::now().date_naive().to_string()
}
