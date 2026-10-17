//! Provider 抽象（开工说明 §7 卡 A：真实 LLM 接入不做，Provider trait + echo 实现）。
//!
//! agent-core 不依赖 tokio：`generate` 是同步的纯函数式步骤产出，
//! 网关层在自己的运行时里调用。v0 只提供 `EchoProvider`（测试用，回显用户输入），
//! 真实模型接入留待后续（返回 `Unsupported` 占位实现不误导能力）。

use serde_json::Value;

use crate::error::CoreError;
use crate::schema::{Message, Mode};

/// 一次回合产出的一个步骤。
#[derive(Debug, Clone, PartialEq)]
pub enum ProviderStep {
    /// 思考过程（事件 `thinking`）。
    Thinking(String),
    /// 回复文本（事件 `text`，同时进 `Message`）。
    Text(String),
    /// 请求调用工具（事件 `tool_use`）；是否执行由权限门决定。
    ToolCall { name: String, args: Value },
    /// 回合结束（事件 `done`）。
    Finished,
}

/// 一次回合送给 Provider 的完整上下文（provider-context 卡）。
///
/// 组成：Composer 按会话模式构建的 system prompt（含已启用记忆摘要、身份变量、
/// 硬规则与门禁片段）+ 会话历史（不含本轮输入）+ 本轮用户输入。
/// 凭据约束：所有字段在进入本结构前已过脱敏器（§6）。
#[derive(Debug, Clone, PartialEq)]
pub struct TurnContext {
    /// 会话 id。
    pub session_id: uuid::Uuid,
    /// 会话模式（决定 Composer 模板）。
    pub mode: Mode,
    /// Composer 构建的系统提示词。
    pub system_prompt: String,
    /// 已启用的三层记忆摘要；`memory.enabled` 关闭时为 `None`。
    pub memory_digest: Option<String>,
    /// 本轮之前的会话历史（时间序，末尾即本轮输入的前一条）。
    pub history: Vec<Message>,
    /// 本轮用户输入（只出现于此，不在 `history` 中重复）。
    pub user_text: String,
}

/// 模型/回合提供方。
pub trait Provider: Send + Sync {
    /// 针对会话最新一条用户输入产出步骤序列（echo provider 返回固定两步）。
    fn next_steps(
        &self,
        session_id: uuid::Uuid,
        user_text: &str,
    ) -> Result<Vec<ProviderStep>, CoreError>;

    /// 针对完整回合上下文产出步骤序列。
    ///
    /// 默认实现降级到旧 `next_steps`（只送本轮输入），保证既有实现方
    /// （`EchoProvider`、网关测试里的 `Slow` 等）无需改动即可继续跑回合；
    /// 需要真实 system prompt / 历史 / 记忆的新适配器覆写本方法。
    fn next_steps_with_context(
        &self,
        context: &TurnContext,
    ) -> Result<Vec<ProviderStep>, CoreError> {
        self.next_steps(context.session_id, &context.user_text)
    }
}

/// 测试用回显 provider：把用户输入原样回显，并产出 `Finished`。
#[derive(Debug, Clone, Copy, Default)]
pub struct EchoProvider;

impl Provider for EchoProvider {
    fn next_steps(
        &self,
        _session_id: uuid::Uuid,
        user_text: &str,
    ) -> Result<Vec<ProviderStep>, CoreError> {
        Ok(vec![
            ProviderStep::Thinking(format!("echo: 收到 {} 个字符", user_text.chars().count())),
            ProviderStep::Text(user_text.to_string()),
            ProviderStep::Finished,
        ])
    }
}

/// 真实模型 provider 占位：明确报未实现，不静默回退到 echo。
#[derive(Debug, Clone, Copy, Default)]
pub struct UnimplementedProvider;

impl Provider for UnimplementedProvider {
    fn next_steps(
        &self,
        _session_id: uuid::Uuid,
        _user_text: &str,
    ) -> Result<Vec<ProviderStep>, CoreError> {
        Err(CoreError::Unsupported(
            "模型 provider 未接入（v0 只做网关与运行时骨架）",
        ))
    }
}
