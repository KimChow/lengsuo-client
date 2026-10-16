//! Provider 抽象（开工说明 §7 卡 A：真实 LLM 接入不做，Provider trait + echo 实现）。
//!
//! agent-core 不依赖 tokio：`generate` 是同步的纯函数式步骤产出，
//! 网关层在自己的运行时里调用。v0 只提供 `EchoProvider`（测试用，回显用户输入），
//! 真实模型接入留待后续（返回 `Unsupported` 占位实现不误导能力）。

use serde_json::Value;

use crate::error::CoreError;

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

/// 模型/回合提供方。
pub trait Provider: Send + Sync {
    /// 针对会话最新一条用户输入产出步骤序列（echo provider 返回固定两步）。
    fn next_steps(
        &self,
        session_id: uuid::Uuid,
        user_text: &str,
    ) -> Result<Vec<ProviderStep>, CoreError>;
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
