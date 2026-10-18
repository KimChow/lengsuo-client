//! 审批流：请求、响应、等待与待审批列表。

use std::time::Duration;

use serde_json::Value;
use uuid::Uuid;

use crate::error::CoreError;
use crate::schema::{ApprovalOutcome, ApprovalRequest};

use super::Runtime;

impl Runtime {
    /// 发起审批（挂起；超时按 deny）。
    pub fn request_approval(
        &self,
        id: Uuid,
        tool: &str,
        args: &Value,
    ) -> Result<ApprovalRequest, CoreError> {
        let session = self.get_session(id)?;
        Ok(self
            .gate
            .request_approval(&session.isolation.key(), tool, args))
    }

    /// 应答审批（`approval:respond`）。
    pub fn respond_approval(
        &self,
        approval_id: Uuid,
        approved: bool,
    ) -> Result<ApprovalOutcome, CoreError> {
        self.gate.respond(approval_id, approved)
    }

    /// 阻塞等待审批结果（网关在 spawn_blocking 里调用）。
    pub fn wait_approval(
        &self,
        approval_id: Uuid,
        timeout: Duration,
    ) -> Result<ApprovalOutcome, CoreError> {
        self.gate.wait(approval_id, timeout)
    }

    /// 某会话隔离键下挂起的审批。
    pub fn pending_approvals(&self, session_id: Uuid) -> Vec<Uuid> {
        let Ok(session) = self.get_session(session_id) else {
            return Vec::new();
        };
        self.gate.list_pending(&session.isolation.key())
    }
}
