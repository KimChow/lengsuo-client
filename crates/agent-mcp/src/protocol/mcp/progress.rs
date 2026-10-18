//! 进度通知参数。

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `notifications/progress` 参数（v0 只解析字段，不做进度状态机）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProgressParams {
    #[serde(rename = "progressToken")]
    pub progress_token: Value,
    pub progress: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
