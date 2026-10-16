//! 运行时配置 v0（开工说明 §2/§4：默认超时、默认模式）。
//!
//! 字段名冻结为 camelCase 序列化；`config:set` 走 `apply_patch`，
//! 未知字段必须报错（不静默忽略），非法值同样拒绝，失败的 set 不改动现值。

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::CoreError;
use crate::schema::Mode;

/// 审批挂起默认超时（§4：默认 120s → deny）。
pub const DEFAULT_APPROVAL_TIMEOUT_MS: u64 = 120_000;
/// RPC 默认超时（§2：默认 30s）。
pub const DEFAULT_RPC_TIMEOUT_MS: u64 = 30_000;

/// 运行时配置（v0 全量字段）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub approval_timeout_ms: u64,
    pub rpc_timeout_ms: u64,
    pub default_mode: Mode,
}

impl RuntimeConfig {
    /// v0 默认值。
    pub fn default_v0() -> Self {
        Self {
            approval_timeout_ms: DEFAULT_APPROVAL_TIMEOUT_MS,
            rpc_timeout_ms: DEFAULT_RPC_TIMEOUT_MS,
            default_mode: Mode::Ask,
        }
    }

    /// 应用补丁：只接受已知字段；值非法则整体失败（原配置不变）。
    pub fn apply_patch(&self, patch: &Value) -> Result<Self, CoreError> {
        let Value::Object(map) = patch else {
            return Err(CoreError::InvalidConfig(
                "config:set 载荷必须是 JSON 对象".into(),
            ));
        };
        let mut next = self.clone();
        for (key, value) in map {
            match key.as_str() {
                "approvalTimeoutMs" => next.approval_timeout_ms = positive_ms(key, value)?,
                "rpcTimeoutMs" => next.rpc_timeout_ms = positive_ms(key, value)?,
                "defaultMode" => {
                    let mode = serde_json::from_value::<Mode>(value.clone()).map_err(|_| {
                        CoreError::InvalidConfig(format!("defaultMode 非法: {value}"))
                    })?;
                    next.default_mode = mode;
                }
                other => return Err(CoreError::InvalidConfig(format!("未知配置字段: {other}"))),
            }
        }
        Ok(next)
    }

    /// 序列化为网关 `config:get` 的 data。
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        match serde_json::to_value(self) {
            Ok(Value::Object(fields)) => map = fields,
            Ok(_) => {}
            Err(e) => return Value::String(format!("<序列化失败: {e}>")),
        }
        Value::Object(map)
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self::default_v0()
    }
}

fn positive_ms(key: &str, value: &Value) -> Result<u64, CoreError> {
    let raw = value
        .as_u64()
        .ok_or_else(|| CoreError::InvalidConfig(format!("{key} 必须是非负整数")))?;
    if raw == 0 {
        return Err(CoreError::InvalidConfig(format!("{key} 必须大于 0")));
    }
    Ok(raw)
}
