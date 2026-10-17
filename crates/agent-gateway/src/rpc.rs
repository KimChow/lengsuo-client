use crate::server::App;
use agent_core::{
    error::CoreError,
    runtime::CreateSession,
    schema::{Mode, PermissionMode},
};
use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;
use uuid::Uuid;

#[derive(Deserialize)]
pub(crate) struct Request {
    action: String,
    #[serde(default)]
    payload: Value,
}
pub(crate) async fn handle(
    State(app): State<App>,
    input: Result<Json<Request>, axum::extract::rejection::JsonRejection>,
) -> Json<Value> {
    let Ok(Json(req)) = input else {
        return Json(envelope(400, "invalid JSON", Value::Null));
    };
    let timeout = Duration::from_millis(app.runtime.config_get().rpc_timeout_ms);
    let work = tokio::task::spawn_blocking(move || dispatch(&app, &req.action, &req.payload));
    Json(match tokio::time::timeout(timeout, work).await {
        Ok(Ok(value)) => value,
        Ok(Err(_)) => envelope(500, "request failed", Value::Null),
        Err(_) => envelope(408, "request timed out", Value::Null),
    })
}
fn envelope(code: u16, msg: &str, data: Value) -> Value {
    json!({"code":code,"msg":msg,"data":data})
}
fn dispatch(app: &App, action: &str, p: &Value) -> Value {
    match run(app, action, p) {
        Ok(data) => envelope(0, "ok", data),
        Err((code, msg)) => envelope(code, &msg, Value::Null),
    }
}
type Failure = (u16, String);
fn bad() -> Failure {
    (400, "invalid payload".into())
}
fn core(e: CoreError) -> Failure {
    match e {
        CoreError::SessionNotFound(_) | CoreError::ApprovalNotFound(_) => (404, "not found".into()),
        CoreError::InvalidConfig(_) => (400, "invalid configuration".into()),
        CoreError::SessionClosed(_) => (409, "session closed".into()),
        _ => (500, "operation failed".into()),
    }
}
fn id(p: &Value, key: &str) -> Result<Uuid, Failure> {
    p.get(key)
        .or_else(|| p.get("sessionId"))
        .or_else(|| p.get("session_id"))
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(bad)
}
fn own(app: &App, p: &Value) -> Result<Uuid, Failure> {
    let id = id(p, "id")?;
    let s = app.runtime.get_session(id).map_err(core)?;
    if s.isolation != app.isolation {
        return Err((403, "forbidden".into()));
    }
    Ok(id)
}
fn run(app: &App, action: &str, p: &Value) -> Result<Value, Failure> {
    let rt = &app.runtime;
    Ok(match action {
        "sys:ping" => json!({"pid":std::process::id()}),
        "config:get" => {
            let config = rt.config_get().to_value();
            if let Some(key) = p.get("key").and_then(Value::as_str) {
                config.get(key).cloned().ok_or_else(bad)?
            } else {
                config
            }
        }
        "config:set" => {
            if let Some(key) = p.get("key").and_then(Value::as_str) {
                let value = p.get("value").cloned().ok_or_else(bad)?;
                rt.config_set(&json!({key:value})).map_err(core)?.to_value()
            } else {
                rt.config_set(p).map_err(core)?.to_value()
            }
        }
        "session:list" => json!(rt.list_sessions(&app.isolation)),
        "session:create" => {
            // Identity and environment authority are supplied by the host, never the RPC caller.
            if p.get("isolation").is_some()
                || p.get("envBinding").is_some()
                || p.get("env_binding").is_some()
            {
                return Err((403, "server-bound identity".into()));
            }
            let mode = p
                .get("mode")
                .map(|v| serde_json::from_value::<Mode>(v.clone()).map_err(|_| bad()))
                .transpose()?
                .unwrap_or(rt.config_get().default_mode);
            let permission_mode = p
                .get("permissionMode")
                .map(|v| serde_json::from_value::<PermissionMode>(v.clone()).map_err(|_| bad()))
                .transpose()?
                .unwrap_or_default();
            json!(rt
                .create_session(&CreateSession {
                    title: p
                        .get("title")
                        .and_then(Value::as_str)
                        .unwrap_or("New session")
                        .to_owned(),
                    workspace_root: p
                        .get("workspaceRoot")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    mode,
                    permission_mode,
                    env_binding: app.isolation.env_id.clone(),
                    isolation: app.isolation.clone()
                })
                .map_err(core)?)
        }
        "session:get" => json!(rt.get_session(own(app, p)?).map_err(core)?),
        "session:send" => {
            let receipt = rt
                .send_text(
                    own(app, p)?,
                    p.get("text")
                        .or_else(|| p.get("content"))
                        .and_then(Value::as_str)
                        .ok_or_else(bad)?,
                )
                .map_err(core)?;
            json!({"sessionId":receipt.session_id,"events":receipt.events,"lastSeq":receipt.last_seq})
        }
        "session:stop" => json!(rt.stop_session(own(app, p)?).map_err(core)?),
        "tool:list" => {
            // 有会话时以会话为准（并做归属校验）；无会话沿用 default_mode 兼容行为。
            let session = if p.get("id").is_some()
                || p.get("sessionId").is_some()
                || p.get("session_id").is_some()
            {
                Some(rt.get_session(own(app, p)?).map_err(core)?)
            } else {
                None
            };
            let mode = session
                .as_ref()
                .map(|s| s.mode)
                .unwrap_or_else(|| rt.config_get().default_mode);
            let gate = rt.gate();
            let mut allowed = gate.whitelist(mode);
            // readonly 会话里非只读类别不可见，与 `PermissionGate::check` 的判定一致；
            // full 只取消该遮挡，不放宽模式白名单。
            if session.is_some_and(|s| s.permission_mode == PermissionMode::ReadOnly) {
                let registry = gate.registry();
                allowed.retain(|name| {
                    registry
                        .get(name)
                        .is_some_and(|t| t.kind.allowed_when_readonly())
                });
            }
            json!(gate.registry().to_value(Some(&allowed)))
        }
        "approval:respond" => {
            let session = own(app, p)?;
            let approval = p
                .get("approvalId")
                .or_else(|| p.get("approval_id"))
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(bad)?;
            if !rt.pending_approvals(session).contains(&approval) {
                return Err((403, "forbidden".into()));
            }
            let result = rt
                .respond_approval(
                    approval,
                    p.get("approved")
                        .and_then(Value::as_bool)
                        .or_else(|| match p.get("decision").and_then(Value::as_str) {
                            Some("allow") => Some(true),
                            Some("deny") => Some(false),
                            _ => None,
                        })
                        .ok_or_else(bad)?,
                )
                .map_err(core)?;
            json!({"approved":result.approved,"timedOut":result.timed_out})
        }
        _ => return Err((404, "unknown action".into())),
    })
}
