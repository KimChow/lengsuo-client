//! TrustedClient 受控门面验收（先失败后实现，TDD 红灯锚点）。
//!
//! 覆盖三条强制：`connect` 前检查 trust 与 server 开关（拒绝时不 spawn）、
//! `call_tool` 前检查 `can_call`（拒绝时不发请求）、撤销后立即拒绝，
//! `shutdown` 回收子进程且之后不再放行。夹具为 tests/fixtures 的 Python
//! 假服务端，只调用假工具 `echo`/`add`/`boom`，不接真实第三方 server。

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_mcp::client::StdioServerCommand;
use agent_mcp::trusted_client::{TrustedClient, TrustedClientError};
use agent_mcp::{ClientConfig, Error, Framing, TrustGate};
use serde_json::json;

/// 行分隔分帧 + 真实 Python 夹具；`Some(path)` 时启用夹具的 pid 文件钩子。
fn config(pid_file: Option<&Path>) -> ClientConfig {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mcp_fixture_server.py");
    let mut command =
        StdioServerCommand::new("python3").with_args([script.to_str().unwrap(), "line"]);
    if let Some(file) = pid_file {
        command = command.with_env("LENGSUO_TEST_PID_FILE", file.to_str().unwrap());
    }
    let mut cfg = ClientConfig::stdio(command, Framing::NewlineDelimited);
    cfg.request_timeout = Duration::from_millis(800);
    cfg.handshake_timeout = Duration::from_secs(3);
    cfg
}

/// 必然 spawn 失败的命令：只有门放行才会被触碰，用来证明「拒绝时不 spawn」。
fn bogus_config() -> ClientConfig {
    let mut cfg = ClientConfig::stdio(
        StdioServerCommand::new("/nonexistent/mcp-fixture-program-that-must-not-run"),
        Framing::NewlineDelimited,
    );
    cfg.request_timeout = Duration::from_millis(800);
    cfg.handshake_timeout = Duration::from_secs(2);
    cfg
}

/// 已登记 echo、可信且启用的门。
fn ready_gate() -> TrustGate {
    let mut gate = TrustGate::new();
    gate.set_trusted(true);
    gate.set_server_enabled(true);
    gate.set_tool_enabled("echo", true);
    gate
}

struct PidFile(PathBuf);

impl PidFile {
    fn new(tag: &str) -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "mcp-trusted-{}-{tag}-{stamp}.pid",
            std::process::id()
        )))
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn connect(gate: TrustGate) -> TrustedClient {
    tokio::time::timeout(
        Duration::from_secs(5),
        TrustedClient::connect(config(None), gate),
    )
    .await
    .expect("connect 超时")
    .expect("门放行时握手必须成功")
}

/// 把工具结果里的文本块拼起来（不依赖具体字段名之外的信息）。
fn result_text(result: &agent_mcp::ToolCallResult) -> String {
    serde_json::to_string(result).unwrap_or_default()
}

#[tokio::test]
async fn connect_denies_untrusted_gate_without_spawning() {
    let mut gate = TrustGate::new();
    gate.set_server_enabled(true);
    gate.set_tool_enabled("echo", true);
    // 合法夹具命令 + pid 钩子：一旦被 spawn，pid 文件必然出现。
    let pid = PidFile::new("untrusted");
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        TrustedClient::connect(config(Some(&pid.0)), gate.clone()),
    )
    .await
    .expect("拒绝路径不得等待")
    .expect_err("未授予 trust 必须拒绝连接");
    assert!(
        matches!(error, TrustedClientError::NotTrusted),
        "期望 NotTrusted，实际 {error:?}"
    );
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(!pid.0.exists(), "拒绝连接时不得 spawn 子进程");
    // 拒绝不改动调用方交出的门：状态仍为未授予 trust。
    assert!(!gate.is_trusted());
}

#[tokio::test]
async fn connect_denies_disabled_server_without_spawning() {
    // 可信但 server 总开关关闭：同样必须在 spawn 之前拒绝。
    let mut gate = ready_gate();
    gate.set_server_enabled(false);
    let pid = PidFile::new("server-off");
    let error = TrustedClient::connect(config(Some(&pid.0)), gate)
        .await
        .expect_err("server 未启用必须拒绝连接");
    assert!(
        matches!(error, TrustedClientError::ServerDisabled),
        "期望 ServerDisabled，实际 {error:?}"
    );
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(!pid.0.exists(), "拒绝连接时不得 spawn 子进程");
}

#[tokio::test]
async fn bogus_command_is_only_reached_after_gate_passes() {
    // 门拒绝时连非法命令都不会被触碰：错误来自门而非传输层。
    let err = TrustedClient::connect(bogus_config(), TrustGate::new())
        .await
        .expect_err("默认门必须拒绝");
    assert!(matches!(err, TrustedClientError::NotTrusted), "{err:?}");

    let mut gate = TrustGate::new();
    gate.set_trusted(true);
    gate.set_server_enabled(true);
    let err = TrustedClient::connect(bogus_config(), gate)
        .await
        .expect_err("门放行后不得掩盖真实 spawn 失败");
    match err {
        TrustedClientError::Client(inner) => assert!(inner.is_connection_fatal(), "{inner:?}"),
        other => panic!("期望透传底层错误，实际 {other:?}"),
    }
}

#[tokio::test]
async fn call_tool_denial_sends_no_request_and_keeps_session_healthy() {
    let mut client = connect(ready_gate()).await;
    // add 从未登记 → 拒绝；拒绝不得发出请求，会话保持可用。
    let err = client
        .call_tool("add", Some(json!({"a": 1, "b": 2})))
        .await
        .expect_err("未登记工具必须拒绝");
    assert!(
        matches!(err, TrustedClientError::ToolNotAllowed { .. }),
        "{err:?}"
    );
    assert!(!client.is_poisoned(), "拒绝调用不得污染连接");
    assert_eq!(client.unmatched_responses(), 0, "拒绝时不得有在途/迟到请求");

    // 同一条连接上随后放行登记过的工具：结果正确即证明此前请求未曾发出。
    let ok = client
        .call_tool("echo", Some(json!({"text": "after denial"})))
        .await
        .expect("登记的调用必须放行");
    assert!(result_text(&ok).contains("after denial"));
    client.disconnect().await;
}

#[tokio::test]
async fn revoking_tool_registration_denies_immediately() {
    let mut client = connect(ready_gate()).await;
    assert!(client
        .call_tool("echo", Some(json!({"text": "first"})))
        .await
        .is_ok());

    client.set_tool_enabled("echo", false);
    let err = client
        .call_tool("echo", Some(json!({"text": "second"})))
        .await
        .expect_err("撤销工具启用必须立即拒绝");
    assert!(
        matches!(err, TrustedClientError::ToolNotAllowed { .. }),
        "{err:?}"
    );

    client.set_tool_enabled("echo", true);
    assert!(client
        .call_tool("echo", Some(json!({"text": "third"})))
        .await
        .is_ok());
    client.disconnect().await;
}

#[tokio::test]
async fn revoking_server_and_trust_denies_calls_immediately() {
    let mut client = connect(ready_gate()).await;
    assert!(client.can_call("echo"));

    client.set_server_enabled(false);
    assert!(!client.can_call("echo"), "停用 server 必须立即拒绝");
    assert!(client.is_trusted(), "停用 server 不得撤销 trust");
    let err = client
        .call_tool("echo", Some(json!({"text": "x"})))
        .await
        .expect_err("停用 server 后必须拒绝");
    assert!(
        matches!(err, TrustedClientError::ToolNotAllowed { .. }),
        "{err:?}"
    );

    client.set_server_enabled(true);
    client.set_trusted(false);
    assert!(!client.can_call("echo"), "撤销 trust 必须立即拒绝");
    assert!(client
        .call_tool("echo", Some(json!({"text": "x"})))
        .await
        .is_err());

    // 重新授予后既有登记仍生效，且连接仍可用（拒绝不破坏会话）。
    client.set_trusted(true);
    client.set_server_enabled(true);
    assert!(client
        .call_tool("echo", Some(json!({"text": "back"})))
        .await
        .is_ok());
    client.disconnect().await;
}

#[tokio::test]
#[cfg(unix)]
async fn shutdown_reaps_fixture_process_and_closes_facade() {
    let pid = PidFile::new("shutdown");
    let mut client = tokio::time::timeout(
        Duration::from_secs(5),
        TrustedClient::connect(config(Some(&pid.0)), ready_gate()),
    )
    .await
    .expect("connect 超时")
    .expect("握手必须成功");
    let raw = std::fs::read_to_string(&pid.0).unwrap();
    let child = Path::new("/proc").join(raw.trim());
    assert!(child.exists(), "夹具子进程应已启动");

    tokio::time::timeout(Duration::from_secs(5), client.shutdown())
        .await
        .expect("shutdown 超时")
        .expect("shutdown 必须成功");
    assert!(!child.exists(), "shutdown 必须回收子进程");
    assert!(client.is_closed(), "shutdown 后门面必须标记为已关闭");

    // 关闭后即使门仍放行，也不得再走调用路径。
    let err = client
        .call_tool("echo", Some(json!({"text": "late"})))
        .await
        .expect_err("关闭后必须拒绝");
    assert!(matches!(err, TrustedClientError::Closed), "{err:?}");
    // 幂等：重复 shutdown 不报错。
    assert!(client.shutdown().await.is_ok());
}

#[tokio::test]
async fn underlying_error_kind_is_preserved_through_facade() {
    // 门放行但夹具侧返回 JSON-RPC error：底层错误类型不得被门面抹平。
    let mut gate = ready_gate();
    gate.set_tool_enabled("boom", true);
    let mut client = connect(gate).await;
    let err = client
        .call_tool("boom", None)
        .await
        .expect_err("夹具必须返回 JSON-RPC 错误");
    match err {
        TrustedClientError::Client(inner) => {
            assert!(
                matches!(inner, Error::JsonRpc { code: -32603, .. }),
                "{inner:?}"
            );
        }
        other => panic!("期望透传底层错误，实际 {other:?}"),
    }
    client.disconnect().await;
}
