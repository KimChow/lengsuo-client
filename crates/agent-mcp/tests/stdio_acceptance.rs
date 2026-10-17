//! Real Python fixture processes; no network or third-party server claim.
use agent_mcp::client::StdioServerCommand;
use agent_mcp::{ClientConfig, Framing, McpClient};
use serde_json::json;
use std::{sync::Arc, time::Duration};
fn config(framing: Framing) -> ClientConfig {
    let mode = if framing == Framing::ContentLength {
        "lsp"
    } else {
        "line"
    };
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mcp_fixture_server.py");
    let mut cfg = ClientConfig::stdio(
        StdioServerCommand::new("python3").with_args([script.to_str().unwrap(), mode]),
        framing,
    );
    cfg.request_timeout = Duration::from_millis(500);
    cfg.handshake_timeout = Duration::from_secs(2);
    cfg
}
async fn connect(f: Framing) -> McpClient {
    tokio::time::timeout(Duration::from_secs(3), McpClient::connect(config(f)))
        .await
        .unwrap()
        .unwrap()
}
#[tokio::test]
async fn initialize_list_call_and_shutdown_both_framings() {
    for framing in [Framing::NewlineDelimited, Framing::ContentLength] {
        let mut c = connect(framing).await;
        assert!(c.has_transport());
        let listed = c.list_tools().await.unwrap();
        assert_eq!(listed.tools.len(), 3);
        let out = c
            .call_tool("echo", Some(json!({"text":"hello fixture"})))
            .await
            .unwrap();
        assert!(serde_json::to_string(&out)
            .unwrap()
            .contains("hello fixture"));
        c.ping().await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), c.shutdown())
            .await
            .unwrap()
            .unwrap();
        assert!(c.is_closed());
    }
}
#[tokio::test]
async fn concurrent_responses_are_correlated_by_id() {
    let c = Arc::new(connect(Framing::NewlineDelimited).await);
    let mut tasks = Vec::new();
    for i in 0..10 {
        let c = c.clone();
        tasks.push(tokio::spawn(async move {
            let result = c
                .request(
                    "test/echo_index",
                    Some(json!({"index":i,"token":format!("fake-{i}")})),
                )
                .await
                .unwrap();
            assert_eq!(result["index"], i);
            assert_eq!(result["echo"], format!("fake-{i}"));
        }));
    }
    for task in tasks {
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
    }
    let mut c = Arc::try_unwrap(c).ok().unwrap();
    c.shutdown().await.unwrap();
}
#[tokio::test]
async fn timed_out_connection_cannot_be_reused() {
    let mut cfg = config(Framing::NewlineDelimited);
    cfg.request_timeout = Duration::from_millis(30);
    let mut c = McpClient::connect(cfg).await.unwrap();
    assert!(tokio::time::timeout(
        Duration::from_secs(2),
        c.request("test/hang_then_respond", None)
    )
    .await
    .unwrap()
    .is_err());
    assert!(c.is_poisoned());
    assert!(c.ping().await.is_err());
    c.disconnect().await;
}
#[tokio::test]
async fn bad_frames_fail_closed_in_both_framings() {
    for framing in [Framing::NewlineDelimited, Framing::ContentLength] {
        let mut c = connect(framing).await;
        assert!(
            tokio::time::timeout(Duration::from_secs(2), c.request("test/bad_frame", None))
                .await
                .unwrap()
                .is_err()
        );
        assert!(c.is_poisoned());
        assert!(c.ping().await.is_err());
        c.disconnect().await;
    }
}
#[tokio::test]
async fn truncated_eof_rejects_pending_request() {
    let mut c = connect(Framing::NewlineDelimited).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(2), c.request("test/truncated", None))
            .await
            .unwrap()
            .is_err()
    );
    assert!(c.is_poisoned());
    c.disconnect().await;
}
#[tokio::test]
async fn unexpected_exit_does_not_hang_request() {
    let mut c = connect(Framing::NewlineDelimited).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(2), c.request("test/exit", None))
            .await
            .unwrap()
            .is_err()
    );
    assert!(c.is_closed());
    c.disconnect().await;
}
#[tokio::test]
async fn notifications_are_delivered_in_order() {
    let mut c = connect(Framing::NewlineDelimited).await;
    let mut rx = c.subscribe_notifications();
    c.request("test/notify", None).await.unwrap();
    for _ in 0..3 {
        let (method, _) = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(method, "notifications/message");
    }
    c.shutdown().await.unwrap();
}

#[tokio::test]
async fn oversized_frames_poison_the_connection() {
    for f in [Framing::NewlineDelimited, Framing::ContentLength] {
        let mut cfg = config(f);
        cfg.max_frame_bytes = 512;
        let mut c = McpClient::connect(cfg).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), c.request("test/oversized", None))
                .await
                .unwrap()
                .is_err()
        );
        assert!(c.is_poisoned());
        assert!(c.ping().await.is_err());
        c.disconnect().await;
    }
}
#[cfg(unix)]
#[tokio::test]
async fn explicit_shutdown_reaps_fixture_process() {
    struct PidFile(std::path::PathBuf);
    impl Drop for PidFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let file = PidFile(
        std::env::temp_dir().join(format!("mcp-test-child-{}-{stamp}.pid", std::process::id())),
    );
    let mut cfg = config(Framing::NewlineDelimited);
    cfg.command = cfg
        .command
        .with_env("LENGSUO_TEST_PID_FILE", file.0.to_str().unwrap());
    let mut c = McpClient::connect(cfg).await.unwrap();
    let pid = std::fs::read_to_string(&file.0).unwrap();
    assert!(std::path::Path::new("/proc").join(&pid).exists());
    tokio::time::timeout(Duration::from_secs(3), c.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(
        !std::path::Path::new("/proc").join(&pid).exists(),
        "fixture must be reaped"
    );
}
