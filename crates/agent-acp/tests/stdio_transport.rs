//! 真实子进程 stdio 集成测试：`spawn_stdio` → 路由 → 拆除全链路。
//!
//! 假 agent 用 `/bin/sh` 跑一个测试运行期写出的脚本（不依赖网络、不依赖仓库
//! 外的可执行文件，`--offline` 可跑）。脚本内容由测试生成，避免 shell 转义。
//!
//! 覆盖：真实 spawn + 环境 scrub 下的请求-响应往返、stdout 超长行 fail-closed
//! 下毒、子进程忽略 stdin EOF 时有界拆除、spawn 失败报错、scrub 规则纯函数。

use std::io::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use agent_acp::client::{Client, ClientConfig};
use agent_acp::error::Error;
use agent_acp::message::RequestId;
use agent_acp::stdio::{
    env_pair_allowed, is_credential_env, spawn_stdio, SpawnConfig, SYSTEM_ENV_KEEP,
};
use agent_acp::{method, ControlSubtype};
use serde_json::Value;

const WAIT: Duration = Duration::from_secs(5);

/// 测试运行期写出的假 agent 脚本；Drop 时清理。
struct Script {
    path: PathBuf,
}

impl Script {
    fn new(name: &str, body: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("acp-p2-{}-{}.sh", std::process::id(), name));
        let mut f = std::fs::File::create(&path).expect("写脚本");
        f.write_all(body.as_bytes()).expect("写脚本体");
        f.sync_all().expect("落盘");
        Self { path }
    }

    fn config(&self) -> SpawnConfig {
        SpawnConfig::new("/bin/sh").arg(self.path.to_string_lossy().to_string())
    }
}

impl Drop for Script {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn fast_config() -> ClientConfig {
    ClientConfig {
        max_events: 16,
        poll_interval: Duration::from_millis(5),
    }
}

/// 真实往返：脚本对每行输入回一条固定响应（id 固定 1，客户端首个数字 id 也是 1）。
#[test]
fn spawn_stdio_round_trip_with_real_child() {
    let script = Script::new(
        "echo",
        r#"while IFS= read -r line; do
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1,"agentInfo":{"name":"sh-echo"}}}'
done
"#,
    );
    let transport = spawn_stdio(&script.config()).expect("spawn");
    let client = Client::with_config(transport, fast_config());

    let handle = client
        .send_request(
            method::INITIALIZE,
            serde_json::json!({"protocolVersion": 1}),
        )
        .expect("发送");
    assert_eq!(handle.id, RequestId::Number(1));
    let outcome = handle.wait_timeout(WAIT).expect("未超时").expect("成功");
    assert_eq!(outcome["agentInfo"]["name"], "sh-echo");

    // 第二个请求：脚本仍回 id 1，此时本端 id=2，回执成为未知 id（不 panic）。
    let second = client
        .send_request(method::LOGOUT, Value::Null)
        .expect("发送");
    assert_eq!(second.id, RequestId::Number(2));
    assert!(
        second.wait_timeout(Duration::from_millis(300)).is_err(),
        "id 不匹配应超时"
    );
    assert!(!client.is_closed(), "未知 id 不得拖垮真实连接");
}

/// stdout 出现超过单行上限的行：解码器 fail-closed，连接被下毒而非静默截断。
#[test]
fn overlong_line_poisons_real_connection() {
    let script = Script::new("long", &format!("printf '%s\\n' '{}'\n", "x".repeat(4096)));
    let mut cfg = script.config();
    cfg.max_line_bytes = 256;
    let transport = spawn_stdio(&cfg).expect("spawn");
    let client = Client::with_config(transport, fast_config());

    let deadline = Instant::now() + WAIT;
    while !client.is_closed() {
        assert!(Instant::now() < deadline, "超长行必须终止连接");
        std::thread::sleep(Duration::from_millis(5));
    }
    let reason = client.closed_reason().unwrap_or_default();
    assert!(
        reason.contains("上限"),
        "终止原因应指向上限，得到 {reason:?}"
    );
    assert!(client.send_request(method::LOGOUT, Value::Null).is_err());
}

/// 子进程不理会 stdin EOF 且不退出：拆除必须有界（kill 兜底），不得挂住调用方。
#[test]
fn teardown_is_bounded_when_child_ignores_eof() {
    let script = Script::new("stubborn", "while :; do sleep 1; done\n");
    let mut cfg = script.config();
    cfg.shutdown_timeout = Duration::from_millis(300);
    let transport = spawn_stdio(&cfg).expect("spawn");
    let mut client = Client::with_config(transport, fast_config());

    let start = Instant::now();
    client.close();
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(4),
        "拆除必须走有界路径，实际 {elapsed:?}"
    );
    assert!(client.is_closed());
}

/// spawn 失败（程序不存在）报 IO 错误，不 panic、不留残留。
#[test]
fn spawn_failure_is_reported_as_io_error() {
    let cfg = SpawnConfig::new("/nonexistent/acp-agent-xyz");
    let err = spawn_stdio(&cfg).expect_err("不存在的程序必须报错");
    assert!(matches!(err, Error::Io { .. }), "得到 {err:?}");
}

/// 环境 scrub 规则：凭据族一律剥离，白名单模式只留系统变量。
#[test]
fn env_scrub_rules() {
    // 凭据族（含云厂商前缀）一律拒绝。
    for name in [
        "ANTHROPIC_API_KEY",
        "GITHUB_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "MY_PASSWORD",
        "SSH_AUTH_SOCK",
        "GOOGLE_APPLICATION_CREDENTIALS",
    ] {
        assert!(is_credential_env(name), "{name} 应判为敏感");
        assert!(!env_pair_allowed(name, false, &[]), "{name} 不得外传");
    }
    // 系统变量默认放行；白名单模式只留白名单内。
    assert!(env_pair_allowed("PATH", false, &[]));
    assert!(env_pair_allowed("PATH", true, &[]));
    assert!(!env_pair_allowed("SOME_RANDOM_VAR", true, &[]));
    assert!(SYSTEM_ENV_KEEP.contains(&"PATH"));
    // 显式 denylist 精确匹配优先。
    assert!(!env_pair_allowed("PATH", false, &["PATH".to_string()]));
    // 非白名单模式：普通变量放行。
    assert!(env_pair_allowed("SOME_RANDOM_VAR", false, &[]));
}

/// 白名单模式仍能跑通真实子进程（PATH 在保留集内，脚本不依赖外部命令）。
#[test]
fn allowlist_only_env_still_spawns_and_round_trips() {
    let script = Script::new(
        "allowlist",
        "while IFS= read -r line; do\n  printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}'\ndone\n",
    );
    let mut cfg = script.config();
    cfg.allowlist_only_env = true;
    let transport = spawn_stdio(&cfg).expect("白名单模式下 spawn 仍应成功");
    let client = Client::with_config(transport, fast_config());
    let handle = client
        .send_request(method::LOGOUT, Value::Null)
        .expect("发送");
    let outcome = handle.wait_timeout(WAIT).expect("未超时").expect("成功");
    assert_eq!(outcome["ok"], true);
}

/// 真实连接上的 control 面：客户端发出的 control_request 信封被子进程按行读走。
#[test]
fn control_request_frame_reaches_real_child() {
    // 脚本把收到的每行原样回显；客户端把它读回来当作入站帧（信封可被重新归类）。
    let script = Script::new(
        "reflect",
        "while IFS= read -r line; do printf '%s\\n' \"$line\"; done\n",
    );
    let transport = spawn_stdio(&script.config()).expect("spawn");
    let client = Client::with_config(transport, fast_config());

    let _handle = client
        .send_control_request(
            RequestId::String("c-1".into()),
            ControlSubtype::SessionUpdate,
            serde_json::json!({"k": 1}),
        )
        .expect("发送");
    // 回显的 control_request 无注册 handler → 入事件队列，可观测。
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(agent_acp::router::ClientEvent::ControlRequest(req)) = client.poll_event() {
            assert_eq!(req.request_id, RequestId::String("c-1".into()));
            assert_eq!(req.request.subtype, ControlSubtype::SessionUpdate);
            assert_eq!(req.request.payload["k"], 1);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "回显的 control_request 应作为事件出现"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
