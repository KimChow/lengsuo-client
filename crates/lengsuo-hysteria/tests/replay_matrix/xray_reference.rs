//! **参考实现对照**：`#[ignore]` 用例，用 `LENGSUO_XRAY` 指向的**参考
//! Xray** 做真实互通取证。
//!
//! ⛔ 全部 `#[ignore]`：必须用 `--ignored` 实跑并贴退出码。
//! ⛔ 禁止用自家 roundtrip 冒充参考互通。
//!
//! # 对照什么
//!
//! 参考实现（固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）
//! 对「常规会话的帧级重放」**不提供**防护：
//! - `proxy/hysteria/protocol.go:28-62` `ReadTCPRequest`：帧格式是
//!   「地址长度 + 地址 + padding 长度 + padding」，**无序号/时间戳/随机数**；
//! - `proxy/hysteria/server.go:153`：`ReadTCPRequest` 之后直接
//!   `net.ParseDestination("tcp:"+addr)` → `WriteTCPResponse(ok=true)`
//!   → 建立出站，**没有任何重放检查**；
//! - `transport/internet/hysteria/hub.go:233` `StreamDispatcher`：
//!   只 peek 帧类型 `0x401`，随后 `addConn(&interConn{...})`。
//!
//! ⇒ 参考行为：重放的 TCPRequest 帧被当成**一条全新请求**处理 ⇒ 目标
//! 被**再接入一次**，收到**同样的字节**。
//!
//! 本文件用**参考 Xray 作为服务端**（inbound hysteria v2 + freedom
//! outbound），本仓客户端向它发起承载；重放同一段 TCPRequest 帧后，
//! 观察参考服务端是否**重复接入**目标。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use super::support::{
    encode_tcp_request, json_escape, pattern, spawn_tcp_target, RawStream, RECLAIM_DEADLINE,
};
use lengsuo_hysteria::quic::HysteriaClient;

/// 参考服务端的口令（**假凭据**，只在本机回环使用；不出现在任何日志）。
const REF_AUTH: &str = "lengsuo-replay-reference-auth";
/// TLS 校验名（自签证书的 SAN 含 `DNS:localhost`）。
const SERVER_NAME: &str = "localhost";
/// 重放用的固定 padding。
const REPLAY_PADDING: &[u8] = b"lengsuo-replay-fixed-padding-0123456789";

fn xray_bin() -> PathBuf {
    let path = std::env::var_os("LENGSUO_XRAY")
        .map(PathBuf::from)
        .expect("环境变量 LENGSUO_XRAY 未设置（参考 /path/to/xray）");
    assert!(path.is_file(), "LENGSUO_XRAY 指向的文件不存在: {path:?}");
    path
}

fn test_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "lengsuo-hy-replay-ref-{}-{}",
        tag,
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("创建临时目录");
    dir
}

fn gen_cert(dir: &Path) -> (PathBuf, PathBuf) {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let out = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args([
            "-days",
            "2",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "keyUsage=critical,digitalSignature,keyEncipherment",
            "-addext",
            "extendedKeyUsage=serverAuth",
        ])
        .output()
        .expect("执行 openssl");
    assert!(
        out.status.success(),
        "openssl 生成自签证书失败: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (cert, key)
}

fn cert_der(cert: &Path, dir: &Path) -> Vec<u8> {
    let der_path = dir.join("cert.der");
    let out = Command::new("openssl")
        .args(["x509", "-in"])
        .arg(cert)
        .args(["-outform", "DER", "-out"])
        .arg(&der_path)
        .output()
        .expect("执行 openssl x509");
    assert!(out.status.success(), "openssl 转 DER 失败");
    std::fs::read(der_path).expect("读取 DER 证书")
}

fn free_udp_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("绑定随机 UDP 端口");
    s.local_addr().expect("读取端口").port()
}

/// 参考 Xray 服务端配置：inbound hysteria v2（clients.auth）+ freedom outbound。
fn xray_config(port: u16, cert: &Path, key: &Path) -> String {
    format!(
        r#"{{
  "log": {{"loglevel": "warning"}},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {port},
    "protocol": "hysteria",
    "settings": {{"version": 2, "clients": [{{"auth": "{REF_AUTH}"}}]}},
    "streamSettings": {{
      "network": "hysteria",
      "hysteriaSettings": {{"version": 2, "auth": "{REF_AUTH}"}},
      "security": "tls",
      "tlsSettings": {{
        "serverName": "{SERVER_NAME}",
        "alpn": ["h3"],
        "certificates": [{{"certificateFile": "{}", "keyFile": "{}"}}]
      }}
    }}
  }}],
  "outbounds": [{{"protocol": "freedom"}}]
}}"#,
        json_escape(&cert.to_string_lossy()),
        json_escape(&key.to_string_lossy())
    )
}

/// 一个参考 Xray 服务端世界。
struct RefWorld {
    child: Child,
    port: u16,
    cert_der: Vec<u8>,
    #[allow(dead_code)]
    dir: PathBuf,
}

impl Drop for RefWorld {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// 汇总参考服务端的 stdout + stderr（参考把启动期错误打到 stdout）。
fn server_logs(dir: &Path) -> String {
    let mut out = String::new();
    for name in ["xray-stdout.log", "xray-stderr.log"] {
        let text = std::fs::read_to_string(dir.join(name)).unwrap_or_default();
        if text.trim().is_empty() {
            continue;
        }
        out.push_str("--- ");
        out.push_str(name);
        out.push_str(" ---\n");
        out.push_str(text.trim_end());
        out.push('\n');
    }
    if out.is_empty() {
        out.push_str("(参考服务端 stdout/stderr 均为空)");
    }
    out
}

async fn start_ref_world(tag: &str) -> RefWorld {
    let dir = test_dir(tag);
    let (cert, key) = gen_cert(&dir);
    let der = cert_der(&cert, &dir);
    let port = free_udp_port();
    let cfg_path = dir.join("xray.json");
    std::fs::write(&cfg_path, xray_config(port, &cert, &key)).expect("写 xray 配置");
    let log_out = std::fs::File::create(dir.join("xray-stdout.log")).expect("建日志文件");
    let log_err = std::fs::File::create(dir.join("xray-stderr.log")).expect("建日志文件");
    let child = Command::new(xray_bin())
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(Stdio::from(log_out))
        .stderr(Stdio::from(log_err))
        .spawn()
        .expect("启动 xray");
    let world = RefWorld {
        child,
        port,
        cert_der: der,
        dir,
    };
    // 就绪探测：完整建连（握手 + H3 认证）。单次尝试自带墙钟上限。
    //
    // ⚠️ 探测用的连接**不复用**：本模块后续用例都自己新建连接
    // （`HysteriaClient::connect` 每次建独立端点），故探测连接可以丢弃。
    let mut last_err = String::new();
    for _ in 0..80 {
        match tokio::time::timeout(
            Duration::from_secs(5),
            HysteriaClient::connect(client_config_for(&world)),
        )
        .await
        {
            Ok(Ok(_client)) => return world,
            Ok(Err(e)) => last_err = format!("{e}"),
            Err(_) => last_err = "单次建连超过 5s 无响应".to_string(),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!(
        "参考 Xray 20s 内未就绪；最后一次探测错误: {last_err}；参考服务端日志:\n{}",
        server_logs(&world.dir)
    );
}

fn client_config_for(world: &RefWorld) -> lengsuo_hysteria::quic::ClientConfig {
    lengsuo_hysteria::quic::ClientConfig {
        server_addr: SocketAddr::from(([127, 0, 0, 1], world.port)),
        server_name: SERVER_NAME.to_string(),
        auth: REF_AUTH.to_string(),
        roots_der: vec![world.cert_der.clone()],
        brutal_down: 0,
        brutal_up: 0,
        congestion: String::new(),
        peer_cc_rx: None,
    }
}

/// **参考对照用例 A**：帧级重放 ⇒ 参考服务端**接受**（当成新请求），
/// 目标被接入**两次**、收到**两份**同样的字节。
///
/// 这条是「本仓行为 vs 参考行为」的一致性锚点：
/// 本仓 `frame_level.rs::same_session_frame_replay_is_accepted_as_new_request`
/// 与本条**必须**给出同样的结论。
#[tokio::test]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn reference_xray_accepts_replayed_frame_as_new_request() {
    super::support::case_within(super::support::CASE_DEADLINE, async {
        let world = start_ref_world("frame").await;
        let client = HysteriaClient::connect(client_config_for(&world))
            .await
            .expect("建连失败");
        let target = spawn_tcp_target().await;
        let addr = target.addr.to_string();

        let payload = pattern(64);
        let mut framed = encode_tcp_request(&addr, REPLAY_PADDING);
        framed.extend_from_slice(&payload);

        // 首帧。
        let mut first = RawStream::open(&client).await.expect("开流失败");
        first.write_raw(&framed).await.expect("首写失败");
        first.finish();
        let got = super::support::wait_until(RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len()
        })
        .await;
        assert!(
            got,
            "参考服务端未转发首帧（received={}）",
            target.received().len()
        );

        // 逐字节重放同一段字节（另一条 QUIC 流）。
        let mut second = RawStream::open(&client).await.expect("开流失败");
        second.write_raw(&framed).await.expect("重放写失败");
        second.finish();

        let got2 = super::support::wait_until(RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len() * 2
        })
        .await;
        assert!(
            got2,
            "参考服务端**未**接受重放帧（received={}）——与「参考不防重放」的结论矛盾",
            target.received().len()
        );
        assert_eq!(
            target.received(),
            [payload.clone(), payload.clone()].concat(),
            "重放字节应与原帧逐字节一致"
        );
        assert_eq!(
            target.accepts(),
            2,
            "参考服务端必须把重放帧当成**新请求**（再接入目标一次）"
        );
    })
    .await;
}

/// **参考对照用例 B**：帧级重放**不得**污染后续会话。
///
/// 参考的 `handleClient`（`hub.go:269`）每连接一个 `httpHandler`；
/// 单条流上的异常只结束那条流 ⇒ 新会话必须照常往返。
///
/// 重放方式：**两条流**（跨流重放）⇒ 参考在每条流上重新读一次
/// TCPRequest（`proxy/hysteria/server.go:153`）⇒ 重放帧被当成新请求。
#[tokio::test]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn reference_xray_new_session_survives_replay() {
    super::support::case_within(super::support::CASE_DEADLINE, async {
        let world = start_ref_world("iso").await;
        let client = HysteriaClient::connect(client_config_for(&world))
            .await
            .expect("建连失败");
        let target = spawn_tcp_target().await;
        let addr = target.addr.to_string();

        let payload = pattern(48);
        let mut framed = encode_tcp_request(&addr, REPLAY_PADDING);
        framed.extend_from_slice(&payload);
        let mut dirty = RawStream::open(&client).await.expect("开流失败");
        dirty.write_raw(&framed).await.expect("写失败");
        dirty.finish();
        let mut replay = RawStream::open(&client).await.expect("开流失败");
        replay.write_raw(&framed).await.expect("重放写失败");
        replay.finish();
        let got = super::support::wait_until(RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len() * 2
        })
        .await;
        assert!(got, "重放未按预期发生（前置条件不满足）");

        // 新会话（新连接）必须正常往返。
        let client2 = HysteriaClient::connect(client_config_for(&world))
            .await
            .expect("新会话建连失败");
        let mut stream = RawStream::open(&client2).await.expect("开流失败");
        let payload2 = pattern(96);
        let mut framed2 = encode_tcp_request(&addr, REPLAY_PADDING);
        framed2.extend_from_slice(&payload2);
        stream.write_raw(&framed2).await.expect("写失败");
        stream.finish();

        let got2 = super::support::wait_until(RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len() * 2 + payload2.len()
        })
        .await;
        assert!(
            got2,
            "重放后新会话未完成往返（received={}）",
            target.received().len()
        );
        let received = target.received();
        assert_eq!(
            &received[payload.len() * 2..],
            &payload2[..],
            "新会话的数据必须逐字节正确"
        );
    })
    .await;
}
