//! AnyTLS 客户端方向真实互通（本仓 tokio-rustls 客户端 ↔ 官方 anytls-server v0.0.13）。
//! 官方 server 无条件自带 TLS；证书是启动时现生成的**自签叶子**（CN/SAN 为空、1 小时
//! 有效），不接受命令行注入证书链。因此本用例用 openssl 现取该叶子并 pin 为唯一信任锚，
//! tokio-rustls 完成真实证书链校验 + 名称校验（期望 127.0.0.1），随后跑通
//! 认证 → Settings(v=2) → SYN → PUSH → SYNACK/PUSH echo → FIN。默认 `#[ignore]`。
//!
//! 安全边界：这里证明「本仓客户端在真实 TLS 下对接官方 server」以及「本仓 TLS 层会校验
//! 证书与名称」；官方 server 证书 SAN 为空导致标准 SAN 匹配对任何非空名都失败，故名称
//! 校验采用 pin + 期望名比对（错误名仍在 TLS 阶段拒绝）。见 `interop_client/tls.rs` 头注。
#[path = "interop_client/harness.rs"]
mod harness;
#[path = "interop_client/session.rs"]
mod session;
#[path = "interop/support.rs"]
mod support;
#[path = "interop_client/tls.rs"]
mod tls;

use lengsuo_anytls::auth::Credential;
use lengsuo_anytls::frame::Frame;
use lengsuo_anytls::Error;
use std::time::Duration;
use tokio::time::timeout;

/// 主用例的单流回程载荷（含二进制字节，验证逐字节一致）。
const PAYLOAD: &[u8] = b"client-real-tls-echo\x00\x01\x02\xff";

/// 本仓客户端经真实 TLS 对接官方 anytls-server：证书链+名称校验 → auth → Settings(v=2)
/// → 单流 echo，回程逐字节一致，恰好 1 条 SYNACK / 1 条流，无 Alert，日志不含口令。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要 LENGSUO_ANYTLS_SERVER 与 openssl"]
async fn rust_client_real_tls_against_official_server_echo() {
    let Some(mut fixture) = harness::Fixture::start("client-echo").await else {
        return;
    };
    let connector = fixture.connector().expect("TLS 客户端配置");
    let echo = harness::spawn_echo().await;

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", fixture.port()))
        .await
        .expect("连接官方 server 端口");
    let mut tls = tls::client_handshake(&connector, tls::EXPECTED_NAME, tcp, support::WAIT)
        .await
        .expect("TLS 握手（含证书链与名称校验）");

    let report = timeout(
        support::TOTAL,
        session::echo_once(
            &mut tls,
            support::PASSWORD.as_bytes(),
            echo,
            PAYLOAD,
            support::WAIT,
            support::TOTAL,
        ),
    )
    .await
    .expect("互通总超时")
    .expect("客户端会话");

    assert_eq!(report.echo, PAYLOAD, "回程逐字节一致");
    assert_eq!(report.syn_acks, 1, "恰好 1 条 SYNACK");
    assert_eq!(report.data_streams.len(), 1, "恰好 1 条流");
    assert!(report.data_streams.contains(&1), "唯一活跃流应为 sid=1");
    assert_eq!(report.alerts, 0, "不应有任何 Alert");
    assert_eq!(
        report.update_padding, 0,
        "padding-md5 对齐，server 不应下发 UpdatePadding"
    );
    assert_eq!(report.peer_version, 2, "应协商到 v2");
    assert!(
        report
            .server_settings
            .as_deref()
            .is_some_and(|text| text.contains("v=2")),
        "应收到 ServerSettings v=2，实际：{:?}",
        report.server_settings
    );
    assert!(
        report.tls_shutdown_ok,
        "TLS close_notify 应干净关闭，无 TLS Alert"
    );

    let (code, log) = fixture.finish();
    println!("anytls-server exit code={code:?}");
    assert!(!log.contains(support::PASSWORD), "server 日志不得出现口令");
}

/// 错误口令：官方 server 认证失败后走空 fallback 并关闭连接。
/// 判据：客户端随后读帧必须得到 `Error::Io`（服务端断连/close_notify），
/// 而不是超时，也不是读到任何帧；发送失败同样视为「已被断连」的等价观测。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要 LENGSUO_ANYTLS_SERVER 与 openssl"]
async fn wrong_password_is_disconnected_by_official_server() {
    let Some(mut fixture) = harness::Fixture::start("client-wrong-pw").await else {
        return;
    };
    let connector = fixture.connector().expect("TLS 客户端配置");
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", fixture.port()))
        .await
        .expect("连接官方 server 端口");
    let mut tls = tls::client_handshake(&connector, tls::EXPECTED_NAME, tcp, support::WAIT)
        .await
        .expect("TLS 握手（含证书链与名称校验）");

    // 只发错误口令的认证字节；参考 server 读到 32 字节即比对失败，随后断连。
    let _ = Credential::new(b"definitely-not-the-interop-password")
        .send(&mut tls, b"", support::WAIT)
        .await;

    let outcome = Frame::read(&mut tls, u16::MAX, support::WAIT).await;
    match outcome {
        Err(Error::Io(err)) => {
            println!("错口令判据命中：官方 server 断连（{err}）");
        }
        Ok(frame) => panic!(
            "错口令后不应收到任何帧，实际读到 cmd={}",
            frame.command as u8
        ),
        Err(other) => panic!("错口令断连判据应为 Io 错误（含读超时意味着未断连），实际 {other:?}"),
    }

    let (code, log) = fixture.finish();
    println!("anytls-server exit code={code:?}");
    assert!(!log.contains(support::PASSWORD), "server 日志不得出现口令");
}

/// 错误 serverName：本仓客户端必须在 TLS 阶段拒绝，证明名称校验生效，而非应用层兜底。
/// 判据：`client_handshake` 返回 Err 且原因涉及名称校验；有对端握手失败则失败。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要 LENGSUO_ANYTLS_SERVER 与 openssl"]
async fn wrong_server_name_is_rejected_at_tls_stage() {
    let Some(mut fixture) = harness::Fixture::start("client-wrong-name").await else {
        return;
    };
    let connector = fixture.connector().expect("TLS 客户端配置");
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", fixture.port()))
        .await
        .expect("连接官方 server 端口");

    let outcome = tls::client_handshake(&connector, "evil.example", tcp, support::WAIT).await;
    match outcome {
        Err(err) => {
            println!("错误 serverName 在 TLS 阶段被拒：{err}");
            assert!(
                err.contains("名称") && err.contains("evil.example"),
                "拒绝原因应指出名称校验失败，实际：{err}"
            );
        }
        Ok(_) => panic!("错误 serverName 竟然通过了 TLS 校验"),
    }

    let (code, log) = fixture.finish();
    println!("anytls-server exit code={code:?}");
    assert!(!log.contains(support::PASSWORD), "server 日志不得出现口令");
}

/// 本用例使用的帧读等待上限（与 support::WAIT 一致，便于报表注明超时语义）。
#[allow(dead_code)]
const WAIT: Duration = support::WAIT;
