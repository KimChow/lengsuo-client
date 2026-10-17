//! 握手文件 → 真实回环 roundtrip：证明 `gateway.json` 是唯一地址/token 来源。
//!
//! 协议（AGENT-KICKOFF.md §2）：网关监听 `127.0.0.1` 随机端口并把 `{port, pid, token}`
//! 写进握手文件。本文件用 mock 网关的实际端口构造文件，再让 `GatewayClient::connect`
//! 走完整链路；另一侧覆盖 fail-closed（缺失/非法一律拒绝，不回退默认端口）。

mod support;

use std::net::SocketAddr;

use lengsuo_shell::gateway::{GatewayClient, GatewayHandshake, HandshakeError, DEFAULT_TIMEOUT};
use serde_json::Value;
use support::{handshake_json, MockGateway, RpcBehaviour, TempHandshakeFile};

/// 测试专用假 token。
const FAKE: &str = "fake-loopback-token-a";

#[tokio::test]
async fn handshake_file_drives_a_real_roundtrip() {
    let mock = MockGateway::rpc(
        vec![RpcBehaviour::Envelope {
            code: 0,
            msg: "ok",
            data: r#"{"pong":true}"#,
        }],
        Some(FAKE.to_owned()),
    )
    .await;
    let file = TempHandshakeFile::with_content(&handshake_json(mock.addr(), FAKE)).expect("写文件");

    let c = GatewayClient::connect(file.path())
        .await
        .expect("合法握手文件应构造客户端");
    assert_eq!(
        c.addr(),
        SocketAddr::from(([127, 0, 0, 1], mock.addr().port())),
        "地址必须来自握手文件的 port，且固定回环"
    );
    assert_eq!(c.timeout(), DEFAULT_TIMEOUT, "默认超时来自协议冻结点");
    let data = c
        .sys_ping()
        .await
        .expect("由握手文件得到的地址与 token 应能完成 roundtrip");
    assert_eq!(data["pong"], Value::Bool(true));
    let seen = mock.seen();
    assert!(
        seen.first()
            .and_then(|r| r.token.as_deref())
            .is_some_and(|t| t == FAKE),
        "文件里的 token 应作为请求头上线"
    );

    mock.shutdown().await;
}

#[tokio::test]
async fn handshake_file_failures_are_fail_closed() {
    let missing = TempHandshakeFile::missing().expect("建临时目录");
    assert!(
        matches!(
            GatewayHandshake::load(missing.path()).await,
            Err(HandshakeError::NotFound { .. })
        ),
        "文件缺失应 NotFound，不回退默认端口"
    );

    let bad_json = TempHandshakeFile::with_content("{not json").expect("写文件");
    assert!(
        matches!(
            GatewayHandshake::load(bad_json.path()).await,
            Err(HandshakeError::Invalid { .. })
        ),
        "JSON 非法应 Invalid"
    );

    // port 为 0 与空 token 都是校验失败，不是「未提供」的宽松回退。
    let zero_port =
        TempHandshakeFile::with_content(&format!(r#"{{"port":0,"pid":1,"token":"{FAKE}"}}"#))
            .expect("写文件");
    assert!(matches!(
        GatewayHandshake::load(zero_port.path()).await,
        Err(HandshakeError::Invalid { .. })
    ));
    let empty_token =
        TempHandshakeFile::with_content(r#"{"port":1,"pid":1,"token":""}"#).expect("写文件");
    assert!(matches!(
        GatewayHandshake::load(empty_token.path()).await,
        Err(HandshakeError::Invalid { .. })
    ));

    // 缺字段同样拒绝，且错误文本不带 token 值。
    let no_token = TempHandshakeFile::with_content(r#"{"port":1,"pid":1}"#).expect("写文件");
    let err = GatewayHandshake::load(no_token.path())
        .await
        .expect_err("缺 token 应拒绝");
    assert!(matches!(err, HandshakeError::Invalid { .. }));
    assert!(
        !format!("{err}").contains(FAKE),
        "握手错误文本不应回显 token"
    );
}

#[tokio::test]
async fn connect_on_a_missing_file_does_not_fall_back_to_any_address() {
    let missing = TempHandshakeFile::missing().expect("建临时目录");
    let err = GatewayClient::connect(missing.path())
        .await
        .expect_err("握手文件缺失时客户端不应构造成功");
    assert!(
        matches!(err, HandshakeError::NotFound { .. }),
        "期望 NotFound，实际 {err:?}"
    );
}
