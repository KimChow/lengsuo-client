//! 产品 TLS 信任链验收：`ClientTrust`（唯一信任锚 = 传入 CA + 名称校验）与
//! `ServerIdentity`（PEM 链 + PKCS#8 私钥）正例与反例矩阵。
//!
//! 反例一律断言失败**发生在 TLS 握手阶段**：建立 TCP 后 `connector.connect(..)`
//! 返回错误，且从未写下任何 anytls 字节（服务端会话拿不到认证块）。配置期错误
//! （空 CA、空名称、不配对私钥）在 `new` 即返回 `Error::TlsConfig`，同样早于任何 I/O。
//!
//! 证书由 `tls_trust/pki.rs` 用 openssl 现造，只写临时目录、用后即删。
#[path = "tls_trust/pki.rs"]
mod pki;

use lengsuo_anytls::{
    auth::Credential,
    frame::{Command, Frame},
    padding::PaddingScheme,
    server::{self, ServerConfig},
    tls::{ClientTrust, ServerIdentity},
    Error,
};
use pki::Pki;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(5);
const PASSWORD: &[u8] = b"tls-trust-password";
const NAME: &str = "localhost";

/// 每个测试独立临时 PKI；无 openssl 时如实跳过（打印原因，不计通过）。
macro_rules! pki_or_skip {
    () => {
        match pki::generate() {
            Some(pki) => pki,
            None => {
                eprintln!("跳过：无 openssl 或证书生成失败，本用例未执行");
                return;
            }
        }
    };
}

/// 起一个 TLS + anytls 服务端，返回端口。用产品层 `ServerIdentity` 装证书。
async fn spawn_server(pki: &Pki) -> u16 {
    let identity = ServerIdentity::new(&pki.chain_pem, &pki.key_pem).expect("服务端身份");
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(identity));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("监听");
    let port = listener.local_addr().expect("地址").port();
    tokio::spawn(async move {
        if let Ok((socket, _)) = listener.accept().await {
            // 只接一条连接：握手失败即结束任务（反例不需要服务端继续）。
            if let Ok(stream) = timeout(WAIT, acceptor.accept(socket))
                .await
                .unwrap_or(Err(std::io::Error::other("握手超时")))
            {
                let _ = server::serve(stream, ServerConfig::new(PASSWORD, WAIT)).await;
            }
        }
    });
    port
}

/// 正例的完整单流往返；`config` 必须由产品层 `ClientTrust::new` 产出。
async fn roundtrip(config: rustls::ClientConfig, name: &str, port: u16) {
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let socket = TcpStream::connect(("127.0.0.1", port)).await.expect("连接");
    let server_name = ClientTrust::server_name(name).expect("服务名");
    let mut stream = timeout(WAIT, connector.connect(server_name, socket))
        .await
        .expect("握手超时")
        .expect("正例 TLS 握手（含 CA + 名称校验）");

    Credential::new(PASSWORD)
        .send(&mut stream, b"", WAIT)
        .await
        .expect("认证");
    let md5 = PaddingScheme::default_scheme().md5().to_owned();
    Frame {
        command: Command::Settings,
        stream_id: 0,
        data: format!("v=2\nclient=tls-trust\npadding-md5={md5}").into_bytes(),
    }
    .write(&mut stream, WAIT)
    .await
    .expect("Settings");
    assert_eq!(
        next_semantic(&mut stream).await.command,
        Command::ServerSettings
    );

    // 回环 echo 目标。
    let echo = TcpListener::bind("127.0.0.1:0").await.expect("echo");
    let echo_addr = echo.local_addr().expect("echo 地址");
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = echo.accept().await {
            let mut buffer = [0u8; 1024];
            while let Ok(count) = socket.read(&mut buffer).await {
                if count == 0 || socket.write_all(&buffer[..count]).await.is_err() {
                    break;
                }
            }
        }
    });

    Frame {
        command: Command::Syn,
        stream_id: 1,
        data: Vec::new(),
    }
    .write(&mut stream, WAIT)
    .await
    .expect("SYN");
    let payload = b"product-tls-trust-single-stream";
    Frame {
        command: Command::Push,
        stream_id: 1,
        data: push_with_target(echo_addr, payload),
    }
    .write(&mut stream, WAIT)
    .await
    .expect("PUSH");
    assert_eq!(next_semantic(&mut stream).await.command, Command::SynAck);
    let echoed = next_semantic(&mut stream).await;
    assert_eq!(echoed.command, Command::Push);
    assert_eq!(echoed.data, payload, "回程逐字节一致");
    Frame {
        command: Command::Fin,
        stream_id: 1,
        data: Vec::new(),
    }
    .write(&mut stream, WAIT)
    .await
    .expect("FIN");
    let _ = stream.shutdown().await;
}

/// 反例：握手必须失败，`reason` 固定失败的真实 TLS 阶段原因（非应用层兜底）。
/// `error` 的文本还需通过「不含证书/私钥材料」断言。
async fn expect_handshake_rejected(
    config: rustls::ClientConfig,
    name: &str,
    port: u16,
    pki: &Pki,
    what: &str,
    reason: &str,
) {
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let socket = TcpStream::connect(("127.0.0.1", port)).await.expect("连接");
    let server_name = ClientTrust::server_name(name).expect("服务名语法");
    let outcome = timeout(WAIT, connector.connect(server_name, socket)).await;
    let error = match outcome {
        Err(_) => panic!("{what}：TLS 握手超时，未按预期在握手阶段拒绝"),
        Ok(Ok(_)) => panic!("{what}：握手意外成功（产品信任链失效）"),
        Ok(Err(err)) => err.to_string(),
    };
    eprintln!("[取证] {what} → {error}");
    assert!(
        error.contains(reason),
        "{what}：握手错误未指向预期原因（预期含 {reason:?}）：{error}"
    );
    assert_no_material(&error, pki, what);
}

fn assert_no_material(text: &str, pki: &Pki, what: &str) {
    for fragment in &pki.fragments {
        assert!(
            !text.contains(fragment.as_str()),
            "{what}：错误信息泄漏了证书/私钥材料片段"
        );
    }
    for marker in [
        "BEGIN CERTIFICATE",
        "BEGIN PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
    ] {
        assert!(!text.contains(marker), "{what}：错误信息含 PEM 头 {marker}");
    }
}

fn push_with_target(addr: std::net::SocketAddr, payload: &[u8]) -> Vec<u8> {
    let std::net::IpAddr::V4(v4) = addr.ip() else {
        panic!("测试固定 IPv4 回环");
    };
    let mut data = vec![0x01];
    data.extend_from_slice(&v4.octets());
    data.extend_from_slice(&addr.port().to_be_bytes());
    data.extend_from_slice(payload);
    data
}

async fn next_semantic<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Frame {
    loop {
        let frame = Frame::read(stream, u16::MAX, WAIT).await.expect("读帧");
        if frame.command != Command::Waste {
            return frame;
        }
    }
}

// ── 正例 ────────────────────────────────────────────────────────────────────

/// CA 匹配 + 名称匹配 → 真实握手 + 一条 anytls 单流往返。
#[tokio::test]
async fn matching_ca_and_name_complete_real_handshake_and_roundtrip() {
    let pki = pki_or_skip!();
    let port = spawn_server(&pki).await;
    let config = ClientTrust::new(&pki.ca_pem, NAME).expect("客户端信任配置");
    roundtrip(config, NAME, port).await;
}

// ── 反例（每条都必须在 TLS 握手阶段失败）─────────────────────────────────────

/// CA 不匹配：出示的链由另一棵 CA 签发，客户端只信任测试 CA。
#[tokio::test]
async fn foreign_ca_is_rejected_at_handshake() {
    let pki = pki_or_skip!();
    let port = spawn_server(&pki).await;
    let config = ClientTrust::new(&pki.other_ca_pem, NAME).expect("客户端信任配置");
    expect_handshake_rejected(config, NAME, port, &pki, "CA 不匹配", "UnknownIssuer").await;
}

/// 名称不匹配：CA 正确，但请求名 `wrong.example` 不在 SAN 内。
#[tokio::test]
async fn wrong_server_name_is_rejected_at_handshake() {
    let pki = pki_or_skip!();
    let port = spawn_server(&pki).await;
    let config = ClientTrust::new(&pki.ca_pem, "wrong.example").expect("客户端信任配置");
    // 服务端 TLS 已就绪，但证书 SAN 不含 wrong.example：必须在握手阶段拒绝。
    expect_handshake_rejected(
        config,
        "wrong.example",
        port,
        &pki,
        "名称不匹配",
        "not valid for name",
    )
    .await;
}

/// 空 CA：配置期 fail-closed（早于任何 I/O）。
#[test]
fn empty_ca_is_rejected_at_configuration() {
    for ca in [&b""[..], b"not a pem at all"] {
        let error = ClientTrust::new(ca, NAME).expect_err("空/非 PEM CA 必须被拒");
        assert!(matches!(error, Error::TlsConfig(_)), "错误变体：{error:?}");
        let text = error.to_string();
        assert!(text.contains("信任锚") || text.contains("CA"), "{text}");
    }
}

/// 空服务名：配置期 fail-closed，且连接 API 同样拒绝空名。
#[test]
fn empty_server_name_is_rejected_at_configuration() {
    let pki = pki_or_skip!();
    let error = ClientTrust::new(&pki.ca_pem, "").expect_err("空服务名必须被拒");
    assert!(matches!(error, Error::TlsConfig(_)), "错误变体：{error:?}");
    assert!(error.to_string().contains("服务名为空"), "{error}");
    let name_error = ClientTrust::server_name("").expect_err("空名解析必须被拒");
    assert!(matches!(name_error, Error::TlsConfig(_)));
}

/// 证书链 PEM 本身不可解析（或被截断）：构造期 fail-closed，不产出半个配置。
#[test]
fn unparsable_certificate_chain_is_rejected() {
    let pki = pki_or_skip!();
    let truncated = &pki.chain_pem[..pki.chain_pem.len() / 2];
    let cases: [&[u8]; 2] = [b"-----BEGIN CERTIFICATE-----\nAAAA\n", truncated];
    for cert in cases {
        let error = ServerIdentity::new(cert, &pki.key_pem).expect_err("坏证书链必须被拒");
        assert!(matches!(error, Error::TlsConfig(_)), "错误变体：{error:?}");
        assert_no_material(&error.to_string(), &pki, "坏证书链");
    }
}

/// 私钥 PEM 无法解析（非 PEM）：构造期 fail-closed。
#[test]
fn unparsable_private_key_is_rejected() {
    let pki = pki_or_skip!();
    let error =
        ServerIdentity::new(&pki.chain_pem, b"not a private key").expect_err("非 PEM 私钥必须被拒");
    assert!(matches!(error, Error::TlsConfig(_)), "错误变体：{error:?}");
    assert_no_material(&error.to_string(), &pki, "坏私钥");
}

/// 私钥与证书不配对：`ServerIdentity::new` 构造期即拒绝（fail-closed）。
#[test]
fn mismatched_key_and_certificate_are_rejected() {
    let pki = pki_or_skip!();
    let error =
        ServerIdentity::new(&pki.chain_pem, &pki.other_key_pem).expect_err("不配对私钥必须被拒");
    assert!(matches!(error, Error::TlsConfig(_)), "错误变体：{error:?}");
    assert_no_material(&error.to_string(), &pki, "不配对私钥");
}

/// 过期证书：CA 与名称都正确，但叶子已于 2021 年过期 → 握手阶段拒绝。
#[tokio::test]
async fn expired_certificate_is_rejected_at_handshake() {
    let pki = pki_or_skip!();
    // 服务端出示过期叶子（配对其自身私钥），客户端信任测试 CA。
    let identity =
        ServerIdentity::new(&pki.expired_chain_pem, &pki.expired_key_pem).expect("过期叶子配置");
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(identity));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("监听");
    let port = listener.local_addr().expect("地址").port();
    tokio::spawn(async move {
        if let Ok((socket, _)) = listener.accept().await {
            let _ = timeout(WAIT, acceptor.accept(socket)).await;
        }
    });
    let config = ClientTrust::new(&pki.ca_pem, NAME).expect("客户端信任配置");
    expect_handshake_rejected(config, NAME, port, &pki, "过期证书", "expired").await;
}

/// 非 PKCS#8 私钥（SEC1 `EC PRIVATE KEY`）必须拒绝。
#[test]
fn non_pkcs8_private_key_is_rejected() {
    let pki = pki_or_skip!();
    let out = std::process::Command::new("openssl")
        .args(["ecparam", "-genkey", "-name", "prime256v1"])
        .output()
        .expect("openssl ecparam 启动");
    if !out.status.success() || out.stdout.is_empty() {
        eprintln!("跳过：openssl 未能生成 SEC1 私钥");
        return;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("BEGIN EC PRIVATE KEY"), "夹具应为 SEC1 私钥");
    let error =
        ServerIdentity::new(&pki.chain_pem, &out.stdout).expect_err("非 PKCS#8 私钥必须被拒");
    assert!(matches!(error, Error::TlsConfig(_)), "错误变体：{error:?}");
    assert_no_material(&error.to_string(), &pki, "非 PKCS#8 私钥");
}

/// `Display` 不泄漏材料：配置错误只给静态原因。
#[test]
fn configuration_errors_never_echo_certificate_material() {
    let pki = pki_or_skip!();
    let cases = [
        ServerIdentity::new(b"", &pki.key_pem).err(),
        ServerIdentity::new(&pki.chain_pem, b"").err(),
        ClientTrust::new(b"", NAME).err(),
    ];
    for error in cases.into_iter().flatten() {
        assert_no_material(&error.to_string(), &pki, "配置错误");
        assert_no_material(&format!("{error:?}"), &pki, "配置错误 Debug");
    }
}
