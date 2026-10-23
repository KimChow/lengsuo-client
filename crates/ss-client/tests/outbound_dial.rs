//! `ss_client::outbound` 的拨号验收用例。
//!
//! 假服务端只服务本测试：直接复用 `ss_core` 的 KDF / AEAD / chunk 原语，
//! 不做任何第二套协议实现，也不伪装成可复用 fixture。
//!
//! 口令与地址全部是测试专用假值：口令 `TESTONLY-PASSWORD`，服务器绑定
//! `127.0.0.1:0`，无真实出口。

use std::net::SocketAddr;
use std::time::Duration;

use ss_client::config::OutboundConfig;
use ss_client::outbound::{DialError, Dialer};
use ss_core::chunk::{read_chunk, write_chunk};
use ss_core::crypto::{CipherSuite, SessionAead};
use ss_core::kdf::{evp_bytes_to_key, hkdf_sha1_subkey};
use ss_core::target::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PASSWORD: &str = "TESTONLY-PASSWORD";
const METHOD: &str = "aes-256-gcm";

/// 构造一份指向 `server` 的假配置（`ss://method:password@host:port`）。
fn config_for(server: SocketAddr, method: &str, password: &str, timeout_ms: u64) -> OutboundConfig {
    OutboundConfig {
        ss_url: format!("ss://{method}:{password}@{server}"),
        udp: false,
        mux: Default::default(),
        connect_timeout_ms: timeout_ms,
    }
}

/// 与服务端同向的 AEAD 上下文（测试侧独立派生）。
fn aead_for(suite: CipherSuite, password: &[u8], salt: &[u8]) -> SessionAead {
    let master = evp_bytes_to_key(password, suite.key_len());
    let subkey = hkdf_sha1_subkey(&master, salt, suite.key_len());
    SessionAead::new(suite, subkey)
}

async fn read_exact_bytes(stream: &mut TcpStream, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.unwrap();
    buf
}

fn target() -> TargetAddr {
    TargetAddr::Domain("example.com".to_owned(), 8080)
}

#[tokio::test]
async fn authenticated_connect_delivers_first_response() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let suite = CipherSuite::Aes256Gcm;

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        // 请求方向：salt + 一个加密 chunk（地址 + 首批载荷）。
        let salt = read_exact_bytes(&mut sock, suite.salt_len()).await;
        let mut request_aead = aead_for(suite, PASSWORD.as_bytes(), &salt);
        let request = read_chunk(&mut sock, &mut request_aead)
            .await
            .unwrap()
            .unwrap();
        // 回程方向：独立 salt + 一个加密 chunk。
        let resp_salt = vec![0x5Au8; suite.salt_len()];
        sock.write_all(&resp_salt).await.unwrap();
        let mut resp_aead = aead_for(suite, PASSWORD.as_bytes(), &resp_salt);
        write_chunk(&mut sock, &mut resp_aead, b"hello from server")
            .await
            .unwrap();
        sock.flush().await.unwrap();
        // 隧道写方向（AsyncWrite）的载荷：同一请求方向的 nonce 序列续用。
        let follow_up = read_chunk(&mut sock, &mut request_aead)
            .await
            .unwrap()
            .unwrap();
        (request, follow_up)
    });

    let dialer = Dialer::new(config_for(addr, METHOD, PASSWORD, 5_000)).unwrap();
    let mut tunnel = dialer.connect(&target(), b"ping").await.unwrap();
    assert_eq!(tunnel.first_response(), b"hello from server");

    // 首个认证 chunk 也是隧道读方向的首批字节。
    let mut got = vec![0u8; 64];
    let n = tunnel.read(&mut got).await.unwrap();
    assert_eq!(&got[..n], b"hello from server");

    // AsyncWrite 走同一条 AEAD 请求方向。
    tunnel.write_all(b"more data").await.unwrap();

    let (request, follow_up) = tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("server must finish")
        .unwrap();
    assert_eq!(follow_up, b"more data");

    // 请求明文 = 目标地址编码 + 首批载荷。
    let mut expected = Vec::new();
    target().encode_checked(&mut expected).unwrap();
    expected.extend_from_slice(b"ping");
    assert_eq!(request, expected);
}

#[tokio::test]
async fn wrong_password_is_auth_failed() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        // 随机密文：salt + 足够长的垃圾，使客户端 size 帧 AEAD 认证必然失败。
        let junk = vec![0xABu8; 32 + 256];
        sock.write_all(&junk).await.unwrap();
        sock.flush().await.unwrap();
        // 保持连接，避免客户端先看到 EOF 而不是认证失败。
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let dialer = Dialer::new(config_for(addr, METHOD, "WRONG-PASSWORD", 2_000)).unwrap();
    let err = dialer
        .connect(&target(), b"ping")
        .await
        .err()
        .expect("wrong password must fail");
    assert!(matches!(err, DialError::AuthFailed), "got {err:?}");
}

#[tokio::test]
async fn server_silent_after_accept_times_out() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        // accept 后不回复，保持连接直到测试结束。
        tokio::time::sleep(Duration::from_secs(5)).await;
        drop(sock);
    });

    let dialer = Dialer::new(config_for(addr, METHOD, PASSWORD, 200)).unwrap();
    let err = tokio::time::timeout(Duration::from_secs(2), dialer.connect(&target(), b"ping"))
        .await
        .expect("connect must return within the deadline")
        .err()
        .expect("silent server must fail the connect");
    assert!(matches!(err, DialError::Timeout), "got {err:?}");
}

#[test]
fn unknown_method_is_unsupported() {
    let addr = "127.0.0.1:1".parse().unwrap();
    let err = Dialer::new(config_for(addr, "rot13", PASSWORD, 5_000))
        .err()
        .expect("unknown method must be rejected");
    assert!(matches!(err, DialError::UnsupportedMethod), "got {err:?}");
}
