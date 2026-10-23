//! `ss_client::runtime` 的验收用例：路由纯函数 + 直连 / 代理路径端到端。
//!
//! 假 SS 服务端只服务本测试：直接复用 `ss_core` 的 KDF / AEAD / chunk 原语，
//! 不做第二套协议实现。口令与地址全部是测试专用假值。

use std::net::SocketAddr;
use std::time::Duration;

use ss_client::config::{load_config_str, ClientConfig};
use ss_client::runtime::{route, Route, Runtime};
use ss_core::chunk::{read_chunk, write_chunk};
use ss_core::crypto::{CipherSuite, SessionAead};
use ss_core::kdf::{evp_bytes_to_key, hkdf_sha1_subkey};
use ss_core::target::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PASSWORD: &str = "TESTONLY-PASSWORD";
const METHOD: &str = "aes-256-gcm";

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// 测试用最小配置：出口指向一个不会被真正连接的假地址。
fn config_with(extra: &str) -> ClientConfig {
    load_config_str(&format!(
        "{extra}\n[outbound]\nss_url = \"ss://{METHOD}:{PASSWORD}@127.0.0.1:1\"\n"
    ))
    .expect("test config must load")
}

// ---------------------------------------------------------------- 路由纯函数

#[test]
fn route_maps_decision_to_route() {
    // 命中 direct 规则 ⇒ Direct。
    let direct = config_with(
        "[[rules]]\nname = \"d\"\naction = \"direct\"\n\
         match = { domain_mode = \"plain\", domain = [\"example.com\"] }\n",
    );
    assert_eq!(
        route(&direct, &TargetAddr::Domain("example.com".to_owned(), 443)),
        Route::Direct
    );

    // 命中 proxy 规则 ⇒ Proxy。
    let proxy = config_with(
        "[[rules]]\nname = \"p\"\naction = \"proxy\"\n\
         match = { port = [\"443\"] }\n",
    );
    assert_eq!(
        route(&proxy, &TargetAddr::V4([8, 8, 8, 8], 443)),
        Route::Proxy
    );

    // 未命中 ⇒ fallback。
    let fallback_direct = config_with("fallback = \"direct\"\n");
    assert_eq!(
        route(&fallback_direct, &TargetAddr::V4([8, 8, 8, 8], 53)),
        Route::Direct
    );

    // 需要解析地址才能判定 ⇒ 一律 Proxy（即使 fallback 是 direct）。
    let unresolved = config_with(
        "fallback = \"direct\"\n\
         [[rules]]\nname = \"lan\"\naction = \"direct\"\n\
         match = { ip = [\"192.168.0.0/16\"] }\n",
    );
    assert_eq!(
        route(
            &unresolved,
            &TargetAddr::Domain("example.com".to_owned(), 443)
        ),
        Route::Proxy
    );
}

// ---------------------------------------------------------------- 端到端辅助

/// 单连接 echo 服务端，返回监听端口。
async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        loop {
            match sock.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    port
}

/// SOCKS5 CONNECT；`payload` 与请求头写在**同一次 write**，用于残留场景。
async fn socks_connect(proxy: SocketAddr, target: &TargetAddr, payload: &[u8]) -> TcpStream {
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);

    let mut request = vec![0x05, 0x00, 0x01];
    target.encode_into(&mut request);
    request.extend_from_slice(payload);
    client.write_all(&request).await.unwrap();

    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "SOCKS5 CONNECT must succeed");
    client
}

async fn spawn_runtime(config: ClientConfig) -> (Runtime, SocketAddr) {
    let runtime = Runtime::with_bind(config, loopback()).await.unwrap();
    let addr = runtime.local_addr().unwrap();
    (runtime, addr)
}

// ---------------------------------------------------------------- 直连路径

#[tokio::test]
async fn direct_route_roundtrips() {
    let echo_port = spawn_echo().await;
    let config = config_with(
        "[[rules]]\nname = \"direct-loopback\"\naction = \"direct\"\n\
         match = { ip = [\"127.0.0.1\"] }\n",
    );
    let (runtime, addr) = spawn_runtime(config).await;
    let target = TargetAddr::V4([127, 0, 0, 1], echo_port);

    // `Tunnel` 目前是 `!Send`，故服务端与客户端用 `join!` 同任务并发，
    // 不经过 `tokio::spawn`（见运行时模块 `run()` 的同一条说明）。
    let (served, ()) = tokio::join!(runtime.serve_one(), async {
        let mut client = socks_connect(addr, &target, b"").await;
        client.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
    });
    served.unwrap();
}

// ---------------------------------------------------------------- 代理路径

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

/// 假 SS 服务端：读首批请求 chunk，按 `respond` 回首个认证 chunk，随后回显。
/// 返回读到的所有请求明文（首个是「目标地址 + 首批载荷」）。
async fn run_fake_ss(listener: TcpListener, respond: fn(&[u8]) -> Vec<u8>) -> Vec<Vec<u8>> {
    let suite = CipherSuite::Aes256Gcm;
    let (mut sock, _) = listener.accept().await.unwrap();
    let salt = read_exact_bytes(&mut sock, suite.salt_len()).await;
    let mut request_aead = aead_for(suite, PASSWORD.as_bytes(), &salt);
    let first = read_chunk(&mut sock, &mut request_aead)
        .await
        .unwrap()
        .unwrap();
    let mut all = vec![first.clone()];

    let response_salt = vec![0x5Au8; suite.salt_len()];
    sock.write_all(&response_salt).await.unwrap();
    let mut response_aead = aead_for(suite, PASSWORD.as_bytes(), &response_salt);
    write_chunk(&mut sock, &mut response_aead, &respond(&first))
        .await
        .unwrap();
    sock.flush().await.unwrap();

    while let Ok(Some(chunk)) = read_chunk(&mut sock, &mut request_aead).await {
        all.push(chunk.clone());
        if write_chunk(&mut sock, &mut response_aead, &chunk)
            .await
            .is_err()
        {
            break;
        }
        let _ = sock.flush().await;
    }
    all
}

fn respond_ack(_: &[u8]) -> Vec<u8> {
    b"ACK".to_vec()
}

/// 回显请求里目标地址之后的载荷。
fn respond_echo_payload(first: &[u8]) -> Vec<u8> {
    let (_, consumed) =
        TargetAddr::decode(first).expect("request must start with a target address");
    first[consumed..].to_vec()
}

fn proxy_config(server: SocketAddr) -> ClientConfig {
    // 无规则 + 缺省 fallback(proxy) ⇒ 走代理。
    load_config_str(&format!(
        "[outbound]\nss_url = \"ss://{METHOD}:{PASSWORD}@{server}\"\n"
    ))
    .unwrap()
}

#[tokio::test]
async fn proxy_route_roundtrips() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let ss_addr = listener.local_addr().unwrap();
    let fake = tokio::spawn(run_fake_ss(listener, respond_ack));

    let (runtime, addr) = spawn_runtime(proxy_config(ss_addr)).await;
    let target = TargetAddr::V4([127, 0, 0, 1], 9);

    let (served, ()) = tokio::join!(runtime.serve_one(), async {
        let mut client = socks_connect(addr, &target, b"").await;
        // 服务端的首个认证 chunk（ACK）经隧道送达客户端。
        let mut ack = [0u8; 3];
        client.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"ACK");

        client.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
    });
    served.unwrap();

    let chunks = tokio::time::timeout(Duration::from_secs(2), fake)
        .await
        .expect("fake server must finish")
        .unwrap();
    let mut expected = Vec::new();
    target.encode_into(&mut expected);
    assert_eq!(
        chunks[0], expected,
        "first chunk is target only (no residual)"
    );
}

#[tokio::test]
async fn residual_payload_reaches_proxy_untouched() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let ss_addr = listener.local_addr().unwrap();
    let fake = tokio::spawn(run_fake_ss(listener, respond_echo_payload));

    let (runtime, addr) = spawn_runtime(proxy_config(ss_addr)).await;
    let payload = b"payload-with-connect";
    let target = TargetAddr::V4([127, 0, 0, 1], 9);

    let (served, ()) = tokio::join!(runtime.serve_one(), async {
        let mut client = socks_connect(addr, &target, payload).await;
        let mut got = vec![0u8; payload.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload, "residual payload must not be lost");
    });
    served.unwrap();

    let chunks = tokio::time::timeout(Duration::from_secs(2), fake)
        .await
        .expect("fake server must finish")
        .unwrap();
    let mut expected = Vec::new();
    target.encode_into(&mut expected);
    expected.extend_from_slice(payload);
    assert_eq!(
        chunks[0], expected,
        "target and residual must be in the same first chunk"
    );
}

// ---------------------------------------------------------------- 配置错误

#[tokio::test]
async fn invalid_method_is_an_error_not_a_panic() {
    let mut config = config_with("");
    config.outbound.ss_url = "ss://rot13:secret@127.0.0.1:1".to_owned();
    assert!(
        Runtime::new(config).await.is_err(),
        "unsupported method must fail Runtime::new"
    );
}
