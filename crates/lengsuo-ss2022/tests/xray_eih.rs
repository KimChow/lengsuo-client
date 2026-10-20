//! SIP023 EIH 与固定 Xray 多用户 SS2022 入站的实跑互通（仅回环、假 PSK）。
//!
//! 判据：
//! - 用户 1 / 用户 2 各自用 `[服务端身份 PSK, 用户 PSK]` 生成一层身份头，
//!   TCP 一次往返逐字节一致；
//! - 用户 1 的完整密文用用户 2 的 PSK 解开必须 `Error::Authentication`（隔离性）；
//! - 四类反例（未知身份、正确身份+错误 body PSK、错误身份子密钥、完全缺 EIH）
//!   服务端必须关闭连接；**读取超时不算通过**，必须实测到 EOF/重置。
#![allow(dead_code)]

#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;

use base64::{engine::general_purpose::STANDARD, Engine};
use lengsuo_ss2022::{
    crypto::{Key, Method},
    eih::IdentityChain,
    receiver::Clock,
    tcp::{receive::clock_at, Direction, Reader, SessionReplay, Writer},
    Error,
};
use serde_json::{json, Value};
use ss_core::target::TargetAddr;
use std::{
    net::Ipv4Addr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{free_port, launch, WAIT};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const OVERALL: Duration = Duration::from_secs(120);
const BIND: &str = "127.0.0.1:0";
const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时钟应晚于纪元")
        .as_secs()
}

fn clock() -> Clock {
    clock_at(now_secs(), Instant::now())
}

fn key(method: Method, psk: &[u8]) -> Key {
    Key::new(method, psk).expect("假 PSK 长度应匹配套件")
}

/// Xray 多用户入站：`password` 是服务端身份 PSK，`clients[*].password` 是用户 PSK。
fn multi_user_config(port: u16, method: &str, identity: &[u8], users: &[(&str, &[u8])]) -> Value {
    let clients: Vec<Value> = users
        .iter()
        .map(|(email, psk)| json!({"email": email, "password": STANDARD.encode(psk)}))
        .collect();
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "shadowsocks",
            "settings": {
                "method": method,
                "password": STANDARD.encode(identity),
                "network": "tcp",
                "clients": clients
            }
        }],
        "outbounds": [{"protocol": "freedom"}]
    })
}

/// 每条连接读一次并原样回写，随后关写半。
async fn serve_echo(listener: TcpListener, connections: usize) {
    for _ in 0..connections {
        let (mut conn, _peer) = timeout(WAIT, listener.accept())
            .await
            .expect("echo 接受超时")
            .expect("echo 应可接受");
        let mut buffer = [0u8; 64];
        let read = timeout(WAIT, conn.read(&mut buffer))
            .await
            .expect("echo 读超时")
            .expect("echo 读失败");
        assert!(read > 0, "echo 在收到载荷前看到 EOF");
        timeout(WAIT, conn.write_all(&buffer[..read]))
            .await
            .expect("echo 回写超时")
            .expect("echo 回写失败");
        let _ = conn.shutdown().await;
    }
}

/// Rust 客户端 → Xray 多用户入站 → freedom → 回环 echo，返回回程字节。
async fn eih_roundtrip(
    port: u16,
    identity: &Key,
    user: &Key,
    echo_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut stream = timeout(WAIT, TcpStream::connect((Ipv4Addr::LOCALHOST, port)))
        .await
        .expect("连接 Xray 超时")
        .expect("应可连接 Xray");
    let mut writer = Writer::random(user, Direction::Request).expect("可构造写端");
    let chain = IdentityChain::new(vec![identity.clone()], user.clone()).expect("身份链");
    writer
        .set_identity_headers(chain.headers(writer.salt()).expect("身份头可编码"))
        .expect("身份头可挂载");
    let target = TargetAddr::V4(LOOPBACK, echo_port);
    timeout(
        WAIT,
        writer.write_request_header(&mut stream, &target, payload, now_secs(), 8),
    )
    .await
    .expect("请求开场超时")
    .expect("请求开场应可写出");
    timeout(WAIT, writer.write_finish(&mut stream))
        .await
        .expect("请求收尾超时")
        .expect("请求收尾应可写出");

    let mut reader =
        Reader::new(user.clone(), Direction::Response, Duration::from_secs(5)).expect("读端");
    let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
    let opened = timeout(
        WAIT,
        reader.open(&mut stream, &mut replay, clock(), Some(writer.salt())),
    )
    .await
    .expect("响应开场超时")
    .expect("响应开场应通过校验");
    let mut reply = opened.payload;
    // 参考服务端收到上游 EOF 后直接关连接，不发零长终止 chunk；收满预期长度即停。
    while reply.len() < payload.len() {
        let chunk = timeout(WAIT, reader.read_payload(&mut stream))
            .await
            .expect("响应载荷超时")
            .expect("响应载荷应可读");
        match chunk {
            Some(chunk) => reply.extend_from_slice(&chunk),
            None => panic!("回程在收满预期载荷前收到终止 chunk"),
        }
    }
    reply
}

/// 身份头构造方式（反例用）。
enum EihAuth<'a> {
    /// 正常：服务端身份 PSK 派生身份子密钥，指纹指向 `final_for_header`。
    Chain {
        identity: &'a Key,
        final_for_header: &'a Key,
    },
    /// 完全省略身份头（模拟单用户客户端）。
    Missing,
}

/// 发出一条请求开场后等待服务端拒绝。EOF 或连接重置算拒绝；
/// **超时不算通过**，任何回程数据都判失败。
async fn expect_rejected(
    port: u16,
    body_key: &Key,
    auth: EihAuth<'_>,
    payload: &[u8],
    label: &str,
) {
    let mut stream = timeout(WAIT, TcpStream::connect((Ipv4Addr::LOCALHOST, port)))
        .await
        .unwrap_or_else(|_| panic!("{label}：连接 Xray 超时"))
        .unwrap_or_else(|error| panic!("{label}：连接 Xray 失败 {error}"));
    let mut writer = Writer::random(body_key, Direction::Request).expect("可构造写端");
    if let EihAuth::Chain {
        identity,
        final_for_header,
    } = auth
    {
        let chain = IdentityChain::new(vec![identity.clone()], final_for_header.clone())
            .expect("身份链可构造");
        writer
            .set_identity_headers(chain.headers(writer.salt()).expect("身份头可编码"))
            .expect("身份头可挂载");
    }
    let target = TargetAddr::V4(LOOPBACK, 9);
    timeout(
        WAIT,
        writer.write_request_header(&mut stream, &target, payload, now_secs(), 0),
    )
    .await
    .unwrap_or_else(|_| panic!("{label}：开场写出超时"))
    .unwrap_or_else(|error| panic!("{label}：开场写出失败 {error:?}"));

    let mut byte = [0u8; 1];
    match timeout(WAIT, stream.read(&mut byte)).await {
        Err(_) => panic!("{label}：超时不判通过，服务端未在限定时间内关闭连接"),
        Ok(Ok(0)) => {}
        Ok(Err(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            ) => {}
        Ok(Ok(read)) => panic!("{label}：服务端不应返回数据，实收 {read} 字节"),
        Ok(Err(error)) => panic!("{label}：意外 I/O 错误 {error}"),
    }
    println!("reject {label}: server closed without reply");
}

/// 两用户各自往返 + 密文隔离。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn eih_multiuser_two_users_roundtrip_and_isolation() {
    timeout(OVERALL, async {
        let method = Method::Aes256;
        let name = "2022-blake3-aes-256-gcm";
        let identity_psk = vec![0xAA; 32];
        let user1_psk = vec![0x11; 32];
        let user2_psk = vec![0x22; 32];
        let echo = TcpListener::bind(BIND).await.expect("echo 应可监听");
        let echo_port = echo.local_addr().expect("echo 有地址").port();
        let echo_task = tokio::spawn(serve_echo(echo, 2));
        let port = free_port();
        let reference = launch(
            multi_user_config(
                port,
                name,
                &identity_psk,
                &[("user1", &user1_psk), ("user2", &user2_psk)],
            ),
            port,
        )
        .await;

        let identity = key(method, &identity_psk);
        let user1 = key(method, &user1_psk);
        let user2 = key(method, &user2_psk);
        for (label, user) in [("user1", &user1), ("user2", &user2)] {
            let payload = format!("eih-roundtrip-{label}\n").into_bytes();
            let reply = eih_roundtrip(port, &identity, user, echo_port, &payload).await;
            assert_eq!(reply, payload, "{label} 往返载荷必须逐字节一致");
            println!("cell eih {label}: roundtrip {} bytes ok", payload.len());
        }

        // 隔离性：用户 1 的完整请求密文（salt+EIH+AEAD）用用户 2 的 PSK 解不开。
        let mut wire = Vec::new();
        let mut writer = Writer::random(&user1, Direction::Request).expect("写端");
        let chain = IdentityChain::new(vec![identity.clone()], user1.clone()).expect("链");
        writer
            .set_identity_headers(chain.headers(writer.salt()).expect("身份头"))
            .expect("挂载");
        writer
            .write_request_header(
                &mut wire,
                &TargetAddr::V4(LOOPBACK, echo_port),
                b"isolation\n",
                now_secs(),
                8,
            )
            .await
            .expect("开场可写");
        writer.write_finish(&mut wire).await.expect("收尾可写");

        let listener = TcpListener::bind(BIND).await.expect("回环可监听");
        let mut client = TcpStream::connect(listener.local_addr().expect("有地址"))
            .await
            .expect("回环可连接");
        let (mut server_stream, _peer) = listener.accept().await.expect("回环可接受");
        client.write_all(&wire).await.expect("写入密文");
        drop(client);
        let mut reader =
            Reader::new(user2.clone(), Direction::Request, Duration::from_secs(2)).expect("读端");
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let outcome = timeout(
            WAIT,
            reader.open(&mut server_stream, &mut replay, clock(), None),
        )
        .await
        .expect("隔离性判定超时");
        match outcome {
            Ok(_) => panic!("user2 的 PSK 不得解开 user1 的密文"),
            Err(error) => assert!(
                matches!(error, Error::Authentication),
                "隔离性应报 Authentication，实际 {error:?}"
            ),
        }
        println!("cell isolation: user1 ciphertext rejected for user2");

        drop(reference);
        timeout(WAIT, echo_task)
            .await
            .expect("echo 任务超时")
            .expect("echo 任务失败");
    })
    .await
    .expect("EIH 往返总超时");
}

/// 四类反例：服务端必须主动关闭，无有效回程；超时不判通过。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn eih_rejects_unknown_identity_and_psk_mismatch() {
    timeout(OVERALL, async {
        let method = Method::Aes128;
        let name = "2022-blake3-aes-128-gcm";
        let identity_psk = vec![0xAA; 16];
        let user1_psk = vec![0x11; 16];
        let user2_psk = vec![0x22; 16];
        let unknown_psk = vec![0x99; 16];
        let port = free_port();
        let reference = launch(
            multi_user_config(
                port,
                name,
                &identity_psk,
                &[("user1", &user1_psk), ("user2", &user2_psk)],
            ),
            port,
        )
        .await;
        let identity = key(method, &identity_psk);
        let user1 = key(method, &user1_psk);
        let user2 = key(method, &user2_psk);
        let unknown = key(method, &unknown_psk);

        // 1) 未知身份指纹：EIH 指向不在 clients 中的 PSK。
        expect_rejected(
            port,
            &user1,
            EihAuth::Chain {
                identity: &identity,
                final_for_header: &unknown,
            },
            b"unknown-uid\n",
            "unknown-identity",
        )
        .await;

        // 2) 正确身份头（user1），但 AEAD body 用 user2 的 PSK。
        expect_rejected(
            port,
            &user2,
            EihAuth::Chain {
                identity: &identity,
                final_for_header: &user1,
            },
            b"wrong-body-psk\n",
            "known-uid-wrong-body-psk",
        )
        .await;

        // 3) 身份子密钥派生用错 PSK（用 user1 当身份 PSK），EIH 解出伪随机指纹。
        expect_rejected(
            port,
            &user1,
            EihAuth::Chain {
                identity: &user1,
                final_for_header: &user1,
            },
            b"wrong-identity-subkey\n",
            "wrong-identity-subkey",
        )
        .await;

        // 4) 完全缺 EIH：多用户入站不得回退到单用户 PSK。
        expect_rejected(
            port,
            &user1,
            EihAuth::Missing,
            b"missing-eih\n",
            "missing-eih",
        )
        .await;

        drop(reference);
        println!("all EIH negative cases rejected by reference server");
    })
    .await
    .expect("EIH 反例总超时");
}
