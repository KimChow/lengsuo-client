//! SIP023 EIH 的 **UDP 侧** 与固定 Xray 多用户 SS2022 入站的实跑互通。
//!
//! 参考事实（必须先读代码确认，勿凭推测）：
//! - Xray `proxy/shadowsocks_2022/inbound_multi.go:190-224` 的 `Process` 在
//!   `network != TCP` 时走 `i.service.NewPacket(...)`，即 **UDP 多用户入站**；
//! - 其底层是 `sing-shadowsocks v0.2.7` 的 `shadowaead_2022.MultiService`，
//!   `service_multi.go:269` 的 `newPacket` **只剥一层身份头**（`binary.Read`
//!   读走 separate header 后 `Advance(16)` 跳过第 1 个身份头块）；
//! - 因此本用例用**一层**身份链（`[服务端身份 PSK, 用户 PSK]`），与参考
//!   逐字节等价；多层链参考侧不可达（见 `docs/ss2022-status.md` 偏离清单）。
//!
//! 判据：
//! - Rust 客户端（1 层身份链）→ Xray 多用户 UDP 入站 → freedom → 回环 echo，
//!   回程逐字节等于请求；
//! - 用户 2 的身份头喂给只注册用户 1 的入站 ⇒ 零抵达（隔离性）。
//!
//! 超时不算通过：必须实测收到回程或明确零抵达。
#![allow(dead_code)]

#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;

use base64::{engine::general_purpose::STANDARD, Engine};
use lengsuo_ss2022::{
    crypto::{Key, Method},
    eih_udp::{EihUdpChain, EihUdpSender},
    receiver::Clock,
};
use serde_json::{json, Value};
use ss_core::target::TargetAddr;
use std::{
    net::Ipv4Addr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{free_port, launch, WAIT};
use tokio::{net::UdpSocket, time::timeout};

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
    Clock {
        unix_seconds: now_secs(),
        monotonic: Instant::now(),
    }
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
                "network": "tcp,udp",
                "clients": clients
            }
        }],
        "outbounds": [{"protocol": "freedom"}]
    })
}

/// 构造 1 层身份链的 UDP 发送端（与参考客户端 `pskList=[iPSK, uPSK]` 等价）。
fn sender(identity: &Key, user: &Key) -> EihUdpSender {
    let chain = EihUdpChain::new(vec![identity.clone(), user.clone()]).expect("身份链应可构造");
    assert_eq!(chain.layers(), 1, "参考服务端只解一层");
    EihUdpSender::new(chain).expect("发送端应可构造")
}

/// Rust 客户端 → Xray 多用户 UDP 入站 → freedom → 回环 echo，返回回程字节。
///
/// 回包是 **SS2022 UDP 响应包**（不是明文）：响应方向的 separate header 由
/// **用户 PSK** 的 AES 块密码加密（参考 `service_multi.go:378`
/// `s.uCipher[user]`），AEAD 会话密钥由用户 PSK 与**服务端会话 id** 派生，
/// 明文体首字节是方向(1=响应) 且带客户端会话 id —— 与本 crate 的
/// `Key::open_server` 语义一致。
async fn udp_roundtrip(
    port: u16,
    identity: &Key,
    user: &Key,
    echo_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let socket = UdpSocket::bind(BIND).await.expect("回环可监听");
    socket
        .connect((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("应可连接 Xray");
    let mut sender = sender(identity, user);
    let packet = sender
        .seal(&TargetAddr::V4(LOOPBACK, echo_port), payload, now_secs(), 0)
        .expect("封包应成功");
    socket.send(&packet).await.expect("应可发出");

    let mut buffer = [0u8; 16384];
    let received = timeout(WAIT, socket.recv(&mut buffer))
        .await
        .expect("回包超时不算通过")
        .expect("应可收到回包");
    let decoded = user
        .open_server(&buffer[..received], now_secs(), sender.session_id())
        .expect("响应方向应可解密");
    decoded.payload
}

/// Rust 客户端 → Xray 多用户 UDP 入站（只注册用户 1）⇒ 零抵达。
async fn expect_no_delivery(port: u16, identity: &Key, user: &Key, echo_port: u16) {
    let socket = UdpSocket::bind(BIND).await.expect("回环可监听");
    socket
        .connect((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("应可连接 Xray");
    let mut sender = sender(identity, user);
    let packet = sender
        .seal(
            &TargetAddr::V4(LOOPBACK, echo_port),
            b"stranger\n",
            now_secs(),
            0,
        )
        .expect("封包应成功");
    socket.send(&packet).await.expect("应可发出");

    let mut buffer = [0u8; 16384];
    match timeout(Duration::from_secs(3), socket.recv(&mut buffer)).await {
        Err(_) => println!("reject unknown-user: no reply within limit"),
        Ok(Ok(received)) => panic!("未注册用户不应得到回包，实收 {received} 字节"),
        Ok(Err(error)) => println!("reject unknown-user: {error}"),
    }
}

/// 用户 1 往返 + 用户 2 隔离性（Xray 多用户 UDP 入站）。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn udp_eih_multiuser_roundtrip_and_isolation() {
    timeout(OVERALL, async {
        let method = Method::Aes256;
        let name = "2022-blake3-aes-256-gcm";
        let identity_psk = vec![0xAA; 32];
        let user1_psk = vec![0x11; 32];
        let user2_psk = vec![0x22; 32];
        // 回环 echo：收到即原样回发。
        let echo = UdpSocket::bind(BIND).await.expect("echo 应可监听");
        let echo_port = echo.local_addr().expect("echo 有地址").port();
        let echo_task = tokio::spawn(async move {
            let mut buffer = [0u8; 16384];
            let (received, peer) = echo.recv_from(&mut buffer).await.expect("echo 应可收到");
            echo.send_to(&buffer[..received], peer)
                .await
                .expect("echo 应可回发");
        });

        let port = free_port();
        let reference = launch(
            multi_user_config(port, name, &identity_psk, &[("user1", &user1_psk)]),
            port,
        )
        .await;

        let identity = key(method, &identity_psk);
        let user1 = key(method, &user1_psk);
        let user2 = key(method, &user2_psk);

        // 用户 1：往返逐字节一致。
        let payload = b"udp-eih-user1-payload";
        let reply = udp_roundtrip(port, &identity, &user1, echo_port, payload).await;
        assert_eq!(reply, payload, "用户 1 往返载荷必须逐字节一致");
        println!("cell udp eih user1: roundtrip {} bytes ok", payload.len());

        // 用户 2 未注册：必须零抵达。
        expect_no_delivery(port, &identity, &user2, echo_port).await;

        drop(reference);
        timeout(WAIT, echo_task)
            .await
            .expect("echo 任务超时")
            .expect("echo 任务失败");
    })
    .await
    .expect("UDP EIH 往返总超时");
}
