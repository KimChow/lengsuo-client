//! SS2022 UDP 错误路径与重放的真实 Xray 参考验收（仅回环、测试专用假密钥）。
//!
//! 判据统一为「是否抵达回环目标」：本测试自己实现的那一段中继（Rust 侧认证解密后
//! 才向目标 UDP 套接字转发）就是交付点；错误密钥与篡改必须在交付点之前失败，同一
//! 密文重放不得产生第二次交付。
//!
//! 固定参考：Xray v26.3.27 / d2758a0。`proxy/shadowsocks_2022/inbound.go` 把 UDP
//! 报文交给 sing-shadowsocks `shadowaead_2022` 服务，`proxy/shadowsocks_2022/outbound.go`
//! 是出站方向。本文件不主张 TCP 方向结论，也不把内部窗口测试当作参考互通证据。

#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;
use base64::{engine::general_purpose::STANDARD, Engine};
use lengsuo_ss2022::{
    crypto::{Key, Method},
    packet::Sender,
    receiver::{Clock, Receiver},
    Error,
};
use serde_json::json;
use ss_core::target::TargetAddr;
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::*;
use tokio::{net::UdpSocket, time::timeout};

/// 判定「不再抵达」的静默窗口：大于参考端正常送达耗时，避免把慢速误判成拒绝。
const SETTLE: Duration = Duration::from_millis(1500);
/// 整体预算：多次 Xray 启动与若干静默窗口的上限。
const BUDGET: Duration = Duration::from_secs(120);
const METHOD: Method = Method::Aes256;
const NAME: &str = "2022-blake3-aes-256-gcm";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn clock() -> Clock {
    Clock {
        unix_seconds: now(),
        monotonic: Instant::now(),
    }
}
/// 测试假密钥：只按填充字节区分，与任何生产密钥无关。
fn psk(byte: u8) -> Vec<u8> {
    vec![byte; METHOD.key_len()]
}
fn key(byte: u8) -> Key {
    Key::new(METHOD, &psk(byte)).expect("假密钥长度应合法")
}
fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
}

/// `Decoded` 故意不实现 `Debug`（载荷不得进日志），因此不能直接 `expect_err`。
/// 成功即 panic，失败交出错误。
fn rejected(outcome: Result<lengsuo_ss2022::packet::Decoded, Error>, what: &str) -> Error {
    match outcome {
        Ok(_) => panic!("{what}：必须失败却返回了已解密的报文"),
        Err(error) => error,
    }
}

/// 取回 `within` 内抵达目标的全部数据报；窗口到点即停，绝不无限读取。
async fn arrivals(target: &UdpSocket, within: Duration) -> Vec<Vec<u8>> {
    let mut got: Vec<Vec<u8>> = Vec::new();
    let mut buffer = [0u8; 2048];
    while got.len() < 8 {
        match timeout(within, target.recv_from(&mut buffer)).await {
            Ok(Ok((length, _peer))) => got.push(buffer[..length].to_vec()),
            _ => break,
        }
    }
    got
}

/// 已连接参考入站的客户端套接字。
async fn client(port: u16) -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(loopback(port)).await.unwrap();
    socket
}

/// Xray SS2022 服务端入站（tcp,udp）+ freedom 出站。
fn server_config(port: u16, byte: u8) -> serde_json::Value {
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"shadowsocks",
            "settings":{"method":NAME,"password":STANDARD.encode(psk(byte)),"network":"tcp,udp"}}],
        "outbounds":[{"protocol":"freedom"}]})
}

/// Xray dokodemo-door(目标) → SS2022 出站 → Rust 监听端口。
fn xray_client_config(port: u16, target_port: u16, rust_port: u16, byte: u8) -> serde_json::Value {
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"dokodemo-door",
            "settings":{"address":"127.0.0.1","port":target_port,"network":"tcp,udp"}}],
        "outbounds":[{"protocol":"shadowsocks","settings":{"servers":[{
            "address":"127.0.0.1","port":rust_port,"method":NAME,
            "password":STANDARD.encode(psk(byte))}]}}]})
}

/// 方向一：Rust 客户端 → Xray SS2022 服务端。错误密钥与篡改密文都不得抵达回环目标。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn xray_server_rejects_wrong_key_and_tampering() {
    timeout(BUDGET, async {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = TargetAddr::V4([127, 0, 0, 1], target.local_addr().unwrap().port());
        let port = free_port();
        let reference = launch(server_config(port, 0x11), port).await;
        let socket = client(port).await;

        // 控制组：正确密钥必须恰好抵达一次，否则后面的否定断言毫无意义。
        let mut sender = Sender::new(key(0x11), None).unwrap();
        socket
            .send(&sender.seal(&target_addr, b"control", now(), 0).unwrap())
            .await
            .unwrap();
        assert_eq!(
            arrivals(&target, SETTLE).await,
            vec![b"control".to_vec()],
            "控制组：正确密钥应抵达回环目标一次"
        );

        // 错误密钥：参考端必须认证失败，目标零抵达。
        let mut wrong = Sender::new(key(0x99), None).unwrap();
        socket
            .send(&wrong.seal(&target_addr, b"wrong-key", now(), 0).unwrap())
            .await
            .unwrap();
        assert!(
            arrivals(&target, SETTLE).await.is_empty(),
            "错误密钥的报文不得抵达回环目标"
        );

        // 篡改：头部加密块首字节 / 载荷认证 tag 末位。
        for which in ["header", "tag"] {
            let mut wire = sender.seal(&target_addr, b"tampered", now(), 0).unwrap();
            if which == "header" {
                wire[0] ^= 0x01;
            } else {
                let last = wire.len() - 1;
                wire[last] ^= 0x01;
            }
            socket.send(&wire).await.unwrap();
            assert!(
                arrivals(&target, SETTLE).await.is_empty(),
                "篡改 {which} 的报文不得抵达回环目标"
            );
        }

        // 正控制收尾：错误路径之后同会话正常报文仍须送达，证明拒绝不是关联失效。
        socket
            .send(&sender.seal(&target_addr, b"alive", now(), 0).unwrap())
            .await
            .unwrap();
        assert_eq!(
            arrivals(&target, SETTLE).await,
            vec![b"alive".to_vec()],
            "错误路径之后正确密钥仍须抵达回环目标"
        );
        drop(reference);
    })
    .await
    .expect("Xray SS2022 服务端错误路径整体超时");
}

/// 方向一：同一密文重放必须观测为「不二次交付」，且同会话新报文仍能送达。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn xray_server_does_not_redeliver_udp_replay() {
    timeout(BUDGET, async {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = TargetAddr::V4([127, 0, 0, 1], target.local_addr().unwrap().port());
        let port = free_port();
        let reference = launch(server_config(port, 0x11), port).await;
        let socket = client(port).await;
        let mut sender = Sender::new(key(0x11), None).unwrap();

        let wire = sender.seal(&target_addr, b"replay", now(), 0).unwrap();
        socket.send(&wire).await.unwrap();
        assert_eq!(
            arrivals(&target, SETTLE).await,
            vec![b"replay".to_vec()],
            "重放验收前提：原始密文必须已交付一次"
        );

        // 同 salt / 同 packet id 的完全相同密文再投两次：不得观测到二次交付。
        for round in 1..=2 {
            socket.send(&wire).await.unwrap();
            let again = arrivals(&target, SETTLE).await;
            assert!(
                again.is_empty(),
                "第 {round} 次重放被参考端二次交付：{again:?}"
            );
        }

        // 正控制：同会话下一个 packet id 仍须送达，证明「无二次交付」不是关联失效。
        socket
            .send(&sender.seal(&target_addr, b"fresh", now(), 0).unwrap())
            .await
            .unwrap();
        assert_eq!(
            arrivals(&target, SETTLE).await,
            vec![b"fresh".to_vec()],
            "重放拒绝后同会话新报文仍须抵达回环目标"
        );
        drop(reference);
    })
    .await
    .expect("Xray SS2022 服务端 UDP 重放整体超时");
}

/// 方向二：Xray 客户端（错误 PSK 出站）→ Rust 服务端。认证必须在交付点之前失败。
/// Xray 确实发出了密文（本端收到字节）即出站关联存活的正控制；每条被拒密文还必须
/// 能被「Xray 实际使用的出站密钥」解出，否则「零抵达」只是空集而非拒绝证据。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn rust_server_rejects_xray_wrong_key_ciphertext() {
    timeout(BUDGET, async {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let target_addr = TargetAddr::V4([127, 0, 0, 1], target_port);
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rust_port = server.local_addr().unwrap().port();
        let port = free_port();
        let reference = launch(xray_client_config(port, target_port, rust_port, 0x99), port).await;
        let mut receiver = Receiver::new(key(0x11), None, 4, Duration::from_secs(60)).unwrap();
        let mut xray_side = Receiver::new(key(0x99), None, 4, Duration::from_secs(60)).unwrap();
        let socket = client(port).await;
        let mut buffer = [0u8; 4096];
        for index in 0..2 {
            socket
                .send(format!("bad-key-{index}").as_bytes())
                .await
                .unwrap();
            let (length, peer) = timeout(WAIT, server.recv_from(&mut buffer))
                .await
                .expect("Xray 客户端应发出密文（出站关联存活正控制）")
                .expect("本端读取密文失败");
            let wire = buffer[..length].to_vec();
            let error = rejected(
                receiver.receive(&wire, peer, clock()),
                "错误 PSK 的密文不得被接受",
            );
            let text = format!("{error:?} {error}");
            assert!(
                !text.contains("0x11") && text.len() < 200,
                "错误消息不应包含密钥线索：{text}"
            );
            assert!(
                matches!(
                    error,
                    Error::Authentication
                        | Error::Timestamp
                        | Error::Direction
                        | Error::Length
                        | Error::HeaderPadding
                ),
                "应为认证/格式类失败，实际 {error:?}"
            );
            // 交付点判据：本端中继只在 receive 成功后才 send_to 目标，故此处必须零抵达。
            assert!(
                arrivals(&target, SETTLE).await.is_empty(),
                "错误 PSK 的密文不得抵达回环目标"
            );
            // 非空集控制：同一条密文用 Xray 实际出站密钥必须能认证解出，
            // 证明上面的拒绝来自密钥不符，而不是报文畸形或关联失效。
            let decoded = xray_side
                .receive(&wire, peer, clock())
                .unwrap_or_else(|e| panic!("第 {index} 条密文对 Xray 出站密钥应可解出：{e:?}"));
            assert_eq!(decoded.target, target_addr);
            assert_eq!(decoded.payload, format!("bad-key-{index}").as_bytes());
        }
        drop(reference);
    })
    .await
    .expect("Rust 服务端拒绝错误 PSK 整体超时");
}

/// 方向二（交付点正向控制）：Xray 出站密钥与 Rust 侧一致时，本端中继认证解密后确实
/// 把载荷转发到回环目标。缺了它，上一项与"中继本来就不会送达任何报文"无法区分。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn rust_server_relays_xray_ciphertext_to_target_positive_control() {
    timeout(BUDGET, async {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rust_port = server.local_addr().unwrap().port();
        let port = free_port();
        let reference = launch(xray_client_config(port, target_port, rust_port, 0x11), port).await;
        let mut receiver = Receiver::new(key(0x11), None, 4, Duration::from_secs(60)).unwrap();
        let socket = client(port).await;
        let mut buffer = [0u8; 4096];
        socket.send(b"relay-control").await.unwrap();
        let (length, peer) = timeout(WAIT, server.recv_from(&mut buffer))
            .await
            .expect("Xray 客户端应发出密文")
            .expect("本端读取密文失败");
        let decoded = receiver
            .receive(&buffer[..length], peer, clock())
            .expect("正向控制：匹配密钥必须认证成功");
        assert_eq!(decoded.payload, b"relay-control".to_vec());
        server
            .send_to(&decoded.payload, loopback(target_port))
            .await
            .unwrap();
        assert_eq!(
            arrivals(&target, SETTLE).await,
            vec![b"relay-control".to_vec()],
            "匹配密钥下本端中继必须把真实 Xray 密文送达回环目标"
        );
        drop(reference);
    })
    .await
    .expect("Rust 服务端中继正向控制整体超时");
}

/// 方向二：真实 Xray 出站密文重复投喂必须判为重放且不二次交付；篡改必须失败。
/// 注：固定参考出站每封一次就递增 packet id / 时间戳，不会自行重发同一条密文，
/// 因此本方向的「重放」由 Rust 侧对真实 Xray 密文重复投喂来观测（见 docs 限制）。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn rust_server_replays_and_rejects_tampered_xray_ciphertext() {
    timeout(BUDGET, async {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let target_addr = TargetAddr::V4([127, 0, 0, 1], target_port);
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rust_port = server.local_addr().unwrap().port();
        let port = free_port();
        let reference = launch(xray_client_config(port, target_port, rust_port, 0x11), port).await;
        let mut receiver = Receiver::new(key(0x11), None, 4, Duration::from_secs(60)).unwrap();
        let socket = client(port).await;

        // 采集两条真实 Xray 出站密文，认证解密后各交付一次到目标。
        let mut captured: Vec<(Vec<u8>, SocketAddr)> = Vec::new();
        let mut buffer = [0u8; 4096];
        for index in 0..2 {
            socket
                .send(format!("real-{index}").as_bytes())
                .await
                .unwrap();
            let (length, peer) = timeout(WAIT, server.recv_from(&mut buffer))
                .await
                .expect("Xray 客户端应发出密文")
                .expect("本端读取密文失败");
            let wire = buffer[..length].to_vec();
            let decoded = receiver
                .receive(&wire, peer, clock())
                .unwrap_or_else(|error| panic!("真实 Xray 密文应可认证解出：{error:?}"));
            assert_eq!(decoded.target, target_addr);
            assert_eq!(decoded.payload, format!("real-{index}").as_bytes());
            server
                .send_to(&decoded.payload, loopback(target_port))
                .await
                .unwrap();
            captured.push((wire, peer));
        }
        assert_eq!(
            arrivals(&target, SETTLE).await,
            vec!["real-0".as_bytes().to_vec(), "real-1".as_bytes().to_vec()],
            "两条真实 Xray 密文应各交付一次"
        );

        // 重复投喂同两条密文：必须判为重放，且不得产生第二次交付。
        for (index, (wire, peer)) in captured.iter().enumerate() {
            let replay = rejected(
                receiver.receive(wire, *peer, clock()),
                "真实 Xray 密文重复投喂必须被拒绝",
            );
            assert!(
                matches!(replay, Error::Replay),
                "第 {index} 条真实 Xray 密文重放应报 Replay，实际 {replay:?}"
            );
            // 区分「因重放被拒」与「因字节本身失效被拒」：全新接收器（空窗口、同
            // 密钥、同时间窗）必须仍能认证并解出同一条真实 Xray 密文。少了这一步，
            // 否定断言会因为报文过期/篡改等无关原因假通过。
            let mut fresh = Receiver::new(key(0x11), None, 4, Duration::from_secs(60)).unwrap();
            let reopened = fresh.receive(wire, *peer, clock()).unwrap_or_else(|error| {
                panic!("第 {index} 条密文对新接收器仍应可认证，否则重放结论不成立：{error:?}")
            });
            assert_eq!(reopened.payload, format!("real-{index}").as_bytes());
        }
        assert!(
            arrivals(&target, SETTLE).await.is_empty(),
            "重放不得抵达回环目标造成二次交付"
        );

        // 篡改真实密文的认证 tag：必须失败且不交付。
        let (second, peer) = &captured[1];
        let mut tampered = second.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let error = rejected(
            receiver.receive(&tampered, *peer, clock()),
            "篡改真实 Xray 密文必须被拒绝",
        );
        assert!(
            !matches!(error, Error::Replay),
            "篡改应先于重放判定失败，实际 {error:?}"
        );
        assert!(
            arrivals(&target, SETTLE).await.is_empty(),
            "篡改密文不得抵达回环目标"
        );
        drop(reference);
    })
    .await
    .expect("Rust 服务端真实密文重放整体超时");
}
