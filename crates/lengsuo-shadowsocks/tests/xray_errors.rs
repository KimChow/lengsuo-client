//! 传统 Shadowsocks AEAD UDP 错误路径的真实 Xray 参考验收（仅回环、测试专用假口令）。
//!
//! 交付点判据：Rust→Xray 方向观测自由出站是否把载荷送达本端绑定的回环目标；
//! Xray→Rust 方向由本实现自己决定是否转发，因此错误口令必须让 `open` 失败且不转发。
//!
//! 参考面：Xray v26.3.27 / d2758a0，`proxy/shadowsocks/protocol.go` 的
//! `EncodeUDPPacket` / `DecodeUDPPacket`。该实现的 UDP 解码每包按 salt 重新派生
//! subkey 并一次解密，**不缓存 salt、没有重放过滤**，因此本方向的重放防护只能
//! 标记为「参考不支持、本端未实现」，见 `docs/ss-error-validation.md`。

#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;
use lengsuo_shadowsocks::{CipherSuite, TargetAddr, UdpCodec};
use serde_json::json;
use std::{net::Ipv4Addr, time::Duration};
use support::*;
use tokio::{net::UdpSocket, time::timeout};

/// 判定「不再抵达」的静默窗口：大于参考端正常送达耗时，避免把慢速误判成拒绝。
const SETTLE: Duration = Duration::from_millis(1500);
/// 整体预算：多次 Xray 启动与若干静默窗口的上限。
const BUDGET: Duration = Duration::from_secs(90);
const NAME: &str = "aes-256-gcm";
/// 测试假口令，与任何生产凭据无关。
const PASSWORD: &str = "ss-error-path-reference-passw0rd";
/// 另一个测试假口令，用于错误口令路径。
const WRONG: &str = "ss-error-path-wrong-passw0rd";

fn codec(password: &str) -> UdpCodec {
    UdpCodec::new(CipherSuite::from_name(NAME).unwrap(), password.as_bytes()).unwrap()
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

async fn client(port: u16) -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect((Ipv4Addr::LOCALHOST, port)).await.unwrap();
    socket
}

fn server_config(port: u16, password: &str) -> serde_json::Value {
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"shadowsocks",
            "settings":{"method":NAME,"password":password,"network":"tcp,udp"}}],
        "outbounds":[{"protocol":"freedom"}]})
}

/// Xray 作为客户端：dokodemo-door(回环目标端口) → shadowsocks 出站（指定口令）→ Rust。
fn xray_client_config(
    port: u16,
    target_port: u16,
    rust_port: u16,
    password: &str,
) -> serde_json::Value {
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"dokodemo-door",
            "settings":{"address":"127.0.0.1","port":target_port,"network":"tcp,udp"}}],
        "outbounds":[{"protocol":"shadowsocks","settings":{"servers":[{
            "address":"127.0.0.1","port":rust_port,"method":NAME,"password":password}]}}]})
}

/// 本端中继（交付点）：解密成功后才向回环目标转发，返回抵达目标的载荷。
/// 只有 open 成功才会 send_to，因此「零抵达」等价于「认证前失败」，且由本函数
/// 的成功路径保证该等价并非空集。
async fn relay_to_target(
    server: &UdpSocket,
    target: &UdpSocket,
    codec: &UdpCodec,
    buffer: &mut [u8],
    expect: &[u8],
    what: &str,
) -> Vec<Vec<u8>> {
    let (length, _peer) = timeout(WAIT, server.recv_from(buffer))
        .await
        .expect("Xray 客户端应发出密文（出站关联存活的正控制）")
        .expect("本端读取密文失败");
    let (address, payload) = codec
        .open(&buffer[..length])
        .unwrap_or_else(|error| panic!("{what}：真实 Xray 密文应可解密：{error:?}"));
    let target_addr = TargetAddr::V4([127, 0, 0, 1], port_of(target));
    assert_eq!(address, target_addr, "{what}：解密出的目标应为本端回环目标");
    assert_eq!(
        payload,
        expect.to_vec(),
        "{what}：解密载荷应与送入的假载荷一致"
    );
    server
        .send_to(&payload, (Ipv4Addr::LOCALHOST, port_of(target)))
        .await
        .unwrap();
    arrivals(target, SETTLE).await
}

fn port_of(socket: &UdpSocket) -> u16 {
    socket.local_addr().unwrap().port()
}

/// 方向一：Rust 客户端 → Xray SS 服务端。错误口令与篡改密文都不得抵达回环目标。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn xray_server_rejects_wrong_password_and_tampering() {
    timeout(BUDGET, async {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = TargetAddr::V4([127, 0, 0, 1], target.local_addr().unwrap().port());
        let port = free_port();
        let reference = launch(server_config(port, PASSWORD), port).await;
        let good = codec(PASSWORD);
        let socket = client(port).await;

        // 控制组：正确口令必须恰好抵达一次，否则后面的否定断言毫无意义。
        let control = good.seal(&target_addr, b"control").unwrap();
        socket.send(&control).await.unwrap();
        assert_eq!(
            arrivals(&target, SETTLE).await,
            vec![b"control".to_vec()],
            "控制组：正确口令应抵达回环目标一次"
        );

        // 错误口令：参考端必须认证失败，目标零抵达。
        let wrong = codec(WRONG).seal(&target_addr, b"wrong-password").unwrap();
        socket.send(&wrong).await.unwrap();
        assert!(
            arrivals(&target, SETTLE).await.is_empty(),
            "错误口令的报文不得抵达回环目标"
        );

        // 篡改：salt 首字节 / 认证 tag 末位，都不构成合法封装。
        for which in ["salt", "tag"] {
            let mut wire = good.seal(&target_addr, b"tampered").unwrap();
            if which == "salt" {
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

        // 正控制收尾：错误路径之后同口令正常报文仍须送达，证明拒绝不是关联失效。
        socket
            .send(&good.seal(&target_addr, b"alive").unwrap())
            .await
            .unwrap();
        assert_eq!(
            arrivals(&target, SETTLE).await,
            vec![b"alive".to_vec()],
            "错误路径之后正确口令仍须抵达回环目标"
        );
        drop(reference);
    })
    .await
    .expect("Xray SS 服务端错误路径整体超时");
}

/// 方向一（传统 SS UDP 重放）：**明确标记为不支持持久重放保护**，并锁定实测行为。
///
/// 先按「不得二次交付」主张跑过一次，实测为每条重复密文都再次交付（2/2 次），
/// 因此本方向的防护既不在固定参考（`proxy/shadowsocks/protocol.go` 的
/// `DecodeUDPPacket` 每包按 salt 重新派生 subkey 并一次解密，不缓存 salt、没有
/// packet id、没有重放过滤器），也不在本实现（`UdpCodec::open` 同样无状态）。
///
/// 本测试因此断言「确实二次交付」这一实测事实，作为该方向缺口的回归锁：若将来
/// 任一侧加入了 salt 过滤而使行为改变，本测试会失败并要求重新核对文档。它**不是**
/// 重放防护已实现的证据，禁止据此宣称持久重放保护完成。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn xray_server_legacy_udp_replay_is_redelivered_marked_unsupported() {
    timeout(BUDGET, async {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = TargetAddr::V4([127, 0, 0, 1], target.local_addr().unwrap().port());
        let port = free_port();
        let reference = launch(server_config(port, PASSWORD), port).await;
        let good = codec(PASSWORD);
        let socket = client(port).await;

        let wire = good.seal(&target_addr, b"replay").unwrap();
        socket.send(&wire).await.unwrap();
        assert_eq!(
            arrivals(&target, SETTLE).await,
            vec![b"replay".to_vec()],
            "重放观测前提：原始密文必须已送达一次"
        );

        // 完全相同密文再投两次：实测每次都再次交付（缺口回归锁）。
        let mut redelivered = 0usize;
        for round in 1..=2 {
            socket.send(&wire).await.unwrap();
            let again = arrivals(&target, SETTLE).await;
            assert_eq!(
                again,
                vec![b"replay".to_vec()],
                "第 {round} 次重复密文的交付与固定参考基线不符：该方向本就无重放过滤，\
                 若行为已改变必须重新核对 docs/ss-error-validation.md"
            );
            redelivered += again.len();
        }
        assert_eq!(
            redelivered, 2,
            "传统 SS UDP 重放缺口：两次重复投递都应再次交付"
        );

        // 本实现同样无 salt 过滤：重复密文仍可解密 ⇒ 入站防重放在本端也未实现。
        assert!(
            good.open(&wire).is_ok() && good.open(&wire).is_ok(),
            "本端无状态解码应可重复解密同包，用于证明本端未实现 salt 过滤"
        );

        // 正控制：同口令新一次封装仍须送达，证明上面结论不是关联失效造成的。
        socket
            .send(&good.seal(&target_addr, b"fresh").unwrap())
            .await
            .unwrap();
        assert_eq!(
            arrivals(&target, SETTLE).await,
            vec![b"fresh".to_vec()],
            "重放观测后正常报文仍须抵达回环目标"
        );
        drop(reference);
    })
    .await
    .expect("传统 SS UDP 重放观测整体超时");
}

/// 方向二：Xray 客户端 → Rust 服务端。先证明本端中继能把正确口令的真实 Xray 密文
/// 送达回环目标（交付点确实会收到字节），再断言错误口令密文必须让 `open` 失败且
/// 零抵达——否则「零抵达」只是空集，不构成任何证据。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn rust_server_rejects_xray_wrong_password_ciphertext() {
    timeout(BUDGET, async {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rust_port = server.local_addr().unwrap().port();
        let port = free_port();
        let reference = launch(
            xray_client_config(port, target_port, rust_port, WRONG),
            port,
        )
        .await;
        let good = codec(PASSWORD);
        let socket = client(port).await;
        let mut buffer = [0u8; 4096];
        for index in 0..2 {
            socket
                .send(format!("bad-key-{index}").as_bytes())
                .await
                .unwrap();
            let (length, _peer) = timeout(WAIT, server.recv_from(&mut buffer))
                .await
                .expect("Xray 客户端应发出密文（出站关联存活的正控制）")
                .expect("本端读取密文失败");
            let wire = buffer[..length].to_vec();
            let error = match good.open(&wire) {
                Ok((address, payload)) => panic!(
                    "错误口令的密文被本实现接受：目标 {address:?}，载荷 {} 字节",
                    payload.len()
                ),
                Err(error) => error,
            };
            let text = format!("{error:?} {error}");
            assert!(
                matches!(error, lengsuo_shadowsocks::UdpError::Authentication),
                "应为认证失败，实际 {text}"
            );
            assert!(!text.contains("passw0rd"), "错误消息不得包含口令：{text}");
            // 交付点判据：本端只在 open 成功后才转发，因此拒绝即零抵达。
            assert!(
                arrivals(&target, SETTLE).await.is_empty(),
                "错误口令的密文不得转发到回环目标：{text}"
            );
            // 同一批真实 Xray 密文用 Xray 实际使用的出站口令必须可解，
            // 证明上面的失败源自口令不符，而不是报文本身畸形。
            let (address, payload) = codec(WRONG)
                .open(&wire)
                .expect("同一密文用 Xray 实际使用的出站口令应可解密（非空集控制）");
            assert_eq!(address, TargetAddr::V4([127, 0, 0, 1], target_port));
            assert_eq!(payload, format!("bad-key-{index}").as_bytes());
        }
        drop(reference);
    })
    .await
    .expect("Rust 服务端拒绝错误口令整体超时");
}

/// 方向二（交付点正向控制组）：Xray 出站口令与 Rust 侧一致时，本端中继解密并转发，
/// 目标必须实际收到载荷。没有这一步，上一项的否定断言无法与"中继根本不会送达"区分。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn rust_server_relays_xray_ciphertext_to_target_positive_control() {
    timeout(BUDGET, async {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rust_port = server.local_addr().unwrap().port();
        let port = free_port();
        let reference = launch(
            xray_client_config(port, target_port, rust_port, PASSWORD),
            port,
        )
        .await;
        let codec = codec(PASSWORD);
        let socket = client(port).await;
        let mut buffer = [0u8; 4096];
        socket.send(b"control").await.unwrap();
        assert_eq!(
            relay_to_target(
                &server,
                &target,
                &codec,
                &mut buffer,
                b"control",
                "正向控制组"
            )
            .await,
            vec![b"control".to_vec()],
            "正确口令下本端中继必须把真实 Xray 密文送达回环目标"
        );
        drop(reference);
    })
    .await
    .expect("Rust 服务端中继正向控制整体超时");
}
