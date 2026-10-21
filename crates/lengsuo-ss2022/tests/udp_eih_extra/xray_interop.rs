//! 与固定版本 Xray 的 **ChaCha UDP 头** 真实互通（`#[ignore]`，必须 `--ignored` 实跑）。
//!
//! 运行：
//! ```text
//! LENGSUO_XRAY=/home/ubuntu/ref/bin/xray cargo test -p lengsuo-ss2022 \
//!     --test udp_eih_extra -- --ignored --nocapture
//! ```
//!
//! ## 为什么参考端是 Xray 而不是自研
//!
//! SS2022 的线上字节由 `sing-shadowsocks/shadowaead_2022` 生成
//! （固定 commit `33d5391`），Xray 只是它的宿主：
//! - `xray/proxy/shadowsocks_2022/inbound.go:7` 直接 import `shadowaead_2022`；
//! - `inbound.go:55` 调 `shadowaead_2022.NewServiceWithPassword`；
//! - `inbound.go:46` 用 `shadowaead_2022.List` 校验方法名，
//!   该列表含 `"2022-blake3-chacha20-poly1305"`（`protocol.go:60`）。
//!
//! 所以「Xray 入站收到的 UDP 字节」= 「shadowaead_2022 生成的字节」，
//! 与固定参考 commit 同源。
//!
//! ## 与本卡固定向量的关系
//!
//! `reference.rs` 的 5 个固定向量由 `golang.org/x/crypto` 的
//! `chacha20poly1305.NewX` / `chacha20.HChaCha20` 直接生成并逐字节核对
//! （生成器见 `docs/ss2022-udp-eih-extra.md`）。
//! 本模块补上**端到端**的一环：真实 Xray 进程在 UDP 线上吐出的字节，
//! 本仓能解密；本仓封出的字节，真实 Xray 能解密。
//!
//! ## 双向判据（缺一不可）
//!
//! 1. **本仓 → Xray**：本仓 `Sender::seal` 封包，Xray 入站解密后转发到 echo，
//!    **回程**由 Xray 按 SS2022 响应方向重新加密，本仓用 `Receiver`（绑定
//!    本方 session id）解开并比对载荷。
//!    ⇒ 证明本仓的「24 字节明文 nonce + AEAD 密文」布局与参考逐字节一致。
//! 2. **Xray → 本仓**：Xray 客户端经 SS2022 出站发 UDP，本仓 `Receiver::receive`
//!    解出目标与载荷；本仓再把回程封成**响应方向**（`type = 1` + 客户端会话 id）。
//!    ⇒ 证明本仓的解码侧（nonce 位置、密文起点、方向字节、客户端会话）与参考一致。

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use lengsuo_ss2022::{
    crypto::{Key, Method},
    packet::Sender,
    receiver::Receiver,
    Error,
};
use serde_json::json;
use ss_core::target::TargetAddr;
use tokio::{net::UdpSocket, time::timeout};

use crate::{
    support::{free_port, launch},
    xray_common::{
        clock, now_secs, psk, spawn_echo, INTEROP_TIMEOUT, LOOPBACK, METHOD_NAME, PAYLOADS,
        UNLISTENED_PORT,
    },
};

/// 本仓 → Xray：本仓封包，Xray SS2022 入站解密并转发到 echo，回程必须原样返回。
///
/// 这是本卡**主判据**：Xray 入站用的是参考 `shadowaead_2022` 的解码侧，
/// 本仓的封包能被它解开并还原出目标地址，就证明「24 字节明文 nonce + AEAD 密文」
/// 的布局与参考逐字节一致。
///
/// ⚠️ 回程是 Xray 按 **SS2022 响应方向**重新加密的（参考
/// `shadowaead_2022/service.go:530-556`），因此必须用绑定本方 session id 的
/// `Receiver`（响应方向）解开，不能当明文直接比。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn rust_client_to_xray_server_chacha_udp_header() {
    timeout(INTEROP_TIMEOUT, async {
        let key = Key::new(Method::ChaCha20, &psk()).expect("32 字节 PSK 合法");
        let (echo_port, echo_task) = spawn_echo(PAYLOADS.len()).await;

        let port = free_port();
        let reference = launch(
            json!({
                "log": {"loglevel": "warning"},
                "inbounds": [{
                    "listen": "127.0.0.1",
                    "port": port,
                    "protocol": "shadowsocks",
                    "settings": {
                        "method": METHOD_NAME,
                        "password": STANDARD.encode(psk()),
                        "network": "tcp,udp"
                    }
                }],
                "outbounds": [{"protocol": "freedom"}]
            }),
            port,
        )
        .await;

        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("客户端应可绑定");
        socket
            .connect((LOOPBACK, port))
            .await
            .expect("客户端应可连接");
        let mut sender = Sender::new(key.clone(), None).expect("发送端应可构造");
        // 响应方向必须绑定本方 session id（参考 `protocol.go:659-666` 校验）。
        let mut receiver = Receiver::new(
            key.clone(),
            Some(sender.session_id()),
            4,
            Duration::from_secs(60),
        )
        .expect("接收端应可构造");
        let mut buffer = [0u8; 16384];

        for length in PAYLOADS {
            let payload = vec![0x42u8; length];
            let packet = sender
                .seal(
                    &TargetAddr::V4([127, 0, 0, 1], echo_port),
                    &payload,
                    now_secs(),
                    0,
                )
                .expect("封包应成功");
            socket.send(&packet).await.expect("发送应成功");
            let received = socket.recv(&mut buffer).await.expect("应收到回程");
            let peer = socket.peer_addr().expect("已连接，应有对端地址");
            let decoded = receiver
                .receive(&buffer[..received], peer, clock())
                .expect("Xray 的响应应可解码");
            assert_eq!(
                decoded.payload, payload,
                "载荷 {length} B 的回程与请求不一致"
            );
            assert_eq!(
                decoded.target,
                TargetAddr::V4([127, 0, 0, 1], echo_port),
                "回程的目标地址应与请求一致"
            );
        }
        echo_task.await.expect("echo 任务应正常结束");
        drop(reference);
    })
    .await
    .expect("互通用例不应超时");
}

/// Xray → 本仓：Xray 客户端经 SS2022 出站发 UDP，本仓解码并把载荷原样回封。
///
/// 本仓 `Receiver::receive` 解出的是**请求方向**（`type = 0`），
/// 目标地址来自明文体里的 SOCKS5 头部（Xray dokodemo-door 指定的地址）；
/// 本仓再把回程封成**响应方向**（`type = 1` + 客户端会话 id）发回 Xray。
///
/// ⚠️ 本仓这台机器上**没有**真的 echo 目标：`dokodemo-door` 的目标端口
/// 故意指向一个无人监听的端口，SS2022 线上只承载「地址 + 载荷」，
/// 由本仓直接回封同一载荷充当回程（与本仓 `tests/xray_udp.rs` 同款做法）。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn xray_client_to_rust_server_chacha_udp_header() {
    timeout(INTEROP_TIMEOUT, async {
        let key = Key::new(Method::ChaCha20, &psk()).expect("32 字节 PSK 合法");
        let server = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("服务端应可绑定");
        let rust_port = server.local_addr().expect("服务端应有本地地址").port();

        let port = free_port();
        let reference = launch(
            json!({
                "log": {"loglevel": "warning"},
                "inbounds": [{
                    "listen": "127.0.0.1",
                    "port": port,
                    "protocol": "dokodemo-door",
                    "settings": {
                        "address": "127.0.0.1",
                        "port": UNLISTENED_PORT,
                        "network": "tcp,udp"
                    }
                }],
                "outbounds": [{
                    "protocol": "shadowsocks",
                    "settings": {"servers": [{
                        "address": "127.0.0.1",
                        "port": rust_port,
                        "method": METHOD_NAME,
                        "password": STANDARD.encode(psk())
                    }]}
                }]
            }),
            port,
        )
        .await;

        // 本仓服务端：解 Xray 的包 → 回封同一载荷（响应方向）→ 发回 Xray。
        let worker = tokio::spawn({
            let key = key.clone();
            async move {
                let mut buffer = [0u8; 16384];
                let mut sender: Option<Sender> = None;
                let mut receiver = Receiver::new(key.clone(), None, 4, Duration::from_secs(60))
                    .expect("接收端应可构造");
                for (index, length) in PAYLOADS.into_iter().enumerate() {
                    let (received, peer) = server
                        .recv_from(&mut buffer)
                        .await
                        .expect("应收到 Xray 的包");
                    let decoded = receiver
                        .receive(&buffer[..received], peer, clock())
                        .expect("Xray 的包应可解码");
                    assert_eq!(decoded.packet_id, index as u64, "packet id 应递增");
                    assert_eq!(
                        decoded.target,
                        TargetAddr::V4([127, 0, 0, 1], UNLISTENED_PORT),
                        "目标地址应与 Xray 的 dokodemo-door 一致"
                    );
                    assert_eq!(decoded.payload, vec![0x42u8; length], "载荷应一致");
                    // 同一包重放必须被拒（fail-closed）。
                    assert!(
                        matches!(
                            receiver.receive(&buffer[..received], peer, clock()),
                            Err(Error::Replay)
                        ),
                        "重放应被拒绝"
                    );
                    let sender = sender.get_or_insert_with(|| {
                        Sender::new(key.clone(), Some(decoded.session_id)).expect("发送端应可构造")
                    });
                    let response = sender
                        .seal(&decoded.target, &decoded.payload, now_secs(), 0)
                        .expect("响应封包应成功");
                    server.send_to(&response, peer).await.expect("回程应可发送");
                }
            }
        });

        // Xray 客户端：明文 UDP 打到 dokodemo-door，由 Xray 的 SS2022 出站加密。
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("客户端应可绑定");
        socket
            .connect((LOOPBACK, port))
            .await
            .expect("客户端应可连接");
        let mut buffer = [0u8; 16384];
        for length in PAYLOADS {
            socket
                .send(&vec![0x42u8; length])
                .await
                .expect("发送应成功");
            let received = socket.recv(&mut buffer).await.expect("应收到回程");
            assert_eq!(
                &buffer[..received],
                &vec![0x42u8; length][..],
                "载荷 {length} B 的回程与请求不一致"
            );
        }
        worker.await.expect("服务端任务应正常结束");
        drop(reference);
    })
    .await
    .expect("互通用例不应超时");
}
