//! Xray → 本仓：**逐字节核对**本仓解出的 ChaCha UDP 明文体布局，
//! 以及**截断包必须被拒绝**（fail-closed）。
//!
//! 参考依据：
//! - `shadowaead_2022/protocol.go:503-533`（客户端写请求方向的明文体字段顺序）；
//! - `shadowaead_2022/protocol.go:561-563`（`ErrPacketTooShort` 的长度阈值）；
//! - `shadowaead_2022/service.go:530-556`（服务端写响应方向，额外带客户端会话 id）。

use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use lengsuo_ss2022::{
    crypto::{Key, Method},
    packet::Sender,
    Error,
};
use serde_json::json;
use ss_core::target::TargetAddr;
use tokio::{net::UdpSocket, time::timeout};

use crate::{
    support::{free_port, launch},
    xray_common::{now_secs, psk, INTEROP_TIMEOUT, LOOPBACK, METHOD_NAME, UNLISTENED_PORT},
};

/// 让 Xray 的 SS2022 出站往本仓发一个 UDP 包，本仓把**原始密文包**抓下来。
///
/// 返回 `(原始包, 目标端口)`。本仓这边同时按响应方向回一个包，
/// 让 Xray 客户端能正常收尾。
async fn capture_one_xray_packet(payload: &[u8]) -> (Vec<u8>, u16) {
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

    let worker = tokio::spawn({
        let key = key.clone();
        async move {
            let mut buffer = [0u8; 16384];
            let (received, peer) = server
                .recv_from(&mut buffer)
                .await
                .expect("应收到 Xray 的包");
            let packet = buffer[..received].to_vec();
            // 解出客户端会话 id，按响应方向回包（让 Xray 客户端能正常收尾）。
            let decoded = key
                .open_client(&packet, now_secs())
                .expect("Xray 的包应可解码");
            let mut sender =
                Sender::new(key.clone(), Some(decoded.session_id)).expect("发送端应可构造");
            let response = sender
                .seal(
                    &TargetAddr::V4([127, 0, 0, 1], UNLISTENED_PORT),
                    b"",
                    now_secs(),
                    0,
                )
                .expect("封包应成功");
            server.send_to(&response, peer).await.expect("回包应可发送");
            packet
        }
    });

    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("客户端应可绑定");
    socket
        .connect((LOOPBACK, port))
        .await
        .expect("客户端应可连接");
    socket.send(payload).await.expect("发送应成功");
    let packet = worker.await.expect("服务端任务应正常结束");
    drop(reference);
    (packet, UNLISTENED_PORT)
}

/// Xray → 本仓：**逐字节核对**本仓解出的 ChaCha UDP 明文体布局。
///
/// 本用例把「参考的明文体字段顺序」钉在本仓解码结果上。
/// 参考 `shadowaead_2022/protocol.go:503-533`（客户端写请求方向）：
/// `session_id(8) | packet_id(8) | type(1) | timestamp(8) | padding_len(2) |
/// padding | ATYP+addr+port | payload`。
///
/// 做法：让 Xray 出站发一个 UDP 包，本仓**旁路**解密（用 `Key::open_client`，
/// 绕过会话/重放层），逐字节断言解密出的明文体。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn xray_udp_plaintext_layout_matches_reference_field_order() {
    timeout(INTEROP_TIMEOUT, async {
        let (packet, echo_port) = capture_one_xray_packet(b"layout-probe").await;

        // 包首 24 字节是明文 nonce，其后是 AEAD 密文（+16 字节 tag）。
        assert!(
            packet.len() > 24 + 16,
            "包应至少含 nonce+tag 之外的明文体，实际 {}",
            packet.len()
        );
        let (nonce, ciphertext) = packet.split_at(24);
        let plaintext = XChaCha20Poly1305::new_from_slice(&psk())
            .expect("32 字节是合法的 XChaCha 密钥长度")
            .decrypt(XNonce::from_slice(nonce), ciphertext)
            .expect("Xray 的包应可用 XChaCha 解开");

        // 明文体字段顺序（参考 `shadowaead_2022/protocol.go:503-533`）。
        let session_id = u64::from_be_bytes(plaintext[0..8].try_into().expect("固定长度"));
        let packet_id = u64::from_be_bytes(plaintext[8..16].try_into().expect("固定长度"));
        assert_eq!(packet_id, 0, "首个包的 packet id 应为 0");
        assert_eq!(plaintext[16], 0x00, "请求方向 type 字节应为 0");
        let timestamp = u64::from_be_bytes(plaintext[17..25].try_into().expect("固定长度"));
        assert!(
            timestamp.abs_diff(now_secs()) <= 30,
            "时间戳应贴近当前时间，实际 {timestamp}"
        );
        // 请求方向**没有**客户端会话（那 8 字节只出现在响应方向）。
        let padding_len = u16::from_be_bytes(plaintext[25..27].try_into().expect("固定长度"));
        assert_eq!(
            plaintext.len(),
            27 + padding_len as usize + 7 + b"layout-probe".len(),
            "明文体长度应等于 字段头 + padding + SOCKS5 地址(7) + 载荷"
        );
        // padding 之后是 SOCKS5 头部：ATYP=1（IPv4）+ 4 字节地址 + 2 字节端口。
        let address = 27 + padding_len as usize;
        assert_eq!(plaintext[address], 0x01, "ATYP 应为 IPv4");
        assert_eq!(
            &plaintext[address + 1..address + 5],
            &[127, 0, 0, 1],
            "地址应为回环"
        );
        assert_eq!(
            u16::from_be_bytes(
                plaintext[address + 5..address + 7]
                    .try_into()
                    .expect("固定长度")
            ),
            echo_port,
            "端口应与 dokodemo-door 一致"
        );
        assert_eq!(&plaintext[address + 7..], b"layout-probe", "载荷应一致");
        // session id 非零（参考 `protocol.go:504` 写 `c.session.sessionId`）。
        assert_ne!(session_id, 0, "session id 不应为 0");
    })
    .await
    .expect("互通用例不应超时");
}

/// 本仓解 Xray 的包时，**错误分类**必须与参考一致：截断包一律拒绝。
///
/// 参考 `shadowaead_2022/protocol.go:561-563`：
/// `buffer.Len() < PacketNonceSize + PacketMinimalHeaderSize` ⇒ `ErrPacketTooShort`。
/// 本仓在 `packet.rs:200-201` 先按 `nonce_len + TAG_LEN` 判长度，
/// 因此「nonce+tag 不足」是 `Error::Length`、「nonce+tag 够但明文体不足」是认证失败。
/// 两者都是 fail-closed，只是错误分类不同（见偏离清单第 4 条）。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn xray_udp_truncated_packets_are_rejected_fail_closed() {
    timeout(INTEROP_TIMEOUT, async {
        let key = Key::new(Method::ChaCha20, &psk()).expect("32 字节 PSK 合法");
        let (packet, _) = capture_one_xray_packet(b"trunc").await;

        // 每个截断位置都必须被拒绝。
        for end in 0..packet.len() {
            assert!(
                key.open_client(&packet[..end], now_secs()).is_err(),
                "截断到 {end} 字节应拒绝"
            );
        }
        // 不足 nonce+tag（24+16=40）⇒ 解密前按长度拒绝。
        for end in 0..40 {
            assert!(
                matches!(
                    key.open_client(&packet[..end], now_secs()),
                    Err(Error::Length)
                ),
                "截断到 {end} 字节应报 Length"
            );
        }
        // 篡改密文任一字节 ⇒ 认证失败。
        for offset in 24..packet.len() {
            let mut broken = packet.clone();
            broken[offset] ^= 0x01;
            assert!(
                matches!(
                    key.open_client(&broken, now_secs()),
                    Err(Error::Authentication)
                ),
                "篡改密文第 {offset} 字节应报认证失败"
            );
        }
    })
    .await
    .expect("互通用例不应超时");
}
