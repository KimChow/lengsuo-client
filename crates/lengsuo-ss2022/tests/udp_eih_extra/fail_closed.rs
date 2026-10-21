//! **拒绝路径**：超长载荷、截断/篡改、ChaCha 与 EIH 的组合边界。
//!
//! 全部判据都要求 fail-closed：宁可拒绝，不许静默截断、静默回退或 panic。

use lengsuo_ss2022::{
    crypto::{Key, Method},
    packet::Sender,
    Error,
};
use ss_core::target::TargetAddr;

use crate::{reference, CASE_TIMEOUT};

/// ⑤ 超长载荷必须被**拒绝**（fail-closed），不是静默截断。
///
/// 判据来源：参考 `shadowaead_2022/protocol.go:40` `MaxPacketSize = 65535`，
/// 且 sing 的 UDP 缓冲上限是 `buf.UDPBufferSize`（16 KiB，标准构建）。
/// 本仓 `crates/lengsuo-ss2022/src/packet.rs:132-153`（`total_len`）以 **65507**
/// （= IPv4 UDP 载荷上限）为硬顶，超过即 `Error::Length`。
///
/// ⛔ 这里断言的是**上限被拒**，不把「具体上限值」写死成 65507：
/// 上限值本身是本卡发现的**待修正缺陷**（见 `docs/ss2022-udp-eih-extra.md` 偏离清单），
/// 硬写死会让本卡去锁定一个错误行为。
#[tokio::test]
async fn oversized_payload_is_rejected_not_truncated() {
    tokio::time::timeout(CASE_TIMEOUT, async {
        let key = Key::new(Method::ChaCha20, &reference::VECTOR_PSK).expect("32 字节 PSK 合法");
        let mut sender = Sender::new(key.clone(), None).expect("发送端应可构造");
        let target = TargetAddr::V4([127, 0, 0, 1], 53);

        // 明显超限：必须报错，且**不得**返回被截断的包。
        for length in [65_507usize, 65_508, 70_000, 200_000] {
            let result = sender.seal(&target, &vec![0u8; length], 1000, 0);
            assert!(
                matches!(result, Err(Error::Length)),
                "载荷 {length} 字节应被拒绝（Error::Length），实际 {:?}",
                result.map(|packet| packet.len())
            );
        }
    })
    .await
    .expect("用例不应超时");
}

/// ⑥ 截断的 UDP 头必须被拒绝；长度字段「说谎」也必须被拒绝。
///
/// - 截断头：不足 24 字节 nonce + 16 字节 tag ⇒ `Error::Length`
///   （本仓 `packet.rs:200-201`；参考 `protocol.go:561-563` `ErrPacketTooShort`）。
/// - 说谎的长度：ChaCha UDP 头**没有**长度字段，载荷长度只由 AEAD 认证保护；
///   因此「声明长度 > 实际」在这条路径上表现为**认证失败**（密文被改）。
///
/// ⚠️ **错误种类的分层**（本仓与参考刻意不同，见偏离清单第 4 条）：
/// - 截断到 **< 24+16 = 40 字节**：本仓在解密**前**按长度拒绝 ⇒ `Error::Length`；
/// - 截断到 **≥ 40 字节**：长度够了，落到 AEAD 解密 ⇒ `Error::Authentication`。
///   参考（`protocol.go:561`）是**单一** `ErrPacketTooShort` 阈值
///   `PacketNonceSize + PacketMinimalHeaderSize = 24 + 30 = 54` 字节，
///   介于两者之间的截断在参考侧是「太短」而在本仓是「认证失败」——
///   两者都是 fail-closed（都拒绝），只是错误分类不同。
/// 本用例断言「每个截断位置都被拒绝」，并对 **< 40** 这一段单独钉死 `Length`。
#[tokio::test]
async fn truncated_header_and_tampered_length_are_rejected() {
    tokio::time::timeout(CASE_TIMEOUT, async {
        let key = Key::new(Method::ChaCha20, &reference::VECTOR_PSK).expect("32 字节 PSK 合法");
        let mut sender = Sender::new(key.clone(), None).expect("发送端应可构造");
        let packet = sender
            .seal(&TargetAddr::V4([127, 0, 0, 1], 53), b"hello", 1000, 0)
            .expect("封包应成功");

        // ⑥a 截断：每一个截断位置都必须被拒。
        for end in 0..packet.len() {
            assert!(
                key.open_client(&packet[..end], 1000).is_err(),
                "截断到 {end} 字节应拒绝"
            );
        }
        // 不足 nonce+tag（24+16=40）⇒ 解密前按长度拒绝。
        for end in 0..(reference::PACKET_NONCE_SIZE + reference::OVERHEAD) {
            assert!(
                matches!(key.open_client(&packet[..end], 1000), Err(Error::Length)),
                "截断到 {end} 字节应报 Length（长度不足 nonce+tag）"
            );
        }
        // 刚好 nonce+tag（40 字节）：长度够解密，但明文为空 ⇒ 认证失败。
        assert!(matches!(
            key.open_client(&packet[..40], 1000),
            Err(Error::Authentication)
        ));

        // ⑥b 说谎的长度：篡改密文任何一字节都会让 AEAD 认证失败。
        for offset in reference::PACKET_NONCE_SIZE..packet.len() {
            let mut broken = packet.clone();
            broken[offset] ^= 0x01;
            assert!(
                matches!(key.open_client(&broken, 1000), Err(Error::Authentication)),
                "篡改密文第 {offset} 字节应报认证失败"
            );
        }
        // 篡改 nonce 同样必须认证失败（nonce 参与认证）。
        let mut broken = packet.clone();
        broken[0] ^= 0x01;
        assert!(matches!(
            key.open_client(&broken, 1000),
            Err(Error::Authentication)
        ));
    })
    .await
    .expect("用例不应超时");
}

/// ⑦ ChaCha 与 EIH 的组合边界：**不可组合**，必须 fail-closed。
///
/// 参考 `shadowaead_2022/protocol.go:495-497` 与 `protocol.go:729`：
/// ChaCha + 多用户（`pskList` 长度 > 1）直接 `panic("unsupported chacha extended header")`。
/// 参考 `shadowaead_2022/service_multi.go:50-56`：`NewMultiService` 对 ChaCha 方法
/// 直接返回 `os.ErrInvalid`（只允许 AES 两种）。
///
/// 本仓 `crates/lengsuo-ss2022/src/eih.rs:392-397`（`require_aes`）与
/// `crates/lengsuo-ss2022/src/eih_udp.rs:76`（`EihUdpChain::new`）把 panic
/// 改成了 `Error::Unsupported` —— **fail-closed 且不 panic**，比参考更安全。
///
/// 本用例锁定：ChaCha 身份链 ⇒ `Error::Unsupported`（不是 panic、不是静默按 AES 处理）。
#[tokio::test]
async fn chacha_with_eih_is_fail_closed_not_panic() {
    tokio::time::timeout(CASE_TIMEOUT, async {
        use lengsuo_ss2022::eih_udp::EihUdpChain;

        let identity = Key::new(Method::ChaCha20, &[0x11; 32]).expect("32 字节 PSK 合法");
        let user = Key::new(Method::ChaCha20, &[0x22; 32]).expect("32 字节 PSK 合法");
        let result = EihUdpChain::new(vec![identity, user]);
        let error = match result {
            Ok(_) => panic!("ChaCha 多用户身份链必须被拒绝"),
            Err(error) => error,
        };
        assert!(
            matches!(error, Error::Unsupported),
            "ChaCha 多用户应报 Unsupported，实际 {error:?}"
        );
        // 错误里不得含 PSK 字节。
        let rendered = format!("{error} {error:?}");
        assert!(
            !rendered.contains("0x11") && !rendered.contains("0x22"),
            "错误不得含 PSK：{rendered}"
        );
    })
    .await
    .expect("用例不应超时");
}
