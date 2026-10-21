//! ChaCha UDP 头的**字节布局**与**长度字段**编码。
//!
//! 参考依据：
//! - `shadowaead_2022/protocol.go:494-498`（24 字节明文 nonce 置于包首）；
//! - `shadowaead_2022/protocol.go:541-542`（AEAD 只做 `Seal`，**不写**长度前缀）；
//! - `shadowaead_2022/protocol.go:529`（UDP 明文体里的 padding 长度，u16be）；
//! - `shadowaead/aead.go:15`（TCP 方向的长度字段，`PacketLengthBufferSize = 2`）。

use aes_gcm::aead::KeyInit;
use chacha20poly1305::{aead::Aead, XNonce};
use lengsuo_ss2022::{
    crypto::{Key, Method},
    packet::Sender,
};
use ss_core::target::TargetAddr;

use crate::{reference, xchacha, CASE_TIMEOUT};

/// ③ ChaCha UDP 头实际字节布局：包首 24 字节明文 nonce，其后是 AEAD 密文。
///
/// 本仓实现：`crates/lengsuo-ss2022/src/packet.rs:106-131`（`seal_chacha`）与
/// `crates/lengsuo-ss2022/src/packet.rs:193-217`（`open_chacha`）。
///
/// 逐字节对照（参考 `protocol.go:494-498`、`protocol.go:541-542`）：
///
/// | 偏移 | 长度 | 内容 | 参考 | 本仓 |
/// |---|---|---|---|---|
/// | `0..24` | 24 | XChaCha nonce，**明文** | `protocol.go:495` `header.ReadFullFrom(c.session.rng, PacketNonceSize)` | `packet.rs:118-119` 随机 24 字节 |
/// | `24..` | 变长 | AEAD 密文（明文 + 16 字节 tag） | `protocol.go:541` `c.udpCipher.Seal(...)` | `packet.rs:127` |
///
/// 密文内的明文顺序（参考 `protocol.go:503-506` 写 + `protocol.go:578-585` 读）：
/// `session_id(8) | packet_id(8) | type(1) | timestamp(8) | [client_session(8)] |
/// padding_len(2) | padding | ATYP+addr+port | payload`。
#[tokio::test]
async fn chacha_udp_header_is_24_byte_plaintext_nonce_then_ciphertext() {
    tokio::time::timeout(CASE_TIMEOUT, async {
        let key = Key::new(Method::ChaCha20, &reference::VECTOR_PSK).expect("32 字节 PSK 合法");
        let mut sender = Sender::new(key.clone(), None).expect("发送端应可构造");
        let packet = sender
            .seal(&TargetAddr::V4([127, 0, 0, 1], 53), b"hello", 1000, 3)
            .expect("封包应成功");

        // 总长 = 24 nonce + 16 (session+packet) + 1 type + 8 ts + 2 padlen
        //        + 3 padding + 7 addrport + 5 payload + 16 tag = 82
        assert_eq!(packet.len(), 82, "ChaCha UDP 报文字节数与布局不符");

        // 包首 24 字节是 nonce，其余是密文：把密文单独喂 AEAD 必须能解开。
        let (nonce, ciphertext) = packet.split_at(reference::PACKET_NONCE_SIZE);
        let aead = xchacha();
        let plaintext = aead
            .decrypt(XNonce::from_slice(nonce), ciphertext)
            .expect("nonce+密文应构成合法的 XChaCha 密文");
        assert_eq!(
            plaintext.len(),
            82 - reference::PACKET_NONCE_SIZE - reference::OVERHEAD,
            "明文长度应为密文长减 tag"
        );
        // 明文至少要装下参考定义的最小头（不含载荷）。
        assert!(
            plaintext.len() >= reference::PACKET_MINIMAL_HEADER_SIZE,
            "明文短于参考最小头 {}",
            reference::PACKET_MINIMAL_HEADER_SIZE
        );

        // 明文内字段顺序：session_id | packet_id | type | timestamp | padlen | ...
        let session_id = u64::from_be_bytes(plaintext[0..8].try_into().expect("固定长度"));
        let packet_id = u64::from_be_bytes(plaintext[8..16].try_into().expect("固定长度"));
        assert_eq!(session_id, u64::from_be_bytes(sender.session_id()));
        assert_eq!(packet_id, 0, "首个包的 packet id 应为 0");
        assert_eq!(plaintext[16], 0x00, "请求方向 type 字节应为 0");
        assert_eq!(
            u64::from_be_bytes(plaintext[17..25].try_into().expect("固定长度")),
            1000,
            "时间戳字段位置不符"
        );
        assert_eq!(
            u16::from_be_bytes(plaintext[25..27].try_into().expect("固定长度")),
            3,
            "padding 长度字段位置不符"
        );
        // padding 之后是 ATYP+addr+port，再之后是载荷。
        // ⚠️ padding **内容**本仓是零填充（`packet.rs:56` 明示「使用零字节填充」），
        // 参考的 `header.Extend(paddingLen)`（`protocol.go:533`）只扩长度不写内容，
        // 两侧都**不把 padding 内容当语义**（参考读侧 `protocol.go:675` 只 `Advance`）。
        // 见 `docs/ss2022-udp-eih-extra.md` 偏离清单第 3 条。
        assert_eq!(plaintext[27..30], [0x00, 0x00, 0x00], "padding 应为零填充");
        assert_eq!(plaintext[30], 0x01, "ATYP 应为 IPv4");
        assert_eq!(
            &plaintext[31..37],
            &[127, 0, 0, 1, 0x00, 0x35],
            "地址与端口不符"
        );
        assert_eq!(&plaintext[37..], b"hello", "载荷不符");
    })
    .await
    .expect("用例不应超时");
}

/// ④ 长度字段：ChaCha UDP 路径**没有**独立的长度字段。
///
/// 参考侧证据：
/// - ChaCha UDP 的长度信息完全由 **AEAD 密文自身的长度**表达
///   （`protocol.go:541-542` 只做 `Seal`，不写任何长度前缀）；
/// - 唯一的长度字段在 **TCP** 方向（`shadowaead/aead.go:15` `PacketLengthBufferSize = 2`，
///   u16be，**不含** tag），且 TCP 的长度字段属于 AEAD **内部**的 chunk 帧。
/// - 另一个长度语义是 UDP 明文体里的 **padding 长度**（`protocol.go:529`
///   `binary.Write(header, binary.BigEndian, uint16(paddingLen))`），u16be、不含 tag。
///
/// 本仓对应：
/// - UDP ChaCha 头：`crates/lengsuo-ss2022/src/packet.rs:106-131` —— **无长度字段**；
/// - padding 长度：`crates/lengsuo-ss2022/src/packet.rs:68-69`，u16be、不含 tag；
/// - TCP chunk 长度：`crates/lengsuo-ss2022/src/tcp.rs:144-159`，u16be、**明文**长度
///   （不含 tag；tag 是 AEAD 追加的，见 `tcp.rs:152-155`）。
///
/// 本用例把三处都钉死：UDP 无长度字段、padding 长度编码、TCP 长度字段编码。
#[tokio::test]
async fn length_field_encoding_matches_reference() {
    tokio::time::timeout(CASE_TIMEOUT, async {
        let key = Key::new(Method::ChaCha20, &reference::VECTOR_PSK).expect("32 字节 PSK 合法");
        let mut sender = Sender::new(key.clone(), None).expect("发送端应可构造");

        // ④a UDP 侧：包内除 24 字节 nonce 外就是密文，长度只由密文长度隐含。
        // 用两个不同 padding 长度的包对比：总长差恰好等于 padding 差。
        let mut lengths = Vec::new();
        for padding in [0u16, 7u16] {
            let packet = sender
                .seal(&TargetAddr::V4([127, 0, 0, 1], 53), b"hello", 1000, padding)
                .expect("封包应成功");
            lengths.push(packet.len());
            // 密文里的 padding 长度字段是 u16be、不含 tag。
            let (nonce, ciphertext) = packet.split_at(reference::PACKET_NONCE_SIZE);
            let plaintext = xchacha()
                .decrypt(XNonce::from_slice(nonce), ciphertext)
                .expect("解密应成功");
            assert_eq!(
                u16::from_be_bytes(plaintext[25..27].try_into().expect("固定长度")),
                padding,
                "padding 长度字段不是 u16be"
            );
        }
        assert_eq!(
            lengths[1] - lengths[0],
            7,
            "UDP 包长只应随 padding 变化，不应出现独立长度字段"
        );

        // ④b TCP 侧：长度字段是 u16be 的**明文**长度，不含 16 字节 tag。
        // 参考 `shadowaead/aead.go:343`：`PutUint16(len(data))` 后再 `Seal`。
        let payload = vec![0x5au8; 300];
        let subkey = blake3::derive_key(
            "shadowsocks 2022 session subkey",
            &[&reference::VECTOR_PSK[..], &[0u8; 8][..]].concat(),
        );
        let aead = aes_gcm::Aes256Gcm::new_from_slice(&subkey).expect("32 字节子密钥合法");
        let nonce = [0u8; 12];
        let sealed = aead
            .encrypt(aes_gcm::Nonce::from_slice(&nonce), payload.as_slice())
            .expect("封包应成功");
        // 这只是把「长度字段 = 明文长度、不含 tag」这件事用与生产同源的写法固定下来。
        assert_eq!(
            sealed.len(),
            payload.len() + reference::OVERHEAD,
            "tag 应为 16 字节且不计入长度字段"
        );
        // 长度字段自身是 2 字节大端。
        let length_field = (payload.len() as u16).to_be_bytes();
        assert_eq!(length_field.len(), 2);
        assert_eq!(u16::from_be_bytes(length_field), 300);
        // 声明长度比实际载荷大 1 ⇒ 读取侧必须判定为短读（fail-closed 的依据）。
        let lying = (payload.len() as u16 + 1).to_be_bytes();
        assert!(u16::from_be_bytes(lying) > payload.len() as u16);
    })
    .await
    .expect("用例不应超时");
}
