//! 参考侧的**组合**金标字节：AEAD 记录层 ⊕ XOR 头部掩蔽同时开启时的线上字节。
//!
//! 既有 `tests/xel_golden.rs` 只分别锁定了两层（AEAD 记录流、XOR 掩蔽流），
//! **没有**锁定「两层同时开启」时参考实现产出的线上字节。而这正是生产配置
//! （`XorMode == 2` ⇒ 参考 `client.go:124` / `server.go:231`）的形态。
//!
//! 本文件补上这一格：把参考实现按其自身的层序组装的输出原样落盘为向量，
//! 再与本仓 [`lengsuo_vless::xel_wire`] 新 API 的输出逐字节对拍。
//!
//! **向量怎么来的**：在参考源码树上按其记录层路径逐字复刻（AEAD 记录层套在
//! XOR 头部掩蔽层之下，密钥/IV/载荷材料与既有 `tests/xel_golden.rs` 完全一致），
//! 实跑产出。参考侧的层序与本仓新 API 的层序是**独立**的两条实现路径，
//! 逐字节一致即证明组合语义（层序、跳过量、密钥流连续性、nonce 推进）都对齐。
//!
//! **与进程级互通无关**：参考的记录层密钥由 ML-KEM 握手派生，配置里没有
//! 「注入会话密钥 / 只开记录层」的入口 ⇒ 进程级互通在本卡不可取证（见分文档
//! 的偏离清单）。本文件是**字节级**对齐证据，不是互通证据。
//!
//! 材料（与既有金标文件同源，便于交叉比对）：
//! - 会话主密钥 = 32×0xA1；
//! - AEAD 派生上下文 = 32 个 ASCII 'B'（0x42）；
//! - XOR 掩蔽密钥材料 = 32×0xA1，CTR IV = 16×0x11；
//! - 载荷四条：`"first XEL golden record"`、`[0x00]`、`[0xEE; 400]`、
//!   `"tail record \xff\x00\x80"`。

use lengsuo_vless::xel::{aead::XelCipher, XelKey};
use lengsuo_vless::xel_wire::{XelWireConfig, XorLayer};

/// 会话主密钥（32×0xA1）。
const UNITED_KEY: [u8; 32] = [0xA1; 32];
/// AEAD 派生上下文（32 个 ASCII 'B' = 0x42）。
const DERIVE_CTX: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
/// XOR 掩蔽的 CTR IV（16×0x11）。
const XOR_IV: [u8; 16] = [0x11; 16];

/// 参考组合流（AES-256-GCM ⊕ XOR 掩蔽）的金标字节。
const HEX_COMPOSED_AES_XOR: &str = include_str!("vectors/xel_composed_aes_xor.hex");
/// 参考组合流（ChaCha20-Poly1305 ⊕ XOR 掩蔽）的金标字节。
const HEX_COMPOSED_CHACHA_XOR: &str = include_str!("vectors/xel_composed_chacha_xor.hex");

/// 解析十六进制向量（忽略空白与换行）。
fn parse_hex(text: &str) -> Vec<u8> {
    let cleaned: String = text
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    assert!(cleaned.len().is_multiple_of(2), "十六进制长度必须为偶数");
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).expect("合法十六进制字节"))
        .collect()
}

/// 参考用的四条载荷（与既有金标文件同源）。
fn payloads() -> Vec<Vec<u8>> {
    vec![
        b"first XEL golden record".to_vec(),
        vec![0x00],
        vec![0xEE; 400],
        b"tail record \xff\x00\x80".to_vec(),
    ]
}

/// 构造「AEAD 记录层 ⊕ XOR 头部掩蔽」的发送端。
///
/// 密钥材料与参考同源：AEAD 侧用 `blake3::DeriveKey(ctx, united)` 的产物，
/// XOR 侧用 `blake3::DeriveKey("VLESS", united)` 的产物（即参考 `xor.go:12`
/// `NewCTR` 的派生）——本仓 `XorLayer` 内部自己派生一次（`src/xel/xor.rs:34`），
/// 所以这里注入的是**未派生的**主密钥材料。
fn composed_sender(cipher: XelCipher) -> lengsuo_vless::xel_wire::XelSender {
    let derived = blake3::derive_key(DERIVE_CTX, &UNITED_KEY);
    let config = XelWireConfig {
        cipher,
        uplink_key: XelKey::new(&derived).expect("派生结果长度合法"),
        downlink_key: XelKey::new(&derived).expect("派生结果长度合法"),
        xor: Some(
            XorLayer::new(
                XelKey::new(&UNITED_KEY).expect("密钥长度合法"),
                &XOR_IV,
                XelKey::new(&UNITED_KEY).expect("密钥长度合法"),
                &XOR_IV,
            )
            .expect("IV 长度合法"),
        ),
    };
    config.split().expect("配置合法").0
}

/// 构造「AEAD 记录层 ⊕ XOR 头部掩蔽」的接收端。
///
/// XOR 接收流与发送流是**同一条**密钥流（参考 `xor.go:29`
/// `NewXorConn(conn, ctr, peerCTR, ...)`：`peerCTR` 是对端的发送流，
/// 即本端的接收流）。
fn composed_receiver(cipher: XelCipher) -> lengsuo_vless::xel_wire::XelReceiver {
    let derived = blake3::derive_key(DERIVE_CTX, &UNITED_KEY);
    let config = XelWireConfig {
        cipher,
        uplink_key: XelKey::new(&derived).expect("派生结果长度合法"),
        downlink_key: XelKey::new(&derived).expect("派生结果长度合法"),
        xor: Some(
            XorLayer::new(
                XelKey::new(&UNITED_KEY).expect("密钥长度合法"),
                &XOR_IV,
                XelKey::new(&UNITED_KEY).expect("密钥长度合法"),
                &XOR_IV,
            )
            .expect("IV 长度合法"),
        ),
    };
    config.split().expect("配置合法").1
}

/// 组合流：金标字节必须与本仓新 API 的输出逐字节一致。
///
/// 判据：长度相同 **且** 每个字节相同。任何「层序写反」「掩蔽多算/少算字节」
/// 「密钥流位置错位」「nonce 推进不同步」都会让对拍失败。
#[test]
fn composed_aead_xor_stream_matches_reference_bytes() {
    for (cipher, hex) in [
        (XelCipher::Aes256Gcm, HEX_COMPOSED_AES_XOR),
        (XelCipher::ChaCha20Poly1305, HEX_COMPOSED_CHACHA_XOR),
    ] {
        let reference = parse_hex(hex);
        let mut sender = composed_sender(cipher);
        let mut ours = Vec::new();
        for payload in payloads() {
            ours.extend_from_slice(&sender.seal(&payload).expect("封包成功"));
        }
        assert_eq!(
            ours.len(),
            reference.len(),
            "{cipher:?}：组合流长度必须与参考一致"
        );
        assert_eq!(
            ours, reference,
            "{cipher:?}：AEAD ⊕ XOR 组合流必须与参考逐字节一致"
        );
    }
}

/// 组合流：本仓新 API 必须能解开参考产出的组合流（反向证据）。
///
/// 上一条只证明「本仓能产出参考的字节」；本条证明「参考的字节本仓能读」——
/// 两个方向都通才算组合语义对齐。
#[test]
fn composed_reference_stream_is_readable_by_new_api() {
    for (cipher, hex) in [
        (XelCipher::Aes256Gcm, HEX_COMPOSED_AES_XOR),
        (XelCipher::ChaCha20Poly1305, HEX_COMPOSED_CHACHA_XOR),
    ] {
        let reference = parse_hex(hex);
        let mut receiver = composed_receiver(cipher);
        let plain = receiver.open(&reference).expect("参考组合流必须可解");
        assert_eq!(
            plain,
            payloads().concat(),
            "{cipher:?}：参考组合流必须逐字节还原"
        );
        receiver.finish().expect("流必须恰好结束");
    }
}

/// 组合流：参考流被任意切分喂入也必须还原（跨块重组 + 掩蔽密钥流连续性）。
///
/// 参考 `xor.go:69` `XorConn.Read` 的掩蔽循环与 `common.go:80`
/// `CommonConn.Read` 的分帧都是**跨调用状态**的：跨块的头部要靠本地缓存的
/// 部分头拼齐，密钥流只在被掩蔽的字节上推进。⇒ 切分点不同，必须仍然还原。
#[test]
fn composed_reference_stream_survives_arbitrary_chunking() {
    let reference = parse_hex(HEX_COMPOSED_AES_XOR);
    for step in [1usize, 3, 7, 22, 64, 512] {
        let mut receiver = composed_receiver(XelCipher::Aes256Gcm);
        let mut plain = Vec::new();
        for chunk in reference.chunks(step) {
            plain.extend_from_slice(&receiver.open(chunk).expect("分块解包成功"));
        }
        receiver.finish().expect("流必须恰好结束");
        assert_eq!(
            plain,
            payloads().concat(),
            "切分步长 {step}：参考组合流必须逐字节还原"
        );
    }
}
