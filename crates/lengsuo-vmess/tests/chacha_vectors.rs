//! VMess 多安全档**逐字节黄金向量**（ChaCha20-Poly1305 档 + AES-128-GCM 对照）。
//!
//! 期望值的来源：`tools/reference/vmess_vectors/main.go` —— 一个**直接调用参考
//! Xray 源码**（固定 commit `d2758a02`）的独立生成器。它只调参考的公开函数
//! （`aead.KDF16` / `encoding.GenerateChacha20Poly1305Key` / `crypto.NewAesGcm`
//! / `chacha20poly1305` / `encoding.NewShakeSizeParser`），**不复制**任何
//! 密码学实现；生成结果已写死在本文件的 `EXPECTED` 表里（复算步骤见该目录
//! 的 README.md）。因此本测试不需要 Go 工具链，也不需要参考检出在场。
//!
//! 固定假值（与生成器一一对应，全是测试假凭据）：
//! - body key = `request-body-key`（16B）、body IV = `request-body-iv!`（16B）
//! - cmd key = `b831381d-6324-4d`（16B）
//! - 载荷 = `vmess body payload`（19B）
//! - 头部载荷 = `version+iv+key+seed+options+security+cmd+address+padding+fnv`
//! - 头部 AuthID = `5a2143658709badcfe01020304050607`、连接 nonce = `1122334455667788`
//!
//! **重要协议事实**（本轮核实并写进 `docs/vmess-status.md`）：参考的**请求头与
//! 响应头两段 AEAD 恒为 AES-128-GCM**，与安全档无关；安全档只作用于**数据段**。
//! 因此本文件里「头部」的向量只有 AES-128-GCM 一组，ChaCha 的向量全部在数据段。

use lengsuo_vmess::aead;
use lengsuo_vmess::bodyframe::{BodyCipher, BodyFrame, BodySuite, SizeMode};
use lengsuo_vmess::chunkframe::DataSizeParser;
use lengsuo_vmess::consts::{SECURITY_AES_128_GCM, SECURITY_CHACHA20_POLY1305};

/// 固定假 body key。
const BODY_KEY: [u8; 16] = *b"request-body-key";
/// 固定假 body IV。
const BODY_IV: [u8; 16] = *b"request-body-iv!";
/// 固定假 cmd key。
const CMD_KEY: [u8; 16] = *b"b831381d-6324-4d";
/// 固定载荷明文。
const PAYLOAD: &[u8] = b"vmess body payload";
/// 固定头部载荷明文。
const PLAIN_HEAD: &[u8] = b"version+iv+key+seed+options+security+cmd+address+padding+fnv";
/// 固定头部 AuthID。
const AUTH_ID: [u8; 16] = [
    0x5A, 0x21, 0x43, 0x65, 0x87, 0x09, 0xBA, 0xDC, 0xFE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
];
/// 固定连接 nonce。
const CONN_NONCE: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

/// 参考生成器产出的期望值（逐字节）。
mod expected {
    /// `GenerateChacha20Poly1305Key(bodyKey)` = MD5(b) || MD5(MD5(b))。
    pub const CHACHA_KEY_EXPANSION: &str =
        "79585b940aae83afd6bcbe2602e7ab1fe180aaf50dac3fef902d29fb018937ef";
    /// `KDF16(bodyKey, "auth_len")`。
    pub const AUTH_LEN_KDF16: &str = "cb4c8ed42cdc6297210522d75de6b09c";
    /// 数据段载荷密文（AES-128-GCM 档，nonce = chunkNonce(iv, 0)）。
    pub const BODY_PAYLOAD_CT_AES: &str =
        "41ac1ac03fcc159fe504894ee498640ce5d682dabbc08e0ca2babafd9f7c2ac235ab";
    /// 数据段载荷密文（ChaCha20-Poly1305 档，同一 nonce/明文）。
    pub const BODY_PAYLOAD_CT_CHACHA: &str =
        "c373a8498816d2af8a06b4163789fc8a9afeb05fee61958bf3a2f6434b0557d3a0e5";
    /// 认证长度段密文（AES-128-GCM 档，18 字节）。
    ///
    /// 语义（参考 `common/crypto/chunk.go` 的 `AEADChunkSizeParser.Encode`）：
    /// 线上明文是 `BE16(总长 - 16)`——参考的写入端把「明文长 + tag + padding」
    /// 交给解析器，解析器再减去 AEAD `Overhead()` 才写进 AEAD 明文，解码端
    /// 加回。因此这里的长度段明文 = 19（载荷明文长），不是 35。
    pub const AUTH_LEN_SEGMENT_AES: &str = "bcc52b50a1abac744d878343fe8ec64d3d7b";
    /// 认证长度段密文（ChaCha20-Poly1305 档，18 字节）。
    pub const AUTH_LEN_SEGMENT_CHACHA: &str = "fd655cc273bda608229e8d101b712abb1509";
    /// Shake 掩码长度段（`ShakeSizeParser` 对总长 41 的编码）。
    pub const MASKED_SIZE_SEGMENT: &str = "745b";
    /// 完整请求头线上字节（恒 AES-128-GCM）。
    pub const HEADER_WIRE: &str = "5a2143658709badcfe01020304050607ab59afc3784646dd6278cbf4ac9648ad37721122334455667788d6e6cbad3dba7561c1e7f498e6d3c984301bb22ed69a3b4606ef6ad163ca98e69c890de952461633ca65272d1735c39a6780cbc24b54d09208e6a3c857550362d82091a680fe17fc279cb3e9";
    /// `SHA256(requestBodyKey)[:16]`。
    pub const RESPONSE_BODY_KEY: &str = "e2b2ca4414773ba7fa95382bb1572e96";
    /// `SHA256(requestBodyIV)[:16]`。
    pub const RESPONSE_BODY_IV: &str = "e4498d71fdf2464fa593079684997089";
}

/// 数据段载荷密文（首帧，nonce 计数 = 0，无 AAD）。
fn body_payload_ct(suite: BodySuite) -> Vec<u8> {
    let mut cipher = BodyCipher::from_suite(suite, &BODY_KEY, &BODY_IV);
    cipher.seal_payload(PAYLOAD).expect("可封")
}

/// 认证长度段密文（首帧）。
fn auth_len_segment(suite: BodySuite) -> Vec<u8> {
    let mut cipher = BodyCipher::from_suite(suite, &BODY_KEY, &BODY_IV);
    cipher
        .enable_authenticated_length(&BODY_KEY, &BODY_IV)
        .expect("可启用");
    cipher
        .seal_len_segment((PAYLOAD.len() + 16) as u16)
        .expect("可封")
}

/// ① ChaCha 档的密钥扩展逐字节等于参考。
#[test]
fn chacha_key_expansion_matches_reference_bytes() {
    let got = lengsuo_vmess::aead_chacha::expand_key(&BODY_KEY);
    assert_eq!(
        hex::encode(got),
        expected::CHACHA_KEY_EXPANSION,
        "ChaCha20-Poly1305 密钥扩展必须逐字节等于参考的 MD5 链结果"
    );
}

/// ② 认证长度段的 KDF 派生逐字节等于参考。
#[test]
fn auth_len_kdf_matches_reference_bytes() {
    let got = lengsuo_vmess::kdf16(&BODY_KEY, &[b"auth_len"]);
    assert_eq!(hex::encode(got), expected::AUTH_LEN_KDF16);
}

/// ③ **ChaCha 档**数据段载荷密文逐字节等于参考。
///
/// 这是本卡的核心断言：选 `SecurityOption::ChaCha20Poly1305` 时线上字节必须
/// 与参考的 ChaCha20-Poly1305 一致，而**不是** AES-128-GCM。
#[test]
fn chacha_body_payload_ciphertext_matches_reference_bytes() {
    let got = body_payload_ct(BodySuite::ChaCha20Poly1305);
    assert_eq!(
        hex::encode(&got),
        expected::BODY_PAYLOAD_CT_CHACHA,
        "ChaCha 档载荷密文必须逐字节等于参考"
    );
    // 反向：与 AES 档的密文**不同**（否则说明走了同一条路径）。
    let aes = body_payload_ct(BodySuite::Aes128Gcm);
    assert_ne!(got, aes, "ChaCha 档不得产生 AES 密文");
    assert_eq!(aes.len(), got.len(), "两档密文长度相同（tag 都是 16B）");
}

/// ④ AES-128-GCM 档数据段载荷密文逐字节等于参考（对照组）。
#[test]
fn aes_body_payload_ciphertext_matches_reference_bytes() {
    let got = body_payload_ct(BodySuite::Aes128Gcm);
    assert_eq!(hex::encode(&got), expected::BODY_PAYLOAD_CT_AES);
}

/// ⑤ 两档的认证长度段密文逐字节等于参考。
#[test]
fn authenticated_length_segments_match_reference_bytes() {
    assert_eq!(
        hex::encode(auth_len_segment(BodySuite::Aes128Gcm)),
        expected::AUTH_LEN_SEGMENT_AES,
    );
    assert_eq!(
        hex::encode(auth_len_segment(BodySuite::ChaCha20Poly1305)),
        expected::AUTH_LEN_SEGMENT_CHACHA,
    );
}

/// ⑥ Shake 掩码长度段逐字节等于参考（`ShakeSizeParser`）。
#[test]
fn masked_size_segment_matches_reference_bytes() {
    let mut parser = DataSizeParser::new(&BODY_IV);
    let wire = parser.encode_size((PAYLOAD.len() + 16) as u16);
    assert_eq!(hex::encode(wire), expected::MASKED_SIZE_SEGMENT);
}

/// ⑦ 完整请求头线上字节逐字节等于参考（**恒 AES-128-GCM**，与安全档无关）。
#[test]
fn header_wire_matches_reference_bytes() {
    let wire = aead::seal_header_with(&CMD_KEY, &AUTH_ID, &CONN_NONCE, PLAIN_HEAD);
    assert_eq!(hex::encode(&wire), expected::HEADER_WIRE);
    // 解回来必须逐字节一致。
    let opened = aead::open_vmess_aead_header(&CMD_KEY, &AUTH_ID, &wire[16..]).expect("可解");
    assert_eq!(opened, PLAIN_HEAD);
}

/// ⑧ 响应方向密钥派生逐字节等于参考。
#[test]
fn response_body_key_iv_match_reference_bytes() {
    let (key, iv) = lengsuo_vmess::server::respond::response_key_iv(&BODY_KEY, &BODY_IV);
    assert_eq!(hex::encode(key), expected::RESPONSE_BODY_KEY);
    assert_eq!(hex::encode(iv), expected::RESPONSE_BODY_IV);
}

/// ⑨ 反例：翻转密文任一字节 ⇒ 解封必须失败（tag 校验）。
#[test]
fn flipped_ciphertext_bit_must_fail_closed() {
    for suite in [BodySuite::Aes128Gcm, BodySuite::ChaCha20Poly1305] {
        let clean = body_payload_ct(suite);
        for index in [0usize, clean.len() / 2, clean.len() - 1] {
            let mut broken = clean.clone();
            broken[index] ^= 0x01;
            let mut cipher = BodyCipher::from_suite(suite, &BODY_KEY, &BODY_IV);
            let result = cipher.open_payload(&broken);
            assert!(
                matches!(result, Err(lengsuo_vmess::Error::AuthFailed)),
                "suite={suite:?} index={index} 实际 {result:?}"
            );
        }
    }
}

/// ⑩ 反例：档位错配 —— 用 AES 档的密文喂 ChaCha 解密 ⇒ 必须失败。
#[test]
fn cross_suite_ciphertext_must_not_open() {
    let aes_ct = body_payload_ct(BodySuite::Aes128Gcm);
    let mut cipher = BodyCipher::from_suite(BodySuite::ChaCha20Poly1305, &BODY_KEY, &BODY_IV);
    let result = cipher.open_payload(&aes_ct);
    assert!(
        matches!(result, Err(lengsuo_vmess::Error::AuthFailed)),
        "档位错配必须失败，实际 {result:?}"
    );

    // 反方向同样失败。
    let chacha_ct = body_payload_ct(BodySuite::ChaCha20Poly1305);
    let mut cipher = BodyCipher::from_suite(BodySuite::Aes128Gcm, &BODY_KEY, &BODY_IV);
    let result = cipher.open_payload(&chacha_ct);
    assert!(
        matches!(result, Err(lengsuo_vmess::Error::AuthFailed)),
        "档位错配必须失败，实际 {result:?}"
    );
}

/// ⑪ 反例：认证长度段档位错配 ⇒ 必须失败。
#[test]
fn cross_suite_auth_len_segment_must_not_open() {
    let aes_seg = auth_len_segment(BodySuite::Aes128Gcm);
    let mut cipher = BodyCipher::from_suite(BodySuite::ChaCha20Poly1305, &BODY_KEY, &BODY_IV);
    cipher
        .enable_authenticated_length(&BODY_KEY, &BODY_IV)
        .expect("可启用");
    let result = cipher.open_len_segment(&aes_seg);
    assert!(
        matches!(result, Err(lengsuo_vmess::Error::AuthFailed)),
        "长度段档位错配必须失败，实际 {result:?}"
    );
}

/// ⑫ 头部 AEAD 的 ChaCha 档必须 fail-closed（参考头部恒 AES-128-GCM）。
#[test]
fn header_chacha_suite_is_rejected_not_silently_aes() {
    let err = aead::seal_vmess_aead_header_with(
        &CMD_KEY,
        PLAIN_HEAD,
        aead::HeaderSuite::ChaCha20Poly1305,
    )
    .expect_err("ChaCha 头部必须被拒");
    assert!(
        matches!(err, lengsuo_vmess::Error::Unsupported { .. }),
        "实际 {err:?}"
    );

    let wire = aead::seal_header_with(&CMD_KEY, &AUTH_ID, &CONN_NONCE, PLAIN_HEAD);
    let err = aead::open_vmess_aead_header_with(
        &CMD_KEY,
        &AUTH_ID,
        &wire[16..],
        aead::HeaderSuite::ChaCha20Poly1305,
    )
    .expect_err("ChaCha 头部必须被拒");
    assert!(
        matches!(err, lengsuo_vmess::Error::Unsupported { .. }),
        "实际 {err:?}"
    );
}

/// ⑬ 完整帧逐字节：ChaCha 档 + 认证长度段 + 掩码 + padding 的整帧字节。
///
/// 帧的**载荷密文**与**长度段密文**分别由 ⑨/⑩ 逐字节锁定；这里额外验证
/// 整帧组装（长度段 + 密文 + padding）在三档下都自洽。
#[test]
fn full_frames_roundtrip_in_every_suite_and_size_mode() {
    for suite in [
        BodySuite::None,
        BodySuite::Aes128Gcm,
        BodySuite::ChaCha20Poly1305,
    ] {
        for option in [0x00u8, 0x04, 0x0C, 0x10, 0x1C] {
            if suite == BodySuite::None && (option & 0x10) != 0 {
                continue; // 参考的 NONE 分支不看 AuthenticatedLength
            }
            let mut seal =
                BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, option)
                    .expect("可建");
            let mut open =
                BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, option)
                    .expect("可建");
            let mut wire = Vec::new();
            seal.seal(&mut wire, PAYLOAD).expect("可写");
            seal.seal(&mut wire, b"").expect("EOF 可写");

            let mut cursor = &wire[..];
            let first = open.open_from(&mut cursor).expect("可解");
            assert_eq!(
                first.as_deref(),
                Some(PAYLOAD),
                "suite={suite:?} option={option:#x}"
            );
            let eof = open.open_from(&mut cursor).expect("可解");
            assert!(eof.is_none(), "suite={suite:?} option={option:#x} 终止帧");
            assert!(cursor.is_empty(), "不得吞尾部字节");
        }
    }
}

/// ⑭ `SizeMode` 的线上长度与参考形态一致（认证长度段 18 字节，其余 2 字节）。
#[test]
fn size_mode_wire_lengths_match_reference_shapes() {
    assert_eq!(SizeMode::Plain.wire_len(), 2);
    assert_eq!(SizeMode::Masked.wire_len(), 2);
    assert_eq!(SizeMode::Authenticated.wire_len(), 18);
    // 认证长度段密文的实际长度就是 18 字节。
    assert_eq!(auth_len_segment(BodySuite::ChaCha20Poly1305).len(), 18);
}

/// ⑮ 安全档字节与参考 `SecurityType` 枚举一致。
#[test]
fn security_bytes_match_reference_enum() {
    use lengsuo_vmess::request::SecurityOption;
    assert_eq!(SecurityOption::None.to_byte(), 5);
    assert_eq!(SecurityOption::Aes128Gcm.to_byte(), 3);
    assert_eq!(SecurityOption::ChaCha20Poly1305.to_byte(), 4);
    assert_eq!(SecurityOption::AutoCipher.to_byte(), 2);
    assert_eq!(SECURITY_AES_128_GCM, 3);
    assert_eq!(SECURITY_CHACHA20_POLY1305, 4);
}
