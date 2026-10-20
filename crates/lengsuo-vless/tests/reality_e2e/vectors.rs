//! 第 1 层：**确定性向量**（不依赖任何外部二进制）。
//!
//! 期望值全部硬编码，来自 RFC 或独立实现（见 `support/vectors.rs`
//! 顶部的来源表），**不是**本仓实现自证。

use crate::support::hex;
use crate::support::vectors as vec;

use lengsuo_vless::reality::auth::{
    build_auth_plaintext, cert_auth_tag, derive_auth_key, open_auth_payload, seal_auth_payload,
};
use lengsuo_vless::reality::hash::hmac::{
    hkdf_extract_sha256, hkdf_sha256, hmac_sha256, hmac_sha512,
};
use lengsuo_vless::reality::hash::sha::{sha256, sha512};
use lengsuo_vless::reality::shortid::parse_short_id;
use lengsuo_vless::reality::tls13::ed25519;
use lengsuo_vless::reality::tls13::record::{content_type, RecordLayer};
use lengsuo_vless::reality::tls13::schedule::{
    expand_label, finished_verify_data, traffic_key, KeySchedule, TrafficKey,
};
use lengsuo_vless::reality::x25519::{x25519, x25519_base};
use lengsuo_vless::reality::ClientVersion;

/// FIPS 180-4 的 SHA-256 / SHA-512 摘要示例。
#[test]
fn sha_digests_match_fips_180_4() {
    assert_eq!(
        hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&sha512(b"abc")),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
}

/// RFC 4231 §4.2 的 HMAC-SHA256 case 1 / case 2。
#[test]
fn hmac_sha256_matches_rfc_4231() {
    assert_eq!(
        hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

/// RFC 4231 §4.3 的 HMAC-SHA512 case 1。
#[test]
fn hmac_sha512_matches_rfc_4231() {
    assert_eq!(
        hex(&hmac_sha512(&[0x0b; 20], b"Hi There")),
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
         daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
    );
}

/// RFC 5869 Appendix A.1 的 HKDF-SHA256 case 1（OKM 42 字节）。
#[test]
fn hkdf_sha256_matches_rfc_5869_case1() {
    let ikm = [0x0b; 22];
    let salt: Vec<u8> = (0x00u8..0x0d).collect();
    let info: Vec<u8> = (0xf0u8..0xfa).collect();
    let mut okm = [0u8; 42];
    hkdf_sha256(Some(&salt), &ikm, &info, &mut okm);
    assert_eq!(
        hex(&okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
    // Extract 段的 PRK 也要对得上（HKDF 的第一步是 extract，不是 expand）。
    assert_eq!(
        hex(&hkdf_extract_sha256(&salt, &ikm)),
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    );
}

/// RFC 7748 §6.1 的 X25519 一次迭代。
///
/// **输入向量**：RFC 7748 §6.1 的迭代输入是 `k = u = 09 00 … 00`
/// （**一个 0x09 后跟 31 个 0x00**），不是 32 个 `0x09`。
/// RFC 的期望输出是
/// `422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079`。
///
/// **独立复算**（Python 纯 Montgomery ladder，与本仓实现无一行共享代码）：
///
/// ```text
/// X25519(09 00…00, 09 00…00) = 422c8e7a…ae3079   ← RFC §6.1
/// X25519(09 09…09, 09 09…09) = 94cae1b7…9bbeb40   ← 旧用例的输入
/// ```
///
/// ⇒ 本仓实现对两种输入都正确；旧用例只是**输入写错了**（32 个 `0x09`
/// 不是 RFC 的迭代向量），期望值也随之写错。本用例改为 RFC 的真实输入。
///
/// **不跑一百万次迭代**：本仓的 X25519 是纯 Rust 实现（无 `unsafe`，无
/// 汇编加速），单次约 0.5 ms（debug 构建），一百万次要 8 分钟以上，会把
/// 门禁拖垮。一百万次迭代的期望值仍然**硬编码**在
/// [`reality_support::vectors::X25519_ITER_1M`] 里，供实现方在需要时核对。
#[test]
fn x25519_matches_rfc_7748_iteration() {
    // RFC 7748 §6.1：`k = u = 09 00 … 00`。
    let mut k = [0u8; 32];
    k[0] = 0x09;
    let u = k;
    // 一次迭代：`k = X25519(k, u)`，结果应等于 u_coordinate。
    let once = x25519(&k, &u).expect("一次迭代不应是低阶点");
    assert_eq!(once.to_vec(), vec::X25519_ITER1.to_vec());
}

/// RFC 7748 §6.1 的 Alice/Bob 公钥与共享密钥。
#[test]
fn x25519_key_agreement_matches_rfc_7748() {
    let a_pub = x25519_base(&vec::X25519_ALICE_SECRET);
    let b_pub = x25519_base(&vec::X25519_BOB_SECRET);
    assert_eq!(a_pub.to_vec(), vec::X25519_ALICE_PUBLIC.to_vec());
    assert_eq!(b_pub.to_vec(), vec::X25519_BOB_PUBLIC.to_vec());
    let ab = x25519(&vec::X25519_ALICE_SECRET, &b_pub).expect("共享密钥不应是低阶点");
    let ba = x25519(&vec::X25519_BOB_SECRET, &a_pub).expect("共享密钥不应是低阶点");
    assert_eq!(ab.to_vec(), vec::X25519_SHARED.to_vec());
    assert_eq!(ab.to_vec(), ba.to_vec());
}

/// 低阶点必须被拒绝（fail-closed），不得返回全零共享密钥。
#[test]
fn x25519_rejects_low_order_points() {
    let all_zero = [0u8; 32];
    assert!(x25519(&[1u8; 32], &all_zero).is_err());
}

/// RFC 8032 §7.1 的三组 Ed25519 向量（签名 + 验签）。
///
/// 一组向量 = `(种子, 公钥, 消息, 签名)`。
type Ed25519Case = (
    &'static [u8; 32],
    &'static [u8; 32],
    &'static [u8],
    &'static [u8; 64],
);

#[test]
fn ed25519_matches_rfc_8032() {
    let cases: [Ed25519Case; 3] = [
        (
            &vec::ED25519_T1_SEED,
            &vec::ED25519_T1_PUBLIC,
            b"",
            &vec::ED25519_T1_SIG,
        ),
        (
            &vec::ED25519_T2_SEED,
            &vec::ED25519_T2_PUBLIC,
            &vec::ED25519_T2_MESSAGE,
            &vec::ED25519_T2_SIG,
        ),
        (
            &vec::ED25519_T3_SEED,
            &vec::ED25519_T3_PUBLIC,
            &vec::ED25519_T2_MESSAGE,
            &vec::ED25519_T3_SIG,
        ),
    ];
    for (seed, public, message, signature) in cases {
        let key = ed25519::SigningKey::from_seed(seed);
        assert_eq!(key.public_key().to_vec(), public.to_vec());
        assert_eq!(key.sign(message).to_vec(), signature.to_vec());
        assert!(ed25519::verify(public, message, signature).is_ok());
        // 篡改消息必须验签失败。
        let mut tampered = message.to_vec();
        tampered.push(0x00);
        assert!(ed25519::verify(public, &tampered, signature).is_err());
    }
}

/// RFC 8448 §3 的 `Expand-Label` 向量。
#[test]
fn expand_label_matches_rfc_8448() {
    let out = expand_label(&vec::RFC8448_SECRET, "traffic upd", &[0x9b; 16], 32);
    assert_eq!(out, vec::RFC8448_EXPAND_LABEL.to_vec());
}

/// TLS 1.3 密钥调度（RFC 8446 §7.1）各段的硬编码期望值。
#[test]
fn key_schedule_matches_expected_segments() {
    let schedule = KeySchedule::new(&vec::KS_SHARED, &vec::KS_CH_SH, &vec::KS_CH_SFIN);
    assert_eq!(
        schedule.client_handshake_traffic.to_vec(),
        vec::KS_CLIENT_HANDSHAKE.to_vec()
    );
    assert_eq!(
        schedule.server_handshake_traffic.to_vec(),
        vec::KS_SERVER_HANDSHAKE.to_vec()
    );
    assert_eq!(
        schedule.client_application_traffic.to_vec(),
        vec::KS_CLIENT_APPLICATION.to_vec()
    );
    assert_eq!(
        schedule.server_application_traffic.to_vec(),
        vec::KS_SERVER_APPLICATION.to_vec()
    );
    // 记录层 key/iv 由流量密钥派生。
    let key = traffic_key(&vec::KS_CLIENT_HANDSHAKE);
    assert_eq!(key.key.to_vec(), vec::KS_CLIENT_HANDSHAKE_KEY.to_vec());
    assert_eq!(key.iv.to_vec(), vec::KS_CLIENT_HANDSHAKE_IV.to_vec());
    // Finished 的 verify_data。
    assert_eq!(
        finished_verify_data(&vec::KS_CLIENT_HANDSHAKE, &vec::KS_CH_SH).to_vec(),
        vec::KS_CLIENT_FINISHED_VERIFY.to_vec()
    );
    // `finished` 子密钥本身。
    assert_eq!(
        expand_label(&vec::KS_CLIENT_HANDSHAKE, "finished", &[], 32),
        vec::KS_CLIENT_FINISHED_KEY.to_vec()
    );
    // `Derive-Secret(., "derived", "")` 的上下文是 `Hash("")`，不是空上下文。
    let zeros = [0u8; 32];
    let early = hkdf_extract_sha256(&zeros, &zeros);
    let derived = expand_label(&early, "derived", &sha256(b""), 32);
    assert_ne!(derived, expand_label(&early, "derived", &[], 32));
}

/// REALITY `auth_key`：`HKDF-SHA256(ikm=ECDH, salt=random[:20], info="REALITY")`。
#[test]
fn reality_auth_key_matches_expected() {
    let key =
        derive_auth_key(&vec::X25519_SHARED, &vec::REALITY_CLIENT_RANDOM).expect("派生不应失败");
    assert_eq!(key.to_vec(), vec::REALITY_AUTH_KEY.to_vec());
}

/// REALITY 认证载荷的 AEAD 密文（16 字节密文 + 16 字节 tag）必须逐字节一致。
#[test]
fn reality_auth_payload_seal_matches_expected() {
    let plaintext = build_auth_plaintext(
        ClientVersion { x: 26, y: 3, z: 27 },
        1_705_618_800,
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    );
    assert_eq!(plaintext.to_vec(), vec::AUTH_PLAINTEXT.to_vec());
    let sealed = seal_auth_payload(&vec::REALITY_AUTH_KEY, &plaintext, &vec::AUTH_CLIENT_HELLO)
        .expect("封装不应失败");
    assert_eq!(sealed.to_vec(), vec::AUTH_SEALED.to_vec());
    // 解封必须还原出同一个明文。
    let mut raw = vec::AUTH_CLIENT_HELLO.to_vec();
    raw[39..71].copy_from_slice(&sealed);
    let opened = open_auth_payload(&vec::REALITY_AUTH_KEY, &raw).expect("解封不应失败");
    assert_eq!(opened.version.x, 26);
    assert_eq!(opened.version.y, 3);
    assert_eq!(opened.version.z, 27);
    assert_eq!(opened.reserved, 0);
    assert_eq!(opened.unix_time, 1_705_618_800);
    assert_eq!(opened.short_id.to_vec(), vec::AUTH_PLAINTEXT[8..].to_vec());
}

/// 证书的 REALITY 标签：`HMAC-SHA512(auth_key, ed25519_pub)`。
#[test]
fn certificate_auth_tag_matches_expected() {
    let key = ed25519::SigningKey::from_seed(&vec::CERT_TAG_SEED);
    assert_eq!(key.public_key().to_vec(), vec::CERT_TAG_PUBLIC.to_vec());
    let signature = key.sign(b"lengsuo-reality-ed25519-vector");
    assert_eq!(signature.to_vec(), vec::CERT_TAG_SIG.to_vec());
    let tag = cert_auth_tag(&vec::REALITY_AUTH_KEY, &key.public_key());
    assert_eq!(tag.to_vec(), vec::CERT_AUTH_TAG.to_vec());
}

/// TLS 1.3 记录层（`TLS_AES_128_GCM_SHA256`）的线上字节必须逐字节一致。
///
/// **内层明文布局**：`TLSInnerPlaintext = content + content_type + zeros`
/// （RFC 8446 §5.2）—— 内容类型在**尾部**。
///
/// * rustls 0.23.31 `src/crypto/ring/tls13.rs:217-219`：
///   `payload.extend_from_chunks(&msg.payload); payload.extend_from_slice(&msg.typ.to_array());`
///   ⇒ payload 在前、类型在后（与 RFC 同款）。
/// * 本仓 `src/reality/tls13/record.rs:152-157` 的 `seal_handshake` 同样是
///   `payload` 后 `push(content_type::HANDSHAKE)` ⇒ **实现正确**。
///
/// **独立复算**（Node `crypto`，AES-128-GCM，AAD = 5 字节记录头，nonce = iv）：
///
/// ```text
/// payload || type = 1703030014f2398e00ee32d431cc102d086d4627696eb13938  ← 本仓输出
/// type || payload = 1703030014853a8f75b9daba8dd3ef1e84d01eeea719495b7b  ← 旧期望
/// ```
#[test]
fn record_layer_bytes_match_expected() {
    let mut layer = RecordLayer::new(&TrafficKey {
        key: vec::RECORD_KEY,
        iv: vec::RECORD_IV,
    });
    let wire = layer.seal_handshake(b"abc").expect("封装不应失败");
    assert_eq!(wire.to_vec(), vec::RECORD_WIRE.to_vec());
    // 记录头：类型 0x17、legacy_version 0x0303、长度 = 明文 + 16 字节标签。
    assert_eq!(wire[0], content_type::APPLICATION_DATA);
    assert_eq!(&wire[1..3], &[0x03, 0x03]);
    assert_eq!(u16::from_be_bytes([wire[3], wire[4]]) as usize, 4 + 16);
    // 对端能解出同样的内容类型与载荷。
    let mut peer = RecordLayer::new(&TrafficKey {
        key: vec::RECORD_KEY,
        iv: vec::RECORD_IV,
    });
    let (kind, payload) = peer.open(&wire).expect("解封不应失败");
    assert_eq!(kind, content_type::HANDSHAKE);
    assert_eq!(payload, b"abc");
}

/// 记录层的 nonce 是 `iv XOR seq`（seq 大端放低 8 字节），序号严格递增。
#[test]
fn record_layer_sequence_advances_and_nonce_varies() {
    let mut layer = RecordLayer::new(&TrafficKey {
        key: vec::RECORD_KEY,
        iv: vec::RECORD_IV,
    });
    let first = layer.seal_application(b"one").expect("封装不应失败");
    let second = layer.seal_application(b"two").expect("封装不应失败");
    assert_eq!(layer.sequence(), 2);
    assert_ne!(first, second);
}

/// 短 ID 解析：十六进制、大小写、空串、奇数长度、超长。
///
/// **语义依据**（Xray 参考）：短 ID 是**十六进制**字符串，不是字面 ASCII。
///
/// * 客户端 `infra/conf/transport_internet.go:952-956`：
///   `config.ShortId = make([]byte, 8)` 后 `hex.Decode(config.ShortId, []byte(c.ShortId))`
///   ⇒ **十六进制解码 + 尾部补零**。
/// * 服务端 `infra/conf/transport_internet.go:888-895`（`shortIds` 数组项）
///   同构：先 `hex.DecodeString` 到 8 字节缓冲，尾部保持 0。
///
/// Go 的 `hex.Decode` 只写「解码出的字节数」，**尾部保持 0**（左对齐高位补零），
/// 奇数长度 hex 返回 `ErrLength` ⇒ 报错。
///
/// ⇒ 本仓 `src/reality/shortid.rs:55-73` 正是对齐这个语义，**实现正确**；
/// 旧用例把期望写成了「字面 ASCII 字节」，是**用例写错了**。
#[test]
fn short_id_parsing_matches_reference() {
    // "12345678" 是 8 个 hex 字符 ⇒ 4 字节，其余 4 字节补零。
    assert_eq!(
        parse_short_id("12345678").unwrap().to_vec(),
        vec![0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0]
    );
    // "abcdef" 是 6 个 hex 字符 ⇒ 3 字节，其余 5 字节补零。
    assert_eq!(
        parse_short_id("abcdef").unwrap().to_vec(),
        vec![0xab, 0xcd, 0xef, 0, 0, 0, 0, 0]
    );
    // 大小写均可（Go 的 `encoding/hex` 接受 `A-F`/`a-f`）。
    assert_eq!(
        parse_short_id("ABCDEF").unwrap().to_vec(),
        vec![0xab, 0xcd, 0xef, 0, 0, 0, 0, 0]
    );
    // 空串：Go 的 `hex.Decode` 返回 `(0, nil)` ⇒ 全 0 的 8 字节（不是错误）。
    assert_eq!(parse_short_id("").unwrap(), [0u8; 8]);
    // 奇数长度 hex ⇒ Go 的 `ErrLength` ⇒ 报错。
    assert!(parse_short_id("abc").is_err());
    // 非 hex 字符 ⇒ Go 的 `InvalidByteError` ⇒ 报错。
    assert!(parse_short_id("zz").is_err());
    // 超过 16 个 hex 字符（客户端 `len > 16` ⇒ `too long "shortId"`）。
    assert!(parse_short_id("010203040506070809").is_err());
}
