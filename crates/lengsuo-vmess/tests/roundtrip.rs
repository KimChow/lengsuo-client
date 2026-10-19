//! Rust↔Rust 回归：crate 自己的「封装 → 解封」链路读回（不依赖外部二进制）。
//!
//! 这些是**非 ignore** 的常规测试，随 `cargo test -p lengsuo-vmess --locked` 一起跑。
//! 定位与 `tests/xray_tcp.rs` 互补：那里证明 Rust↔真实 Xray 互通；这里把同一套
//! crate 原语拼成完整请求/响应并读回，锁住「客户端写端 ↔ 服务端读端」两侧共用
//! 的同一批实现不会单侧漂移。响应头方向 crate 只有解封、没有封装，因此用
//! `aes-gcm` 直接在测试里按参考布局封出密文，再交给 crate 解封（参考
//! `proxy/vmess/encoding/server.go` `EncodeResponseHeader`）。

use lengsuo_vmess::aead;
use lengsuo_vmess::authid;
use lengsuo_vmess::chunkframe::{self, DataCipher, DataSizeParser, MAX_CHUNK_PAYLOAD};
use lengsuo_vmess::consts::SECURITY_AES_128_GCM;
use lengsuo_vmess::request::{fnv1a32, Command, HeaderPlanner, KeySource, RequestHeader, SecurityOption};
use ss_core::target::TargetAddr;

/// `responseBodyKey = SHA256(requestBodyKey)[..16]`、`responseBodyIV = SHA256(requestBodyIV)[..16]`
/// （与 `proxy/vmess/encoding/server.go` 的派生一致；本文件只在本测试内使用）。
fn derive_resp(body_key: &[u8; 16], body_iv: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    use sha2::{Digest as _, Sha256};
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&Sha256::digest(body_key)[..16]);
    iv.copy_from_slice(&Sha256::digest(body_iv)[..16]);
    (key, iv)
}

/// 请求头：`HeaderPlanner` 出明文 → `seal_vmess_aead_header` 封 → 取 AuthID →
/// `open_vmess_aead_header` 解，逐字节一致；AuthID 再由 `decode_auth_id` 自检。
#[test]
fn request_header_self_roundtrip() {
    let cmd_key = [0x5Au8; 16];
    let keys = KeySource::generate().expect("生成会话密钥");
    let planner = HeaderPlanner::new(KeySource {
        body_key: keys.body_key,
        body_iv: keys.body_iv,
        response_header: keys.response_header,
    });
    let header = RequestHeader {
        target: Some(TargetAddr::Domain("example.invalid".into(), 443)),
        command: Command::Tcp,
        security: SecurityOption::Aes128Gcm,
        option: 0,
        padding_len: 0,
    };
    let plain = planner.plan(&header).expect("规划请求头明文");

    let wire = aead::seal_vmess_aead_header(&cmd_key, &plain).expect("封装请求头");
    assert_eq!(wire.len(), 16 + 18 + 8 + plain.len() + 16, "线长结构");

    let auth = aead::parse_auth_id_from_header(&wire).expect("取 AuthID");
    let opened = aead::open_vmess_aead_header(&cmd_key, &auth, &wire[16..]).expect("解封请求头");
    assert_eq!(opened, plain, "头明文逐字节一致");

    // 明文布局自洽：版本字节 + FNV1a 尾。
    assert_eq!(plain[0], 1, "版本字节");
    let tail = u32::from_be_bytes(plain[plain.len() - 4..].try_into().unwrap());
    assert_eq!(tail, fnv1a32(&plain[..plain.len() - 4]), "FNV 尾");

    // AuthID 完整校验路径（含 CRC 与时间窗）。
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    authid::decode_auth_id(&cmd_key, &auth, now).expect("AuthID 应在时间窗内且 CRC 自洽");
}

/// 请求体：按 `write_request` 的切分规则（`MAX_CHUNK_PAYLOAD`）写三段 + EOF 帧，
/// 再用新 cipher 逐帧读回，逐字节一致且帧数正确（无掩码，option=0 合法简化）。
#[tokio::test]
async fn request_body_self_roundtrip() {
    let key = *b"request-body-key";
    let iv = *b"request-body-iv!";
    let payload: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();

    let mut seal = DataCipher::new(SECURITY_AES_128_GCM, &key, &iv);
    let mut wire = Vec::new();
    for piece in payload.chunks(MAX_CHUNK_PAYLOAD) {
        chunkframe::seal_data_chunk(&mut seal, None, &mut wire, piece).expect("封数据段");
    }
    chunkframe::write_data_eof(&mut seal, None, &mut wire).expect("封 EOF 帧");

    let mut open = DataCipher::new(SECURITY_AES_128_GCM, &key, &iv);
    let mut cursor: &[u8] = &wire;
    let mut got = Vec::new();
    let mut frames = 0usize;
    loop {
        match chunkframe::read_data_chunk(&mut open, None, &mut cursor)
            .await
            .expect("读数据段")
        {
            Some(plain) => {
                got.extend_from_slice(&plain);
                frames += 1;
            }
            None => break,
        }
    }
    assert!(cursor.is_empty(), "读回不得吞/漏尾部字节");
    assert_eq!(frames, 3, "40000 字节 = 16384+16384+7232 三段");
    assert_eq!(got, payload, "请求体逐字节一致");
}

/// 掩码分帧变体：`DataSizeParser` 掩码流两侧同源、跨 chunk 推进。
#[tokio::test]
async fn request_body_masked_self_roundtrip() {
    let key = *b"request-body-key";
    let iv = *b"request-body-iv!";
    let payloads: [&[u8]; 2] = [b"one", &[0x77u8; 300]];

    let mut seal = DataCipher::new(SECURITY_AES_128_GCM, &key, &iv);
    let mut enc_mask = DataSizeParser::new(&iv);
    let mut wire = Vec::new();
    for payload in payloads {
        chunkframe::seal_data_chunk(&mut seal, Some(&mut enc_mask), &mut wire, payload)
            .expect("封数据段");
    }
    chunkframe::write_data_eof(&mut seal, Some(&mut enc_mask), &mut wire).expect("封 EOF 帧");

    let mut open = DataCipher::new(SECURITY_AES_128_GCM, &key, &iv);
    let mut dec_mask = DataSizeParser::new(&iv);
    let mut cursor: &[u8] = &wire;
    for expected in payloads {
        let got = chunkframe::read_data_chunk(&mut open, Some(&mut dec_mask), &mut cursor)
            .await
            .expect("读数据段")
            .expect("应有帧");
        assert_eq!(got, expected);
    }
    assert!(
        chunkframe::read_data_chunk(&mut open, Some(&mut dec_mask), &mut cursor)
            .await
            .expect("读 EOF")
            .is_none(),
        "以 EOF 帧收尾"
    );
    assert!(cursor.is_empty(), "读回不得吞/漏尾部字节");
}

/// 响应头：crate 只有解封。这里用 `aes-gcm` 直接按 `EncodeResponseHeader` 封出
/// 长度段(18B)与载荷段(20B)（无 AAD、KDF 派生密钥/IV），再交 crate 两段解封。
#[test]
fn response_header_reference_seal_opens_via_crate() {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::Aes128Gcm;

    let body_key = [0x11u8; 16];
    let body_iv = [0x22u8; 16];
    let (resp_key, resp_iv) = derive_resp(&body_key, &body_iv);
    let header_plain = [0x33u8, 0x00, 0x00, 0x00];

    let (len_key, len_iv) = aead::response_header_length_key_iv(&resp_key, &resp_iv);
    let len_wire = Aes128Gcm::new_from_slice(&len_key)
        .unwrap()
        .encrypt(
            (&len_iv).into(),
            Payload {
                msg: &(header_plain.len() as u16).to_be_bytes(),
                aad: b"",
            },
        )
        .unwrap();
    assert_eq!(len_wire.len(), 18, "长度段密文 2+16");

    let (pay_key, pay_iv) = aead::response_header_payload_key_iv(&resp_key, &resp_iv);
    let pay_wire = Aes128Gcm::new_from_slice(&pay_key)
        .unwrap()
        .encrypt(
            (&pay_iv).into(),
            Payload {
                msg: &header_plain,
                aad: b"",
            },
        )
        .unwrap();
    assert_eq!(pay_wire.len(), 20, "载荷段密文 4+16");

    let opened_len = aead::open_response_header_length(
        &resp_key,
        &resp_iv,
        len_wire.as_slice().try_into().unwrap(),
    )
    .expect("长度段可解");
    assert_eq!(opened_len, header_plain.len() as u16);

    let opened_pay =
        aead::open_response_header_payload(&resp_key, &resp_iv, &pay_wire).expect("载荷段可解");
    assert_eq!(opened_pay, header_plain, "响应头明文逐字节一致");
}

/// 响应体分帧：用 `SHA256(requestBodyKey/IV)` 派生的响应 body key/iv 走一遍
/// DataCipher 封/解（服务端回程方向的读取路径）。
#[tokio::test]
async fn response_body_self_roundtrip() {
    let body_key = [0x44u8; 16];
    let body_iv = [0x55u8; 16];
    let (resp_key, resp_iv) = derive_resp(&body_key, &body_iv);
    let payload: Vec<u8> = (0..5000).map(|i| (i % 197) as u8).collect();

    let mut seal = DataCipher::new(SECURITY_AES_128_GCM, &resp_key, &resp_iv);
    let mut wire = Vec::new();
    chunkframe::seal_data_chunk(&mut seal, None, &mut wire, &payload).expect("封响应体");
    chunkframe::write_data_eof(&mut seal, None, &mut wire).expect("封 EOF 帧");

    let mut open = DataCipher::new(SECURITY_AES_128_GCM, &resp_key, &resp_iv);
    let mut cursor: &[u8] = &wire;
    let got = chunkframe::read_data_chunk(&mut open, None, &mut cursor)
        .await
        .expect("读响应体")
        .expect("应有帧");
    assert_eq!(got, payload, "响应体逐字节一致");
    assert!(
        chunkframe::read_data_chunk(&mut open, None, &mut cursor)
            .await
            .expect("读 EOF")
            .is_none(),
        "以 EOF 帧收尾"
    );
    assert!(cursor.is_empty(), "读回不得吞/漏尾部字节");
}