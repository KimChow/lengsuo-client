//! 服务端解码非 ignore 测试：固定向量、逐错误变体、Rust↔Rust 全链路。
//!
//! 全部不依赖 Xray 二进制；互通实跑见 `tests/xray_vmess_server.rs`（ignore）。

use std::io::Cursor;

use lengsuo_vmess::aead::seal_header_with;
use lengsuo_vmess::authid::create_auth_id_with;
use lengsuo_vmess::chunkframe::{open_data_chunk, seal_data_chunk, DataCipher};
use lengsuo_vmess::consts::SECURITY_AES_128_GCM;
use lengsuo_vmess::request::{fnv1a32, HeaderPlanner, KeySource, RequestHeader};
use lengsuo_vmess::response::read_response_header;
use lengsuo_vmess::server::{
    decode_request_header, encode_response_header, InboundCommand, HeaderDecodeError,
    HeaderSecurity, ResponseHeader,
};
use lengsuo_vmess::{Command, SecurityOption};
use ss_core::target::TargetAddr;

const CMD_KEY: [u8; 16] = [0xA1u8; 16];
const OTHER_KEY: [u8; 16] = [0xB2u8; 16];
const NOW: i64 = 1_700_000_000;
const RANDOM: [u8; 4] = [0x0D, 0x0C, 0x0B, 0x0A];
const NONCE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

fn keys() -> KeySource {
    KeySource {
        body_key: [0x11u8; 16],
        body_iv: [0x22u8; 16],
        response_header: 0x5C,
    }
}

fn plan_payload(security: SecurityOption, target: Option<&TargetAddr>, padding: &[u8]) -> Vec<u8> {
    HeaderPlanner::new(keys()).plan_with(
        &RequestHeader {
            target: target.cloned(),
            command: Command::Tcp,
            security,
            option: 0,
            padding_len: padding.len() as u8,
        },
        padding,
    )
    .expect("可编码")
}

fn seal_for(payload: &[u8], cmd_key: &[u8; 16], now: i64) -> Vec<u8> {
    let auth = create_auth_id_with(cmd_key, now, &RANDOM);
    let mut wire = Vec::new();
    wire.extend_from_slice(auth.as_bytes());
    let sealed = seal_header_with(cmd_key, auth.as_bytes(), &NONCE, payload);
    wire.extend_from_slice(&sealed[16..]);
    wire
}

fn decode_from(wire: &[u8]) -> Result<lengsuo_vmess::server::DecodedRequest, HeaderDecodeError> {
    let mut history: Vec<[u8; 48]> = Vec::new();
    decode_request_header(
        &[CMD_KEY, OTHER_KEY],
        &mut Cursor::new(wire),
        NOW,
        &mut |user, key, iv| {
            let mut entry = [0u8; 48];
            entry[..16].copy_from_slice(user);
            entry[16..32].copy_from_slice(key);
            entry[32..].copy_from_slice(iv);
            if history.contains(&entry) {
                false
            } else {
                history.push(entry);
                true
            }
        },
    )
}

fn sample_target() -> TargetAddr {
    TargetAddr::Domain("echo.internal".into(), 8443)
}

#[test]
fn fixed_vector_full_header_decodes() {
    let payload = plan_payload(
        SecurityOption::Aes128Gcm,
        Some(&sample_target()),
        &[0x77u8; 5],
    );
    let wire = seal_for(&payload, &CMD_KEY, NOW);
    let decoded = decode_from(&wire).expect("合法头必须可解");

    assert_eq!(decoded.user_index, 0, "命中第一个用户");
    assert_eq!(decoded.command, InboundCommand::Tcp);
    assert_eq!(decoded.target.as_ref(), Some(&sample_target()));
    assert_eq!(decoded.security, HeaderSecurity::Aes128Gcm);
    assert_eq!(decoded.option, 0);
    assert_eq!(decoded.request_body_key, keys().body_key);
    assert_eq!(decoded.request_body_iv, keys().body_iv);
    assert_eq!(decoded.response_header, 0x5C);
}

#[test]
fn second_user_key_matches_user_index() {
    let payload = plan_payload(SecurityOption::None, Some(&sample_target()), &[]);
    let wire = seal_for(&payload, &OTHER_KEY, NOW);
    let decoded = decode_from(&wire).expect("第二用户的合法头必须可解");
    assert_eq!(decoded.user_index, 1);
    assert_eq!(decoded.security, HeaderSecurity::None);
}

#[test]
fn wrong_cmd_key_is_invalid_user() {
    let payload = plan_payload(SecurityOption::Aes128Gcm, Some(&sample_target()), &[]);
    let evil = [0xEEu8; 16];
    let wire = seal_for(&payload, &evil, NOW);
    assert!(matches!(decode_from(&wire), Err(HeaderDecodeError::InvalidUser)));
}

#[test]
fn expired_time_window_is_invalid_user() {
    let payload = plan_payload(SecurityOption::Aes128Gcm, Some(&sample_target()), &[]);
    // AuthID 时间戳比 now 早 121 秒（窗口 ±120 秒之外）。
    let wire = seal_for(&payload, &CMD_KEY, NOW - 121);
    assert!(matches!(decode_from(&wire), Err(HeaderDecodeError::InvalidUser)));
    // 恰好在窗口边缘（±120 秒）仍然通过。
    let wire = seal_for(&payload, &CMD_KEY, NOW + 120);
    assert!(decode_from(&wire).is_ok());
}

#[test]
fn tampered_length_and_payload_tags_map_to_distinct_variants() {
    let payload = plan_payload(SecurityOption::Aes128Gcm, Some(&sample_target()), &[]);
    let mut wire = seal_for(&payload, &CMD_KEY, NOW);
    // 长度段 = wire[16..34]（16B AuthID 之后 18B）。
    wire[20] ^= 0x01;
    assert!(matches!(
        decode_from(&wire),
        Err(HeaderDecodeError::AeadLengthTag)
    ));

    let mut wire = seal_for(&payload, &CMD_KEY, NOW);
    let last = wire.len() - 1;
    wire[last] ^= 0x01; // 载荷段 tag 末字节
    assert!(matches!(
        decode_from(&wire),
        Err(HeaderDecodeError::AeadPayloadTag)
    ));
}

#[test]
fn unknown_and_auto_security_types_are_rejected() {
    let payload = plan_payload(SecurityOption::Aes128Gcm, Some(&sample_target()), &[]);
    let base = payload.clone();
    for nibble in [0u8, 1, 2, 7, 15] {
        let mut plain = base.clone();
        plain[35] = (plain[35] & 0xF0) | nibble;
        let n = plain.len();
        let tail = fnv1a32(&plain[..n - 4]).to_be_bytes();
        plain[n - 4..].copy_from_slice(&tail);
        let wire = seal_for(&plain, &CMD_KEY, NOW);
        let error = decode_from(&wire).err().expect("必须拒绝");
        assert!(
            matches!(error, HeaderDecodeError::UnknownSecurity),
            "nibble {nibble} 应报 UnknownSecurity，实际 {error:?}"
        );
    }
    // ZERO(6)：头阶段放行（对齐参考），体阶段才拒。
    let mut plain = base;
    plain[35] = (plain[35] & 0xF0) | 6;
    let n = plain.len();
    let tail = fnv1a32(&plain[..n - 4]).to_be_bytes();
    plain[n - 4..].copy_from_slice(&tail);
    let wire = seal_for(&plain, &CMD_KEY, NOW);
    let decoded = decode_from(&wire).expect("ZERO 头阶段必须放行");
    assert_eq!(decoded.security, HeaderSecurity::Zero);
}

#[test]
fn invalid_addresses_are_rejected() {
    let base = plan_payload(SecurityOption::Aes128Gcm, Some(&sample_target()), &[]);
    // 手工替换地址段：取前 38 字节固定前缀，构造「未知类型字节 9」地址。
    let mut plain = Vec::new();
    plain.extend_from_slice(&base[..38]);
    plain.extend_from_slice(&[0x1F, 0x90, 0x09]); // port 8080 + type 9
    plain.extend_from_slice(&[0u8; 4]); // FNV 占位
    let n = plain.len();
    let tail = fnv1a32(&plain[..n - 4]).to_be_bytes();
    plain[n - 4..].copy_from_slice(&tail);
    let wire = seal_for(&plain, &CMD_KEY, NOW);
    let error = decode_from(&wire).err().expect("未知地址类型必须被拒");
    assert!(
        matches!(error, HeaderDecodeError::InvalidAddress),
        "未知地址类型应报 InvalidAddress，实际 {error:?}"
    );

    // 非法命令字节（0x00）：参考的 switch 落空 → 地址保持 nil → 解完头之后
    // 报 "invalid remote address"。注意服务端此时**不再解地址**，因此地址字节
    // 不被消费：padding 与 FNV 尾的位置与合法请求不同（padding 紧跟在命令字节
    // 之后）。构造时按「不解地址」重排尾部，FNV 覆盖到 padding 结束。
    let mut plain = Vec::new();
    plain.extend_from_slice(&base[..38]); // 固定前缀（padLen=0，见 plan_payload）
    plain[37] = 0x00; // 命令字节非法
    plain.extend_from_slice(&[0u8; 4]); // FNV 占位
    let n = plain.len();
    let tail = fnv1a32(&plain[..n - 4]).to_be_bytes();
    plain[n - 4..].copy_from_slice(&tail);
    let wire = seal_for(&plain, &CMD_KEY, NOW);
    let error = decode_from(&wire).err().expect("非法命令字节必须被拒");
    assert!(
        matches!(error, HeaderDecodeError::InvalidAddress),
        "非法命令字节应报 InvalidAddress，实际 {error:?}"
    );
}

#[test]
fn fnv_mismatch_and_truncation_are_rejected() {
    let mut payload = plan_payload(SecurityOption::Aes128Gcm, Some(&sample_target()), &[]);
    let n = payload.len();
    payload[n - 1] ^= 0x01; // 破坏校验和末字节
    let wire = seal_for(&payload, &CMD_KEY, NOW);
    assert!(matches!(
        decode_from(&wire),
        Err(HeaderDecodeError::ChecksumMismatch)
    ));

    // 头明文截断：直接构造 20 字节明文。
    let wire = seal_for(&[0u8; 20], &CMD_KEY, NOW);
    assert!(matches!(
        decode_from(&wire),
        Err(HeaderDecodeError::Truncated { need: 38, got: 20 })
    ));
    // 线上字节截断（AuthID 之后不足 18+8）：读端断连按 Io 报。
    let full = seal_for(&payload, &CMD_KEY, NOW);
    let mut cut = full[..30].to_vec();
    cut.truncate(24);
    assert!(matches!(
        decode_from(&cut),
        Err(HeaderDecodeError::Io(_))
    ));
}

#[test]
fn replayed_session_is_rejected() {
    let payload = plan_payload(SecurityOption::Aes128Gcm, Some(&sample_target()), &[]);
    let wire = seal_for(&payload, &CMD_KEY, NOW);
    // 同一会话历史两次解码：第二次必须 Replay。
    let mut seen: Vec<[u8; 48]> = Vec::new();
    let mut take = |user: &[u8; 16], key: &[u8; 16], iv: &[u8; 16]| {
        let mut entry = [0u8; 48];
        entry[..16].copy_from_slice(user);
        entry[16..32].copy_from_slice(key);
        entry[32..].copy_from_slice(iv);
        if seen.contains(&entry) {
            false
        } else {
            seen.push(entry);
            true
        }
    };
    let first = decode_request_header(&[CMD_KEY], &mut Cursor::new(&wire), NOW, &mut take);
    assert!(first.is_ok());
    let second = decode_request_header(&[CMD_KEY], &mut Cursor::new(&wire), NOW, &mut take);
    assert!(matches!(second, Err(HeaderDecodeError::Replay)));
}

/// Rust↔Rust 全链路：客户端组头 + 体分帧 → 服务端解码 + 体解帧 → 服务端响应
/// 封装 → 客户端读响应头 + 体解帧。与 Xray 无关的纯内存一致性锁定。
#[tokio::test]
async fn rust_to_rust_full_chain() {
    let target = sample_target();
    let keys = keys();

    // ---- 客户端：请求头 + 体分帧（option=0，AES-128-GCM，无掩码）。----
    let payload = plan_payload(SecurityOption::Aes128Gcm, Some(&target), &[]);
    // 必须用时间戳可控的封装（`seal_header_with` + `create_auth_id_with(NOW)`）：
    // `seal_vmess_aead_header` 取系统当前时间，而本测试的服务端按固定 `NOW`
    // 校验时间窗（±120s），两者相差 2023 年 → 会成为 InvalidUser。
    let wire = seal_for(&payload, &CMD_KEY, NOW);
    let body_plain: Vec<u8> = (0u32..4096u32).map(|i| (i % 251) as u8).collect();
    let mut client_cipher = DataCipher::new(SECURITY_AES_128_GCM, &keys.body_key, &keys.body_iv);
    let mut body_wire = Vec::new();
    for piece in body_plain.chunks(1024) {
        seal_data_chunk(&mut client_cipher, None, &mut body_wire, piece).expect("可封");
    }
    seal_data_chunk(&mut client_cipher, None, &mut body_wire, &[]).expect("EOF 帧可封");

    // ---- 服务端：解码头 + 解帧体。----
    let mut upstream = Vec::new();
    upstream.extend_from_slice(&wire);
    upstream.extend_from_slice(&body_wire);
    let decoded = decode_from(&upstream).expect("全链路服务端解头");
    assert_eq!(decoded.target.as_ref(), Some(&target));

    let mut server_cipher =
        DataCipher::new(SECURITY_AES_128_GCM, &decoded.request_body_key, &decoded.request_body_iv);
    let mut received = Vec::new();
    let mut offset = wire.len();
    loop {
        let declared = u16::from_be_bytes([upstream[offset], upstream[offset + 1]]);
        let frame_end = offset + 2 + declared as usize;
        let frame = &upstream[offset..frame_end];
        match open_data_chunk(&mut server_cipher, None, frame).expect("可解") {
            Some(plain) => received.extend_from_slice(&plain),
            None => break,
        }
        offset = frame_end;
    }
    assert_eq!(received, body_plain, "服务端解出的请求体必须与发送一致");

    // ---- 服务端：响应头 + 体分帧（响应体密钥 = SHA256 派生）。----
    let mut response_wire = Vec::new();
    encode_response_header(
        decoded.response_header,
        &decoded.request_body_key,
        &decoded.request_body_iv,
        &ResponseHeader::new(),
        &mut response_wire,
    )
    .expect("响应头可封");
    let (resp_key, resp_iv) = lengsuo_vmess::server::response_key_iv(
        &decoded.request_body_key,
        &decoded.request_body_iv,
    );
    let mut resp_cipher = DataCipher::new(SECURITY_AES_128_GCM, &resp_key, &resp_iv);
    for piece in received.chunks(1024) {
        seal_data_chunk(&mut resp_cipher, None, &mut response_wire, piece).expect("可封");
    }
    seal_data_chunk(&mut resp_cipher, None, &mut response_wire, &[]).expect("EOF 帧可封");

    // ---- 客户端：读响应头 + 体解帧。----
    let parsed = read_response_header(
        &mut &response_wire[..],
        &keys.body_key,
        &keys.body_iv,
        keys.response_header,
    )
    .await
    .expect("客户端可读响应头");
    assert_eq!(parsed.option, 0, "响应头种子已在 read 内校验，option 应为 0");

    let mut client_resp = DataCipher::new(SECURITY_AES_128_GCM, &resp_key, &resp_iv);
    let mut echoed = Vec::new();
    let mut offset = 18 + 4 + 16; // 跳过响应头两段
    loop {
        let declared = u16::from_be_bytes([response_wire[offset], response_wire[offset + 1]]);
        let frame_end = offset + 2 + declared as usize;
        let frame = &response_wire[offset..frame_end];
        match open_data_chunk(&mut client_resp, None, frame).expect("可解") {
            Some(plain) => echoed.extend_from_slice(&plain),
            None => break,
        }
        offset = frame_end;
    }
    assert_eq!(echoed, body_plain, "客户端解出的响应体必须与服务端发送一致");
}
