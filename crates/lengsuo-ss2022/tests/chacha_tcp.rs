//! SS2022 ChaCha（`2022-blake3-chacha20-poly1305`）**TCP 侧**回归锁：salt→subkey 派生
//! 已知答案（线格式逐字节）、纯 Rust 完整会话 roundtrip、fail-closed 与 salt 等长约束。
//!
//! 已知答案向量由**参考原语独立生成**，不依赖本仓任何代码：
//! - subkey：BLAKE3 官方 python 绑定，`blake3(psk||salt,
//!   derive_key_context="shadowsocks 2022 session subkey").digest(32)`，语义锚点
//!   `sing-shadowsocks/shadowaead_2022/protocol.go:155-164`（`SessionKey`）；
//! - AEAD：OpenSSL ChaCha20-Poly1305（IETF 12B nonce），锚点 `protocol.go:110-112`
//!   （chacha TCP 构造器 = `chacha20poly1305.New`）；
//! - nonce 序列：`shadowaead/aead.go:459-466` 的 12 字节小端逐字节自增，从全 0 起，
//!   每完成一次 `Seal` 递增一次。
//!
//! 固定输入：PSK = 32×0x11，请求 salt = 32×0x22，响应 salt = 32×0x33，
//! timestamp = 1_700_000_000，目标 = 127.0.0.1:443。请求方向帧序列：
//! 固定头（11B 明文）→ 变长头（ATYP+addr+port + padding_len=0 + 首批载荷 `P`，10B）
//! → 载荷帧 `PING` → 终止 chunk；响应方向：固定头（type=1 + ts + 回指请求 salt，
//! 43B 明文，兼首个 length chunk）→ 首批载荷 `OK` → 载荷帧 `PONG` → 终止 chunk。
//!
//! 与固定版本 Xray 的真实互通（TCP 双方向 × 三载荷含 ChaCha）由
//! `tests/xray_tcp_matrix.rs`（`#[ignore]`）实跑覆盖；本文件全部用例纯 Rust、免参考
//! 二进制，进普通门禁。UDP 侧布局/向量/互通见 `udp_eih_extra*` 与 `xray_udp.rs`。

use lengsuo_ss2022::{
    crypto::{Key, Method},
    tcp::Association,
    tcp::{
        receive::clock_at, salt_len, Direction, Opening, Reader, SessionReplay, Writer,
        MAX_CHUNK_PAYLOAD,
    },
    Error,
};
use ss_core::target::TargetAddr;
use std::time::{Duration, Instant};

/// 请求方向线上字节已知答案：salt(32) + AEAD 固定头(27) + AEAD 变长头(26) +
/// AEAD 长度(18) + AEAD 载荷(20) + AEAD 终止(18) = 141 字节。
const REQUEST_WIRE_HEX: &str = "222222222222222222222222222222222222222222222222222222222222222205a74b9d6c097f7573f05a322bdf78ae187beccfd4c8a9268b7d13424d63cdc18a1ddf3fe3df9e0fba8ea2572bf2e29a43677952fcc460e885911494699edd9995b913df17ba1b420bcda48940e999ca6e2db11b95bdf4080db2d21b0968ddbcd4e494fd38303e8aff3f2c91df";

/// 响应方向线上字节已知答案：salt(32) + AEAD 固定头(59) + AEAD 首批载荷(18) +
/// AEAD 长度(18) + AEAD 载荷(20) + AEAD 终止(18) = 165 字节。
const RESPONSE_WIRE_HEX: &str = "33333333333333333333333333333333333333333333333333333333333333337e49d3c3fda3ec7d11995185774998c812fb677679d9313de41208433f36760561129fa68f3b8e14528d5b416e98cddf0f3c85c70892994407c6e225d4eb124b979b5f062f1c13a1f78c7583df94751f1ec5416e14e3df3195f59325d85bdd5afbc2cd6db836ff057e57c018d611efd26ad883b38e1fcb405847000aff45a3312ee983f6a6";

/// 生成向量时的固定时间戳。
const TS: u64 = 1_700_000_000;

/// 请求方向假 PSK 与两方向注入 salt（全部为测试专用假值）。
const PSK: [u8; 32] = [0x11; 32];
const REQUEST_SALT: [u8; 32] = [0x22; 32];
const RESPONSE_SALT: [u8; 32] = [0x33; 32];

fn chacha_key() -> Key {
    Key::new(Method::ChaCha20, &PSK).expect("32 字节假 PSK 合法")
}

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("合法十六进制"))
        .collect()
}

fn injected(salt: &[u8; 32]) -> Opening {
    Opening::injected(salt)
}

/// 请求方向 KAT：Writer 产出的线上字节必须与参考原语独立算出的向量逐字节一致。
/// subkey 派生（BLAKE3 derive-key）、IETF ChaCha20-Poly1305 选型、u96le nonce 计数、
/// salt/固定头/变长头/载荷帧布局全部被这一个向量钉死。
#[tokio::test]
async fn chacha_tcp_request_wire_matches_reference_known_answer() {
    let key = chacha_key();
    let mut writer = Writer::new(&key, Direction::Request, injected(&REQUEST_SALT))
        .expect("32 字节 salt 应与套件密钥等长");
    let mut wire = Vec::new();
    writer
        .write_request_header(&mut wire, &TargetAddr::V4([127, 0, 0, 1], 443), b"P", TS, 0)
        .await
        .expect("请求开场应可写出");
    writer
        .write_payload(&mut wire, b"PING")
        .await
        .expect("载荷帧应可写出");
    writer
        .write_finish(&mut wire)
        .await
        .expect("EOF 帧应可写出");
    assert_eq!(wire.len(), 141, "ChaCha 请求线长偏离布局常量");
    assert_eq!(&wire[..32], &REQUEST_SALT, "包首必须是请求 salt 原文");
    assert_eq!(
        wire,
        unhex(REQUEST_WIRE_HEX),
        "请求线格式偏离参考原语独立生成的已知答案"
    );
}

/// 响应方向 KAT：固定头原样回指请求 salt、本身充当首个 length chunk 的布局被钉死。
#[tokio::test]
async fn chacha_tcp_response_wire_matches_reference_known_answer() {
    let key = chacha_key();
    let mut writer = Writer::new(&key, Direction::Response, injected(&RESPONSE_SALT))
        .expect("32 字节 salt 应与套件密钥等长");
    let mut wire = Vec::new();
    writer
        .write_response_header(&mut wire, &REQUEST_SALT, b"OK", TS)
        .await
        .expect("响应开场应可写出");
    writer
        .write_payload(&mut wire, b"PONG")
        .await
        .expect("载荷帧应可写出");
    writer
        .write_finish(&mut wire)
        .await
        .expect("EOF 帧应可写出");
    assert_eq!(wire.len(), 165, "ChaCha 响应线长偏离布局常量");
    assert_eq!(&wire[..32], &RESPONSE_SALT, "包首必须是响应自身 salt 原文");
    assert_eq!(
        wire,
        unhex(RESPONSE_WIRE_HEX),
        "响应线格式偏离参考原语独立生成的已知答案"
    );
}

/// 纯 Rust 完整会话：客户端 Writer → 服务端 Reader、服务端 Writer → 客户端 Reader，
/// 载荷含恰好 65535 字节（单块上限）的帧，双向逐字节还原，EOF 帧正常收尾。
#[tokio::test]
async fn chacha_tcp_full_session_roundtrips_both_directions() {
    let key = chacha_key();
    let body: Vec<u8> = (0..70_000u32).map(|index| (index % 251) as u8).collect();
    let target = TargetAddr::V4([127, 0, 0, 1], 443);

    // 请求方向：首批载荷 1000B + 上限帧 65535B + 余量 3454B。
    let mut client =
        Writer::new(&key, Direction::Request, injected(&REQUEST_SALT)).expect("注入 salt 应合法");
    let mut request_wire = Vec::new();
    client
        .write_request_header(&mut request_wire, &target, &body[..1000], TS, 0)
        .await
        .expect("请求开场应可写出");
    client
        .write_payload(&mut request_wire, &body[1000..66_535])
        .await
        .expect("上限长度载荷帧应可写出");
    client
        .write_payload(&mut request_wire, &body[66_535..])
        .await
        .expect("余量载荷帧应可写出");
    client
        .write_finish(&mut request_wire)
        .await
        .expect("EOF 帧应可写出");

    let mut cursor: &[u8] = &request_wire;
    let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
    let mut server =
        Reader::new(key.clone(), Direction::Request, Duration::from_secs(5)).expect("可构造读端");
    let opened = server
        .open(&mut cursor, &mut replay, clock_at(TS, Instant::now()), None)
        .await
        .expect("请求开场应通过全部校验");
    assert_eq!(opened.timestamp, TS);
    assert_eq!(
        opened.association,
        Association::Request(target),
        "变长头应解出原目标地址"
    );
    assert_eq!(opened.request_salt, REQUEST_SALT);
    let mut got = opened.payload;
    for _ in 0..8 {
        match server.read_payload(&mut cursor).await.expect("载荷可读") {
            Some(chunk) => got.extend_from_slice(&chunk),
            None => break,
        }
    }
    assert_eq!(got, body, "请求方向载荷应逐字节还原");

    // 响应方向：服务端写 → 客户端按请求 salt 归属。
    let mut responder =
        Writer::new(&key, Direction::Response, injected(&RESPONSE_SALT)).expect("注入 salt 应合法");
    let mut reply_wire = Vec::new();
    responder
        .write_response_header(&mut reply_wire, &REQUEST_SALT, &body[..500], TS)
        .await
        .expect("响应开场应可写出");
    for piece in body[500..].chunks(MAX_CHUNK_PAYLOAD) {
        responder
            .write_payload(&mut reply_wire, piece)
            .await
            .expect("载荷帧应可写出");
    }
    responder
        .write_finish(&mut reply_wire)
        .await
        .expect("EOF 帧应可写出");

    let mut reply_cursor: &[u8] = &reply_wire;
    let mut client_replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
    let mut client_reader =
        Reader::new(key, Direction::Response, Duration::from_secs(5)).expect("可构造读端");
    let back = client_reader
        .open(
            &mut reply_cursor,
            &mut client_replay,
            clock_at(TS, Instant::now()),
            Some(&REQUEST_SALT),
        )
        .await
        .expect("响应开场应通过归属校验");
    assert_eq!(
        back.association,
        Association::Response(REQUEST_SALT.to_vec()),
        "响应关联块必须原样回指请求 salt"
    );
    assert_eq!(
        back.request_salt, RESPONSE_SALT,
        "开场应交出响应流自身 salt"
    );
    let mut echoed = back.payload;
    for _ in 0..8 {
        match client_reader
            .read_payload(&mut reply_cursor)
            .await
            .expect("载荷可读")
        {
            Some(chunk) => echoed.extend_from_slice(&chunk),
            None => break,
        }
    }
    assert_eq!(echoed, body, "响应方向载荷应逐字节还原");
}

/// fail-closed：错误 PSK 与篡改 AEAD 字节必须报 `Authentication` 并 poison 读端；
/// 截断（含空流）必须报 `Length`，绝不降级明文或悬挂。
#[tokio::test]
async fn chacha_tcp_fail_closed_on_wrong_key_tamper_and_truncation() {
    let key = chacha_key();
    let mut writer =
        Writer::new(&key, Direction::Request, injected(&REQUEST_SALT)).expect("注入 salt 应合法");
    let mut wire = Vec::new();
    writer
        .write_request_header(&mut wire, &TargetAddr::V4([127, 0, 0, 1], 443), b"P", TS, 0)
        .await
        .expect("请求开场应可写出");

    // 1) 错误 PSK：同 salt 同密文，另一把密钥的读端必须认证失败。
    {
        let wrong_key = Key::new(Method::ChaCha20, &[0x99; 32]).expect("假 PSK 合法");
        let mut cursor: &[u8] = &wire;
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let mut reader =
            Reader::new(wrong_key, Direction::Request, Duration::from_secs(5)).expect("可构造读端");
        let outcome = reader
            .open(&mut cursor, &mut replay, clock_at(TS, Instant::now()), None)
            .await;
        assert!(
            matches!(outcome, Err(Error::Authentication)),
            "错误 PSK 必须报 Authentication"
        );
        assert!(reader.is_poisoned(), "认证失败后读端必须 poison");
    }

    // 2) 篡改固定头 AEAD 密文首字节：认证失败并 poison。
    {
        let mut bad = wire.clone();
        bad[32] ^= 0x01;
        let mut cursor: &[u8] = &bad;
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let mut reader = Reader::new(key.clone(), Direction::Request, Duration::from_secs(5))
            .expect("可构造读端");
        let outcome = reader
            .open(&mut cursor, &mut replay, clock_at(TS, Instant::now()), None)
            .await;
        assert!(
            matches!(outcome, Err(Error::Authentication)),
            "篡改密文必须报 Authentication"
        );
        assert!(reader.is_poisoned(), "认证失败后读端必须 poison");
    }

    // 3) 截断：只给 salt + 半个固定头密文，读端必须报 Length 而非悬挂。
    {
        let mut cursor: &[u8] = &wire[..32 + 10];
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let mut reader = Reader::new(key.clone(), Direction::Request, Duration::from_secs(5))
            .expect("可构造读端");
        let outcome = reader
            .open(&mut cursor, &mut replay, clock_at(TS, Instant::now()), None)
            .await;
        assert!(
            matches!(outcome, Err(Error::Length)),
            "截断固定头必须报 Length"
        );
        assert!(reader.is_poisoned(), "截断后读端必须 poison");
    }

    // 4) 空流：salt 都读不满，同样 fail-closed。
    {
        let mut cursor: &[u8] = &[];
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let mut reader =
            Reader::new(key, Direction::Request, Duration::from_secs(5)).expect("可构造读端");
        let outcome = reader
            .open(&mut cursor, &mut replay, clock_at(TS, Instant::now()), None)
            .await;
        assert!(matches!(outcome, Err(Error::Length)), "空流必须报 Length");
        assert!(reader.is_poisoned(), "空流失败后读端必须 poison");
    }
}

/// salt 长度约束：ChaCha 的 salt 必须与套件密钥等长（32 字节），两方向同样受检。
#[test]
fn chacha_tcp_salt_must_equal_key_length() {
    let key = chacha_key();
    assert_eq!(salt_len(&key), 32, "ChaCha salt 应与 32 字节 PSK 等长");
    assert!(matches!(
        Writer::new(&key, Direction::Request, Opening::injected(&[0x44; 16])),
        Err(Error::KeyLength)
    ));
    assert!(matches!(
        Writer::new(&key, Direction::Response, Opening::injected(&[0x44; 16])),
        Err(Error::KeyLength)
    ));
    assert!(
        Writer::new(&key, Direction::Request, Opening::injected(&[0x44; 32])).is_ok(),
        "32 字节 salt 应可注入"
    );
}
