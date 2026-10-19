//! 响应方 msg2 独立向量测试。
//!
//! 向量由仓外 Go 程序（`golang.org/x/crypto` 的 blake2s/chacha20poly1305/
//! curve25519，镜像 wireguard-go `noise-helpers.go` + `noise-protocol.go`，程序见
//! `/tmp/wgvec/main.go`）独立生成，**非本 crate 函数互证**。覆盖：无 PSK、显式
//! PSK、错误 MAC1、错误 MAC2、TAI64N 时间戳漂移/重放、未知 sender index。
//!
//! 所有私钥/PSK/临时种子都是固定假值，仅测试用，不代表任何真实凭据。

use lengsuo_wireguard::handshake::{Responder, ResponderError};

// 仅测试：固定假私钥/临时种子。客户端静态 0x11、服务端静态 0x22、服务端临时 0x77。
const SERVER_STATIC: [u8; 32] = [0x22; 32];
const SERVER_EPH: [u8; 32] = [0x77; 32];
// 仅测试：固定假 PSK。
const PSK: [u8; 32] = [0x33; 32];

// 独立 Go 向量（0x11 客户端静态私钥生成的公钥；hex 小写）。
const CLIENT_PUB: &str = "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13";
// initiation：sender=0x12345678，TAI64N 时间戳 0x400000000000000a+0x12345678 / 0x0F000000。
const INIT: &str = "010000007856341214ca9e4d387bccf35746e0407daaacc6b28a4f8445ef5a5158894db983e240700613673afa4b88e5e0aa508e64c90efb71d60e443d76b6699f992392d2d5d5eae7523b008b4f60584f3addbdffd0c61498d395d700e3e50bf0074e579828687126de9c88f85b6113fa3edd2614e82fe158a99202f1897e3baaee053000000000000000000000000000000000";
const MSG2_NOPSK: &str = "0200000034122620785634121cf579aba45a10ba1d1ef06d91fca2aa9ed0a1150515653155405d0b18cb9a67b900becbc70fc340de33442faa83bf9e79dc922994ebc097d4342b0c72bbc1e100000000000000000000000000000000";
const MSG2_PSK: &str = "0200000034122620785634121cf579aba45a10ba1d1ef06d91fca2aa9ed0a1150515653155405d0b18cb9a67a12f06c03e6cdb11089b4014512d273ebf4866137998d37bb91e4316ee21fb4800000000000000000000000000000000";
// 同密钥/同时戳，仅 sender index 换成 0xdeadbeef（“未知 sender index”）。
const INIT_ALT_SENDER: &str = "01000000efbeadde14ca9e4d387bccf35746e0407daaacc6b28a4f8445ef5a5158894db983e240700613673afa4b88e5e0aa508e64c90efb71d60e443d76b6699f992392d2d5d5eae7523b008b4f60584f3addbdffd0c61498d395d700e3e50bf0074e579828687126de9c88f85b6113fa3edd262d26f46e8eaa70ce3e94413d81d3218100000000000000000000000000000000";
const MSG2_ALT_SENDER: &str = "0200000034122620efbeadde1cf579aba45a10ba1d1ef06d91fca2aa9ed0a1150515653155405d0b18cb9a67b900becbc70fc340de33442faa83bf9e655dd894c92b75cc17a151f857db220600000000000000000000000000000000";
// 时间戳早 1 秒（0x12345677），用于 TAI64N 漂移/重放拒绝。
const INIT_OLD_TS: &str = "010000007856341214ca9e4d387bccf35746e0407daaacc6b28a4f8445ef5a5158894db983e240700613673afa4b88e5e0aa508e64c90efb71d60e443d76b6699f992392d2d5d5eae7523b008b4f60584f3addbdffd0c61498d395d700e3e508f0074e57af07df5451bc8c235e6f9c19d0ca90c84f5a0f3609f40552e58d7229c184675600000000000000000000000000000000";

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "hex 必须是偶数长度");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("合法 hex"))
        .collect()
}

fn hex32(s: &str) -> [u8; 32] {
    hex(s).try_into().expect("32B hex")
}

fn to_hex(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() * 2);
    for x in b {
        out.push_str(&format!("{x:02x}"));
    }
    out
}

/// 用服务端假私钥 + 客户端公钥构造响应方；local_index 由 `create_response` 再定。
fn responder(psk: Option<[u8; 32]>) -> Responder {
    Responder::new(&SERVER_STATIC, &hex32(CLIENT_PUB), psk, 0).expect("响应方可构造")
}

/// msg2 逐字节比对（无 PSK）。
#[test]
fn msg2_no_psk_matches_independent_go_vector() {
    let mut r = responder(None);
    r.consume_initiation(&hex(INIT))
        .expect("initiation 剥壳成功");
    let mut msg = r
        .create_response(SERVER_EPH, 0x20261234)
        .expect("response 可生成");
    r.add_macs(&mut msg);
    assert_eq!(
        to_hex(&msg),
        MSG2_NOPSK,
        "msg2（无 PSK）必须与 Go 向量逐字节一致"
    );
    // 方向性字段 sanity：type2 + local sender + 回显的 remote receiver。
    assert_eq!(&msg[..4], &2u32.to_le_bytes());
    assert_eq!(&msg[4..8], &0x20261234u32.to_le_bytes());
    assert_eq!(&msg[8..12], &0x12345678u32.to_le_bytes());
}

/// msg2 逐字节比对（显式 PSK=0x33）。
#[test]
fn msg2_explicit_psk_matches_independent_go_vector() {
    let mut r = responder(Some(PSK));
    r.consume_initiation(&hex(INIT))
        .expect("initiation 剥壳成功");
    let mut msg = r
        .create_response(SERVER_EPH, 0x20261234)
        .expect("response 可生成");
    r.add_macs(&mut msg);
    assert_eq!(
        to_hex(&msg),
        MSG2_PSK,
        "msg2（显式 PSK）必须与 Go 向量逐字节一致"
    );
}

/// 错误 MAC1：篡改 MAC1 任一字节都应被 `check_mac1` 拒绝。
#[test]
fn wrong_mac1_rejected() {
    let r = responder(None);
    let good = hex(INIT);
    assert!(r.check_mac1(&good), "原始 initiation 的 MAC1 应校验通过");
    let mut bad = good.clone();
    bad[117] ^= 0xff; // MAC1 位于 [116..132)，翻转首字节
    assert!(!r.check_mac1(&bad), "篡改 MAC1 必须被拒绝");
}

/// 错误 MAC2：建立 cookie secret 后，MAC2 全零的 initiation 仍必须被拒。
#[test]
fn wrong_mac2_rejected() {
    let mut r = responder(None);
    let init = hex(INIT);
    // secret 尚未生成（cookie reply 未签发）时，MAC2 校验必然失败。
    assert!(!r.check_mac2(&init, b"192.0.2.1:51820"));
    // 签发一次 cookie reply 以落盘 secret（seed/nonce 仅测试假值）。
    let reply = r.create_cookie_reply(&init, b"192.0.2.1:51820", [0x44; 32], [0x55; 24]);
    assert_eq!(reply.len(), 64);
    assert_eq!(&reply[..4], &3u32.to_le_bytes(), "cookie reply 类型为 3");
    // 之后仍拿一条 MAC2 全零的 initiation 来校验：错误 MAC2 必须被拒。
    assert!(
        !r.check_mac2(&init, b"192.0.2.1:51820"),
        "错误 MAC2 必须被拒绝"
    );
}

/// TAI64N 重放：同一条 initiation（时间戳相等，`After` 为严格大于）必须被拒。
#[test]
fn replay_equal_timestamp_rejected() {
    let mut r = responder(None);
    r.consume_initiation(&hex(INIT)).expect("首次剥壳成功");
    assert_eq!(
        r.consume_initiation(&hex(INIT)),
        Err(ResponderError::Replay),
        "相同时间戳的 initiation 必须判为重放"
    );
}

/// TAI64N 漂移：先消费较新时间戳，再投递早 1 秒的 initiation 必须被拒。
#[test]
fn older_timestamp_drift_rejected() {
    let mut r = responder(None);
    r.consume_initiation(&hex(INIT))
        .expect("较新时间戳剥壳成功");
    assert_eq!(
        r.consume_initiation(&hex(INIT_OLD_TS)),
        Err(ResponderError::Replay),
        "更早时间戳（TAI64N 漂移）必须判为重放"
    );
}

/// 未知 sender index：响应方不按 sender index 查表，应接受并原样回显到 response
/// 的 receiver 字段，msg2 仍与独立 Go 向量逐字节一致。
#[test]
fn unknown_sender_index_accepted_and_echoed() {
    let mut r = responder(None);
    r.consume_initiation(&hex(INIT_ALT_SENDER))
        .expect("未知 sender index 的 initiation 也应被接受");
    let mut msg = r
        .create_response(SERVER_EPH, 0x20261234)
        .expect("response 可生成");
    r.add_macs(&mut msg);
    assert_eq!(
        to_hex(&msg),
        MSG2_ALT_SENDER,
        "未知 sender index 的 msg2 必须与 Go 向量逐字节一致"
    );
    assert_eq!(
        &msg[8..12],
        &0xdeadbeefu32.to_le_bytes(),
        "须原样回显 sender index"
    );
}

/// 未知对端静态公钥：initiation 解密出的对端非配置公钥 → `UnknownPeer`。
#[test]
fn unknown_peer_static_rejected() {
    // 用服务端静态私钥派生一个“别的”公钥会成对端；这里直接配一个错误公钥，
    // 让 initiation 解密出的 client_pub 与配置不符。
    let wrong_remote = [0xee; 32]; // 仅测试：错误对端公钥
    let mut r = Responder::new(&SERVER_STATIC, &wrong_remote, None, 0)
        .expect("响应方可构造（对端公钥仅占位，consume 时才校验）");
    assert_eq!(
        r.consume_initiation(&hex(INIT)),
        Err(ResponderError::UnknownPeer),
        "解密出的对端静态公钥与配置不符必须拒绝"
    );
}
