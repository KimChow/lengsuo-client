//! 共享夹具：安全档表、请求头构造、数据段构造。
//!
//! 语义基线：Xray commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。

use std::time::Duration;

use lengsuo_vmess::aead;
use lengsuo_vmess::bodyframe::{BodyFrame, BodySuite};
use lengsuo_vmess::request::{Command, HeaderPlanner, KeySource, RequestHeader, SecurityOption};
use ss_core::target::TargetAddr;

/// 每个用例的总超时上限（避免 CI 挂死）。
pub const CASE_TIMEOUT: Duration = Duration::from_secs(10);

/// 假 cmd key（测试假凭据，非真实账号）。
pub const CMD_KEY: [u8; 16] = *b"b831381d-6324-4d";
/// 假会话 body key。
pub const BODY_KEY: [u8; 16] = *b"request-body-key";
/// 假会话 body iv。
pub const BODY_IV: [u8; 16] = *b"request-body-iv!";
/// 固定 unix 秒（AuthID 时间窗可控）。
pub const NOW: i64 = 1_700_000_000;
/// 数据段 option：只开 chunk masking。
///
/// 对齐参考出口 `proxy/vmess/outbound/outbound.go:108-110`：AES / NONE /
/// CHACHA 三档都置 `RequestOptionChunkMasking`（本仓 option 字节 0x04）。
pub const OPTION: u8 = 0x04;

/// 本仓**受支持**的安全档（`SecurityOption` 的三个具体档，不含 AUTO 哨兵）。
///
/// 依据：
/// - `crates/lengsuo-vmess/src/request.rs:82-97`（`SecurityOption` 枚举）；
/// - `crates/lengsuo-vmess/src/bodyframe.rs:64-71`（`BodySuite` 枚举）；
/// - `crates/lengsuo-vmess/src/consts.rs:28,30,32`（线上字节 5 / 3 / 4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tier {
    /// 档位名（用例名与断言消息里用）。
    pub name: &'static str,
    /// 头里的安全档（`SecurityOption`）。
    pub option: SecurityOption,
    /// 数据段套件（`BodySuite`）。
    pub suite: BodySuite,
    /// 线上安全档字节（`security` 字段低 4 位）。
    pub wire: u8,
}

/// 三个受支持档位。
pub const TIERS: [Tier; 3] = [
    Tier {
        name: "none",
        option: SecurityOption::None,
        suite: BodySuite::None,
        wire: lengsuo_vmess::consts::SECURITY_NONE,
    },
    Tier {
        name: "aes128gcm",
        option: SecurityOption::Aes128Gcm,
        suite: BodySuite::Aes128Gcm,
        wire: lengsuo_vmess::consts::SECURITY_AES_128_GCM,
    },
    Tier {
        name: "chacha20poly1305",
        option: SecurityOption::ChaCha20Poly1305,
        suite: BodySuite::ChaCha20Poly1305,
        wire: lengsuo_vmess::consts::SECURITY_CHACHA20_POLY1305,
    },
];

impl Tier {
    /// 数据段上下文（请求方向）。
    pub fn body_frame(&self) -> BodyFrame {
        BodyFrame::for_request(self.suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, OPTION)
            .expect("档位上下文可建")
    }
}

/// 请求头明文（固定 padding 长度，消掉随机项）。
pub fn plan_header(security: SecurityOption) -> Vec<u8> {
    let planner = HeaderPlanner::new(KeySource {
        body_key: BODY_KEY,
        body_iv: BODY_IV,
        response_header: 0x33,
    });
    let header = RequestHeader {
        target: Some(TargetAddr::Domain("example.invalid".into(), 443)),
        command: Command::Tcp,
        security,
        option: OPTION,
        padding_len: 0,
    };
    planner.plan_with(&header, &[]).expect("请求头明文可编码")
}

/// 请求头明文，但**改写 security 低 4 位**并重算 FNV 尾部。
///
/// 用于构造「档位枚举越界」的合法封装请求：FNV 覆盖整个明文（含 security
/// 字节），所以改完必须重算尾部，否则服务端会先在校验和上拒绝，测不到
/// security 判定。
pub fn plan_header_with_security_nibble(security: SecurityOption, nibble: u8) -> Vec<u8> {
    let mut plain = plan_header(security);
    // 明文布局：第 35 字节 = padding<<4 | security（见 request.rs:236,253）。
    plain[35] = (plain[35] & 0xF0) | (nibble & 0x0F);
    let body_len = plain.len() - 4;
    let tail = lengsuo_vmess::request::fnv1a32(&plain[..body_len]).to_be_bytes();
    plain[body_len..].copy_from_slice(&tail);
    plain
}

/// 请求头明文里 security 字节的**偏移**。
///
/// 对齐参考 `proxy/vmess/encoding/server.go:203` 的 `buffer.Byte(35) & 0x0F`
/// （服务端解完头部 AEAD 后，在**明文**里读第 35 字节）。
/// 本仓同位置：`crates/lengsuo-vmess/src/request.rs:236,253` 构造
/// `paddingLen << 4 | Security`，落在明文第 35 字节；
/// `crates/lengsuo-vmess/src/server/decode.rs:217` 读 `payload[35] & 0x0F`。
pub const SECURITY_BYTE_OFFSET: usize = 35;

/// 从**实际序列化**的请求头明文里取 security 低 4 位。
///
/// ⛔ 这条存在的理由：只断言 `SecurityOption::to_byte()` 断言的是**枚举映射
/// 函数**，不是**发出去的那条线上的字节**——历史上出过「断言了某个字节但
/// 发出去的字节不是它」的坑。这里的取值直接来自
/// [`plan_header`] 的输出（即真正被 AEAD 封进请求头的明文）。
pub fn serialized_security_nibble(plain: &[u8]) -> u8 {
    assert!(
        plain.len() > SECURITY_BYTE_OFFSET,
        "请求头明文短于 security 字节位置"
    );
    plain[SECURITY_BYTE_OFFSET] & 0x0F
}

/// 封装一条完整请求头线上字节（AuthID 时间固定在窗口内）。
pub fn seal_request(security: SecurityOption) -> Vec<u8> {
    seal_plain_header(&plan_header(security))
}

/// 用给定明文封装请求头线上字节。
pub fn seal_plain_header(plain: &[u8]) -> Vec<u8> {
    let auth = lengsuo_vmess::create_auth_id_with(&CMD_KEY, NOW, &[0x01, 0x02, 0x03, 0x04]);
    aead::seal_header_with(&CMD_KEY, auth.as_bytes(), &[0x11; 8], plain)
}

/// 从**已封装的请求头线上字节**里把明文解回来，取出 security 低 4 位。
///
/// ⛔ 存在的理由（同 [`serialized_security_nibble`]）：断言必须落在
/// **真正发出去的那条线**上。请求头是 AEAD 封着的，security 字节在**明文**里
/// （偏移 35），线上字节是密文——所以这里先解开（用同一个 cmd key），
/// 再读明文第 35 字节，断言的是「这条线解出来之后声明的档位」。
///
/// 解不开（AEAD tag 失败）就 panic：能走到这里说明封/解是自洽的。
pub fn wire_security_nibble(wire: &[u8]) -> u8 {
    let auth_id = lengsuo_vmess::aead::parse_auth_id_from_header(wire).expect("线上有 AuthID");
    let plain = lengsuo_vmess::aead::open_vmess_aead_header(&CMD_KEY, &auth_id, &wire[16..])
        .expect("本仓自己封的头必须能解开");
    serialized_security_nibble(&plain)
}

/// 一次性会话过滤器（总是接受）。
pub fn accept_session() -> impl FnMut(&[u8; 16], &[u8; 16], &[u8; 16]) -> bool {
    |_, _, _| true
}

/// 封一帧数据段（长度段 + 载荷密文）。
pub fn seal_body(suite: BodySuite, payload: &[u8]) -> Vec<u8> {
    let mut frame = BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, OPTION)
        .expect("档位上下文可建");
    let mut wire = Vec::new();
    frame.seal(&mut wire, payload).expect("可写");
    wire
}
