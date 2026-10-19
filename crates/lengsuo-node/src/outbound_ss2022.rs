//! SS2022（SIP022）出口：TCP → 请求流开场 → **响应流 salt 归属校验** 正向确认。
//!
//! 语义来源（只读参考，固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）：
//! SIP022 §3.1.2/§3.1.3——请求流 = `salt + 固定头(11B) chunk + 变长头 chunk`
//! （变长头 = 目标地址 + padding 声明 + padding + 首批载荷）；响应流 =
//! `salt + 固定头(27/43B) chunk`，其中固定头**原样回传请求 salt**，是客户端
//! 判定「这条流属于我的那次请求」的唯一依据。
//!
//! **认证完成的正向证据**：`Reader::open` 对响应方向要求
//! `expected_peer = Some(请求 salt)`，逐字节比对固定头里的 request salt；
//! 不一致即 `ClientSession` 错误。错误 PSK 下服务端解不出请求变长头，
//! 要么不发响应、要么发送的响应无法通过 AEAD 认证，两种情况都 fail-closed。
//!
//! 偏离：本卡用无 padding（`padding = 0`）+ 首批载荷非空的开场。SIP022 要求
//! 变长头「载荷与 padding 至少一个非零」，非零载荷即满足；padding 是抗指纹
//! 需求，dry-run 不引入随机 padding（不影响协议合法性）。

use std::time::{Duration, Instant};

use lengsuo_ss2022::crypto::{Key, Method};
use lengsuo_ss2022::tcp::receive::{clock_at, Association, Opened, Reader, SessionReplay};
use lengsuo_ss2022::tcp::{Direction, Opening, Writer};
use ss_core::target::TargetAddr;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::config::NodeConfig;
use crate::outbound::{connect_tcp, probe_target, DialError};

/// dry-run 首批载荷：让变长头非空壳（SIP022 要求载荷与 padding 至少一个非零）。
const DRY_RUN_PAYLOAD: &[u8] = b"lengsuo-node-dryrun";
/// 本端请求 salt 的记忆保留期（SIP022 §3.1.4 最短 60 秒）。
const REPLAY_RETENTION: Duration = Duration::from_secs(60);

/// ss2022 出站会话：请求流开场已写出，响应流开场已通过 salt 归属校验。
pub struct Ss2022Outbound {
    pub stream: TcpStream,
    /// 请求流 salt（响应归属依据，也是后续同流双向子密钥的种子）。
    pub request_salt: Vec<u8>,
    /// 已通过校验的响应开场（含服务端首批载荷）。
    pub opened: Opened,
    pub target: TargetAddr,
}

/// ss2022 出站：选方法 → 建 TCP → 写请求开场 → 读并校验响应开场。
pub async fn dial_ss2022(config: &NodeConfig, wait: Duration) -> Result<Ss2022Outbound, DialError> {
    let method = method_from_name(config.method.as_deref())?;
    let psk = psk_from_config(config, method)?;
    let key = Key::new(method, &psk)?;
    let mut stream = connect_tcp(config, wait).await?;
    let target = probe_target(config);

    // 请求流开场：salt 随机（Opening::random），时间戳取当前系统时间。
    let mut writer = Writer::random(&key, Direction::Request)?;
    writer
        .write_request_header(&mut stream, &target, DRY_RUN_PAYLOAD, now_secs(), 0)
        .await?;

    // 响应流开场：固定头必须回带本端请求 salt，否则不是这条流的响应。
    let request_salt = writer.salt().to_vec();
    let mut reader = Reader::new(key.clone(), Direction::Response, wait)?;
    let mut replay = SessionReplay::new(REPLAY_RETENTION)?;
    let opened = timeout(
        wait,
        reader.open(
            &mut stream,
            &mut replay,
            clock_at(now_secs(), Instant::now()),
            Some(&request_salt),
        ),
    )
    .await
    .map_err(|_| DialError::Timeout)??;

    // 归属断言（对齐参考：响应回指的 salt 必须逐字节等于请求 salt）。
    match &opened.association {
        Association::Response(salt) if salt == &request_salt => {}
        _ => {
            return Err(DialError::Rejected(
                "ss2022 响应未回指本端请求 salt".to_owned(),
            ))
        }
    }
    Ok(Ss2022Outbound {
        stream,
        request_salt,
        opened,
        target,
    })
}

/// SIP022 方法名 → 方法枚举（`2022-blake3-aes-128-gcm` 等）。
pub(crate) fn method_from_name(name: Option<&str>) -> Result<Method, DialError> {
    let Some(name) = name else {
        return Err(DialError::Rejected("ss2022 缺少 method".to_owned()));
    };
    match name {
        "2022-blake3-aes-128-gcm" => Ok(Method::Aes128),
        "2022-blake3-aes-256-gcm" => Ok(Method::Aes256),
        "2022-blake3-chacha20-poly1305" => Ok(Method::ChaCha20),
        other => Err(DialError::Rejected(format!(
            "不支持的 ss2022 方法：{other}"
        ))),
    }
}

/// PSK：SIP022 要求 base64，且解码后长度必须等于方法密钥长度。
/// 也接受与密钥长度相同的原始字节串（16 字节 AES-128 PSK 的十六进制写法）。
fn psk_from_config(config: &NodeConfig, method: Method) -> Result<Vec<u8>, DialError> {
    let raw = config
        .auth
        .secret_key
        .as_deref()
        .ok_or_else(|| DialError::Rejected("ss2022 缺少 auth.secret_key".to_owned()))?;
    let decoded = base64_decode(raw)
        .ok_or_else(|| DialError::Rejected("ss2022 PSK 不是合法 base64".to_owned()))?;
    if decoded.len() != method.key_len() {
        return Err(DialError::Rejected(format!(
            "ss2022 PSK 长度 {} 字节，方法要求 {} 字节",
            decoded.len(),
            method.key_len()
        )));
    }
    Ok(decoded)
}

/// 标准 base64（含 padding）解码的公开入口（WireGuard 静态密钥也用同一套）。
#[must_use]
pub fn base64_decode_public(text: &str) -> Option<Vec<u8>> {
    base64_decode(text)
}

/// 标准 base64（含 padding）解码；失败返回 `None`。
/// 只支持标准字母表，不做 URL-safe 变体（SIP022 用标准 base64）。
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    const INVALID: u8 = 0xFF;
    fn value(byte: u8) -> u8 {
        match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => INVALID,
        }
    }
    let bytes: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|b| **b == b'=').count();
        let mut acc = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            let value = if *byte == b'=' { 0 } else { value(*byte) };
            if value == INVALID {
                return None;
            }
            // 非末组的 '=' 非法。
            if *byte == b'=' && index < 2 {
                return None;
            }
            acc = (acc << 6) | u32::from(value);
        }
        out.push((acc >> 16) as u8);
        if pad < 2 {
            out.push((acc >> 8) as u8);
        }
        if pad < 1 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

/// 当前 Unix 秒（SIP022 固定头时间戳）。
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 由 `Opening` 显式构造请求写端（供测试固定 salt）。
pub fn writer_with_salt(key: &Key, salt: &[u8]) -> Result<Writer, DialError> {
    Ok(Writer::new(
        key,
        Direction::Request,
        Opening::injected(salt),
    )?)
}
