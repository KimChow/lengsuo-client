//! 请求头解码（对齐 `proxy/vmess/encoding/server.go` `DecodeRequestHeader`）。
//!
//! 消费顺序与错误口径逐条对齐参考：
//! 1. 读 16B AuthID（失败 = 读头失败，无 drain）；
//! 2. 逐用户（cmdKey）解密校验 AuthID（CRC32 + 时间窗）——全部失败即
//!    「invalid user」；时间窗过期同样表现为 invalid user（参考 validator 语义）；
//! 3. `OpenVMessAEADHeader` 流式解头部：长度段 tag 错与载荷段 tag 错分别成
//!    独立错误变体（参考里两者 shouldDrain=true，读截断 shouldDrain=false）；
//! 4. 明文 < 38B = 截断；
//! 5. **会话重放检查在地址解析之前**（参考 `sessionHistory.addIfNotExits`）；
//! 6. Mux（命令 3）地址固定 `v1.mux.cool:0`；TCP/UDP 解析 PortThenAddress；
//!    非法命令字节不解地址（对齐参考 switch 落空 → Address 为 nil）；
//! 7. padding 与 4B FNV 校验随后；校验失败 = 「invalid auth」；
//! 8. 地址缺失/解析失败 = 「invalid remote address」；
//! 9. security 低 4 位：0（向后兼容映射 AUTO）与 2（AUTO）均拒（unknown
//!    security type）；1 与 7..15 不在 SecurityType_name 里 → UNKNOWN → 拒；
//!    6（ZERO）头阶段放行（对齐参考），体阶段由上层拒。
//!
//! drain 行为本身（`BehaviorSeedLimitedDrainer` 的 16+38/3266/64 参数）是
//! 连接层策略，不在本原语层实现；调用方拿错误变体自行决定（见
//! `docs/vmess-status.md` 断言口径）。

use std::io::Read;

use ss_core::target::TargetAddr;

use crate::aead::{open_vmess_aead_header_stream, OpenHeaderError};
use crate::authid::decode_auth_id;
use crate::consts::{
    CMD_NONE_TCP, CMD_UDP, SECURITY_AES_128_GCM, SECURITY_CHACHA20_POLY1305, SECURITY_NONE,
};
use crate::request::fnv1a32;

/// 命令字节：Mux（参考 `protocol.RequestCommand_Mux`）。
pub const CMD_MUX: u8 = 3;
/// 头部明文固定前缀长度（版本 1 + IV 16 + key 16 + 响应种子 1 + option 1 +
/// security 1 + 保留 1 + 命令 1）。
pub const HEADER_FIXED_LEN: usize = 38;
/// Mux 请求的固定目标（参考 `net.DomainAddress("v1.mux.cool")`，端口 0）。
pub const MUX_DESTINATION: &str = "v1.mux.cool";

/// 入站命令（比客户端枚举多 Mux：头阶段按参考放行，数据面由上层处理）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundCommand {
    Tcp,
    Udp,
    Mux,
}

impl InboundCommand {
    /// 命令字节解析；1/2/3 以外返回 `None`（对齐参考：不解地址、最终报
    /// invalid remote address）。
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            CMD_NONE_TCP => Some(Self::Tcp),
            CMD_UDP => Some(Self::Udp),
            CMD_MUX => Some(Self::Mux),
            _ => None,
        }
    }
}

/// 头阶段认得的 security 低 4 位值（`parseSecurityType` 的映射结果）。
/// `Zero`（6）对齐参考：头阶段放行，体阶段拒绝。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderSecurity {
    Aes128Gcm,
    ChaCha20Poly1305,
    None,
    Zero,
}

impl HeaderSecurity {
    /// 低 4 位解析；0/2（→AUTO）与 1/7..15（不在枚举表）返回 `None`。
    /// AUTO/UNKNOWN 在头阶段就必须拒绝，因此不进入本枚举。
    #[must_use]
    pub const fn from_nibble(nibble: u8) -> Option<Self> {
        match nibble {
            SECURITY_AES_128_GCM => Some(Self::Aes128Gcm),
            SECURITY_CHACHA20_POLY1305 => Some(Self::ChaCha20Poly1305),
            SECURITY_NONE => Some(Self::None),
            6 => Some(Self::Zero),
            _ => None,
        }
    }

    /// 对应 [`crate::consts`] 的线字节值。
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Aes128Gcm => SECURITY_AES_128_GCM,
            Self::ChaCha20Poly1305 => SECURITY_CHACHA20_POLY1305,
            Self::None => SECURITY_NONE,
            Self::Zero => 6,
        }
    }
}

/// 解码成功的请求头（含会话密钥；不实现 Debug，避免密钥泄漏）。
pub struct DecodedRequest {
    /// 命中用户的下标（`cmd_keys` 中的位置；调用方据此取 UUID/账号信息）。
    pub user_index: usize,
    pub command: InboundCommand,
    /// Mux 时为 `Domain("v1.mux.cool", 0)`；解析失败时 `None`（不该出现——
    /// 失败即整条请求被拒）。
    pub target: Option<TargetAddr>,
    pub security: HeaderSecurity,
    /// 请求 option 字节（决定体分帧方式：掩码/padding/authenticated length）。
    pub option: u8,
    /// 请求体对称密钥（数据段 AEAD key）。
    pub request_body_key: [u8; 16],
    /// 请求体 IV（数据段 nonce 基值 + 掩码种子）。
    pub request_body_iv: [u8; 16],
    /// 客户端在请求头里声明的响应头首字节（响应必须原样回带）。
    pub response_header: u8,
}

/// 每种失败一个变体（对齐参考错误消息；不携带密钥/明文字节）。
#[derive(Debug, thiserror::Error)]
pub enum HeaderDecodeError {
    /// 读 AuthID / AEAD 段时连接断（参考「failed to read request header」）。
    #[error("failed to read request header")]
    Io(String),

    /// AuthID 不匹配任何用户（含 CRC 失败与时间窗过期）。
    #[error("invalid user")]
    InvalidUser,

    /// AEAD 长度段认证失败（参考 shouldDrain=true 路径）。
    #[error("AEAD length open failed")]
    AeadLengthTag,

    /// AEAD 载荷段认证失败（参考 shouldDrain=true 路径）。
    #[error("AEAD payload open failed")]
    AeadPayloadTag,

    /// 头明文不足以容纳固定前缀/padding/校验和。
    #[error("request header truncated: need {need} bytes, got {got}")]
    Truncated { need: usize, got: usize },

    /// 会话重放（`duplicated session id, possibly under replay attack`）。
    #[error("duplicated session id")]
    Replay,

    /// FNV1a 校验失败（参考「invalid auth, but this is a AEAD request」）。
    #[error("invalid auth")]
    ChecksumMismatch,

    /// 地址缺失或非法（参考「invalid remote address」）。
    #[error("invalid remote address")]
    InvalidAddress,

    /// security 低 4 位非法或 0/2（参考「unknown security type」）。
    #[error("unknown security type")]
    UnknownSecurity,
}

/// 会话重放过滤器回调：`(userId, bodyKey, bodyIV)` 首次出现返回 `true`，
/// 重复出现返回 `false`。语义对齐 `SessionHistory.addIfNotExits`（3 分钟过期
/// 由调用方实现）。
pub type SessionFilter<'a> = dyn FnMut(&[u8; 16], &[u8; 16], &[u8; 16]) -> bool + 'a;

/// `DecodeRequestHeader`：从 `reader` 读一条完整请求头并解码。
///
/// `cmd_keys` 是本入站全部用户的 cmdKey；`now_unix` 注入当前时间（时间窗
/// 判据 `|ts - now| <= 120` 秒）。重放过滤以回调注入。
pub fn decode_request_header<R: Read>(
    cmd_keys: &[[u8; 16]],
    reader: &mut R,
    now_unix: i64,
    take_session: &mut SessionFilter<'_>,
) -> Result<DecodedRequest, HeaderDecodeError> {
    // 1) AuthID（读失败即断连，无 drain）。
    let mut auth_id = [0u8; 16];
    read_exact(reader, &mut auth_id)?;

    // 2) 逐用户校验（对齐 validator：CRC + 时间窗，全败即 invalid user）。
    let mut user_index = usize::MAX;
    for (index, cmd_key) in cmd_keys.iter().enumerate() {
        if decode_auth_id(cmd_key, &auth_id, now_unix).is_ok() {
            user_index = index;
            break;
        }
    }
    if user_index == usize::MAX {
        return Err(HeaderDecodeError::InvalidUser);
    }

    // 3) AEAD 头部流式解密。
    let (payload, _bytes_read) =
        open_vmess_aead_header_stream(&cmd_keys[user_index], &auth_id, reader)
            .map_err(map_open_error)?;

    parse_request_payload(cmd_keys, user_index, &payload, take_session)
}

/// 纯解析段（解密后的头明文 → 字段）。独立出来便于固定向量直测。
pub fn parse_request_payload(
    cmd_keys: &[[u8; 16]],
    user_index: usize,
    payload: &[u8],
    take_session: &mut SessionFilter<'_>,
) -> Result<DecodedRequest, HeaderDecodeError> {
    // 4) 固定前缀。
    if payload.len() < HEADER_FIXED_LEN {
        return Err(HeaderDecodeError::Truncated {
            need: HEADER_FIXED_LEN,
            got: payload.len(),
        });
    }
    let request_body_iv: [u8; 16] = payload[1..17].try_into().expect("16 字节");
    let request_body_key: [u8; 16] = payload[17..33].try_into().expect("16 字节");
    let response_header = payload[33];
    let option = payload[34];
    let padding_len = (payload[35] >> 4) as usize;
    let security_nibble = payload[35] & 0x0F;
    let command = InboundCommand::from_byte(payload[37]);

    // 5) 重放检查在地址解析之前（对齐参考顺序）。
    let user_id: [u8; 16] = cmd_keys
        .get(user_index)
        .copied()
        .ok_or(HeaderDecodeError::InvalidUser)?;
    if !take_session(&user_id, &request_body_key, &request_body_iv) {
        return Err(HeaderDecodeError::Replay);
    }

    // 6) 地址段（PortThenAddress）。
    let mut address_failed = false;
    let (target, offset) = match command {
        Some(InboundCommand::Mux) => (
            Some(TargetAddr::Domain(MUX_DESTINATION.to_string(), 0)),
            HEADER_FIXED_LEN,
        ),
        Some(InboundCommand::Tcp | InboundCommand::Udp) => {
            match parse_port_then_address(&payload[HEADER_FIXED_LEN..]) {
                Ok((addr, len)) => (Some(addr), HEADER_FIXED_LEN + len),
                // 解析失败：port 与 type 字节已消费（对齐参考「port 入 buffer、
                // type 消费不入 buffer」的字节推进；此路径最终必拒，仅 FNV
                // 覆盖范围与其一致）。Mux 以外命令解析失败地址记 None。
                Err(_) => {
                    address_failed = true;
                    (None, HEADER_FIXED_LEN + 3)
                }
            }
        }
        None => (None, HEADER_FIXED_LEN),
    };

    // 7) padding + 4B 校验和。
    let padded_end = offset + padding_len;
    if payload.len() < padded_end + 4 {
        return Err(HeaderDecodeError::Truncated {
            need: padded_end + 4,
            got: payload.len(),
        });
    }
    let expected = u32::from_be_bytes(
        payload[padded_end..padded_end + 4]
            .try_into()
            .expect("4 字节"),
    );
    if fnv1a32(&payload[..padded_end]) != expected {
        return Err(HeaderDecodeError::ChecksumMismatch);
    }
    // 校验和之后的残余明文：参考不再读取（decryptor 剩余即忽略），对齐忽略。

    // 8) 地址判定在 FNV 之后（对齐参考顺序）。
    if address_failed || target.is_none() {
        return Err(HeaderDecodeError::InvalidAddress);
    }

    // 9) security 判定最后（对齐参考顺序）。
    let security =
        HeaderSecurity::from_nibble(security_nibble).ok_or(HeaderDecodeError::UnknownSecurity)?;

    Ok(DecodedRequest {
        user_index,
        command: command.unwrap_or(InboundCommand::Tcp),
        target,
        security,
        option,
        request_body_key,
        request_body_iv,
        response_header,
    })
}

/// PortThenAddress 读端：`Port(BE16) | Type(1) | ADDR`，Type 1=IPv4/2=Domain/3=IPv6。
/// 返回地址与消耗的字节数；未知类型或长度越界即失败。
fn parse_port_then_address(bytes: &[u8]) -> Result<(TargetAddr, usize), ()> {
    if bytes.len() < 3 {
        return Err(());
    }
    let port = u16::from_be_bytes([bytes[0], bytes[1]]);
    match bytes[2] {
        1 => {
            if bytes.len() < 3 + 4 {
                return Err(());
            }
            let ip: [u8; 4] = bytes[3..7].try_into().expect("4 字节");
            Ok((TargetAddr::V4(ip, port), 7))
        }
        2 => {
            let domain_len = bytes[3] as usize;
            if bytes.len() < 4 + domain_len || domain_len == 0 {
                return Err(());
            }
            let host = std::str::from_utf8(&bytes[4..4 + domain_len]).map_err(|_| ())?;
            if host.contains('\0') {
                return Err(());
            }
            Ok((TargetAddr::Domain(host.to_string(), port), 4 + domain_len))
        }
        3 => {
            if bytes.len() < 3 + 16 {
                return Err(());
            }
            let ip: [u8; 16] = bytes[3..19].try_into().expect("16 字节");
            Ok((TargetAddr::V6(ip, port), 19))
        }
        _ => Err(()),
    }
}

fn read_exact<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), HeaderDecodeError> {
    reader
        .read_exact(buf)
        .map_err(|e| HeaderDecodeError::Io(format!("{:?}", e.kind())))
}

fn map_open_error(error: OpenHeaderError) -> HeaderDecodeError {
    match error {
        OpenHeaderError::LengthTag => HeaderDecodeError::AeadLengthTag,
        OpenHeaderError::PayloadTag => HeaderDecodeError::AeadPayloadTag,
        OpenHeaderError::Truncated { need, got } => HeaderDecodeError::Truncated { need, got },
        OpenHeaderError::Io(kind) => HeaderDecodeError::Io(kind),
    }
}
