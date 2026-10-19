//! Mux 帧编解码（对照 Xray `common/mux/frame.go` 固定 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）。
//!
//! 帧布局（`frame.go` 头注释逐字）：
//! ```text
//! 2 bytes - length      // metaLen，不含自身
//! 2 bytes - session id  // BE16
//! 1 bytes - status
//! 1 bytes - option
//! -------------------- 以上 4 字节计入 metaLen
//! 1 byte  - network     // 仅 status==New（或 Keep+UDP 目标）时出现
//! 2 bytes - port        // PortThenAddress：端口在前
//! n bytes - address
//! ```
//! 其后可选:`status==New` 时的 source/local 地址（`Inbound.Source` 语义，
//! 本层不写、读侧按 `read_source_and_local` 开关消费），以及 `OptionData`
//! 之后的 `BE16 数据长度 || 数据`（[`read_data`] / [`write_data_frame`]）。
//!
//! 关键语义（逐条对齐参考，不可「等价」改写）：
//! - **`metaLen` 上限 512**：`Unmarshal` 里 `if metaLen > 512 { invalid metalen }`；
//! - `SessionStatus`：New=1、Keep=2、End=3、KeepAlive=4；其余值 = unknown status；
//! - `Option`：OptionData=0x01、OptionError=0x02；
//! - `TargetNetwork`：TCP=1、UDP=2（与 VMess 请求头命令字节同值但**不同域**）；
//! - 地址解析**只在** `status==New` 或（`status==Keep` 且余量 >4 且首字节 UDP）时进行
//!   （`MUST check the flag first`）；
//! - `status==New` 且余量为 0 或首字节为 0 时判为 heartbeat/padding，直接返回成功；
//! - 未知 network / 未知 status / 地址解析失败均 fail-closed 返回错误。
//!
//! 与参考的字段差异：参考的 `FrameMetadata.Inbound`（reverse mux）本层不承载，
//! 读侧以 [`FrameMetadata::source`]/[`FrameMetadata::local`] 暴露原始地址对，
//! 由调用方决定是否使用（写侧恒不发，等价于 `Inbound == nil` 且 `b.UDP == nil`）。

use std::io::Read;

use ss_core::target::TargetAddr;

/// `SessionStatusNew`。
pub const SESSION_STATUS_NEW: u8 = 0x01;
/// `SessionStatusKeep`。
pub const SESSION_STATUS_KEEP: u8 = 0x02;
/// `SessionStatusEnd`。
pub const SESSION_STATUS_END: u8 = 0x03;
/// `SessionStatusKeepAlive`。
pub const SESSION_STATUS_KEEP_ALIVE: u8 = 0x04;

/// `OptionData`。
pub const OPTION_DATA: u8 = 0x01;
/// `OptionError`。
pub const OPTION_ERROR: u8 = 0x02;

/// `TargetNetworkTCP`。
pub const TARGET_NETWORK_TCP: u8 = 0x01;
/// `TargetNetworkUDP`。
pub const TARGET_NETWORK_UDP: u8 = 0x02;

/// `Unmarshal` 的 metaLen 上限（参考常量 512，硬编码）。
pub const MAX_META_LEN: usize = 512;
/// 每个会话的子流分片大小（参考 `buf.SplitSize(mb, 8*1024)`）。
pub const SESSION_CHUNK_SIZE: usize = 8 * 1024;

/// 会话状态（[`SESSION_STATUS_NEW`] 等）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    /// 新会话，携带目标地址。
    New,
    /// 既有会话的后续数据。
    Keep,
    /// 会话结束。
    End,
    /// 保活探测（无会话语义）。
    KeepAlive,
}

impl SessionStatus {
    /// 线上字节。
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            SessionStatus::New => SESSION_STATUS_NEW,
            SessionStatus::Keep => SESSION_STATUS_KEEP,
            SessionStatus::End => SESSION_STATUS_END,
            SessionStatus::KeepAlive => SESSION_STATUS_KEEP_ALIVE,
        }
    }

    /// 由线上字节解析；参考 `switch` 的 default 分支即 unknown status。
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            SESSION_STATUS_NEW => Some(SessionStatus::New),
            SESSION_STATUS_KEEP => Some(SessionStatus::Keep),
            SESSION_STATUS_END => Some(SessionStatus::End),
            SESSION_STATUS_KEEP_ALIVE => Some(SessionStatus::KeepAlive),
            _ => None,
        }
    }
}

/// 目标网络（`net.Network` 的 mux 线表示）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetNetwork {
    Tcp,
    Udp,
}

impl TargetNetwork {
    /// 线上字节。
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            TargetNetwork::Tcp => TARGET_NETWORK_TCP,
            TargetNetwork::Udp => TARGET_NETWORK_UDP,
        }
    }

    /// 由线上字节解析；0 与其它值都不是合法 network。
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            TARGET_NETWORK_TCP => Some(TargetNetwork::Tcp),
            TARGET_NETWORK_UDP => Some(TargetNetwork::Udp),
            _ => None,
        }
    }
}

/// 帧元数据（`FrameMetadata`）。含目标地址；不含密钥材料，可安全 Debug。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameMetadata {
    pub session_id: u16,
    pub status: SessionStatus,
    pub option: u8,
    /// 目标地址；只有 `New`（或 `Keep` + UDP）帧才可能非 `None`。
    pub target: Option<(TargetAddr, TargetNetwork)>,
    /// `status==New` 且读侧要求时的 source 地址（参考 `Inbound.Source`）。
    pub source: Option<(TargetAddr, TargetNetwork)>,
    /// `status==New` 且读侧要求时的 local 地址（参考 `Inbound.Local`）。
    pub local: Option<(TargetAddr, TargetNetwork)>,
}

impl FrameMetadata {
    /// `Option.Has(OptionData)`。
    #[must_use]
    pub const fn has_data(&self) -> bool {
        self.option & OPTION_DATA != 0
    }

    /// `Option.Has(OptionError)`。
    #[must_use]
    pub const fn has_error(&self) -> bool {
        self.option & OPTION_ERROR != 0
    }

    /// `WriteTo`：把元数据写入 `out`（不含数据段）。
    ///
    /// 语义逐条对齐参考：`status==New` 时写 network + 地址；`status!=New`
    /// 且目标网络为 UDP 时也写 network + 地址（参考 `b.UDP != nil` 分支，
    /// 由调用方通过 [`FrameMetadata::target`] 表达）。`metaLen` 取「写完全部
    /// 可选段后的总长」再回填前 2 字节。
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), FrameError> {
        let start = out.len();
        out.extend_from_slice(&[0, 0]); // len 占位（metaLen 不含自身）
        let len0 = out.len(); // = start + 2，即参考的 len0
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.push(self.status.to_byte());
        out.push(self.option);

        let address_written = match (self.status, self.target.as_ref()) {
            (SessionStatus::New, Some((addr, network))) => {
                out.push(network.to_byte());
                encode_address_port(out, addr)?;
                true
            }
            // 参考：`else if b.UDP != nil` —— 非 New 帧若带 UDP 目标也写地址。
            (_, Some((addr, network))) if *network == TargetNetwork::Udp => {
                out.push(TARGET_NETWORK_UDP);
                encode_address_port(out, addr)?;
                true
            }
            _ => false,
        };
        if self.status == SessionStatus::New && address_written {
            // 参考在 `Inbound != nil` 时写 source/local；本层恒不发（等价 Inbound==nil
            // 且 b.UDP == nil 的参考分支，不写 GlobalID）。
        }
        let len = out.len() - len0;
        let len = u16::try_from(len).map_err(|_| FrameError::MetaTooLong)?;
        out[start..start + 2].copy_from_slice(&len.to_be_bytes());
        Ok(())
    }

    /// `Unmarshal`：从 `reader` 读一个完整帧头。`read_source_and_local` 对应
    /// 参考的 `session.IsReverseMuxFromContext`。
    pub fn decode_from<R: Read>(
        reader: &mut R,
        read_source_and_local: bool,
    ) -> Result<Self, FrameError> {
        let mut len_wire = [0u8; 2];
        read_exact(reader, &mut len_wire)?;
        let meta_len = usize::from(u16::from_be_bytes(len_wire));
        if meta_len > MAX_META_LEN {
            return Err(FrameError::MetaTooLong);
        }
        let mut body = vec![0u8; meta_len];
        read_exact(reader, &mut body)?;
        Self::decode_meta(&body, read_source_and_local)
    }

    /// `UnmarshalFromBuffer`：解析已读入的元数据体（`metaLen` 字节）。
    pub fn decode_meta(body: &[u8], read_source_and_local: bool) -> Result<Self, FrameError> {
        if body.len() < 4 {
            return Err(FrameError::ShortMeta { got: body.len() });
        }
        let session_id = u16::from_be_bytes([body[0], body[1]]);
        let status = SessionStatus::from_byte(body[2])
            .ok_or(FrameError::UnknownStatus { status: body[2] })?;
        let option = body[3];
        let mut cursor = 4usize;

        let mut target = None;
        // `f.SessionStatus == New || (Keep && b.Len() > 4 && b.Byte(4) == UDP)`
        let wants_address = status == SessionStatus::New
            || (status == SessionStatus::Keep && body.len() > 4 && body[4] == TARGET_NETWORK_UDP);
        if wants_address {
            if body.len() < 8 {
                return Err(FrameError::ShortMeta { got: body.len() });
            }
            let network = TargetNetwork::from_byte(body[4])
                .ok_or(FrameError::UnknownNetwork { network: body[4] })?;
            cursor = 5;
            let (addr, used) = decode_address_port(&body[cursor..])?;
            cursor += used;
            target = Some((addr, network));
        }

        let mut source = None;
        let mut local = None;
        if status == SessionStatus::New && read_source_and_local && body.len() > cursor {
            {
                if body[cursor] != 0 {
                    let network = TargetNetwork::from_byte(body[cursor]).ok_or(
                        FrameError::UnknownNetwork {
                            network: body[cursor],
                        },
                    )?;
                    cursor += 1;
                    let (addr, used) = decode_address_port(&body[cursor..])?;
                    cursor += used;
                    source = Some((addr, network));
                    if body.len() > cursor && body[cursor] != 0 {
                        let network = TargetNetwork::from_byte(body[cursor]).ok_or(
                            FrameError::UnknownNetwork {
                                network: body[cursor],
                            },
                        )?;
                        cursor += 1;
                        let (addr, _used) = decode_address_port(&body[cursor..])?;
                        local = Some((addr, network));
                    }
                }
            }
        }

        Ok(FrameMetadata {
            session_id,
            status,
            option,
            target,
            source,
            local,
        })
    }
}

/// 帧错误（fail-closed；不携带地址/密钥字节）。
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// 读帧头失败（EOF/超时等）。
    #[error("failed to read mux frame: {0}")]
    Io(String),
    /// `metaLen > 512`（参考 `invalid metalen`）。
    #[error("invalid metalen")]
    MetaTooLong,
    /// 元数据体不足以容纳固定 4 字节 / 声明的可选段。
    #[error("insufficient buffer: {got}")]
    ShortMeta { got: usize },
    /// 未知会话状态。
    #[error("unknown status: {status}")]
    UnknownStatus { status: u8 },
    /// 未知 network 字节。
    #[error("unknown network type: {network}")]
    UnknownNetwork { network: u8 },
    /// 地址段不合法。
    #[error("failed to parse address and port")]
    Address,
    /// 声明的数据长度超过 buf.Size（参考 `packet size too large`）。
    #[error("packet size too large: {size}")]
    PacketTooLarge { size: u16 },
}

/// 地址段写端（`protocol.PortThenAddress`）：`Port(BE16) | Type(1) | ADDR`。
pub fn encode_address_port(out: &mut Vec<u8>, addr: &TargetAddr) -> Result<(), FrameError> {
    let (port, kind, bytes) = split_addr(addr);
    out.extend_from_slice(&port.to_be_bytes());
    out.push(kind);
    out.extend_from_slice(&bytes);
    Ok(())
}

/// 地址段读端；返回地址与消耗字节数。
pub fn decode_address_port(bytes: &[u8]) -> Result<(TargetAddr, usize), FrameError> {
    if bytes.len() < 3 {
        return Err(FrameError::Address);
    }
    let port = u16::from_be_bytes([bytes[0], bytes[1]]);
    match bytes[2] {
        1 => {
            if bytes.len() < 7 {
                return Err(FrameError::Address);
            }
            let ip: [u8; 4] = bytes[3..7].try_into().expect("4 字节");
            Ok((TargetAddr::V4(ip, port), 7))
        }
        2 => {
            let domain_len = usize::from(bytes[3]);
            if domain_len == 0 || bytes.len() < 4 + domain_len {
                return Err(FrameError::Address);
            }
            let host =
                std::str::from_utf8(&bytes[4..4 + domain_len]).map_err(|_| FrameError::Address)?;
            if host.contains('\0') {
                return Err(FrameError::Address);
            }
            Ok((TargetAddr::Domain(host.to_string(), port), 4 + domain_len))
        }
        3 => {
            if bytes.len() < 19 {
                return Err(FrameError::Address);
            }
            let ip: [u8; 16] = bytes[3..19].try_into().expect("16 字节");
            Ok((TargetAddr::V6(ip, port), 19))
        }
        _ => Err(FrameError::Address),
    }
}

fn split_addr(addr: &TargetAddr) -> (u16, u8, Vec<u8>) {
    match addr {
        TargetAddr::V4(ip, port) => (*port, 1, ip.to_vec()),
        TargetAddr::V6(ip, port) => (*port, 3, ip.to_vec()),
        TargetAddr::Domain(host, port) => {
            let mut bytes = Vec::with_capacity(1 + host.len());
            bytes.push(host.len() as u8);
            bytes.extend_from_slice(host.as_bytes());
            (*port, 2, bytes)
        }
    }
}

fn read_exact<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), FrameError> {
    reader
        .read_exact(buf)
        .map_err(|error| FrameError::Io(format!("{:?}", error.kind())))
}

/// 会话数据段读端（`NewStreamReader` + `PacketReader`）：`BE16 长度 || 数据`。
///
/// `stream` 为 true 时语义等价 `buf.SplitSize(mb, 8192)` 的一帧（长度 1..=8192）；
/// 为 false 时等价 `PacketReader`（长度 1..=buf.Size，且**每帧独立**。
/// 由调用方按会话 transferType 选择。
pub fn read_data<R: Read>(reader: &mut R, stream: bool) -> Result<Vec<u8>, FrameError> {
    let mut len_wire = [0u8; 2];
    read_exact(reader, &mut len_wire)?;
    let size = u16::from_be_bytes(len_wire);
    let limit = if stream { SESSION_CHUNK_SIZE } else { 8192 } as u16;
    if size > limit {
        return Err(FrameError::PacketTooLarge { size });
    }
    let mut body = vec![0u8; usize::from(size)];
    read_exact(reader, &mut body)?;
    Ok(body)
}

/// 会话数据段写端：`BE16 长度 || 数据`。
pub fn encode_data_into(out: &mut Vec<u8>, payload: &[u8]) -> Result<(), FrameError> {
    let len =
        u16::try_from(payload.len()).map_err(|_| FrameError::PacketTooLarge { size: u16::MAX })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_and_network_maps_match_reference() {
        assert_eq!(SessionStatus::New.to_byte(), 0x01);
        assert_eq!(SessionStatus::Keep.to_byte(), 0x02);
        assert_eq!(SessionStatus::End.to_byte(), 0x03);
        assert_eq!(SessionStatus::KeepAlive.to_byte(), 0x04);
        assert_eq!(SessionStatus::from_byte(0x05), None);
        assert_eq!(SessionStatus::from_byte(0x00), None);
        assert_eq!(TargetNetwork::Tcp.to_byte(), 0x01);
        assert_eq!(TargetNetwork::Udp.to_byte(), 0x02);
        assert_eq!(TargetNetwork::from_byte(0x00), None);
        assert_eq!(TargetNetwork::from_byte(0x03), None);
    }

    #[test]
    fn new_frame_roundtrip_port_then_address() {
        let meta = FrameMetadata {
            session_id: 0x1234,
            status: SessionStatus::New,
            option: OPTION_DATA,
            target: Some((
                TargetAddr::Domain("example.invalid".to_string(), 443),
                TargetNetwork::Tcp,
            )),
            source: None,
            local: None,
        };
        let mut wire = Vec::new();
        meta.encode_into(&mut wire).expect("可编码");
        // metaLen = 2(id) + 1(status) + 1(option) + 1(network) + 2(port) + 1(len) + 15
        assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 24);
        assert_eq!(&wire[2..], &{
            let mut v = vec![0x12, 0x34, 0x01, 0x01, 0x01, 0x01, 0xBB, 0x02, 15];
            v.extend_from_slice(b"example.invalid");
            v
        });
        let decoded = FrameMetadata::decode_meta(&wire[2..], true).expect("可解码");
        assert_eq!(decoded, meta);
    }

    #[test]
    fn end_frame_has_no_address() {
        let meta = FrameMetadata {
            session_id: 7,
            status: SessionStatus::End,
            option: 0,
            target: None,
            source: None,
            local: None,
        };
        let mut wire = Vec::new();
        meta.encode_into(&mut wire).expect("可编码");
        assert_eq!(wire.len(), 6, "metaLen 回填为 4（id2+status1+option1）");
        let decoded = FrameMetadata::decode_meta(&wire[2..], true).expect("可解码");
        assert_eq!(decoded.status, SessionStatus::End);
        assert!(decoded.target.is_none());
    }

    #[test]
    fn keep_without_address_is_four_byte_meta() {
        let body = [0x00, 0x05, SESSION_STATUS_KEEP, OPTION_DATA];
        let decoded = FrameMetadata::decode_meta(&body, true).expect("可解码");
        assert_eq!(decoded.session_id, 5);
        assert_eq!(decoded.status, SessionStatus::Keep);
        assert!(decoded.has_data());
    }

    #[test]
    fn oversized_metalen_is_rejected() {
        let mut wire = vec![0x02, 0x01]; // 513
        wire.extend_from_slice(&[0u8; 513]);
        let err = FrameMetadata::decode_from(&mut &wire[..], false);
        assert!(matches!(err, Err(FrameError::MetaTooLong)));
    }

    #[test]
    fn unknown_status_is_rejected() {
        let body = [0x00, 0x01, 0x09, 0x00];
        let err = FrameMetadata::decode_meta(&body, false);
        assert!(matches!(err, Err(FrameError::UnknownStatus { status: 9 })));
    }

    #[test]
    fn short_new_meta_without_address_is_insufficient() {
        let body = [0x00, 0x01, SESSION_STATUS_NEW, OPTION_DATA];
        let err = FrameMetadata::decode_meta(&body, true);
        assert!(matches!(err, Err(FrameError::ShortMeta { got: 4 })));
    }

    #[test]
    fn data_frame_roundtrip_and_size_guard() {
        let mut wire = Vec::new();
        encode_data_into(&mut wire, b"hello").expect("可编码");
        assert_eq!(&wire[..2], &[0x00, 0x05]);
        assert_eq!(read_data(&mut &wire[..], true).expect("可读"), b"hello");
        // 写端不设 8KiB 上限（参考的 8192 是 SplitSize 分片大小，不是拒绝阈值）；
        // 读端才按 `size > buf.Size` 拒绝。
        let big = vec![0u8; SESSION_CHUNK_SIZE + 1];
        encode_data_into(&mut Vec::new(), &big).expect("写端允许超过分片大小");
        let mut oversize = vec![0x20, 0x01]; // 8193
        oversize.extend_from_slice(&big);
        assert!(matches!(
            read_data(&mut &oversize[..], true),
            Err(FrameError::PacketTooLarge { size: 8193 })
        ));
    }
}
