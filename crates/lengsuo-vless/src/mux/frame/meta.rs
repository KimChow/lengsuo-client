//! 帧元数据：会话状态 / 目标网络 / [`FrameMetadata`] / 帧错误。
//!
//! 从父模块拆出以保持单文件 ≤400 行（软约束）。语义逐条对齐参考
//! `common/mux/frame.go`（固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`），
//! 逐条要点见父模块文档。

use std::io::Read;

use ss_core::target::TargetAddr;

use super::address::{decode_address_port, encode_address_port};
use super::payload::read_exact;
use super::MAX_META_LEN;

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

/// 帧元数据（`FrameMetadata`）。不含 `GlobalID` 与密钥材料，可安全 Debug。
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
    /// 非 `New` 帧是否按「分组会话续帧」写目标地址（参考 `b.UDP != nil` 分支）。
    ///
    /// 参考里该分支由缓冲上挂的 UDP 目标触发；本层由调用方显式声明。
    pub udp_continuation: bool,
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
    /// 语义逐条对齐参考：`status==New` 时写 network + 地址；**仅 UDP 目标**的帧
    /// （`b.UDP != nil`，即分组会话的续帧）也写 network + 地址。参考的 `WriteTo` 用
    /// 「缓冲上挂了 UDP 目标」表示后者，本层无法从 `(addr, network)` 推断出缓冲是否
    /// 挂了 UDP，故由 [`FrameMetadata::udp_continuation`] 显式承载（TCP 续帧不带地址，
    /// 与参考一致）。`metaLen` 取「写完全部可选段后的总长」再回填前 2 字节。
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), FrameError> {
        let start = out.len();
        out.extend_from_slice(&[0, 0]); // len 占位（metaLen 不含自身）
        let len0 = out.len(); // = start + 2，即参考的 len0
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.push(self.status.to_byte());
        out.push(self.option);

        let mut address_written = false;
        if self.status == SessionStatus::New {
            if let Some((addr, network)) = self.target.as_ref() {
                out.push(network.to_byte());
                encode_address_port(out, addr)?;
                address_written = true;
            }
        } else if self.udp_continuation {
            // 参考 `else if b.UDP != nil { WriteByte(TargetNetworkUDP); WriteAddressPort }`。
            if let Some((addr, _)) = self.target.as_ref() {
                out.push(TARGET_NETWORK_UDP);
                encode_address_port(out, addr)?;
            }
        }

        if self.status == SessionStatus::New && address_written {
            // 参考写 source/local 的前置条件是 `Inbound != nil`（即读侧
            // `IsReverseMuxFromContext`）。本层不发 GlobalID：参考的
            // `else if b.UDP != nil { b.Write(f.GlobalID[:]) }` 属 XUDP 跨连接恢复，
            // 不在本卡范围，见模块头「与参考的差异」。
            if let Some((addr, network)) = self.source.as_ref() {
                out.push(network.to_byte());
                encode_address_port(out, addr)?;
                if let Some((addr, network)) = self.local.as_ref() {
                    out.push(network.to_byte());
                    encode_address_port(out, addr)?;
                }
            }
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
        // `New || (Keep && b.Len() > 4 && b.Byte(4) == UDP)` —— MUST check the flag first。
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
            // 参考：`b.Len() == 0` 直接返回（heartbeat/padding）；首字节 0 也返回。
            if body[cursor] != 0 {
                let network =
                    TargetNetwork::from_byte(body[cursor]).ok_or(FrameError::UnknownNetwork {
                        network: body[cursor],
                    })?;
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

        Ok(FrameMetadata {
            session_id,
            status,
            option,
            target,
            source,
            local,
            // 读侧不推断「缓冲上是否挂了 UDP 目标」；解出的目标地址即足够，写侧
            // 由调用方显式声明（见字段文档）。
            udp_continuation: false,
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
    /// 声明的数据长度超过 `buf.Size`（参考 `packet size too large`）。
    #[error("packet size too large: {size}")]
    PacketTooLarge { size: u16 },
}
