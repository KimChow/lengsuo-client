//! Mux 帧的元数据：会话状态、目标网络与帧头编解码。
//!
//! 语义来源：参考 `common/mux/frame.go` 的 `FrameMetadata` / `SessionStatus` /
//! `TargetNetwork`，固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。

use std::io::Read;

use ss_core::target::TargetAddr;

use super::address::{decode_address_port, encode_address_port};
use super::data::read_exact;
use super::error::FrameError;
use super::{
    SESSION_STATUS_END, SESSION_STATUS_KEEP, SESSION_STATUS_KEEP_ALIVE, SESSION_STATUS_NEW,
    TARGET_NETWORK_TCP, TARGET_NETWORK_UDP,
};

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
        self.option & super::OPTION_DATA != 0
    }

    /// `Option.Has(OptionError)`。
    #[must_use]
    pub const fn has_error(&self) -> bool {
        self.option & super::OPTION_ERROR != 0
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
