//! L3 密文帧：帧边界格式与编解码。
//!
//! 本模块把「一帧 ACP 明文」变成「一个可放进 UDP 数据报的密文单元」，
//! 并定义这个单元的**边界格式**（长度、序号、类型），让两端能无歧义地切分与重组。
//!
//! 分层位置：**L3 密文帧**。L1 传输（UDP、打洞）由 `crates/lengsuo-tunnel` 负责，
//! L2 密钥（握手、密钥协商）由后续卡负责，L4 通道协商 / L5 ACP 语义**都不在本卡**。
//!
//! # 边界格式
//!
//! 帧头定长 20 字节，字段一律**大端（网络字节序）**：
//!
//! ```text
//! 偏移  宽度  字段        语义
//! 0     2    magic       0x4C53（"LS"）
//! 2     1    version     协议版本（1）
//! 3     1    frame_type  帧类型（1=数据 2=控制 3=keepalive）
//! 4     8    seq         帧序号
//! 12    2    payload_len 载荷（密文包）字节数
//! 14    2    flags       保留位，必须为 0
//! 16    4    header_crc  帧头前 16 字节的 CRC-32
//! 20    ..   payload     载荷
//! ```
//!
//! 完整规范见仓内 `docs/link-frame-spec.md`。
//!
//! # 无状态
//!
//! 本模块**不持有**任何会话状态：序号由调用方提供，AEAD 上下文
//! （`Sender` / `Receiver`）由调用方持有并以 `&mut` 借用传入。
//! 本 crate 无 socket、无文件、无线程、无计时器。

pub mod error;
pub mod header;

use lengsuo_wireguard::transport::{Receiver, Sender};

pub use error::FrameError;
pub use header::{
    header_crc32, FrameHeader, FrameType, CRC_COVERED_LEN, FRAME_HEADER_LEN, FRAME_MAGIC,
    FRAME_VERSION, PAYLOAD_LEN_FIELD_MAX, PAYLOAD_LEN_LEN,
};

/// 传输层单包硬上限（对齐参考端默认 MTU 1420 字节）。
pub const MAX_TRANSPORT_PACKET_LEN: usize = lengsuo_wireguard::transport::MAX_PACKET_LEN;

/// 单帧**总长**上限（帧头 + 载荷）＝ 1420 字节，与传输层的单包硬上限一致。
///
/// 这样一帧可以**原样**塞进一个 UDP 数据报，不会超出参考端的 MTU 预算
/// （1420 字节的 UDP 载荷 + 20 字节 IPv4 头 + 8 字节 UDP 头 = 1448 < 1500）。
pub const MAX_FRAME_LEN: usize = MAX_TRANSPORT_PACKET_LEN;

/// 本协议单帧允许的最大**密文载荷**长度（＝ 总长上限 − 帧头长度 ＝ 1400 字节）。
pub const MAX_FRAME_PAYLOAD_LEN: usize = MAX_FRAME_LEN - FRAME_HEADER_LEN;

/// 本协议单帧允许的最大**明文**长度。
///
/// 密文包 = 16 字节传输头 + 密文正文（与明文等长）+ 16 字节认证标签，
/// 故明文比密文载荷少 32 字节。
pub const MAX_PLAIN_LEN: usize = MAX_FRAME_PAYLOAD_LEN - 32;

/// 一帧的完整内容：帧头字段 + 载荷（密文包）。
///
/// `Debug` **只输出类型、序号与载荷长度**，绝不输出载荷字节
/// （载荷是密文，但长度信息之外的任何字节都可能泄漏业务内容）。
#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    /// 帧类型。
    pub frame_type: FrameType,
    /// 帧序号：由调用方提供，本 crate 原样带出去。
    pub seq: u64,
    /// 载荷（AEAD 密文包）。
    pub payload: Vec<u8>,
}

impl core::fmt::Debug for Frame {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Frame")
            .field("frame_type", &self.frame_type)
            .field("seq", &self.seq)
            .field("payload_len", &self.payload.len())
            // 故意不输出 payload。
            .finish_non_exhaustive()
    }
}

impl Frame {
    /// 构造一帧。
    #[must_use]
    pub fn new(frame_type: FrameType, seq: u64, payload: Vec<u8>) -> Self {
        Self {
            frame_type,
            seq,
            payload,
        }
    }

    /// 编码成线上字节：20 字节帧头 + 载荷。
    ///
    /// # Errors
    /// 载荷长度超过 `MAX_FRAME_PAYLOAD_LEN` 时返回 `FrameError::PayloadTooLong`，
    /// **不截断**。
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.payload.len() > MAX_FRAME_PAYLOAD_LEN {
            return Err(FrameError::PayloadTooLong {
                declared: self.payload.len(),
                limit: MAX_FRAME_PAYLOAD_LEN,
            });
        }
        let header = FrameHeader {
            frame_type: self.frame_type,
            seq: self.seq,
            payload_len: self.payload.len(),
            flags: 0,
        };
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + self.payload.len());
        let mut head = [0u8; FRAME_HEADER_LEN];
        header.write_to(&mut head)?;
        out.extend_from_slice(&head);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }
}

/// 切分出一个帧：返回帧内容与**已消费的字节数**。
///
/// `consumed` 支持粘包：缓冲里可以有多帧连续排列，本函数只切出**第一帧**，
/// 调用方拿 `consumed` 推进自己的游标后继续切下一帧。
///
/// **长度纪律**：本函数**只按帧头声明的长度**切帧。
/// - 缓冲不足一帧 ⇒ `FrameError::Incomplete`（**不返回部分数据**）。
/// - 缓冲多于一帧 ⇒ **正常返回第一帧**（粘包是常态，不是错误），
///   多余字节由调用方按 `consumed` 自行处理。
/// - 需要「缓冲必须恰好一帧」时用 [`decode_exact`]。
///
/// # Errors
/// - 缓冲不足一个完整帧 ⇒ `FrameError::Incomplete`。
/// - 帧头字段非法（魔数/版本/类型/保留位/长度/CRC）⇒ 对应错误。
pub fn decode(buf: &[u8]) -> Result<(Frame, usize), FrameError> {
    let header = FrameHeader::parse(buf)?;
    let total = FRAME_HEADER_LEN + header.payload_len;
    if buf.len() < total {
        return Err(FrameError::Incomplete {
            needed: total,
            available: buf.len(),
        });
    }
    Ok((
        Frame::new(
            header.frame_type,
            header.seq,
            buf[FRAME_HEADER_LEN..total].to_vec(),
        ),
        total,
    ))
}

/// 切分出**恰好一个**帧：缓冲里多一个字节都算错。
///
/// 与 [`decode`] 的区别：粘包场景请用 [`decode`]（它会返回已消费字节数）。
///
/// # Errors
/// - 缓冲不足一个完整帧 ⇒ `FrameError::Incomplete`。
/// - 帧头字段非法 ⇒ 对应错误。
/// - 缓冲多于一个帧 ⇒ `FrameError::LengthMismatch`（**不按实际长度猜**）。
pub fn decode_exact(buf: &[u8]) -> Result<Frame, FrameError> {
    let header = FrameHeader::parse(buf)?;
    let total = FRAME_HEADER_LEN + header.payload_len;
    if buf.len() < total {
        return Err(FrameError::Incomplete {
            needed: total,
            available: buf.len(),
        });
    }
    if buf.len() > total {
        return Err(FrameError::LengthMismatch {
            declared: total,
            actual: buf.len(),
        });
    }
    Ok(Frame::new(
        header.frame_type,
        header.seq,
        buf[FRAME_HEADER_LEN..total].to_vec(),
    ))
}

/// 判断缓冲**是否以帧魔数开头**（长度不足 2 字节时按已给的字节前缀比较）。
///
/// 用于区分「被截断的帧头」与「错位垃圾」：
/// 前缀一致 ⇒ 是本协议的帧（只是没传完）；前缀不一致 ⇒ 不是帧。
fn starts_with_magic(buf: &[u8]) -> bool {
    let magic = FRAME_MAGIC.to_be_bytes();
    let n = buf.len().min(magic.len());
    buf[..n] == magic[..n]
}

/// 切分粘在**一起**的若干帧：返回切出的全部帧。
///
/// 逐帧推进游标；每一步都按帧头声明的长度切，**不猜测**。
/// 若某个帧边界处不是帧头（魔数不匹配），说明发生了**帧边界错位**
/// （截断拼接、字节丢失等）⇒ `FrameError::Desync`，并给出错位偏移。
///
/// # Errors
/// - 任一帧不完整 ⇒ `FrameError::Incomplete`（**已切出的帧也不返回**——
///   本函数要么给出全部帧，要么报错，不给半截结果）。
/// - 任一帧头非法 ⇒ 对应错误。
/// - 帧边界处魔数不匹配 ⇒ `FrameError::Desync`。
pub fn split_frames(buf: &[u8]) -> Result<Vec<Frame>, FrameError> {
    let mut frames = Vec::new();
    let mut rest = buf;
    let mut offset = 0usize;
    while !rest.is_empty() {
        match decode(rest) {
            Ok((frame, consumed)) => {
                frames.push(frame);
                offset += consumed;
                rest = &rest[consumed..];
            }
            // 边界处不是帧头：报错位，而不是把垃圾字节当载荷。
            Err(FrameError::BadMagic { .. }) => return Err(FrameError::Desync { offset }),
            // 尾部不足一个完整帧头：先看**魔数前缀**再定性。
            //  - 前缀与 magic 一致 ⇒ 是被截断的帧头 ⇒ Incomplete（等更多字节）。
            //  - 前缀与 magic 不一致 ⇒ 是错位垃圾 ⇒ Desync。
            // 这一步是必要的：UDP 数据报**没有"更多字节"这种后续**，
            // 尾部垃圾必须当场判错，不能报成"缓冲不足"让人无限等。
            Err(FrameError::Incomplete { .. }) => {
                if !starts_with_magic(rest) {
                    return Err(FrameError::Desync { offset });
                }
                return Err(FrameError::Incomplete {
                    needed: FRAME_HEADER_LEN,
                    available: rest.len(),
                });
            }
            Err(other) => return Err(other),
        }
    }
    Ok(frames)
}

/// 编码明文 → 密封 → 成帧：产出可直接放进 UDP 数据报的字节。
///
/// 借用调用方持有的 `Sender`（**本模块不持有任何会话状态**）。
///
/// 步骤：`Sender::seal`（AEAD 封密文）→ 加上 20 字节帧头。
///
/// # Errors
/// - 明文超过 `MAX_PLAIN_LEN` ⇒ `FrameError::PayloadTooLong`（写入前拒绝，
///   **不消耗发送侧计数器**）。
/// - 传输层失败（poisoned / 计数器用尽 / 封装失败）⇒ 对应的 `FrameError`。
pub fn seal_frame(
    sender: &mut Sender,
    frame_type: FrameType,
    seq: u64,
    plain: &[u8],
) -> Result<Vec<u8>, FrameError> {
    if plain.len() > MAX_PLAIN_LEN {
        // 在触碰 sender 之前拒绝：计数器不推进，传输层也不报错。
        return Err(FrameError::PayloadTooLong {
            declared: plain.len(),
            limit: MAX_PLAIN_LEN,
        });
    }
    let payload = sender.seal(plain)?;
    let frame = Frame::new(frame_type, seq, payload);
    frame.encode()
}

/// 解帧 → 认证解封 → 交还明文。
///
/// 借用调用方持有的 `Receiver`（**本模块不持有任何会话状态**）。
///
/// 步骤：切帧 → `Receiver::open`（AEAD 认证解密）→ 交还明文与帧头字段。
///
/// # Errors
/// - 切帧失败 ⇒ 对应的 `FrameError`（**不返回部分数据**）。
/// - AEAD 认证失败 ⇒ `FrameError::AuthFailed`（**不回退明文**，且 `Receiver`
///   已永久 poison）。
/// - 重放窗口拒绝 ⇒ `FrameError::ReplayRejected`（丢包，不改窗口状态）。
#[derive(Clone, PartialEq, Eq)]
pub struct OpenedFrame {
    /// 帧类型。
    pub frame_type: FrameType,
    /// 帧序号。
    pub seq: u64,
    /// 认证解密后的明文。
    pub plaintext: Vec<u8>,
}

impl core::fmt::Debug for OpenedFrame {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OpenedFrame")
            .field("frame_type", &self.frame_type)
            .field("seq", &self.seq)
            .field("plaintext_len", &self.plaintext.len())
            // 故意不输出 plaintext。
            .finish_non_exhaustive()
    }
}

/// 解帧并认证解封（见 [`open_frame`]）。
pub fn open_frame(receiver: &mut Receiver, buf: &[u8]) -> Result<OpenedFrame, FrameError> {
    let frame = decode_exact(buf)?;
    let decrypted = receiver.open(&frame.payload)?;
    Ok(OpenedFrame {
        frame_type: frame.frame_type,
        seq: frame.seq,
        plaintext: decrypted.plaintext,
    })
}
