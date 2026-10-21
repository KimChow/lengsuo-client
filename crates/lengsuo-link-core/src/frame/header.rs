//! 帧头布局与解析。
//!
//! 线上格式（**大端 / 网络字节序**，定长帧头 20 字节）：
//!
//! ```text
//! 偏移  宽度  字段            语义
//! 0     2    magic           帧起始标记（0x4C53，"LS"）
//! 2     1    version         协议版本（当前 1）
//! 3     1    frame_type      帧类型（数据/控制/keepalive）
//! 4     8    seq             帧序号（调用方提供，本 crate 不维护）
//! 12    2    payload_len     载荷字节数（密文包长度）
//! 14    2    flags           保留标志位，当前必须为 0
//! 16    4    header_crc      帧头前 16 字节的 CRC-32
//! 20    ..   payload         载荷（AEAD 密文包）
//! ```
//!
//! **为什么是定长 20 字节 + CRC-32**：定长头让接收侧可以在不读完载荷的情况下
//! 判断「下一个帧从哪里开始」，从而支持粘包切分；CRC-32 覆盖帧头前 16 字节，
//! 用于在**解密之前**就发现头部被损坏（比特翻转、错位拼接、伪造的魔数），
//! 避免把坏帧送进 AEAD 去浪费一次认证尝试。

/// 帧头魔数：`0x4C53`（ASCII "LS"）。用于识别帧起点。
pub const FRAME_MAGIC: u16 = 0x4C53;

/// 当前协议版本。
pub const FRAME_VERSION: u8 = 1;

/// 帧头固定长度：magic(2) + version(1) + type(1) + seq(8) + len(2) + flags(2) + crc(4)。
pub const FRAME_HEADER_LEN: usize = 20;

/// 帧头中参与 CRC 计算的字节数（帧头前 16 字节，不含 CRC 自身）。
pub const CRC_COVERED_LEN: usize = 16;

/// 载荷长度字段的字节宽度。
pub const PAYLOAD_LEN_LEN: usize = 2;

/// 载荷长度字段能表示的最大值（`u16::MAX`）——**只是字段的表示范围**，
/// 实际允许的载荷长度以 [`crate::frame::MAX_FRAME_PAYLOAD_LEN`] 为准
/// （密文包还要塞进一个 UDP 数据报）。
pub const PAYLOAD_LEN_FIELD_MAX: usize = u16::MAX as usize;

/// 帧类型。
///
/// **未知类型必须被显式拒绝**（见 `FrameError::UnknownFrameType`），
/// 绝不当成数据帧解析——否则未来新增的帧类型会被旧端误解。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameType {
    /// 数据帧：载荷是密文包，解开后是一帧 ACP 明文。
    Data,
    /// 控制帧：载荷是密文包，解开后是链路控制语义（L4 协商等，由上层定义）。
    Control,
    /// keepalive 帧：零长载荷语义。
    Keepalive,
}

impl FrameType {
    /// 线上字节值。
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Data => 0x01,
            Self::Control => 0x02,
            Self::Keepalive => 0x03,
        }
    }

    /// 由线上字节值还原；未知值返回 `None`（调用方据此 fail-closed 拒绝）。
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Data),
            0x02 => Some(Self::Control),
            0x03 => Some(Self::Keepalive),
            _ => None,
        }
    }
}

/// 帧头字段的解析结果（不含载荷）。
///
/// 刻意**不**实现 `Clone`/`Copy` 之外的派生：这里没有密钥材料，
/// 保持结构简单。`Debug` 只出字段值，不含任何载荷字节。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    /// 帧类型。
    pub frame_type: FrameType,
    /// 帧序号：由调用方提供，本 crate 只负责原样带出去。
    pub seq: u64,
    /// 载荷长度（密文包字节数）。
    pub payload_len: usize,
    /// 保留标志位：当前必须为 0。
    pub flags: u16,
}

impl FrameHeader {
    /// 解析帧头（**不检查载荷**）。`buf` 至少要有 `FRAME_HEADER_LEN` 字节。
    ///
    /// 校验顺序：魔数 → 版本 → 类型 → 载荷长度上限 → 保留位 → CRC。
    /// 先查廉价的固定字段，最后才算 CRC，避免对明显错误的帧做无谓计算。
    ///
    /// # Errors
    /// 任何字段不合法都返回对应错误，**绝不**返回「尽力猜出来的」帧头。
    pub fn parse(buf: &[u8]) -> Result<Self, crate::frame::error::FrameError> {
        use crate::frame::error::FrameError;
        if buf.len() < FRAME_HEADER_LEN {
            return Err(FrameError::Incomplete {
                needed: FRAME_HEADER_LEN,
                available: buf.len(),
            });
        }
        let magic = u16::from_be_bytes([buf[0], buf[1]]);
        if magic != FRAME_MAGIC {
            return Err(FrameError::BadMagic {
                expected: FRAME_MAGIC,
                got: magic,
            });
        }
        let version = buf[2];
        if version != FRAME_VERSION {
            return Err(FrameError::UnsupportedVersion {
                expected: FRAME_VERSION,
                got: version,
            });
        }
        let raw_type = buf[3];
        let Some(frame_type) = FrameType::from_u8(raw_type) else {
            return Err(FrameError::UnknownFrameType { got: raw_type });
        };
        let seq = u64::from_be_bytes([
            buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
        ]);
        let payload_len = usize::from(u16::from_be_bytes([buf[12], buf[13]]));
        let flags = u16::from_be_bytes([buf[14], buf[15]]);
        if flags != 0 {
            return Err(FrameError::ReservedFlags { got: flags });
        }
        if payload_len > crate::frame::MAX_FRAME_PAYLOAD_LEN {
            return Err(FrameError::PayloadTooLong {
                declared: payload_len,
                limit: crate::frame::MAX_FRAME_PAYLOAD_LEN,
            });
        }
        let expected = header_crc32(&buf[..CRC_COVERED_LEN]);
        let got = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
        if expected != got {
            return Err(FrameError::HeaderCrcMismatch { expected, got });
        }
        Ok(Self {
            frame_type,
            seq,
            payload_len,
            flags,
        })
    }

    /// 把帧头字段写进 20 字节定长缓冲（含 CRC）。
    ///
    /// # Errors
    /// 载荷长度超过 `u16` 上限时返回 `FrameError::PayloadTooLong`。
    pub fn write_to(&self, out: &mut [u8]) -> Result<(), crate::frame::error::FrameError> {
        use crate::frame::error::FrameError;
        if out.len() < FRAME_HEADER_LEN {
            return Err(FrameError::Incomplete {
                needed: FRAME_HEADER_LEN,
                available: out.len(),
            });
        }
        if self.payload_len > crate::frame::MAX_FRAME_PAYLOAD_LEN {
            return Err(FrameError::PayloadTooLong {
                declared: self.payload_len,
                limit: crate::frame::MAX_FRAME_PAYLOAD_LEN,
            });
        }
        out[0..2].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
        out[2] = FRAME_VERSION;
        out[3] = self.frame_type.to_u8();
        out[4..12].copy_from_slice(&self.seq.to_be_bytes());
        out[12..14].copy_from_slice(&(self.payload_len as u16).to_be_bytes());
        out[14..16].copy_from_slice(&self.flags.to_be_bytes());
        let crc = header_crc32(&out[..CRC_COVERED_LEN]);
        out[16..20].copy_from_slice(&crc.to_be_bytes());
        Ok(())
    }
}

/// 帧头前 16 字节的 CRC-32（IEEE 多项式，init 0xFFFFFFFF，末位取反）。
///
/// 用固定查表实现，避免为本 crate 引入 `crc32fast` 依赖（本卡不新增依赖，
/// Cargo.toml 属共享区）。查表在进程内一次性构造（`OnceLock`），无 IO、无线程。
pub fn header_crc32(bytes: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(build_crc_table);
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        let index = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[index];
    }
    !crc
}

/// 生成 CRC-32 查表。
fn build_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                0xEDB8_8320 ^ (crc >> 1)
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}
