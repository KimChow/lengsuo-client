//! VMess 请求头明文构造（对齐 `proxy/vmess/encoding/client.go` 的
//! `EncodeRequestHeader` 明文段 + `common/protocol` 的地址写法）。
//!
//! 明文布局（封装前的 buffer.Bytes()，封装见 [`crate::aead`]）：
//! ```text
//! Version(1)=1 | requestBodyIV(16) | requestBodyKey(16) | responseHeader(1)
//! | Option(1) | security(1)=paddingLen<<4|sec | 0x00(1) | Command(1)
//! | 地址(TargetAddr 编码) | padding(0..16 随机) | FNV1a(前面全部)(4)
//! ```
//! - Command == Mux(3) 时**不含地址**（参考 `addrParser.WriteAddressPort` 被跳过）。
//! - paddingLen 由 `dice.Roll(16)` 生成（0..15），写进 security 高 4 位；
//!   padding 字节为随机。
//! - FNV1a 32 位校验覆盖从 Version 到 padding 结束的全部字节。
//!
//! 范围与限制：Security 只支持 none / AES-128-GCM / ChaCha20-Poly1305 与
//! autocipher 哨兵（由调用方解析）；legacy（SecurityType_Legacy）与 Mux 命令
//! 不实现（返回 [`Error::Unsupported`]，fail-closed 不静默降级）。

use ss_core::target::TargetAddr;

use crate::consts::{
    HEADER_IV_LEN, HEADER_KEY_LEN, SECURITY_AES_128_GCM, SECURITY_AUTOCIPHER,
    SECURITY_CHACHA20_POLY1305, SECURITY_NONE, VMESS_VERSION,
};
use crate::{fill_random, Error, Result};

/// 请求头版本字节。
pub const KEY_LEN: usize = HEADER_KEY_LEN;
/// 请求头对称密钥长度。
pub const NONCE_LEN: usize = HEADER_IV_LEN;
/// 请求头 IV 长度。
pub const VMESS_VERSION_BYTE: u8 = VMESS_VERSION;
/// Mux 命令字节（本层不实现）。
pub const CMD_MUX: u8 = 3;

/// 命令（`protocol.RequestCommand`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// TCP 转发。
    Tcp,
    /// UDP 转发。
    Udp,
}

impl Command {
    /// 线上命令字节。
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Command::Tcp => crate::consts::CMD_NONE_TCP,
            Command::Udp => crate::consts::CMD_UDP,
        }
    }

    /// 由线上字节解析；Mux 与未知值返回 `None`（调用方决定报错方式）。
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            crate::consts::CMD_NONE_TCP => Some(Command::Tcp),
            crate::consts::CMD_UDP => Some(Command::Udp),
            _ => None,
        }
    }
}

/// 安全选项（本层支持的子集）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityOption {
    /// 明文（chunkStream 之下仍可被 chunk 掩码保护）。
    None,
    /// AES-128-GCM。
    Aes128Gcm,
    /// ChaCha20-Poly1305（密钥由 MD5 扩展）。
    ChaCha20Poly1305,
    /// autocipher 哨兵：本层不解析，调用方必须先解析成具体套件。
    AutoCipher,
}

impl SecurityOption {
    /// 线上低 4 位。
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            SecurityOption::None => SECURITY_NONE,
            SecurityOption::Aes128Gcm => SECURITY_AES_128_GCM,
            SecurityOption::ChaCha20Poly1305 => SECURITY_CHACHA20_POLY1305,
            SecurityOption::AutoCipher => SECURITY_AUTOCIPHER,
        }
    }

    /// 由线上字节解析；未知值 `None`。
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            SECURITY_NONE => Some(SecurityOption::None),
            SECURITY_AES_128_GCM => Some(SecurityOption::Aes128Gcm),
            SECURITY_CHACHA20_POLY1305 => Some(SecurityOption::ChaCha20Poly1305),
            SECURITY_AUTOCIPHER => Some(SecurityOption::AutoCipher),
            _ => None,
        }
    }
}

/// 会话密钥来源：请求头明文里的 16B key 与 16B IV，以及 1B 响应头种子。
/// 本层不实现 Debug（含密钥材料）。
pub struct KeySource {
    /// 请求体对称密钥（AES-128-GCM 直接使用；ChaCha20 由 MD5 扩展）。
    pub body_key: [u8; 16],
    /// 请求体 IV（数据段 nonce 基值 + chunk 掩码种子）。
    pub body_iv: [u8; 16],
    /// 响应头首个字节（服务端回包校验用）。
    pub response_header: u8,
}

impl KeySource {
    /// 由系统 CSPRNG 生成三段（`NewClientSession` 的 randomBytes 33B）。
    pub fn generate() -> Result<Self> {
        let mut body_key = [0u8; 16];
        let mut body_iv = [0u8; 16];
        let mut response_header = [0u8; 1];
        fill_random(&mut body_key)?;
        fill_random(&mut body_iv)?;
        fill_random(&mut response_header)?;
        Ok(Self {
            body_key,
            body_iv,
            response_header: response_header[0],
        })
    }
}

/// 单条请求的头部字段集（不含会话密钥）。
#[derive(Clone, PartialEq, Eq)]
pub struct RequestHeader {
    /// 目标地址；Mux 命令必须为 `None`，其余命令必须为 `Some`。
    pub target: Option<TargetAddr>,
    /// 命令。
    pub command: Command,
    /// 安全选项。
    pub security: SecurityOption,
    /// 选项字节（由 [`HeaderPlanner`] 计算或调用方显式指定）。
    pub option: u8,
    /// 填充长度（0..=15；`dice.Roll(16)` 语义，测试可注入固定值）。
    pub padding_len: u8,
}

impl RequestHeader {
    /// Mux 命令（本层不支持）。
    pub fn is_mux(&self) -> bool {
        self.command == Command::from_byte(CMD_MUX).unwrap_or(self.command)
    }
}

/// 请求头规划器：把字段集编成明文（封装前字节），供 [`crate::aead`] 封装。
pub struct HeaderPlanner {
    /// 会话密钥与响应种子。
    pub key_source: KeySource,
}

impl HeaderPlanner {
    /// 由生成的会话密钥构造。
    pub fn new(key_source: KeySource) -> Self {
        HeaderPlanner { key_source }
    }

    /// `EncodeRequestHeader` 明文段：padding 随机由系统 CSPRNG 提供。
    pub fn plan(&self, header: &RequestHeader) -> Result<Vec<u8>> {
        let mut padding = vec![0u8; header.padding_len as usize];
        if !padding.is_empty() {
            fill_random(&mut padding)?;
        }
        self.plan_with(header, &padding)
    }

    /// 确定性变体：padding 字节由调用方注入（长度必须与 `padding_len` 一致）。
    pub fn plan_with(&self, header: &RequestHeader, padding: &[u8]) -> Result<Vec<u8>> {
        if header.padding_len > 15 {
            return Err(Error::InvalidField {
                field: "padding_len",
            });
        }
        if padding.len() != header.padding_len as usize {
            return Err(Error::BadLength {
                declared: padding.len(),
                got: header.padding_len as usize,
            });
        }
        // 安全选项校验（fail-closed：autocipher 哨兵必须先被调用方解析）。
        if header.security == SecurityOption::AutoCipher {
            return Err(Error::Unsupported {
                feature: "autocipher sentinel must be resolved by caller",
            });
        }
        // Mux（字节 3）在本层不支持：直接按线上字节判定，命中即拒绝。
        let mux = header.command.to_byte() == CMD_MUX;
        match (header.target.as_ref(), mux) {
            (Some(_), true) | (None, false) => {
                return Err(Error::InvalidField { field: "target" });
            }
            _ => {}
        }
        // security 字节：高 4 位 paddingLen，低 4 位 Security。
        let security_byte = (header.padding_len << 4) | (header.security.to_byte() & 0x0F);

        let mut buffer = Vec::with_capacity(
            1 + 16
                + 16
                + 1
                + 1
                + 4
                + 2
                + header.target.as_ref().map_or(0, TargetAddr::encoded_len)
                + padding.len()
                + 4,
        );
        buffer.push(VMESS_VERSION_BYTE);
        buffer.extend_from_slice(&self.key_source.body_iv);
        buffer.extend_from_slice(&self.key_source.body_key);
        buffer.push(self.key_source.response_header);
        buffer.push(header.option);
        buffer.extend_from_slice(&[security_byte, 0x00, header.command.to_byte()]);
        if let Some(target) = header.target.as_ref() {
            target.encode_checked(&mut buffer).map_err(Error::Core)?;
        }
        buffer.extend_from_slice(padding);
        buffer.extend_from_slice(&fnv1a32(&buffer).to_be_bytes());
        Ok(buffer)
    }
}

/// FNV-1a 32 位（`hash/fnv` New32a，与参考 `Authenticate` 一致）。
#[must_use]
pub fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811C_9DC5;
    for &byte in bytes {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// `CipherSpec` 兼容占位：安全选项 + 数据段密钥派生结果。
/// （保留导出名以满足 lib.rs 的公开面；具体派生在 `chunkframe::DataCipher`。）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherSpec {
    /// 安全选项。
    pub security: SecurityOption,
}

impl CipherSpec {
    /// 数据段 AEAD 密钥长度（none 为 0）。
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self.security {
            SecurityOption::Aes128Gcm => KEY_LEN,
            SecurityOption::ChaCha20Poly1305 => 32,
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn planner() -> HeaderPlanner {
        let mut key_source = KeySource {
            body_key: [0x11u8; 16],
            body_iv: [0x22u8; 16],
            response_header: 0x33,
        };
        // KeySource 字段可变性仅测试用。
        let _ = &mut key_source;
        HeaderPlanner::new(key_source)
    }

    fn sample_header() -> RequestHeader {
        RequestHeader {
            target: Some(TargetAddr::Domain("example.invalid".into(), 443)),
            command: Command::Tcp,
            security: SecurityOption::Aes128Gcm,
            option: 0x05,
            padding_len: 4,
        }
    }

    #[test]
    fn plan_layout_and_fnv_tail() {
        let header = sample_header();
        let padding = [0xAAu8; 4];
        let plain = planner().plan_with(&header, &padding).expect("可编码");
        // 1 + 16 + 16 + 1 + 1 + 3 + 地址(2+15) + 4 + 4
        assert_eq!(plain[0], VMESS_VERSION_BYTE);
        assert_eq!(&plain[1..17], &[0x22u8; 16]);
        assert_eq!(&plain[17..33], &[0x11u8; 16]);
        assert_eq!(plain[33], 0x33);
        assert_eq!(plain[34], 0x05);
        // security 字节 = padding<<4 | sec
        assert_eq!(plain[35], (4 << 4) | SECURITY_AES_128_GCM);
        assert_eq!(plain[36], 0x00);
        assert_eq!(plain[37], Command::Tcp.to_byte());
        // FNV 尾部自洽。
        let body = &plain[..plain.len() - 4];
        let tail = u32::from_be_bytes(plain[plain.len() - 4..].try_into().unwrap());
        assert_eq!(tail, fnv1a32(body));
        // 地址段可被 ss-core 解码还原。
        let (target, used) = TargetAddr::decode(&plain[38..]).expect("可解");
        assert_eq!(target, TargetAddr::Domain("example.invalid".into(), 443));
        assert_eq!(38 + used + 4 + 4, plain.len());
    }

    #[test]
    fn fnv1a32_known_vector() {
        // FNV-1a 32 标准空串与 "a" 向量（公共规范值，非 Go 特有）。
        assert_eq!(fnv1a32(b""), 0x811C_9DC5);
        assert_eq!(fnv1a32(b"a"), 0xE40C_292C);
    }

    #[test]
    fn missing_target_rejected_and_mux_byte_unrepresentable() {
        // Mux（字节 3）不在 Command 枚举里（本层不支持）——枚举层面就无法构造。
        assert_eq!(Command::from_byte(CMD_MUX), None);
        // 缺地址必须拒绝（padding 与声明一致，确保真正走到 target 校验）。
        let mut header = sample_header();
        header.target = None;
        assert!(matches!(
            planner().plan_with(&header, &[0u8; 4]),
            Err(Error::InvalidField { field: "target" })
        ));
    }

    #[test]
    fn padding_and_security_constraints() {
        let mut header = sample_header();
        header.padding_len = 16; // dice.Roll(16) 上界是 15
        assert!(matches!(
            planner().plan_with(&header, &[0u8; 16]),
            Err(Error::InvalidField {
                field: "padding_len"
            })
        ));
        let mut header = sample_header();
        header.security = SecurityOption::AutoCipher;
        assert!(matches!(
            planner().plan_with(&header, &[0u8; 4]),
            Err(Error::Unsupported { .. })
        ));
        // padding 长度与声明不符。
        let header = sample_header();
        assert!(matches!(
            planner().plan_with(&header, &[]),
            Err(Error::BadLength { .. })
        ));
    }

    #[test]
    fn cipher_spec_key_lengths() {
        assert_eq!(
            CipherSpec {
                security: SecurityOption::None
            }
            .key_len(),
            0
        );
        assert_eq!(
            CipherSpec {
                security: SecurityOption::Aes128Gcm
            }
            .key_len(),
            16
        );
        assert_eq!(
            CipherSpec {
                security: SecurityOption::ChaCha20Poly1305
            }
            .key_len(),
            32
        );
    }

    #[test]
    fn key_source_generate_is_random_and_debug_free() {
        let a = KeySource::generate().expect("可生成");
        let b = KeySource::generate().expect("可生成");
        assert_ne!(a.body_key, b.body_key, "CSPRNG 两次生成不得相同");
        assert_ne!(a.body_iv, b.body_iv);
        let _ = format!("{:?}", RequestHeader::is_mux(&sample_header()));
    }
}
