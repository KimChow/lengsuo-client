//! 请求头的枚举与会话密钥来源。
//!
//! 语义来源：参考 `common/protocol/headers.pb.go` 的 `SecurityType` 与
//! `common/protocol/headers.go` 的 `RequestCommand`，固定 commit `d2758a02`。

use crate::consts::{
    SECURITY_AES_128_GCM, SECURITY_AUTOCIPHER, SECURITY_CHACHA20_POLY1305, SECURITY_NONE,
};
use crate::{fill_random, Result};

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
///
/// 语义来源：参考 `common/protocol/headers.pb.go` 的 `SecurityType`
/// （UNKNOWN=0、AUTO=2、AES128_GCM=3、CHACHA20_POLY1305=4、NONE=5、ZERO=6）
/// 与 `infra/conf/vmess.go` 的配置取值（`aes-128-gcm` / `chacha20-poly1305` /
/// `auto` / `none` / `zero`）。
///
/// **作用范围**：安全档只作用于**数据段**（body）的 AEAD 与长度段；请求头
/// 与响应头两段的 AEAD 在参考里恒为 AES-128-GCM
/// （`proxy/vmess/aead/encrypt.go` 两侧都写死 `crypto.NewAesGcm`），
/// 与安全档无关。详见 [`crate::bodyframe`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityOption {
    /// 无 AEAD（载荷明文 + chunk 掩码；参考 `SecurityType_NONE`）。
    None,
    /// AES-128-GCM（数据段密钥 = 16B bodyKey）。
    Aes128Gcm,
    /// ChaCha20-Poly1305（数据段密钥 = `MD5(b) || MD5(MD5(b))` 扩展出的 32B）。
    ChaCha20Poly1305,
    /// autocipher 哨兵（`SecurityType_AUTO`）：本层**不解析**，调用方必须先
    /// 解析成具体套件；未解析即使用一律 fail-closed。
    ///
    /// 参考的解析规则在 `common/protocol/headers.go` 的
    /// `SecurityConfig.GetSecurityType()`：AUTO 在有 AES-GCM 硬件支持时解析成
    /// AES-128-GCM，否则解析成 ChaCha20-Poly1305。**本层刻意不代劳**——
    /// 自动选档是调用方/会话层的策略，原语层不替它做决定，但也不会默认 AES。
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

    /// 解析成数据段套件；`AutoCipher` 哨兵**不解析**，返回 `None`。
    ///
    /// 调用方拿到 `None` 必须自己决定档位或拒绝——原语层不默认 AES。
    #[must_use]
    pub const fn resolve(self) -> Option<crate::bodyframe::BodySuite> {
        match self {
            SecurityOption::None => Some(crate::bodyframe::BodySuite::None),
            SecurityOption::Aes128Gcm => Some(crate::bodyframe::BodySuite::Aes128Gcm),
            SecurityOption::ChaCha20Poly1305 => Some(crate::bodyframe::BodySuite::ChaCha20Poly1305),
            SecurityOption::AutoCipher => None,
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
