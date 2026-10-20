//! 多安全档测试胶水：按档位构造请求头明文与数据段帧。
//!
//! 本模块只做**胶水**（把 `lengsuo_vmess` 的原语拼成可上线的字节），
//! 不实现任何密码学——套件分派与分帧全部由 `lengsuo_vmess::bodyframe` 负责。
//!
//! 档位与线格式的对应（对齐参考固定 commit `d2758a02`）：
//! - 安全档只作用于**数据段**；请求头 / 响应头两段恒为 AES-128-GCM
//!   （`proxy/vmess/aead/encrypt.go` 两侧都写死 `crypto.NewAesGcm`）。
//! - `none` 档在参考里**必须**配 `ChunkStream`：否则服务端退化成无分帧裸流
//!   （`proxy/vmess/encoding/server.go` 的 `SecurityType_NONE` 分支最后一档
//!   `buf.NewReader(reader)`）。
//! - `none` 档**不吃** `GlobalPadding`：参考的 NONE 分支走
//!   `ChunkStreamReader/Writer`，整条 padding 路径被跳过（两端都跳过）。
//! - `aes-128-gcm` / `chacha20-poly1305` 走 `AuthenticationReader/Writer`：
//!   长度段形态由 option 决定（裸 / Shake 掩码 / AEAD 认证），载荷恒 AEAD。
//! - `AuthenticatedLength` 只影响长度段：载荷 AEAD 与长度段 AEAD 各持**独立**
//!   的 nonce 计数器（参考里是两个独立的 `GenerateChunkNonce` 闭包）。

#![allow(dead_code)] // 本模块被多个测试编译单元共享，各单元只用自己的子集。

use lengsuo_vmess::bodyframe::{BodyFrame, BodySuite};
use lengsuo_vmess::request::{Command, HeaderPlanner, KeySource, RequestHeader, SecurityOption};
use lengsuo_vmess::Error;
use ss_core::target::TargetAddr;

/// 一个可参与互通的安全档。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// `SecurityType_NONE`（线上字节 5）。
    None,
    /// `SecurityType_AES128_GCM`（线上字节 3）。
    Aes,
    /// `SecurityType_CHACHA20_POLY1305`（线上字节 4）。
    ChaCha,
}

impl Tier {
    /// 三个可互通档位（`AutoCipher` 哨兵不在此列——它必须先被调用方解析）。
    pub const ALL: [Self; 3] = [Self::None, Self::Aes, Self::ChaCha];

    /// 对应的请求头安全档枚举。
    #[must_use]
    pub const fn security(self) -> SecurityOption {
        match self {
            Self::None => SecurityOption::None,
            Self::Aes => SecurityOption::Aes128Gcm,
            Self::ChaCha => SecurityOption::ChaCha20Poly1305,
        }
    }

    /// 对应的数据段套件。
    #[must_use]
    pub const fn body_suite(self) -> BodySuite {
        match self {
            Self::None => BodySuite::None,
            Self::Aes => BodySuite::Aes128Gcm,
            Self::ChaCha => BodySuite::ChaCha20Poly1305,
        }
    }

    /// Xray 配置里 `security` 字段的取值。
    #[must_use]
    pub const fn xray_name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Aes => "aes-128-gcm",
            Self::ChaCha => "chacha20-poly1305",
        }
    }

    /// 本档位使用的请求 option 位。
    ///
    /// - `none`：`ChunkStream | ChunkMasking`（参考 NONE 分支要求 ChunkStream；
    ///   且该分支跳过 GlobalPadding）。
    /// - `aes` / `chacha`：`ChunkStream | ChunkMasking | GlobalPadding`
    ///   （与参考出口 `proxy/vmess/outbound/outbound.go` 的默认组合一致）。
    #[must_use]
    pub const fn request_option(self) -> u8 {
        match self {
            Self::None => 0x01 | 0x04,
            Self::Aes | Self::ChaCha => 0x01 | 0x04 | 0x08,
        }
    }

    /// 叠加 `AuthenticatedLength` 后的 option（参考用 `experiments` 开关）。
    #[must_use]
    pub const fn request_option_auth_len(self) -> u8 {
        self.request_option() | 0x10
    }
}

/// 由解码出的头安全档反推数据段套件；`Zero`（参考头阶段放行、体阶段拒绝）→ `None`。
#[must_use]
pub fn suite_from_header_security(
    security: lengsuo_vmess::server::HeaderSecurity,
) -> Option<BodySuite> {
    use lengsuo_vmess::server::HeaderSecurity;
    match security {
        HeaderSecurity::None => Some(BodySuite::None),
        HeaderSecurity::Aes128Gcm => Some(BodySuite::Aes128Gcm),
        HeaderSecurity::ChaCha20Poly1305 => Some(BodySuite::ChaCha20Poly1305),
        HeaderSecurity::Zero => None,
    }
}

/// 请求头明文（封装前字节）：档位写进 security 字节低 4 位。
pub fn build_request_plaintext(
    keys: &KeySource,
    target: &TargetAddr,
    tier: Tier,
    option: u8,
) -> Result<Vec<u8>, Error> {
    let planner = HeaderPlanner::new(KeySource {
        body_key: keys.body_key,
        body_iv: keys.body_iv,
        response_header: keys.response_header,
    });
    planner.plan_with(
        &RequestHeader {
            target: Some(target.clone()),
            command: Command::Tcp,
            security: tier.security(),
            option,
            padding_len: 0,
        },
        &[],
    )
}

/// 请求方向的数据段帧上下文（载荷用请求方向的 body key/iv）。
pub fn request_frame(
    suite: BodySuite,
    body_key: &[u8; 16],
    body_iv: &[u8; 16],
    option: u8,
) -> Result<BodyFrame, Error> {
    BodyFrame::for_request(suite, body_key, body_iv, body_key, body_iv, option)
}

/// 响应方向的数据段帧上下文。
///
/// 载荷用响应方向的 body key/iv（`SHA256(requestBodyKey/IV)[:16]`）；认证长度段
/// 仍取**请求方向**的 key/iv（对齐参考 `proxy/vmess/encoding/server.go` 的
/// `EncodeResponseBody`：`KDF16(s.requestBodyKey, "auth_len")` +
/// `GenerateChunkNonce(s.requestBodyIV)`）。
pub fn response_frame(
    suite: BodySuite,
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    request_key: &[u8; 16],
    request_iv: &[u8; 16],
    option: u8,
) -> Result<BodyFrame, Error> {
    BodyFrame::for_request(
        suite,
        response_key,
        response_iv,
        request_key,
        request_iv,
        option,
    )
}
