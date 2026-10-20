//! REALITY 客户端握手层（X25519 + 认证载荷 + 短 ID）。
//!
//! 参考与 VLESS 同基线：Xray v26.3.27 `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，
//! 权威实现见 `transport/internet/reality/reality.go` 的 `UClient` 内联块，
//! 服务端校验见 `github.com/xtls/reality` 的 `tls.go`（`X25519` 共享密钥 +
//! `hkdf(SHA-256)` + `AES-256-GCM` 认证载荷）与 `handshake_server_tls13.go`
//! （`HMAC-SHA512` 证书签名）。本模块转写这两侧都用到的那部分。
//!
//! **范围**：纯逻辑层——ClientHello 字段（SessionId 32 字节布局）的构造与
//! 校验、X25519 密钥协商、认证载荷 AEAD 封装/解封、证书 Ed25519 公钥的
//! `HMAC-SHA512` 校验。**不建真实 TLS 记录层、不做 uTLS 浏览器指纹伪装**，
//! 这两项由独立卡覆盖（见 `docs/vless-status.md`）。
//!
//! # 认证载荷布局（32 字节明文，见参考 `tls.go` 服务端解密后的字段偏移）
//!
//! ```text
//! [0]    = Version_x      \
//! [1]    = Version_y       |  客户端 Xray 版本三元组
//! [2]    = Version_z      /
//! [3]    = 0（保留）
//! [4..7] = Unix 时间戳（big-endian u32）
//! [8..31] = 短 ID 填充区（客户端 `copy(SessionId[8:], config.ShortId)`，
//!          不足 8 字节的短 ID 在高位补 0，服务端取 `plainText[8:]` 即 24 字节；
//!          服务端 `c.ShortIds` 以 `[8]byte` 为键，因此只有前 8 字节参与匹配）
//! ```
//!
//! 加密为 `AES-256-GCM`，nonce = `ClientHello.random[20:32]`，AAD = 完整
//! ClientHello 原始字节，输出（密文 32 + tag 16 = 48 字节）从
//! `SessionId` 起始处就地写回 `raw[39..87]`。
//!
//! # 与参考的唯一既定偏离
//!
//! 参考 `reality.go:168` 把 **HKDF 输出写回同一个 `AuthKey` 切片**，随后
//! `crypto.NewAesGcm(uConn.AuthKey)` 当密钥用——即 TCP 上的真实密钥是
//! `HKDF-SHA256(ikm=ECDH, salt=random[:20], info="REALITY")`。
//! `xtls/reality` 服务端 `tls.go:230-236` 同样如此（`X25519` → 同一 HKDF），
//! 两端一致，本模块按此对齐。注意 `UClient` 里 **`hello.SessionId` 30 字节的
//! `copy` 不会发生**（`make([]byte,32)` 恒为 32 字节），所以 `[30]/[31]` 始终
//! 为 0，这是参考的实际行为，本模块照搬而非「修正」。

pub mod auth;
pub mod client;
pub mod hash;
pub mod server;
pub mod session;
pub mod shortid;
pub mod tls13;
pub mod x25519;

use thiserror::Error;

/// 客户端 Xray 版本三元组。参考写在 `SessionId[0..3]`
/// （`core.Version_x/y/z`，`reality.go:139-141`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientVersion {
    pub x: u8,
    pub y: u8,
    pub z: u8,
}

impl ClientVersion {
    /// 编码为 `SessionId[0..3]`。
    pub fn to_bytes(self) -> [u8; 3] {
        [self.x, self.y, self.z]
    }
}

/// REALITY 客户端配置。
///
/// 字段语义对齐 `transport/internet/reality/config.pb.go` 的客户端子集：
/// `server_name`(22) / `public_key`(23) / `short_id`(24) / `Fingerprint`(21)。
#[derive(Debug, Clone)]
pub struct RealityClientConfig {
    /// `serverName`。参考里为空时回退到目标地址（`reality.go:128-130`）。
    pub server_name: Option<String>,
    /// 服务端 X25519 公钥（base64 raw-url 解码后的 32 字节）。
    pub public_key: [u8; 32],
    /// 短 ID。默认全 0（8 字节）。
    pub short_id: [u8; 8],
    /// uTLS 指纹。本卡**不实现**指纹伪装，仅做 fail-closed 的取值校验。
    pub fingerprint: Fingerprint,
}

impl RealityClientConfig {
    /// `serverName` 为空时按参考回退到目标地址。
    pub fn effective_server_name<'a>(&'a self, dest: &'a str) -> &'a str {
        match self.server_name.as_deref() {
            Some(s) if !s.is_empty() => s,
            _ => dest,
        }
    }
}

/// uTLS ClientHello 指纹。
///
/// 参考 `tls.GetFingerprint`（`transport/internet/tls/tls.go:180`）：
/// 空串归一为 `HelloChrome_Auto`；命中预设表返回对应 `ClientHelloID`；
/// **未识别值返回 `nil`**，`UClient` 随即报错
/// （`reality.go:131-134`："failed to get fingerprint"）。
///
/// 即：未识别值在参考里是**硬失败**而非回退 Chrome，本枚举按此 fail-closed。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fingerprint {
    /// `""` → `utls.HelloChrome_Auto`（参考的默认值，不是「无指纹」）。
    Default,
    Chrome,
    Firefox,
    Safari,
    Ios,
    Android,
    Edge,
    /// `"360"`。
    ThreeSixty,
    /// `"qq"`。
    Qq,
    /// `"randomized"` / `"randomizednoalpn"`：参考配置期为 `nil`
    /// （实际值在启动时从 `ModernFingerprints` 随机挑选）。
    Randomized,
    /// `"unsafe"`：参考显式登记为 `nil`，同样在启动时才落实。
    Unsafe,
    /// `ModernFingerprints` 里的具名指纹（如 `hellochrome_131`）。
    Modern(&'static str),
}

/// 指纹解析失败。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FingerprintError {
    /// 参考在此返回 `nil` 指纹并让 `UClient` 报错。**不得静默降级**。
    #[error("REALITY: unrecognized fingerprint: {0}")]
    Unrecognized(String),
}

impl Fingerprint {
    /// 按参考 `GetFingerprint` 的查表语义解析。
    ///
    /// 注意：`"random"` 在参考里映射到 `nil`（表里显式写出 `nil` 值），
    /// 走的是 `GetFingerprint` 末尾的 `return`（零值），因此**同样失败**。
    pub fn parse(name: &str) -> Result<Self, FingerprintError> {
        let fp = match name {
            "" => Self::Default,
            "chrome" => Self::Chrome,
            "firefox" => Self::Firefox,
            "safari" => Self::Safari,
            "ios" => Self::Ios,
            "android" => Self::Android,
            "edge" => Self::Edge,
            "360" => Self::ThreeSixty,
            "qq" => Self::Qq,
            "randomized" | "randomizednoalpn" => Self::Randomized,
            "unsafe" => Self::Unsafe,
            // 参考的 `PresetFingerprints` 里 "random" 是 nil，归零后失败。
            "random" => return Err(FingerprintError::Unrecognized(name.to_string())),
            _ => match MODERN_FINGERPRINTS.iter().find(|f| **f == name) {
                Some(f) => Self::Modern(f),
                None => return Err(FingerprintError::Unrecognized(name.to_string())),
            },
        };
        Ok(fp)
    }
}

/// `tls.ModernFingerprints` 的具名键（`tls.go:210+`）。
///
/// 仅登记**名字**用于取值校验；本卡不实现对应的 ClientHello 构造。
pub(crate) const MODERN_FINGERPRINTS: &[&str] = &[
    "hellofirefox_99",
    "hellofirefox_102",
    "hellofirefox_105",
    "hellofirefox_120",
    "hellochrome_83",
    "hellochrome_87",
    "hellochrome_96",
    "hellochrome_100",
    "hellochrome_102",
    "hellochrome_106_shuffle",
    "hellochrome_120",
    "hellochrome_131",
    "helloios_13",
    "helloios_14",
    "helloedge_85",
    "helloedge_106",
    "hellosafari_16_0",
];

/// REALITY 握手层错误。全部 fail-closed：任一步失败都不得继续明文外发。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RealityError {
    #[error(transparent)]
    Fingerprint(#[from] FingerprintError),
    #[error(transparent)]
    ShortId(#[from] shortid::ShortIdError),
    #[error(transparent)]
    Auth(#[from] auth::AuthError),
}
