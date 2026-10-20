//! VMess 线格式常量（对照 Xray `proxy/vmess/aead/consts.go` 与 `proxy/vmess/encoding/*.go`）。
//!
//! 派生路径常量逐字照抄 `consts.go`；**不要**改动任何字符串内容，改动即协议偏离。
//! 注意语义差异：VMess 数据段 nonce 为**大端**递增（`common/crypto.go` 对 uint64 做
//! `binary.Write(BigEndian)`），与 ss-core `crypto::NonceCounter` 的小端进位方向相反，
//! 因此数据段不能复用该计数器。

/// AuthID 长度（AEAD 封装的 8B 时间戳 + 4B 随机 + 4B CRC32 后单块 AES-128-ECB 加密）。
pub const AUTH_ID_LEN: usize = 16;
/// 连接侧随机 nonce 长度（`SealVMessAEADHeader` 的 connectionNonce）。
pub const CONNECTION_NONCE_LEN: usize = 8;
/// 请求头明文里的 IV 长度（安全项开启时兼作数据段初始 nonce，大端递增）。
pub const HEADER_IV_LEN: usize = 16;
/// 请求头明文里的对称密钥长度（同时用作数据段认证密钥与 ID 派生种子）。
pub const HEADER_KEY_LEN: usize = 16;
/// 认证响应密文长度（`AuthResponseEncrypt`：4B 明文 + 16B tag）。
pub const AUTH_RESPONSE_LEN: usize = 20;
/// VMess 请求头版本字节。
pub const VMESS_VERSION: u8 = 1;

/// 命令字节：转发 TCP。
pub const CMD_NONE_TCP: u8 = 1;
/// 命令字节：转发 UDP。
pub const CMD_UDP: u8 = 2;

/// 安全选项（`common/protocol/headers.pb.go` 的 SecurityType，线字节即枚举值）：
/// UNKNOWN=0、AUTO=2、AES128_GCM=3、CHACHA20_POLY1305=4、NONE=5、ZERO=6。
pub const SECURITY_NONE: u8 = 5;
/// 安全选项：请求头与数据段使用 AES-128-GCM（`SecurityType_AES128_GCM`）。
pub const SECURITY_AES_128_GCM: u8 = 3;
/// 安全选项：请求头与数据段使用 ChaCha20-Poly1305（`SecurityType_CHACHA20_POLY1305`）。
pub const SECURITY_CHACHA20_POLY1305: u8 = 4;
/// `SecurityType_AUTO`（=2）的 autocipher 哨兵值；本层不解析，调用方先解析为具体套件。
pub const SECURITY_AUTOCIPHER: u8 = 2;

/// AES-128-GCM 的 key/nonce 长度。
pub const AES_GCM_KEY_LEN: usize = 16;
/// AES-128-GCM nonce 长度。
pub const AES_GCM_NONCE_LEN: usize = 12;
/// ChaCha20-Poly1305（IETF）key 长度。
pub const CHACHA_KEY_LEN: usize = 32;
/// ChaCha20-Poly1305（IETF）nonce 长度。
pub const CHACHA_NONCE_LEN: usize = 12;
/// AEAD tag 长度。
pub const AEAD_TAG_LEN: usize = 16;

/// `SecurityConfig` 各方法的密钥长度（`protocol.go`）。
pub fn security_key_len(security: u8) -> Option<usize> {
    match security {
        SECURITY_NONE => Some(0),
        SECURITY_AES_128_GCM => Some(16),
        SECURITY_CHACHA20_POLY1305 => Some(32),
        _ => None,
    }
}

/// `SecurityConfig` 各方法的认证密钥长度（`protocol.go` 的 AuthKeyLen）。
pub fn security_auth_key_len(security: u8) -> Option<usize> {
    match security {
        SECURITY_NONE => Some(0),
        SECURITY_AES_128_GCM | SECURITY_CHACHA20_POLY1305 => Some(16),
        _ => None,
    }
}

/// `SecurityConfig` 各方法的请求头 IV 长度（`protocol.go` 的 RequestHeaderIVLen 等）。
pub fn security_iv_len(security: u8) -> Option<usize> {
    match security {
        SECURITY_NONE => Some(0),
        SECURITY_AES_128_GCM | SECURITY_CHACHA20_POLY1305 => Some(12),
        _ => None,
    }
}

// ---- KDF 派生路径常量（对应 KDFSaltConst*）----

/// `KDFSaltConstAuthIDEncryptionKey`
pub const KDF_SALT_AUTH_ID_ENCRYPTION_KEY: &str = "AES Auth ID Encryption";
/// `KDFSaltConstAEADRespHeaderLenKey`
pub const KDF_SALT_AEAD_RESP_HEADER_LEN_KEY: &str = "AEAD Resp Header Len Key";
/// `KDFSaltConstAEADRespHeaderLenIV`
pub const KDF_SALT_AEAD_RESP_HEADER_LEN_IV: &str = "AEAD Resp Header Len IV";
/// `KDFSaltConstAEADRespHeaderPayloadKey`
pub const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY: &str = "AEAD Resp Header Key";
/// `KDFSaltConstAEADRespHeaderPayloadIV`
pub const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV: &str = "AEAD Resp Header IV";
/// `KDFSaltConstVMessAEADKDF`：KDF 外层恒定 HMAC key。
pub const KDF_SALT_VMESS_AEAD_KDF: &str = "VMess AEAD KDF";
/// `KDFSaltConstVMessHeaderPayloadAEADKey`
pub const KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_KEY: &str = "VMess Header AEAD Key";
/// `KDFSaltConstVMessHeaderPayloadAEADIV`
pub const KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_IV: &str = "VMess Header AEAD Nonce";
/// `KDFSaltConstVMessHeaderPayloadLengthAEADKey`
pub const KDF_SALT_VMESS_HEADER_LEN_AEAD_KEY: &str = "VMess Header AEAD Key_Length";
/// `KDFSaltConstVMessHeaderPayloadLengthAEADIV`
pub const KDF_SALT_VMESS_HEADER_LEN_AEAD_IV: &str = "VMess Header AEAD Nonce_Length";

// ---- 客户端解码响应头用的服务端固定盐（对应旧客户端写法）----

/// 服务端认证响应的 ID 派生盐（旧客户端硬编码的 "b12abad82361fc57"）。
pub const AUTH_RESPONSE_ID_SALT: &[u8] = b"b12abad82361fc57";
/// 服务端认证响应的 AES key 派生盐（"u8mgbskx0wkcnalc"）。
pub const AUTH_RESPONSE_KEY_SALT: &[u8] = b"u8mgbskx0wkcnalc";
/// 服务端认证响应的 nonce 派生盐，并取其前 12 字节（"chkv9mg3p6omkmu"）。
pub const AUTH_RESPONSE_IV_SALT: &[u8] = b"chkv9mg3p6omkmu";
/// MD5 链式派生输出的认证密钥长度（旧客户端使用 8 字节，而非 Go 的 16 字节）。
pub const AUTH_RESPONSE_AUTH_KEY_LEN: usize = 8;

// ---- 选项字节（`common/protocol/headers.go` 的 `RequestOption*` 位掩码）----
//
// 现行参考（固定 commit d2758a02）用 0x01/0x04/0x08/0x10 四位；0x02 是历史
// 遗留位（参考注释 "0x02 legacy setting"），0x04 不是旧版的 http-upgrade。

/// `RequestOptionChunkStream`：载荷按 chunk 分帧（参考 0x01）。
pub const OPTION_CHUNK_STREAM: u8 = 0x01;
/// `RequestOptionChunkMasking`：长度段用 SHA3-Shake128 掩码（参考 0x04）。
pub const OPTION_CHUNK_MASKING: u8 = 0x04;
/// `RequestOptionGlobalPadding`：每帧追加明文随机 padding（参考 0x08）。
///
/// 参考要求同时开启 `ChunkMasking`（padding 长度取自同一条 Shake 流），
/// 否则参考直接报 `invalid option: RequestOptionGlobalPadding`。
pub const OPTION_GLOBAL_PADDING: u8 = 0x08;
/// `RequestOptionAuthenticatedLength`：长度段本身走 AEAD（参考 0x10）。
///
/// 长度段密钥 = `KDF16(requestBodyKey, "auth_len")` 再按安全档派生
/// （AES 直接用 16B；ChaCha 走 MD5 链扩展成 32B），nonce 基值取**请求方向**的
/// requestBodyIV，计数器与载荷段各自独立。
pub const OPTION_AUTHENTICATED_LENGTH: u8 = 0x10;

/// 参考出口对 AES-128-GCM / ChaCha20-Poly1305 / none 的默认选项组合
/// （`proxy/vmess/outbound/outbound.go`：ChunkStream | ChunkMasking |
/// GlobalPadding）。
pub const REQUEST_OPTIONS: u8 = OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING;

// ---- 旧版选项位（仅历史参考，仓库内无使用点）----
//
// 旧版 VMess 曾用 0x01/0x02/0x04 表示 additional-data / one-time-auth /
// http-upgrade。现行参考已不再发送这些位（见 `proxy/vmess/encoding/client.go`
// 的 `EncodeRequestHeader`），保留常量仅供历史对照，不得用于新代码。

/// 旧版：全局附加数据。
pub const OPTION_GLOBAL_ADDITIONAL_DATA: u8 = 0x01;
/// 旧版：一次性认证。
pub const OPTION_ONE_TIME_AUTHENTICATION: u8 = 0x02;
/// 旧版：HTTP 升级。
pub const OPTION_HTTP_UPGRADE: u8 = 0x04;

/// 短 ID 长度（`id.go` 的 GenerateID 取 MD5(UUID)[:8]）。
pub const SHORT_ID_LEN: usize = 8;
/// 短 ID 毫秒时间戳长度（BE 6 字节，`client.go` 的 binary.BigEndian.PutUint32 + uint16 秒补齐）。
pub const SHORT_ID_TS_LEN: usize = 6;
/// 短 ID 派生用的动态校验盐（`id.go` 的 DynamicPayloadVerifiedSalt）。
pub const SHORT_ID_DPV_SALT: &[u8] = b"0dc423380c124852322e1830bf6a2e7e";
/// 短 ID AES-ECB 密钥派生盐（`id.go` 的 DeriveKdfKey）。
pub const SHORT_ID_KDF_SALT: &[u8] = b"05a308d1df3928b3fb4c011112717e51";

/// 时间窗默认值（`authid.go` 的 Match 判据：|ts - now| > 120 秒即无效）。
pub const AUTH_ID_TIME_WINDOW_SECS: i64 = 120;
