//! VLESS **XEL 承载**接线：把 `lengsuo_vless::xel_wire` 的库级原语接成 node 的
//! 产品级承载（`VlessStream::Xel`）。
//!
//! # 分层（与参考逐层对齐）
//!
//! 参考 `proxy/vless/outbound/outbound.go:211-216`（固定 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）：
//!
//! ```go
//! if h.encryption != nil {
//!     if conn, err = h.encryption.Handshake(conn); err != nil { ... }
//! }
//! ```
//!
//! ⇒ XEL **紧贴传输层、在 VLESS 请求头之前**：请求头、响应头与全部业务载荷都
//! 走记录层（`proxy/vless/encoding/encoding.go:30` 的 `EncodeRequestHeader` 写的
//! `conn` 此时已是 `*encryption.CommonConn`）。
//!
//! 线上的字节顺序来自参考 `proxy/vless/encryption/{common.go,xor.go}`：
//!
//! ```text
//! 明文 → AEAD 记录(5 字节头作 AAD + 记录体) → XOR 掩蔽 5 字节头 → TCP
//! ```
//!
//! 本仓 `lengsuo_vless::xel_wire::XelStream` 已把这套顺序（以及 8192 字节分块、
//! 锁定步序号、fail-closed poison）完整实现 ⇒ **本模块只做「配置 → 建流」的
//! 编排**，不复制任何记录层逻辑。
//!
//! # 与参考的有意偏离（ML-KEM 会话握手）
//!
//! 参考的 `Handshake`（`proxy/vless/encryption/client.go`）走
//! `mlkem768x25519plus.` 会话握手：UnitedKey / IV / 两端 AEAD 由 ML-KEM-768 +
//! X25519 协商得出，线上握手报文（`ivAndRealysLength + pfsKeyExchangeLength`）
//! 也由它产生。本仓没有 ML-KEM ⇒ 本模块从「**会话密钥与 IV 已就绪**」这一层接：
//! 密钥与 IV 由配置给出（与 `outbound_vless_vision` 记录层的偏离口径一致）。
//!
//! ⇒ **带 XEL 的连接无法与参考进程互通**（参考先要跑 ML-KEM 握手，本仓不发那段
//! 报文）。回环用例因此用本仓自己的对端（同一套原语，方向对调），不冒充互通。
//!
//! # 用例为什么让**服务端先写**
//!
//! 参考服务端的响应头被 `buf.BufferedWriter` 滞留到第一次 `WriteMultiBuffer`
//! （`common/buf/writer.go:165` 的 `flushNext` 只在**下一次**写时触发），而
//! `outbound_vless` 的主链路是「写请求头 → 等响应头」。本仓的 VLESS 回环服务端
//! 因此先发响应头再读请求头：线上顺序仍是「请求头在前、响应头在后」（TCP 全双工，
//! 与参考客户端/服务端各自的读写顺序一致），同时避免用例互锁。

use std::time::Duration;

use lengsuo_vless::header::Request;
use lengsuo_vless::stream::{receive_response, send_request};
use lengsuo_vless::xel::aead::XelCipher;
use lengsuo_vless::xel::XelKey;
use lengsuo_vless::xel_wire::{Error as XelWireError, XelStream, XelWireConfig, XorLayer};
use tokio::io::AsyncWrite;

use crate::config::NodeConfig;
use crate::outbound::DialError;

/// XEL 是否启用（参考 `a.Encryption != "" && a.Encryption != "none"`）。
#[must_use]
pub fn xel_enabled(config: &NodeConfig) -> bool {
    config.xel.is_some()
}

/// XEL 线路错误 → 拨号错误（fail-closed；消息不含密钥材料）。
pub fn xel_dial_error(error: XelWireError) -> DialError {
    DialError::Rejected(format!("xel 配置非法：{error}"))
}

/// 十六进制文本 → 字节（大小写不敏感；奇数长度或非法字符 ⇒ 失败）。
///
/// XEL 的密钥在参考里来自 ML-KEM 会话握手（本仓没有，见模块文档），
/// 故由配置以十六进制文本给出。
pub(crate) fn hex_to_bytes(text: &str) -> Result<Vec<u8>, XelWireError> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let invalid = || {
        XelWireError::Record(lengsuo_vless::xel::Error::InvalidKeyLength {
            got: compact.len(),
            want: lengsuo_vless::xel::KEY_LEN,
        })
    };
    if !compact.len().is_multiple_of(2) {
        return Err(invalid());
    }
    let mut out = Vec::with_capacity(compact.len() / 2);
    for pair in compact.as_bytes().chunks(2) {
        let high = (pair[0] as char).to_digit(16).ok_or_else(invalid)?;
        let low = (pair[1] as char).to_digit(16).ok_or_else(invalid)?;
        out.push(((high << 4) | low) as u8);
    }
    Ok(out)
}

/// 套件名 → 协议 crate 的 [`XelCipher`]（参考 `useAES` 二选一）。
///
/// 参考按**本端 CPU** 是否支持 AES-GCM 选 `useAES`（`protocol.HasAESGCMHardwareSupport`）；
/// 那是本地实现细节而非线上协商字段 ⇒ 本仓按配置名显式选择，两端可不同。
fn cipher_from_name(name: &str) -> Result<XelCipher, XelWireError> {
    match name {
        "aes-256-gcm" => Ok(XelCipher::Aes256Gcm),
        "chacha20-poly1305" => Ok(XelCipher::ChaCha20Poly1305),
        other => Err(XelWireError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("xel.cipher 未知：{other}"),
        ))),
    }
}

/// 定长 IV（16 字节 AES 块长；错误的长度由 `XorLayer::new` 拒绝，此处先校验便于
/// 给出配置级报错）。
fn iv_from_hex(text: &str) -> Result<[u8; lengsuo_vless::xel_wire::XOR_IV_LEN], XelWireError> {
    let bytes = hex_to_bytes(text)?;
    let want = lengsuo_vless::xel_wire::XOR_IV_LEN;
    if bytes.len() != want {
        return Err(XelWireError::Record(
            lengsuo_vless::xel::Error::InvalidIvLength {
                got: bytes.len(),
                want,
            },
        ));
    }
    let mut iv = [0u8; lengsuo_vless::xel_wire::XOR_IV_LEN];
    iv.copy_from_slice(&bytes);
    Ok(iv)
}

/// node 配置 → 协议 crate 的 XEL 配置。
///
/// 密钥方向以**本端**为基准（`uplink_key` = 本端发送）：对端必须把同一份材料
/// 对调（服务端的 `uplink` = 客户端的 `downlink`）。
fn wire_config(config: &NodeConfig) -> Result<XelWireConfig, XelWireError> {
    let Some(xel) = &config.xel else {
        return Err(XelWireError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "未配置 xel 段",
        )));
    };
    let uplink_key = XelKey::new(&hex_to_bytes(&xel.uplink_key)?)?;
    let downlink_key = XelKey::new(&hex_to_bytes(&xel.downlink_key)?)?;
    // 参考 `encryption/client.go:123` 的 `XorMode == 2` 才套 XorConn；`XorMode == 1`
    // 与 0 都只用 `CommonConn`（`xor: None`）。
    let xor = match &xel.xor {
        Some(xor) => Some(XorLayer::new(
            XelKey::new(&hex_to_bytes(&xor.send_key)?)?,
            &iv_from_hex(&xor.send_iv)?,
            XelKey::new(&hex_to_bytes(&xor.recv_key)?)?,
            &iv_from_hex(&xor.recv_iv)?,
        )?),
        None => None,
    };
    Ok(XelWireConfig {
        cipher: cipher_from_name(&xel.cipher)?,
        uplink_key,
        downlink_key,
        xor,
    })
}

/// 建流前的配置预检（fail-closed）：密钥 / IV / 套件任何一项非法 ⇒ 在**建任何
/// 连接之前**失败（参考在拨号前就已完成 `encryption.Init`，不会带着坏配置去连）。
pub fn precheck(config: &NodeConfig) -> Result<(), XelWireError> {
    wire_config(config).map(|_| ())
}

/// 把已握好的承载包装成 XEL 记录层字节流。
///
/// 承载可以是 TLS（`NodeTlsStream`）、REALITY（`RealityStream`）或别的字节流：
/// XEL 记录层只要求「一条已建立的字节流」（参考里就是 `conn`）。
pub fn wrap<T>(transport: T, config: &NodeConfig) -> Result<XelStream, XelWireError>
where
    T: AsyncWrite + tokio::io::AsyncRead + Unpin + Send + 'static,
{
    XelStream::new(transport, wire_config(config)?)
}

/// XEL 承载上的 VLESS 握手：写请求头 → 读成功响应头（`[0, 0]`）。
///
/// 与普通 TLS 承载**完全同一条主链路**（`send_request` + `receive_response`）——
/// 记录层已经把 `XelStream` 变成普通字节流。认证判据因此与 Vision 侧口径一致：
/// 只有拿到成功响应头才算认证完成。
pub async fn handshake(
    stream: &mut XelStream,
    request: &Request,
    credential: [u8; 16],
    wait: Duration,
) -> Result<(), DialError> {
    send_request(stream, request, &credential, wait).await?;
    receive_response(stream, wait).await?;
    Ok(())
}
