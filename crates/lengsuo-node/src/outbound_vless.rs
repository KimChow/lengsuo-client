//! VLESS 出口：TLS（或 REALITY）→ 请求头 → **成功响应头** 正向确认。
//!
//! 语义来源（只读参考，固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）：
//! Xray `proxy/vless/outbound/outbound.go` 的 `Process` 里，客户端在写出请求头后
//! 会读服务端响应：`proxy/vless/outbound/outbound.go` 调用
//! `encoding.DecodeResponse`/`ReadOnce`，期望**恰好两个零字节**（
//! `proxy/vless/inbound/inbound.go` 在目标连接建立成功后才写 `[0, 0]`）。
//! 因此 vless 与 trojan 不同：它有明确的**正向**认证完成证据。
//!
//! 本仓 `lengsuo-vless` 的 `stream::receive_response` 正是这两个字节的校验
//! （非 `[0, 0]` 一律 `Err(Unsupported)`），因此这里不需要观察窗。
//!
//! ## 两条安全层路径（判据相同）
//!
//! | 配置 | 承载 | 说明 |
//! | --- | --- | --- |
//! | 无 `reality` 段 | 普通 TLS（`lengsuo_tls`） | 既有行为，逐字节不变 |
//! | 有 `reality` 段 | REALITY + TLS 1.3（`lengsuo_vless::reality_link`） | 库级原语接进产品链路 |
//!
//! 两条路径**共用同一段 VLESS 主链路**：`stream::send_request` →
//! `stream::receive_response`。认证完成判据都是「收到 `[0, 0]`」。
//! REALITY 分支的握手语义**全部**来自协议 crate
//! （`lengsuo_vless::reality_config` / `lengsuo_vless::reality_link`），
//! node 侧只做「配置 → 建流」的编排。
//!
//! 偏离：uuid → 16 字节凭据直接取 UUID 文本的十六进制字节（`ss_core` 无 UUID
//! 类型，且参考的 ID 在线上就是原始 16 字节）；Vision/flow 不在本卡范围。

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use lengsuo_vless::header::{Command as VlessCommand, Request};
use lengsuo_vless::reality_config::{RealityConfig, RealitySettings};
use lengsuo_vless::reality_link::RealityStream;
use lengsuo_vless::stream::{receive_response, send_request};
use ss_core::target::TargetAddr;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::config::NodeConfig;
use crate::outbound::{connect_tls, probe_target, resolve_public, DialError, NodeTlsStream};

/// vless 出站的承载流：普通 TLS 或 REALITY。
///
/// 两种承载都实现 `AsyncRead` + `AsyncWrite`（REALITY 侧由
/// `lengsuo_vless::reality_link::RealityStream` 提供），所以 **VLESS 主链路
/// 函数（`send_request` / `receive_response`）对两者完全一致**。
pub enum VlessStream {
    /// 普通 TLS 承载（`TlsStream<TcpStream>`）。
    ///
    /// 装箱：`TlsStream` 体积远大于 REALITY 承载，不装箱会让整个枚举按最大
    /// 变体对齐（对齐 `forward::session` 里 `OutboundReader` 的同一处理）。
    Tls(Box<NodeTlsStream>),
    /// REALITY + TLS 1.3 承载（记录层已摊平成字节流）。
    Reality(RealityStream),
}

impl AsyncRead for VlessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Tls(stream) => Pin::new(&mut **stream).poll_read(cx, buf),
            Self::Reality(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Tls(stream) => Pin::new(&mut **stream).poll_write(cx, buf),
            Self::Reality(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Tls(stream) => Pin::new(&mut **stream).poll_flush(cx),
            Self::Reality(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Tls(stream) => Pin::new(&mut **stream).poll_shutdown(cx),
            Self::Reality(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// vless 出站会话：请求头已写出且成功响应头已收到，可转发 TCP 载荷。
pub struct VlessOutbound {
    /// 已完成握手的承载流（响应头已消费，后续字节即目标数据）。
    pub stream: VlessStream,
    /// dry-run 里使用的目标地址（诊断用，不含凭据）。
    pub target: TargetAddr,
}

impl std::fmt::Debug for VlessOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 承载流不打印（TLS/REALITY 状态无诊断价值，且可能夹带会话材料）。
        f.debug_struct("VlessOutbound")
            .field("stream", &"<stream>")
            .field("target", &self.target)
            .finish()
    }
}

/// vless 出站：TLS（或 REALITY）→ 请求头 → 等服务端成功响应头。
pub async fn dial_vless(config: &NodeConfig, wait: Duration) -> Result<VlessOutbound, DialError> {
    let mut stream = open_stream(config, wait).await?;
    let credential = uuid_bytes(&config.auth.password)?;
    let target = probe_target(config);
    let request = Request {
        command: VlessCommand::Tcp,
        target: target.clone(),
    };
    send_request(&mut stream, &request, &credential, wait).await?;
    // 正向证据：服务端在目标连接建立后才写 [0, 0]；超时/非零字节都是失败。
    receive_response(&mut stream, wait).await?;
    // dry-run 不转发业务载荷，此处只要让请求头确实上线即可。
    tokio::io::AsyncWriteExt::flush(&mut stream)
        .await
        .map_err(lengsuo_tls::Error::from)?;
    Ok(VlessOutbound { stream, target })
}

/// 选承载并建流：配置了 `reality` 段走 REALITY，否则走普通 TLS。
///
/// REALITY 配置非法 ⇒ 拨号**整体失败**（不回退普通 TLS、不发任何明文）。
async fn open_stream(config: &NodeConfig, wait: Duration) -> Result<VlessStream, DialError> {
    if config.reality.is_some() {
        let stream = connect_reality(config, wait).await?;
        return Ok(VlessStream::Reality(stream));
    }
    let stream = connect_tls(config, wait).await?;
    Ok(VlessStream::Tls(Box::new(stream)))
}

/// node 配置 → 协议 crate 的 REALITY 配置。
///
/// SNI 取值顺序：`reality.server_name` → `tls.server_name` → `endpoint.host`
/// （都没有时协议 crate 按参考语义回退到目标地址）。
///
/// base64 raw-url 解码、十六进制短 ID、指纹查表**全部**由协议 crate 的
/// `RealityConfig::from_settings` 负责（node 侧不复制实现）。任一步失败都
/// 上抛 ⇒ 拨号整体失败，**不回退普通 TLS**。
fn reality_config(config: &NodeConfig) -> Result<RealityConfig, DialError> {
    let Some(reality) = &config.reality else {
        return Err(DialError::RealityConfig(
            lengsuo_vless::reality_config::ConfigError::EmptyPublicKey,
        ));
    };
    let server_name = reality
        .server_name
        .clone()
        .filter(|name| !name.trim().is_empty())
        .or_else(|| {
            config
                .tls
                .as_ref()
                .and_then(|tls| tls.server_name.clone())
                .filter(|name| !name.trim().is_empty())
        })
        .unwrap_or_else(|| config.endpoint.host.clone());
    let settings = RealitySettings {
        server_name,
        password: reality.password.clone().unwrap_or_default(),
        public_key: reality.public_key.clone(),
        short_id: reality.short_id.clone(),
        // 缺省指纹由协议 crate 归一（参考里空串即 `HelloChrome_Auto`）。
        fingerprint: reality.fingerprint.clone().unwrap_or_default(),
    };
    Ok(RealityConfig::from_settings(settings)?)
}

/// REALITY 建流：解析节点端点 → REALITY + TLS 1.3 握手。
///
/// 解析用 node 自己的 `resolve`（异步 DNS + 截止时间），再把已解析的
/// `SocketAddr` 交给协议 crate，避免二次解析。
async fn connect_reality(config: &NodeConfig, wait: Duration) -> Result<RealityStream, DialError> {
    // 配置先校验：坏配置下**一条字节都不发**。
    let reality = reality_config(config)?;
    let address = resolve_public(&config.endpoint.host, config.endpoint.port, wait).await?;
    let endpoint = format!("{}:{}", address.ip(), address.port());
    Ok(RealityStream::connect(&endpoint, &reality, wait).await?)
}

/// UUID 文本 → 16 字节凭据。形态已在 `config::validate` 校验过；
/// 这里再做一次 fail-closed 解析（配置对象可能被上层直接构造）。
pub(crate) fn uuid_bytes(text: &str) -> Result<[u8; 16], DialError> {
    let compact: String = text.chars().filter(|c| *c != '-').collect();
    if compact.len() != 32 {
        return Err(DialError::Rejected("凭据不是 16 字节 UUID".to_owned()));
    }
    let mut bytes = [0u8; 16];
    for (index, slot) in bytes.iter_mut().enumerate() {
        let pair = &compact[index * 2..index * 2 + 2];
        *slot = u8::from_str_radix(pair, 16)
            .map_err(|_| DialError::Rejected("凭据不是 16 字节 UUID".to_owned()))?;
    }
    Ok(bytes)
}
