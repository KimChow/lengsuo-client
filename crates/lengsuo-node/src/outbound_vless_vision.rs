//! VLESS Vision 出站接线：把**流量层**（`vision`）与**记录层**（`encryption`）
//! 接进 node 的 VLESS 出站路径。
//!
//! # 分层（与参考逐层对齐）
//!
//! 参考 `proxy/vless/outbound/outbound.go`（固定 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）：
//!
//! ```text
//! 上行：payload → [Vision 流量层] → [记录层 AEAD] → 线上
//! 下行：线上 → [记录层 AEAD] → [VLESS 响应头] → [Vision 流量层] → payload
//! ```
//!
//! 依据：
//!
//! - `outbound.go:324-330`：`bufferWriter` 包 `conn`；`EncodeBodyAddons` 把
//!   **Vision 包装套在 `bufferWriter` 外层** ⇒ **流量层在外、记录层在内**。
//! - `outbound.go:384-393`：`DecodeResponseHeader(conn, …)` →
//!   `DecodeBodyAddons(conn, …)` → `NewVisionReader(…)` ⇒ **响应头在 Vision 层
//!   之外**，且它在记录层**之内**（`conn` 在启用 `encryption` 时就是
//!   `*encryption.CommonConn`；参考服务端把响应头写进 `bufferWriter` → `connection`，
//!   见 `proxy/vless/inbound/inbound.go:276` 与 `:619` ⇒ **响应头是走记录层加密
//!   的**）。
//!
//! ⇒ 本模块的组合：
//!
//! ```text
//! VisionStream<ResponseHeaderStream<RecordStream<S>>>   （记录层开启）
//! VisionStream<ResponseHeaderStream<S>>                  （记录层关闭）
//! ```
//!
//! 上行没有 `ResponseHeaderStream`（响应头只影响**读**方向），故上行路径是
//! `VisionStream<RecordStream<S>>` / `VisionStream<S>`——与任务书的写法同义。
//!
//! # 一个 VisionClient 同时管上下行（与参考一致）
//!
//! 参考客户端**只有一份** `trafficState`（`outbound.go:314`），上行写与下行读
//! 共用它 ⇒ 顶层 `NumberOfPacketToFilter`（TLS-in-TLS 过滤计数）是**共享**的。
//! 本仓 `lengsuo_vless::vision_wire` 的 `VisionStream` 同样把上下行放在**同一个**
//! `VisionClient` 里 ⇒ 本模块也只造**一个** `VisionStream`（不拆成上下行两套），
//! 语义与参考一致。
//!
//! # 与参考的**有意偏离**（ML-KEM）
//!
//! 参考的 `encryption` 走 `mlkem768x25519plus.` **会话握手**
//! （`infra/conf/vless.go:97`、`:321-357`；`outbound.go:211-216` 的
//! `h.encryption.Handshake(conn)`）：会话密钥与 IV 由 ML-KEM-768 + X25519 协商。
//! 本仓**没有 ML-KEM** ⇒ 本模块从「**会话密钥与 IV 已就绪**」这一层接：`ctx` 与
//! `key` 由配置给出。
//!
//! ⇒ **带 `encryption` 的连接与参考进程级互通在结构上不可达**（如实记入偏离清单）。

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use lengsuo_vless::header::{self, Flow, Request};
use lengsuo_vless::vision::record::Cipher;
use lengsuo_vless::vision_wire::{
    RecordConfig, RecordStream, ResponseHeader, ResponseHeaderStream, VisionStream,
    VisionWireConfig, VisionWireError,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::config::NodeConfig;
use crate::outbound::DialError;

/// 流量层模式名（参考 `vless.XRV`）。
pub const FLOW_XTLS_RPRX_VISION: &str = "xtls-rprx-vision";

/// 承载流的最小 trait 抽象：`AsyncRead + AsyncWrite + Unpin + Send`。
///
/// 用 `Box<dyn …>` 而不是泛型，是为了让 `VlessStream` 的第三个变体保持**装箱**
/// （装箱理由与 `Tls` 变体一致：避免整个枚举按最大变体对齐）。
pub trait VisionCarrier: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> VisionCarrier for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// 装箱后的承载流。
pub type BoxedCarrier = Box<dyn VisionCarrier>;

/// 记录层配置的构造失败（fail-closed）。
#[derive(Debug, thiserror::Error)]
pub enum VisionConfigError {
    /// `vision.flow` 未知（配置校验已拦一道，这里再兜一道）。
    #[error("流量层 flow 未知：{0}")]
    UnknownFlow(String),
    /// `encryption.cipher` 未知（配置校验已拦一道，这里再兜一道）。
    #[error("记录层 cipher 未知：{0}")]
    UnknownCipher(String),
    /// `encryption.key` 不是合法十六进制。
    #[error("记录层 key 不是合法十六进制文本")]
    InvalidKey,
    /// `encryption.key` 解码后为空。
    #[error("记录层 key 解码后为空")]
    EmptyKey,
    /// 记录层构造失败（空 ctx / 空 key，参考 `RecordStream::new` 的判据）。
    #[error("记录层构造失败：{0}")]
    Record(#[from] VisionWireError),
}

/// 记录层 AEAD 套件名 → 协议 crate 的 [`Cipher`]（参考 `useAES` 二选一）。
fn cipher_from_name(name: &str) -> Result<Cipher, VisionConfigError> {
    match name {
        "aes-256-gcm" => Ok(Cipher::Aes256Gcm),
        "chacha20-poly1305" => Ok(Cipher::ChaCha20Poly1305),
        other => Err(VisionConfigError::UnknownCipher(other.to_owned())),
    }
}

/// 十六进制文本 → 字节（大小写不敏感；奇数长度或非法字符 ⇒ 失败）。
///
/// 参考的记录层密钥来自 ML-KEM 会话握手（**本仓没有**，见模块文档的偏离说明）
/// ⇒ `key` 由配置直接给出，用十六进制文本承载。
fn hex_to_bytes(text: &str) -> Result<Vec<u8>, VisionConfigError> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if !compact.len().is_multiple_of(2) {
        return Err(VisionConfigError::InvalidKey);
    }
    let mut out = Vec::with_capacity(compact.len() / 2);
    for pair in compact.as_bytes().chunks(2) {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or(VisionConfigError::InvalidKey)?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or(VisionConfigError::InvalidKey)?;
        out.push(((high << 4) | low) as u8);
    }
    if out.is_empty() {
        return Err(VisionConfigError::EmptyKey);
    }
    Ok(out)
}

/// node 配置 → 协议 crate 的**流量层**配置（`VisionWireConfig`）。
///
/// `uuid` 取 `auth.password` 的 16 字节（参考 `TrafficState.UserUUID`）。
/// `testseed` 缺省 ⇒ 参考默认 `{900, 500, 900, 256}`（协议 crate 内处理）。
fn vision_wire_config(config: &NodeConfig, uuid: [u8; 16]) -> VisionWireConfig {
    VisionWireConfig {
        uuid,
        testseed: config.vision.as_ref().and_then(|vision| vision.testseed),
    }
}

/// node 配置 → 协议 crate 的**记录层**配置（`RecordConfig`）。
fn record_config(config: &NodeConfig) -> Result<RecordConfig, VisionConfigError> {
    let Some(encryption) = &config.encryption else {
        return Err(VisionConfigError::UnknownCipher("未配置记录层".to_owned()));
    };
    let cipher = cipher_from_name(&encryption.cipher)?;
    let key = hex_to_bytes(&encryption.key)?;
    Ok(RecordConfig {
        ctx: encryption.ctx.clone(),
        key,
        cipher,
    })
}

/// 记录层是否启用（参考 `account.Encryption != "" && != "none"`）。
#[must_use]
pub fn record_enabled(config: &NodeConfig) -> bool {
    config.encryption.is_some()
}

/// 流量层是否启用（参考 `account.Flow == vless.XRV`）。
///
/// 判据是「**配置了流量层段**」，而不是「flow 名恰好是 `xtls-rprx-vision`」：
/// 未知的 flow 名由 [`precheck`] **显式报错**（fail-closed），**不**静默退回
/// 无流量层路径。
#[must_use]
pub fn vision_enabled(config: &NodeConfig) -> bool {
    config.vision.is_some()
}

/// node 出站的 **Vision 承载**（`VlessStream` 的第三个变体）。
///
/// - 上行：明文 → Vision 流量层 → 记录层 → 线上。
/// - 下行：线上 → 记录层 → VLESS 响应头 → Vision 流量层 → 明文。
///
/// `pending` 存「握手期读出、尚未交给上层」的明文：握手期间为了确认响应头读了
/// 一个字节，那个字节已是解好的明文，不能丢。
pub struct VlessVisionStream {
    inner: VisionInner,
    /// 已解出的响应头（`ResponseHeaderStream` 被 `VisionStream` 拥有，故用共享
    /// 单元格回读）。
    response: Arc<Mutex<Option<ResponseHeader>>>,
    /// 握手期读出、待交付给上层的明文。
    pending: Vec<u8>,
}

/// Vision 承载的内部形态（记录层开 / 关）。
///
/// 两种形态的**读方向**都是 `VisionStream<ResponseHeaderStream<…>>`：
/// 响应头在 Vision 层之外、记录层之内（与参考一致）。
///
/// 两种变体都**装箱**：记录层那一支比流量层那一支大 232 字节以上，不装箱会让
/// 整个枚举按最大变体对齐（`clippy::large_enum_variant`）。
enum VisionInner {
    /// 只有流量层（与参考互通时的普通 vision 流：`decryption: "none"`）。
    Plain(Box<VisionStream<ResponseHeaderStream<BoxedCarrier>>>),
    /// 流量层 + 记录层（参考 `VisionWriter` 套在 `CommonConn` 之上）。
    Record(Box<VisionStream<ResponseHeaderStream<RecordStream<BoxedCarrier>>>>),
}

impl std::fmt::Debug for VlessVisionStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 承载流不打印（会话材料无诊断价值，且可能夹带密钥）。
        f.debug_struct("VlessVisionStream")
            .field("inner", &"<stream>")
            .field("response", &self.response_header())
            .field("pending", &self.pending.len())
            .finish()
    }
}

impl VlessVisionStream {
    /// 已解出的下行 VLESS 响应头（`None` ⇒ 尚未读到）。
    pub fn response_header(&self) -> Option<ResponseHeader> {
        self.response.lock().ok().and_then(|guard| guard.clone())
    }

    /// 预留「与首个 vision 块同一次写出」的前导字节（参考：VLESS 请求头）。
    ///
    /// 参考 `postRequest` 先写请求头、再写首个 padding 块，两者经同一个
    /// `buf.BufferedWriter` 一次刷出 ⇒ 对端首读能一次拿到「头 + 首块」。
    fn set_preamble(&mut self, bytes: &[u8]) {
        match &mut self.inner {
            VisionInner::Plain(stream) => stream.set_preamble(bytes),
            VisionInner::Record(stream) => stream.set_preamble(bytes),
        }
    }

    /// 写首个 vision 块（与前导字节同一次写出）。
    ///
    /// `payload = None` ⇒ 插入 0 内容 `Continue` 长 padding 块遮蔽 VLESS 头长度
    /// （参考 `postRequest`：500ms 内无首包时的分支）。node 的拨号阶段没有业务
    /// 载荷可发，故走这一支。
    async fn write_first(&mut self, payload: Option<&[u8]>) -> Result<(), VisionWireError> {
        match &mut self.inner {
            VisionInner::Plain(stream) => stream.write_first(payload).await,
            VisionInner::Record(stream) => stream.write_first(payload).await,
        }
    }
}

impl AsyncRead for VlessVisionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = &mut *self;
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !me.pending.is_empty() {
            let take = me.pending.len().min(buf.remaining());
            buf.put_slice(&me.pending[..take]);
            me.pending.drain(..take);
            return Poll::Ready(Ok(()));
        }
        match &mut me.inner {
            VisionInner::Plain(stream) => Pin::new(&mut **stream).poll_read(cx, buf),
            VisionInner::Record(stream) => Pin::new(&mut **stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for VlessVisionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut self.inner {
            VisionInner::Plain(stream) => Pin::new(&mut **stream).poll_write(cx, buf),
            VisionInner::Record(stream) => Pin::new(&mut **stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.inner {
            VisionInner::Plain(stream) => Pin::new(&mut **stream).poll_flush(cx),
            VisionInner::Record(stream) => Pin::new(&mut **stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.inner {
            VisionInner::Plain(stream) => Pin::new(&mut **stream).poll_shutdown(cx),
            VisionInner::Record(stream) => Pin::new(&mut **stream).poll_shutdown(cx),
        }
    }
}

/// 建流前的配置预检（fail-closed）。
///
/// - 未知 `flow` 名 ⇒ **显式报错**，绝不静默退回「无流量层」路径。
/// - 记录层配置非法（未知 cipher / 非法十六进制 / 空 key）⇒ 在**建任何连接之前**
///   失败（参考在拨号前就已完成 `encryption` 的装配，不会带着坏配置去连对端）。
pub fn precheck(config: &NodeConfig) -> Result<(), VisionConfigError> {
    if let Some(vision) = &config.vision {
        if vision.flow != FLOW_XTLS_RPRX_VISION {
            return Err(VisionConfigError::UnknownFlow(vision.flow.clone()));
        }
    }
    if record_enabled(config) {
        record_config(config)?;
    }
    Ok(())
}

/// 建 Vision 承载。
///
/// 记录层开启 ⇒ `VisionStream<ResponseHeaderStream<RecordStream<S>>>`；
/// 关闭 ⇒ `VisionStream<ResponseHeaderStream<S>>`。
pub fn build(
    carrier: BoxedCarrier,
    config: &NodeConfig,
    uuid: [u8; 16],
) -> Result<VlessVisionStream, VisionConfigError> {
    let wire = vision_wire_config(config, uuid);
    if record_enabled(config) {
        let record = RecordStream::new(carrier, &record_config(config)?)?;
        let header = ResponseHeaderStream::new(record);
        let response = header.header_handle();
        Ok(VlessVisionStream {
            inner: VisionInner::Record(Box::new(VisionStream::new(header, wire))),
            response,
            pending: Vec::new(),
        })
    } else {
        let header = ResponseHeaderStream::new(carrier);
        let response = header.header_handle();
        Ok(VlessVisionStream {
            inner: VisionInner::Plain(Box::new(VisionStream::new(header, wire))),
            response,
            pending: Vec::new(),
        })
    }
}

/// Vision 握手：写请求头（带 `flow=xtls-rprx-vision` addons）+ 首个 vision 块，
/// 再确认下行的 VLESS 成功响应头。
///
/// 参考 `postRequest` + `getResponse`：
/// - 请求头由 `encoding.EncodeRequestHeader` 写，`flow` 走 addons（参考
///   `EncodeHeaderAddons`：长度字节 0x12 + `[0x0A, 0x10]` + `"xtls-rprx-vision"`）。
/// - 首包决策：node 拨号阶段没有业务载荷 ⇒ 插入 0 内容 `Continue` 长 padding 块
///   （参考 `postRequest` 中 500ms 内无首包的分支）。
/// - 响应头由 `DecodeResponseHeader` 读并校验（版本 / addons 长度）。
///
/// **正向证据**：响应头被成功解出 ⇒ 服务端已认证本连接（参考入站只在目标连接
/// 建立成功后才写响应头）。读不到 ⇒ 失败（fail-closed，不回落明文路径）。
///
/// # 为什么用 `poll_fn` 而不是「读满 2 字节即返回」
///
/// 参考是**直读 conn** 拿响应头（`outbound.go:384`：`DecodeResponseHeader(conn, …)`
/// 在包 vision 读者**之前**），所以参考**不等**目标数据就能确认认证。
///
/// 本仓的 `ResponseHeaderStream` 是**惰性**解头的：它在被 poll 时读齐头字节、解出
/// 并写进共享单元格，但**同一次 poll 会继续**去读后续字节（那已经是 vision 流量）。
/// 若把握手写成「`read()` 返回即算握手完成」，就会一直等到 vision 层**吐出明文**
/// —— 服务端此时可能还没收到客户端载荷 ⇒ **死锁**。
///
/// ⇒ 这里用 `poll_fn`：**每次 poll 之后检查共享单元格**，响应头一旦解出就立刻
/// 握手完成，不等明文（与参考的「直读响应头」语义等价）。
///
/// 顺带读到的东西**不丢**：poll 返回 `Ready` 时读到的明文进 `pending`，下次读
/// 先交付它。
pub async fn handshake(
    stream: &mut VlessVisionStream,
    request: &Request,
    uuid: [u8; 16],
    wait: Duration,
) -> Result<(), DialError> {
    let bytes = header::encode_with_flow(request, &uuid, Flow::XtlsRprxVision)
        .map_err(DialError::VlessHeader)?;
    stream.set_preamble(&bytes);
    // 请求头与首个 vision 块**同一次**写出（参考 `postRequest` 的同一个
    // `buf.BufferedWriter`）。
    stream.write_first(None).await.map_err(vision_error)?;

    let deadline = tokio::time::Instant::now() + wait;
    let mut scratch = [0u8; 4096];
    tokio::time::timeout_at(
        deadline,
        std::future::poll_fn(|cx| -> Poll<Result<(), DialError>> {
            // 响应头已解出 ⇒ 握手完成（不等载荷，与参考一致）。
            if stream.response_header().is_some() {
                return Poll::Ready(Ok(()));
            }
            let mut buf = ReadBuf::new(&mut scratch);
            match Pin::new(&mut *stream).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) => {
                    let read = buf.filled().len();
                    if read > 0 {
                        // 顺带读到的明文不能丢（响应头可能与它同批到达）。
                        stream.pending.extend_from_slice(buf.filled());
                    }
                    if stream.response_header().is_some() {
                        Poll::Ready(Ok(()))
                    } else {
                        // EOF 且没有响应头 ⇒ 对端拒绝（fail-closed）。
                        Poll::Ready(Err(DialError::Rejected(
                            "vision 未收到成功响应头".to_owned(),
                        )))
                    }
                }
                Poll::Ready(Err(error)) => {
                    // 错误也可能发生在「**响应头已解出之后**」：响应头与后续字节
                    // 同批到达时，vision 层解析后续字节失败会让同一次 poll 返回
                    // 错误。响应头才是认证证据 ⇒ 已解出就握手成功，错误留给
                    // 后续读暴露（与参考「先直读响应头、再包 vision 读者」一致）。
                    if stream.response_header().is_some() {
                        Poll::Ready(Ok(()))
                    } else {
                        // 响应头没读到 ⇒ 对端拒绝或线路失败；错误点名 Vision 层
                        // （参考 `failed to decode response header` 的定位方式）。
                        Poll::Ready(Err(DialError::Rejected(format!(
                            "vision 未收到成功响应头：{error}"
                        ))))
                    }
                }
                Poll::Pending => {
                    // 读挂起时响应头可能**已经**解出（响应头与后续字节同批到达）。
                    if stream.response_header().is_some() {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    }
                }
            }
        }),
    )
    .await
    .map_err(|_| DialError::Timeout)?
}

/// Vision 线路错误 → 拨号错误（fail-closed；消息不含密钥材料）。
fn vision_error(error: VisionWireError) -> DialError {
    match error {
        VisionWireError::Io(io) => vision_io_error(io),
        other => DialError::Rejected(format!("vision 线路失败：{other}")),
    }
}

/// 承载流 I/O 错误 → 拨号错误。
fn vision_io_error(error: std::io::Error) -> DialError {
    DialError::Vless(lengsuo_vless::stream::Error::Io(error))
}
