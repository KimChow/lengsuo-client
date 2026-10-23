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

use lengsuo_vless::vision_wire::VisionWireError;
use tokio::io::{AsyncRead, AsyncWrite};

mod build;
mod config;
mod stream;

pub use build::{build, handshake, precheck};
pub use config::{record_enabled, vision_enabled};
pub use stream::VlessVisionStream;

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
