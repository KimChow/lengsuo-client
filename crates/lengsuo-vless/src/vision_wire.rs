//! VLESS Vision **线路原语**（`vision_wire`）：把一条**已建立**的承载流包装成
//! 「vision 分帧后」/「AEAD 记录加密后」的字节流，供生产代码（node 出站）直接调用。
//!
//! # 两个参考特性、两条独立原语
//!
//! 参考实现里 `flow=xtls-rprx-vision`（**流量层**，`proxy/proxy.go` 的
//! `VisionWriter` / `VisionReader`）与 VLESS `encryption`（**AEAD 记录层**，
//! `proxy/vless/encryption/common.go` 的 `CommonConn`）是**两个不同**的特性：
//! 前者给流量加 padding 块（`XtlsPadding`），后者给整条连接加 AEAD 记录
//! （`NewAEAD` + `EncodeHeader`）。参考把它们串起来用
//! （`proxy/vless/outbound/outbound.go`：`VisionWriter` 套在 `CommonConn` 之上），
//! 但**互不依赖**：与参考互通时，普通 vision 流只有流量层（`decryption: "none"`）。
//!
//! 因此本模块给出两个**可组合**的流包装器，而不是把两套语义揉成一个：
//!
//! | 类型 | 对应参考 | 复用的既有原语 |
//! |---|---|---|
//! | [`flow::VisionStream`] | `proxy/proxy.go` 的 `VisionWriter` / `VisionReader` | [`crate::vision::client::VisionClient`] |
//! | [`record::RecordStream`] | `proxy/vless/encryption/common.go` 的 `CommonConn` | [`crate::vision::record::RecordWriter`] / `RecordReader`] |
//! | [`header::ResponseHeaderStream`] | `proxy/vless/encoding` 的 `DecodeResponseHeader` | 无（纯线上字节层） |
//!
//! 组合顺序与参考一致（流量层在外、记录层在内）：`VisionStream<RecordStream<S>>`。
//! 响应头在**两层之外**（参考 `getResponse`：`DecodeResponseHeader` →
//! `DecodeBodyAddons` → `NewVisionReader`），故下行接线是
//! `VisionStream<ResponseHeaderStream<S>>`。
//!
//! # 没有第二份实现
//!
//! 本模块**不含**任何加密或分帧算法：
//! - padding 块 / 解帧：[`crate::vision::client::VisionClient`]（既有实现，逐点对齐
//!   `XtlsPadding` / `XtlsUnpadding` / `XtlsFilterTls` / `IsCompleteRecord` /
//!   `ReshapeMultiBuffer`）；
//! - AEAD 记录：[`crate::vision::record`]（既有实现，逐点对齐 `NewAEAD` / `Seal` /
//!   `Open` / `EncodeHeader` / `DecodeHeader` / `IncreaseNonce`）；
//! - 握手 padding 参数：[`crate::vision::padding`]（既有实现，逐点对齐
//!   `ParsePadding` / `CreatPadding`）。
//!
//! 本模块只做**接线**：把上述原语接到一条 `AsyncRead + AsyncWrite` 的承载流上。
//!
//! # fail-closed
//!
//! - 记录层：认证失败 / 头非法 / 截断 / nonce 用尽 ⇒ 立即返回错误，**不**产出
//!   半成品字节，也**不**回退明文（语义来自既有 [`crate::vision::record`]）。
//! - 配置：记录层上下文或密钥材料为空 ⇒ 构造即失败（[`VisionWireError::InvalidConfig`]）。
//! - 握手 padding 参数非法 ⇒ 返回 [`VisionWireError::Padding`]（既有
//!   [`crate::vision::padding`] 的判据），不静默改用默认表。
//! - 流量层本身**按参考就是字节透传**的（参考 `XtlsUnpadding` 遇到非 vision 块
//!   原样返回），因此流量层没有「非法输入」这一失败分支；需要认证的语义由记录层
//!   提供。
//!
//! # 参考基线
//!
//! Xray v26.3.27 `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。
//! 本模块不含 `unsafe`（crate 根 `lib.rs` 已 `#![forbid(unsafe_code)]`）。

mod flow;
mod header;
mod link;
mod record;

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::aead::rand_core::RngCore;
use tokio::io::AsyncWrite;

use crate::vision::padding::{create_padding, parse_padding, PaddingError};
use crate::vision::record::{Cipher, Error as RecordError};

pub use flow::VisionStream;
pub use header::{ResponseHeader, ResponseHeaderStream, RESPONSE_HEADER_LEN, RESPONSE_VERSION};
pub use link::VisionSession;
pub use record::RecordStream;

/// 读侧一次从承载流取的字节数（承载流是 TLS/REALITY 之类，块大小无关紧要）。
const READ_CHUNK: usize = 4096;

/// 线路层失败原因。全部 fail-closed：出错即返回，不产出半成品、不回退明文。
#[derive(Debug, thiserror::Error)]
pub enum VisionWireError {
    /// 记录层（AEAD）失败：认证失败、头非法、截断、nonce 用尽等。
    #[error("vision 记录层失败：{0}")]
    Record(#[from] RecordError),
    /// 握手 padding 参数非法（参考 `ParsePadding` 的失败分支）。
    #[error("vision 握手 padding 参数非法：{0}")]
    Padding(#[from] PaddingError),
    /// 配置非法（空上下文 / 空密钥材料等）。
    #[error("vision 线路配置非法：{0}")]
    InvalidConfig(&'static str),
    /// VLESS 响应头非法（参考 `DecodeResponseHeader` 的版本 / addons 校验分支）。
    #[error("vision VLESS 响应头非法：{0}")]
    ResponseHeader(&'static str),
    /// 承载流 I/O 失败。
    #[error("vision 承载流 I/O 失败")]
    Io(#[from] io::Error),
    /// 上行已收尾后再写。
    #[error("vision 上行已收尾，不能再写")]
    UplinkFinished,
}

/// VLESS Vision 流量层配置。
#[derive(Clone, PartialEq, Eq)]
pub struct VisionWireConfig {
    /// 用户 UUID（参考 `TrafficState.UserUUID`）：vision **首个** padding 块携带它。
    pub uuid: [u8; 16],
    /// 参考 `testseed`；`None` ⇒ 参考默认 `{900, 500, 900, 256}`。
    pub testseed: Option<[u32; 4]>,
}

impl fmt::Debug for VisionWireConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // UUID 是账号标识（凭据），不进 Debug。
        formatter
            .debug_struct("VisionWireConfig")
            .field("uuid", &"<redacted>")
            .field("testseed", &self.testseed)
            .finish()
    }
}

/// VLESS Vision 记录层（AEAD）配置。
#[derive(Clone, PartialEq, Eq)]
pub struct RecordConfig {
    /// 记录层派生上下文（参考 `NewAEAD(ctx, key, useAES)` 的 `ctx`）。
    pub ctx: String,
    /// 记录层密钥材料（参考 `NewAEAD(ctx, key, useAES)` 的 `key`）。
    pub key: Vec<u8>,
    /// AEAD 套件（参考 `useAES`）。
    pub cipher: Cipher,
}

impl fmt::Debug for RecordConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 密钥材料不进 Debug（只报长度）。
        formatter
            .debug_struct("RecordConfig")
            .field("ctx", &self.ctx)
            .field("key_len", &self.key.len())
            .field("cipher", &self.cipher)
            .finish()
    }
}

/// 握手 padding 计划（参考 `ParsePadding` + `CreatPadding` 的返回）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakePadding {
    /// 总字节数。
    pub length: usize,
    /// 每段长度。
    pub lens: Vec<usize>,
    /// 每段间隔（毫秒）。
    pub gaps: Vec<u64>,
}

/// 解析握手 padding 参数并生成一次握手的 padding 计划。
///
/// 复用 [`crate::vision::padding::parse_padding`] 与
/// [`crate::vision::padding::create_padding`]（既有实现，逐点对齐参考
/// `ParsePadding` / `CreatPadding`）。参数非法 ⇒ 返回 [`VisionWireError::Padding`]，
/// **不**静默改用参考默认表。
pub fn handshake_padding(
    spec: &str,
    rng: &mut impl RngCore,
) -> Result<HandshakePadding, VisionWireError> {
    let mut lens = Vec::new();
    let mut gaps = Vec::new();
    parse_padding(spec, &mut lens, &mut gaps)?;
    let (length, lens, gaps) = create_padding(&lens, &gaps, rng);
    Ok(HandshakePadding { length, lens, gaps })
}

/// 待写进承载流的线上字节缓冲（内部用；两个流包装器共用）。
///
/// 关键点：tokio 的 `AsyncWrite::poll_write` 契约要求「返回 `Pending` 时，调用方
/// 必须用**同一个** buffer 再次调用 `poll_write`」。因此这里把「已编码的线上
/// 字节」与「它对应的源明文字节数」分开记账：只有整轮线上字节真的写进承载流
/// 之后，才向调用方报告**源明文**长度（padding 会让线上字节多于源明文，
/// 报告的必须是源明文长度）。
///
/// 记号：
/// - `wire` / `written`：待写 / 已写的线上字节；
/// - `src_len`：本轮对应的源明文字节数（`None` ⇒ 本轮无源明文，如收尾块）；
/// - `reported`：本轮是否已向调用方报告过字节数（`false` ⇒ 上一轮
///   `poll_write` 返回过 `Pending`，调用方会带着**同一个** buffer 回来）。
pub(crate) struct WireOutbox {
    wire: Vec<u8>,
    written: usize,
    src_len: Option<usize>,
    reported: bool,
}

impl WireOutbox {
    pub(crate) fn new() -> Self {
        Self {
            wire: Vec::new(),
            written: 0,
            src_len: None,
            reported: true,
        }
    }

    /// 是否没有「未报告」的轮次（可以开始新一轮）。
    pub(crate) fn is_idle(&self) -> bool {
        self.reported
    }

    /// 开始新一轮：清空线上缓冲并记下本轮源明文长度。
    pub(crate) fn begin(&mut self, src_len: Option<usize>) {
        debug_assert!(self.reported, "上一轮未报告完，不能开始新一轮");
        self.wire.clear();
        self.written = 0;
        self.src_len = src_len;
        self.reported = false;
    }

    /// 追加已编码的线上字节（前导字节 / 收尾块 / 本轮密文）。
    pub(crate) fn push_raw(&mut self, bytes: &[u8]) {
        self.wire.extend_from_slice(bytes);
    }

    /// 把剩余线上字节写进承载流；返回 `Ready(Ok(()))` 表示**全部写完**。
    pub(crate) fn poll_drain<S: AsyncWrite + Unpin>(
        &mut self,
        inner: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while self.written < self.wire.len() {
            match Pin::new(&mut *inner).poll_write(cx, &self.wire[self.written..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "vision 承载流不再接受写入",
                    )))
                }
                Poll::Ready(Ok(count)) => {
                    self.written += count;
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    /// 异步版整轮写出（供 `write_first` / `finish_uplink` 用）。
    pub(crate) async fn drain_all<S: AsyncWrite + Unpin>(
        &mut self,
        inner: &mut S,
    ) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;
        while self.written < self.wire.len() {
            let count = inner.write(&self.wire[self.written..]).await?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "vision 承载流不再接受写入",
                ));
            }
            self.written += count;
        }
        Ok(())
    }

    /// 本轮线上字节全部写完 ⇒ 报告源明文字节数并结束本轮。
    pub(crate) fn report(&mut self) -> usize {
        self.reported = true;
        self.wire.clear();
        self.written = 0;
        self.src_len.take().unwrap_or(0)
    }
}
