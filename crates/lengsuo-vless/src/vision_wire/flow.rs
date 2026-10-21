//! VLESS Vision **流量层**流包装器：把承载流变成「vision 分帧后」的字节流。
//!
//! 对应参考 `proxy/proxy.go` 的 `VisionWriter`（写）/ `VisionReader`（读）。
//! 分帧与解帧**全部**由既有 [`crate::vision::client::VisionClient`] 完成，
//! 本文件不含第二套 padding 逻辑。
//!
//! # 分层
//!
//! 本层是**纯流量层**：它操作的字节流里**不含** VLESS 头 / 响应头。参考的
//! `NewVisionReader` 同样只包在「已剥掉响应头」的流外面（参考 outbound
//! `getResponse`：`DecodeResponseHeader` → `DecodeBodyAddons` → `NewVisionReader`）。
//! 响应头的剥离由 [`super::header::ResponseHeaderStream`] 负责，两层可组合。
//!
//! 参考基线：Xray v26.3.27 `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::aead::rand_core::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::vision::client::{TrafficState, VisionClient};

use super::{VisionWireConfig, VisionWireError, WireOutbox, READ_CHUNK};

/// VLESS Vision 流量层流。
///
/// - 写：调用方明文 → [`VisionClient::encode_uplink`]（参考 `VisionWriter` 的
///   `XtlsPadding` 分帧）→ 承载流。
/// - 读：承载流 → [`VisionClient::decode_downlink`]（参考 `VisionReader` 的
///   `XtlsUnpadding` 解帧）→ 调用方明文。
///
/// 参考 outbound `postRequest` 的**首包直发决策**（首包随 VLESS 头一起直发；
/// 500ms 内无首包则插入 0 内容长 padding 块遮蔽头长度）由
/// [`VisionStream::write_first`] 承担。
///
/// 流量层**按参考就是字节透传**的（参考 `XtlsUnpadding` 遇到非 vision 块原样
/// 返回），所以本层没有「非法输入」失败分支；需要认证的语义由记录层提供。
pub struct VisionStream<S> {
    /// 承载流（TLS / REALITY / 任何 `AsyncRead + AsyncWrite`）。
    inner: S,
    /// 既有流量层原语（复用，不复制实现）。
    vision: VisionClient,
    /// 前导字节（参考：VLESS 头），与首个 vision 块**同一次**写出。
    preamble: Vec<u8>,
    /// 待写进承载流的线上字节 + 本轮源明文字节数。
    outbox: WireOutbox,
    /// 已解包、待交付给调用方的明文。
    plaintext: Vec<u8>,
    /// 首个块是否已发。
    first_done: bool,
    /// 上行是否已收尾。
    closed: bool,
}

impl<S> fmt::Debug for VisionStream<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VisionStream")
            .field("inner", &"<stream>")
            .field("first_done", &self.first_done)
            .field("closed", &self.closed)
            .field("plaintext_len", &self.plaintext.len())
            .finish()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> VisionStream<S> {
    /// 用系统 CSPRNG 建立（生产路径便捷入口）。
    pub fn new(inner: S, config: VisionWireConfig) -> Self {
        Self::with_rng(inner, config, Box::new(aes_gcm::aead::OsRng))
    }

    /// 用注入的随机源建立（测试用确定性 RNG 复现线上字节）。
    ///
    /// `rng` 需 `Send`：本流要能进生产链路（node 转发器的 `tokio::task::spawn`）。
    pub fn with_rng(inner: S, config: VisionWireConfig, rng: Box<dyn RngCore + Send>) -> Self {
        let vision = VisionClient::new(config.uuid, config.testseed, rng);
        Self {
            inner,
            vision,
            preamble: Vec::new(),
            outbox: WireOutbox::new(),
            plaintext: Vec::new(),
            first_done: false,
            closed: false,
        }
    }

    /// 预留「与首个 vision 块同一次写出」的前导字节（参考：VLESS 请求头）。
    ///
    /// 参考 `postRequest` 先写请求头、再写首个 padding 块，两者经同一个
    /// `buf.BufferedWriter` 一次刷出；本方法把这一语义显式化。
    pub fn set_preamble(&mut self, bytes: &[u8]) {
        self.preamble = bytes.to_vec();
    }

    /// 取回承载流（拆出未经 vision 处理的原始流）。
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// 流量状态（诊断用；不含密钥）。
    pub fn traffic_state(&self) -> &TrafficState {
        self.vision.traffic_state()
    }

    /// 参考 outbound `postRequest` 的**首包直发决策**：
    /// - `Some(payload)`：首包已就绪，直接随 VLESS 头一起发出；
    /// - `None`：500ms 内无首包 ⇒ 插入 0 内容 `Continue` 长 padding 块遮蔽头长度。
    ///
    /// 前导字节（若已 [`VisionStream::set_preamble`]）与首个块**同一次**写出。
    pub async fn write_first(&mut self, payload: Option<&[u8]>) -> Result<(), VisionWireError> {
        if self.first_done || self.closed {
            return Err(VisionWireError::UplinkFinished);
        }
        self.first_done = true;
        self.outbox.begin(None);
        self.outbox.push_raw(&self.preamble);
        self.preamble.clear();
        // 既有流量层原语：参考 `postRequest` 的首包直发决策。
        let block = self.vision.encode_first_uplink(payload);
        self.outbox.push_raw(&block);
        self.outbox.drain_all(&mut self.inner).await?;
        self.outbox.report();
        Ok(())
    }

    /// 上行收尾：若仍处于 padding 状态，补发 0 内容 `End` 块
    /// （与参考 `XtlsPadding(…, COMMAND_PADDING_END, …)` 字节一致），使对端退出
    /// padding 状态。语义来自既有 [`VisionClient::encode_uplink_finish`]。
    pub async fn finish_uplink(&mut self) -> Result<(), VisionWireError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let tail = self.vision.encode_uplink_finish();
        if !tail.is_empty() {
            self.outbox.begin(None);
            self.outbox.push_raw(&tail);
            self.outbox.drain_all(&mut self.inner).await?;
            self.outbox.report();
        }
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = &mut *self;
        loop {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if !me.plaintext.is_empty() {
                let take = me.plaintext.len().min(buf.remaining());
                buf.put_slice(&me.plaintext[..take]);
                me.plaintext.drain(..take);
                return Poll::Ready(Ok(()));
            }
            let mut chunk = [0u8; READ_CHUNK];
            let mut inner_buf = ReadBuf::new(&mut chunk);
            match Pin::new(&mut me.inner).poll_read(cx, &mut inner_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let filled = inner_buf.filled();
                    if filled.is_empty() {
                        // 承载流 EOF：参考 `buf.Copy` 同样以 EOF 结束搬运。
                        return Poll::Ready(Ok(()));
                    }
                    // **参考分层**：响应头在 vision 流量层**之外**——本层收到的字节
                    // **就是** vision 块字节（参考 outbound `getResponse`：
                    // `DecodeResponseHeader` → `DecodeBodyAddons` → `NewVisionReader`）。
                    // 响应头的剥离由 [`super::header::ResponseHeaderStream`] 负责。
                    let mut out = Vec::new();
                    me.vision.decode_downlink(filled, &mut out);
                    me.plaintext = out;
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = &mut *self;
        if me.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "vision 上行已收尾",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !me.outbox.is_idle() {
            // Previous round not yet fully written (poll_write returned Pending):
            // tokio contract requires the caller to come back with the SAME buffer,
            // so this round encodes nothing new and only drains the previous round.
            return match me.outbox.poll_drain(&mut me.inner, cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => Poll::Ready(Ok(me.outbox.report())),
            };
        }
        me.first_done = true;
        me.outbox.begin(Some(buf.len()));
        // Preamble and first block are written together (reference: VLESS header +
        // first vision block flushed in one go).
        if !me.preamble.is_empty() {
            me.outbox.push_raw(&me.preamble);
            me.preamble.clear();
        }
        // Existing traffic-layer primitive: reference VisionWriter.WriteMultiBuffer.
        let block = me.vision.encode_uplink(buf);
        me.outbox.push_raw(&block);
        match me.outbox.poll_drain(&mut me.inner, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(me.outbox.report())),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        if !me.outbox.is_idle() {
            match me.outbox.poll_drain(&mut me.inner, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                // Do NOT clear `reported` here: if the previous poll_write returned
                // Pending, the caller will come back with the same buffer and still
                // needs its byte count.
                Poll::Ready(Ok(())) => {}
            }
        }
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        if !me.closed {
            me.closed = true;
            // 参考收尾：仍处于 padding 状态时补发 0 内容 `End` 块。
            let tail = me.vision.encode_uplink_finish();
            if !tail.is_empty() {
                me.outbox.push_raw(&tail);
            }
        }
        match me.outbox.poll_drain(&mut me.inner, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut me.inner).poll_shutdown(cx),
        }
    }
}
