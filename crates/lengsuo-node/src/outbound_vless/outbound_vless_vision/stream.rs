//! Vision 承载流：`VlessVisionStream` + 其 `AsyncRead` / `AsyncWrite` 实现。

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use lengsuo_vless::vision_wire::{
    RecordStream, ResponseHeader, ResponseHeaderStream, VisionStream, VisionWireError,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::BoxedCarrier;

/// node 出站的 **Vision 承载**（`VlessStream` 的第三个变体）。
///
/// - 上行：明文 → Vision 流量层 → 记录层 → 线上。
/// - 下行：线上 → 记录层 → VLESS 响应头 → Vision 流量层 → 明文。
///
/// `pending` 存「握手期读出、尚未交给上层」的明文：握手期间为了确认响应头读了
/// 一个字节，那个字节已是解好的明文，不能丢。
pub struct VlessVisionStream {
    pub(super) inner: VisionInner,
    /// 已解出的响应头（`ResponseHeaderStream` 被 `VisionStream` 拥有，故用共享
    /// 单元格回读）。
    pub(super) response: Arc<Mutex<Option<ResponseHeader>>>,
    /// 握手期读出、待交付给上层的明文。
    pub(super) pending: Vec<u8>,
}

/// Vision 承载的内部形态（记录层开 / 关）。
///
/// 两种形态的**读方向**都是 `VisionStream<ResponseHeaderStream<…>>`：
/// 响应头在 Vision 层之外、记录层之内（与参考一致）。
///
/// 两种变体都**装箱**：记录层那一支比流量层那一支大 232 字节以上，不装箱会让
/// 整个枚举按最大变体对齐（`clippy::large_enum_variant`）。
pub(super) enum VisionInner {
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
    pub(super) fn set_preamble(&mut self, bytes: &[u8]) {
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
    pub(super) async fn write_first(
        &mut self,
        payload: Option<&[u8]>,
    ) -> Result<(), VisionWireError> {
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
