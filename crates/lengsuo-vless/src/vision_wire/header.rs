//! VLESS **响应头**层：把「承载流」变成「剥掉响应头后的字节流」。
//!
//! # 参考分层
//!
//! 参考 `proxy/vless/outbound/outbound.go` 的 `getResponse`：
//!
//! ```text
//! responseAddons, err := encoding.DecodeResponseHeader(conn, request)  // ① 先读响应头
//! serverReader := encoding.DecodeBodyAddons(conn, request, responseAddons) // ② 再包 vision
//! serverReader = proxy.NewVisionReader(serverReader, trafficState, …)   // ③
//! ```
//!
//! 关键点：**响应头在 vision 流量层之外**。服务端先写响应头，客户端必须**先**把
//! 响应头读走，**再**把剩余字节交给 vision 读者；若把响应头一起喂给 vision 解包器，
//! 块头会错位，解出的明文全是垃圾。
//!
//! 本模块提供 [`ResponseHeader`]（响应头编解码）与 [`ResponseHeaderStream`]
//! （在字节流上剥掉响应头的适配器）。适配器**只**影响读方向：写方向原样透传。
//!
//! # 读多少读多少
//!
//! 参考 `DecodeResponseHeader` 用 `ReadFullFrom(reader, 1)` 读版本字节，再用
//! `ReadFullFrom(reader, length)` 读 addons 载荷——**精确**读头，不多读。本适配器
//! 同样只向承载流索取**当前还缺**的那些字节，因此不会把 vision 层的字节提前吞进
//! 自己的缓冲（多层嵌套时这一点很重要）。
//!
//! # fail-closed
//!
//! - 版本字节与期望版本不符 ⇒ 报错（参考 `unexpected response version`）；
//! - addons 长度字节与实际字节数不符 ⇒ 报错；
//! - 承载流在头读全之前 EOF ⇒ 报 `UnexpectedEof`（参考 `ReadFullFrom` 的
//!   `io.ErrUnexpectedEOF`），**不**把残缺头当有效头。
//!
//! 参考基线：Xray v26.3.27 `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。
//! 本文件不含 `unsafe`。

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::VisionWireError;

/// VLESS 响应头长度（参考 `EncodeResponseHeader`：1 字节版本 + 1 字节 addons 长度）。
pub const RESPONSE_HEADER_LEN: usize = 2;

/// VLESS 协议版本（参考 `proxy/vless/encoding` 的 `Version = byte(0)`）。
pub const RESPONSE_VERSION: u8 = 0;

/// VLESS **响应头**（参考 `proxy/vless/encoding` 的 `EncodeResponseHeader` /
/// `DecodeResponseHeader`）。
///
/// 布局：`[version(1)][addons 长度(1)][addons 载荷(addons 长度字节)]`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHeader {
    /// 协议版本（参考 `encoding.Version` = 0）。
    pub version: u8,
    /// addons 载荷（参考的响应 addons 恒为空，故长度 0）。
    pub addons: Vec<u8>,
}

impl ResponseHeader {
    /// 线上字节（参考 `EncodeResponseHeader`：版本字节 + addons 长度 + 载荷）。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RESPONSE_HEADER_LEN + self.addons.len());
        out.push(self.version);
        out.push(self.addons.len() as u8);
        out.extend_from_slice(&self.addons);
        out
    }

    /// 从线上字节解析（参考 `DecodeResponseHeader` + `DecodeHeaderAddons`）。
    ///
    /// - 版本字节必须等于期望版本，否则**报错**（参考：
    ///   `unexpected response version`）；
    /// - addons 长度字节 0 ⇒ 无载荷；非 0 ⇒ 载荷长度必须与该字节一致
    ///   （参考 `DecodeHeaderAddons` 的 `length != 0` 分支）。
    ///
    /// `input` 必须**只含**响应头；多余字节视为非法（调用方按参考分层先切头）。
    pub fn decode(input: &[u8], expected_version: u8) -> Result<Self, VisionWireError> {
        if input.len() < RESPONSE_HEADER_LEN {
            return Err(VisionWireError::ResponseHeader("响应头不足 2 字节"));
        }
        if input[0] != expected_version {
            return Err(VisionWireError::ResponseHeader("响应版本与请求版本不一致"));
        }
        let addons_len = usize::from(input[1]);
        if input.len() != RESPONSE_HEADER_LEN + addons_len {
            return Err(VisionWireError::ResponseHeader(
                "响应头长度与 addons 长度不符",
            ));
        }
        Ok(Self {
            version: input[0],
            addons: input[RESPONSE_HEADER_LEN..].to_vec(),
        })
    }
}

/// 剥掉下行 VLESS 响应头的字节流适配器。
///
/// 读方向：第一次读之前先解掉响应头（校验版本 / addons 长度），之后原样透传
/// 承载流的字节（那些字节属于 vision 层）。
///
/// 写方向：原样透传（响应头是**下行**的东西，上行不经过本适配器）。
///
/// 已解出的响应头放在共享单元格里，供上层（如 [`super::link::VisionSession`]）
/// 查询；共享而非直接暴露，是为了让适配器能被 `VisionStream` 拥有，而上层仍能
/// 在会话存活期间读到响应头。
pub struct ResponseHeaderStream<S> {
    /// 承载流。
    inner: S,
    /// 已解出的响应头（共享给上层查询）。
    header: Arc<Mutex<Option<ResponseHeader>>>,
    /// 期望的响应版本（参考 `DecodeResponseHeader` 比对 `request.Version`）。
    expected_version: u8,
    /// 尚未凑齐的响应头字节。
    buffer: Vec<u8>,
    /// 响应头是否已解（`true` ⇒ 后续字节直接透传）。
    done: bool,
}

impl<S> std::fmt::Debug for ResponseHeaderStream<S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResponseHeaderStream")
            .field("inner", &"<stream>")
            .field("done", &self.done)
            .field("buffered", &self.buffer.len())
            .finish()
    }
}

impl<S> ResponseHeaderStream<S> {
    /// 建立适配器（期望的响应版本取参考 `encoding.Version` = 0）。
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            header: Arc::new(Mutex::new(None)),
            expected_version: RESPONSE_VERSION,
            buffer: Vec::new(),
            done: false,
        }
    }

    /// 建立适配器并指定期望的响应版本。
    pub fn with_version(inner: S, expected_version: u8) -> Self {
        Self {
            inner,
            header: Arc::new(Mutex::new(None)),
            expected_version,
            buffer: Vec::new(),
            done: false,
        }
    }

    /// 取回已解出的响应头（`None` ⇒ 尚未读到）。
    pub fn header(&self) -> Option<ResponseHeader> {
        self.header.lock().ok().and_then(|guard| guard.clone())
    }

    /// 共享句柄：上层可另行持有一份，用于在会话存活期间查询响应头。
    pub fn header_handle(&self) -> Arc<Mutex<Option<ResponseHeader>>> {
        Arc::clone(&self.header)
    }

    /// 拆出承载流。
    pub fn into_inner(self) -> S {
        self.inner
    }
}

/// 响应头还差多少字节才算齐（`None` ⇒ 长度字节都还没到）。
fn missing(buffer: &[u8]) -> Option<usize> {
    if buffer.len() < RESPONSE_HEADER_LEN {
        Some(RESPONSE_HEADER_LEN - buffer.len())
    } else {
        let total = RESPONSE_HEADER_LEN + usize::from(buffer[1]);
        if buffer.len() < total {
            Some(total - buffer.len())
        } else {
            None
        }
    }
}

impl<S: AsyncRead + Unpin> ResponseHeaderStream<S> {
    /// 读一次承载流，最多取 `want` 字节进 `buffer`。
    ///
    /// 返回 `Ok(false)` 表示承载流已 EOF。
    fn fill(&mut self, cx: &mut Context<'_>, want: usize) -> Poll<io::Result<bool>> {
        let start = self.buffer.len();
        self.buffer.resize(start + want, 0);
        let mut chunk = ReadBuf::new(&mut self.buffer[start..]);
        match Pin::new(&mut self.inner).poll_read(cx, &mut chunk) {
            Poll::Pending => {
                self.buffer.truncate(start);
                Poll::Pending
            }
            Poll::Ready(Err(error)) => {
                self.buffer.truncate(start);
                Poll::Ready(Err(error))
            }
            Poll::Ready(Ok(())) => {
                let filled = chunk.filled().len();
                self.buffer.truncate(start + filled);
                Poll::Ready(Ok(filled > 0))
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ResponseHeaderStream<S> {
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
            if me.done {
                // 响应头已解 ⇒ 剩余字节属于 vision 层，原样透传。
                return Pin::new(&mut me.inner).poll_read(cx, buf);
            }
            let Some(want) = missing(&me.buffer) else {
                // 头已齐：解头、转入透传。
                let header =
                    ResponseHeader::decode(&me.buffer, me.expected_version).map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                    })?;
                if let Ok(mut guard) = me.header.lock() {
                    *guard = Some(header);
                }
                me.buffer.clear();
                me.done = true;
                continue;
            };
            match me.fill(cx, want) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                // EOF：头还没齐 ⇒ 截断 ⇒ fail-closed（参考 `io.ErrUnexpectedEOF`）。
                Poll::Ready(Ok(false)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "vision VLESS 响应头未读全",
                    )))
                }
                Poll::Ready(Ok(true)) => continue,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ResponseHeaderStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
