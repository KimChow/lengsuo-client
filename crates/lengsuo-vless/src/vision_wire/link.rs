//! VLESS Vision **生产接线**：把 vision 流量层接进 VLESS 出站链路。
//!
//! # 为什么需要这一层
//!
//! [`crate::vision`] 的原语（[`VisionClient`]）此前只有测试引用（审计 §5 孤岛 #3：
//! 「组件孤岛」）。本模块提供**生产可调用**的出站原语：给定一条**已建立**的
//! 承载流（TLS / REALITY / 任何 `AsyncRead + AsyncWrite`），完成
//! 「VLESS 请求头 → vision 流量层 → 应用载荷」的完整出站流程。
//!
//! # 参考基线与分层
//!
//! 参考 `proxy/vless/outbound/outbound.go` 的 `postRequest` / `getResponse`：
//!
//! ```text
//! 承载流 ──▶ [VLESS 请求头] ──▶ [vision 流量层] ──▶ 应用载荷   （上行）
//! 承载流 ◀── [VLESS 响应头] ◀── [vision 流量层] ◀── 应用载荷   （下行）
//! ```
//!
//! 注意 **VLESS 头在 vision 层之外**（参考 `getResponse`：
//! `DecodeResponseHeader` → `DecodeBodyAddons` → `NewVisionReader`），
//! 本模块按同一分层接线：`VisionStream<ResponseHeaderStream<S>>`。
//!
//! # 与既有主链路的关系
//!
//! 主链路（[`crate::stream`]）的契约是「传入流必须由调用方完成安全传输认证」。
//! 本模块**不**重复那份契约，而是把 vision 流量层**插在**认证流与主链路之间：
//!
//! ```text
//! RealityStream / TlsStream ──▶ VisionSession ──▶ stream::send_request / …
//! ```
//!
//! # fail-closed
//!
//! - VLESS 请求头编码失败 ⇒ 立即返回错误，**不**落到裸流上；
//! - 下行响应头非法（版本不符 / addons 长度不符）⇒ 读路径报错，**不**把响应头
//!   字节当明文吐给上层；
//! - 首包之后的上行写入失败 ⇒ 原样上抛，不吞。
//!
//! 参考基线：Xray v26.3.27 `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。
//! 本文件不含 `unsafe`。

use std::sync::{Arc, Mutex};

use aes_gcm::aead::rand_core::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::header::{self, Flow, Request};

use super::flow::VisionStream;
use super::header::{ResponseHeader, ResponseHeaderStream};
use super::{VisionWireConfig, VisionWireError};

/// VLESS Vision **出站会话**：VLESS 请求头 + vision 流量层的组合体。
///
/// 生产用法：
///
/// ```no_run
/// # use lengsuo_vless::header::{Command, Request};
/// # use lengsuo_vless::vision_wire::{VisionSession, VisionWireConfig};
/// # use ss_core::target::TargetAddr;
/// # async fn demo<S>(stream: S, uuid: [u8; 16]) -> Result<(), Box<dyn std::error::Error>>
/// # where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {
/// let mut session = VisionSession::new(stream, VisionWireConfig { uuid, testseed: None });
/// let request = Request { command: Command::Tcp, target: TargetAddr::V4([127, 0, 0, 1], 80) };
/// // 写请求头 + 首包，然后正常收发应用数据。
/// session.start(&request, Some(b"GET / HTTP/1.1\r\n\r\n")).await?;
/// let mut buf = [0u8; 4096];
/// let _ = session.read(&mut buf).await?;
/// # Ok(())
/// # }
/// ```
///
/// 上行：应用载荷 → vision 块（[`crate::vision::client::VisionClient::encode_uplink`]）。
/// 下行：承载流 → VLESS 响应头（[`ResponseHeader`]）→ vision 块
/// （[`crate::vision::client::VisionClient::decode_downlink`]）→ 应用载荷。
pub struct VisionSession<S> {
    /// 上行/下行的 vision 流量层（包在响应头层**之外**；响应头层由它拥有）。
    vision: VisionStream<ResponseHeaderStream<S>>,
    /// 已解出的响应头共享句柄（`ResponseHeaderStream` 被 `vision` 拥有，故用
    /// 共享单元格外读）。
    response: Arc<Mutex<Option<ResponseHeader>>>,
    /// 用户 UUID（写 VLESS 请求头用）。
    uuid: [u8; 16],
    /// 是否已发过请求头。
    started: bool,
}

impl<S> std::fmt::Debug for VisionSession<S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VisionSession")
            .field("inner", &"<stream>")
            .field("started", &self.started)
            .finish()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> VisionSession<S> {
    /// 建立会话（用系统 CSPRNG）。
    pub fn new(inner: S, config: VisionWireConfig) -> Self {
        Self::with_rng(inner, config, Box::new(aes_gcm::aead::OsRng))
    }

    /// 建立会话（注入随机源；测试用确定性 RNG 复现线上字节）。
    pub fn with_rng(inner: S, config: VisionWireConfig, rng: Box<dyn RngCore + Send>) -> Self {
        let uuid = config.uuid;
        let header = ResponseHeaderStream::new(inner);
        let response = header.header_handle();
        let vision = VisionStream::with_rng(header, config, rng);
        Self {
            vision,
            response,
            uuid,
            started: false,
        }
    }

    /// 写 VLESS 请求头 + **首个** vision 块。
    ///
    /// 参考 outbound `postRequest`：
    /// - 请求头（含 `flow=xtls-rprx-vision` 的 addons）先写；
    /// - 首包决策：有数据 ⇒ 首包随请求头**同一次**写出；无数据 ⇒ 插入 0 内容
    ///   `Continue` 长 padding 块遮蔽头长度（见 [`VisionStream::write_first`]）。
    ///
    /// 已发过请求头再调 ⇒ [`VisionWireError::UplinkFinished`]。
    pub async fn start(
        &mut self,
        request: &Request,
        first_payload: Option<&[u8]>,
    ) -> Result<(), VisionWireError> {
        if self.started {
            return Err(VisionWireError::UplinkFinished);
        }
        self.started = true;
        let bytes = header::encode_with_flow(request, &self.uuid, Flow::XtlsRprxVision)
            .map_err(|_| VisionWireError::InvalidConfig("VLESS 请求头编码失败"))?;
        // 请求头与首个块同一次写出（参考 `postRequest` 用同一个 buffered writer）。
        self.vision.set_preamble(&bytes);
        self.vision.write_first(first_payload).await?;
        Ok(())
    }

    /// 读下行：先解 VLESS 响应头，再解 vision 块，返回应用明文。
    ///
    /// 响应头非法 ⇒ **报错**（fail-closed），不把响应头字节当明文返回。
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, VisionWireError> {
        Ok(self.vision.read(buf).await?)
    }

    /// 写上行应用载荷（vision 分帧由 [`VisionStream`] 完成）。
    pub async fn write(&mut self, data: &[u8]) -> Result<usize, VisionWireError> {
        Ok(self.vision.write(data).await?)
    }

    /// 写上行应用载荷直到写完。
    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), VisionWireError> {
        Ok(self.vision.write_all(data).await?)
    }

    /// 上行收尾：若仍在 padding 状态，补发 0 内容 `End` 块（参考
    /// `XtlsPadding(…, COMMAND_PADDING_END, …)` 字节一致）。
    pub async fn finish(&mut self) -> Result<(), VisionWireError> {
        self.vision.finish_uplink().await?;
        Ok(())
    }

    /// 关闭承载流（先补发收尾块，再 shutdown）。
    pub async fn shutdown(&mut self) -> Result<(), VisionWireError> {
        self.vision.finish_uplink().await?;
        Ok(self.vision.shutdown().await?)
    }

    /// 已解出的下行 VLESS 响应头（`None` ⇒ 尚未读到）。
    pub fn response_header(&self) -> Option<ResponseHeader> {
        self.response.lock().ok().and_then(|guard| guard.clone())
    }

    /// 流量状态（诊断用；不含密钥）。
    pub fn traffic_state(&self) -> &crate::vision::client::TrafficState {
        self.vision.traffic_state()
    }

    /// 拆出底层承载流（不经 vision 处理）。
    pub fn into_inner(self) -> S {
        self.vision.into_inner().into_inner()
    }
}
