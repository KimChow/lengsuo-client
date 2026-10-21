//! `vision_wire` 的**参考互通**共用件：Xray 入站配置、线上字节 tee、回环 echo
//! 驱动器。
//!
//! 被两个测试目标共用：
//! - `tests/vision_wire.rs`（本仓客户端 ↔ 参考 Xray 入站，含响应头**线上字节**
//!   的独立断言）；
//! - `tests/vision_wire_xray.rs`（首包 / padding 规则互通矩阵）。
//!
//! ⚠️ 本模块只提供**共用件**；`#[ignore]` 用例本体在各自文件里。
//!
//! 方向：**本仓客户端**（`vision_wire::VisionSession`，VLESS 头 + Vision 流量层）→
//! **Xray 入站**（`flow=xtls-rprx-vision`）→ 回环 echo → 回程由 Xray 下行发回，
//! 本仓用**新 API** 解包。
//!
//! 与既有 `tests/xray_vision.rs` 的区别：后者直接调既有原语
//! （`VisionClient::encode_first_uplink` / `encode_uplink`，且**自己**剥响应头）；
//! **本卡走的是新增的 `vision_wire::VisionSession`**——它按参考分层
//! （`DecodeResponseHeader` → `NewVisionReader`）**自己**解响应头，是「新 API 的
//! 线上字节真的被参考实现接受、且新 API 能自己收对下行」的硬证据，而不是自回路
//! 自证。
//!
//! 用例默认 `#[ignore]`，必须显式 `--ignored` 运行；未设置 `LENGSUO_XRAY` 时打印
//! 跳过原因后返回（跳过**不是**互通通过）。
//!
//! 本文件不含 `unsafe`；只用回环地址、临时端口与假凭据；日志不含密钥/明文。

#![allow(dead_code)]

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use crate::support::*;
use lengsuo_tls::TlsClient;
use lengsuo_vless::{
    header::{Command, Request},
    vision_wire::{VisionSession, VisionWireConfig},
};
use serde_json::json;
use ss_core::target::TargetAddr;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpListener,
    time::timeout,
};

/// 上行分块大小：参考 `ReshapeMultiBuffer` 会把 ≥`buf.Size-21`（8171）的缓冲拆开；
/// 取 4096，覆盖「跨多条块」且不触发负 padding 边界。
pub(crate) const UPLINK_CHUNK: usize = 4096;

/// 全部网络操作的上限（超时必须存在）。
pub(crate) const LIMIT: Duration = Duration::from_secs(20);

/// 参考 `Settings`：flow 写在 client 条目的 `"flow"` 字段；`decryption: "none"`
/// ⇒ 参考只跑 **vision 流量层**（不做 AEAD 记录层），与本仓 `VisionStream` 同层。
pub(crate) fn vision_config(port: u16, cert: &rcgen::CertifiedKey) -> serde_json::Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": ID, "flow": "xtls-rprx-vision"}],
                "decryption": "none"
            },
            "streamSettings": {
                "security": "tls",
                "tlsSettings": {"certificates": [{
                    "certificate": cert.cert.pem().lines().collect::<Vec<_>>(),
                    "key": cert.key_pair.serialize_pem().lines().collect::<Vec<_>>()
                }]}
            }
        }],
        "outbounds": [{"protocol": "freedom"}]
    })
}

/// 记录线上字节的 tee：套在承载流（TLS）**外面**，把 `VisionSession` 写出的
/// **上行**线上字节与读到的**下行**线上字节原样留下来。
///
/// 记账正确性：
/// - 写方向：只在底层 `poll_write` 返回 `Ready(Ok(n))` 时记 `buf[..n]`；返回
///   `Pending` 时不记（tokio 契约：调用方会用同一段 buffer 回来），故不重复记账。
/// - 读方向：只记 `ReadBuf` 本次**填满**的字节（`filled()`），`Pending` 不记。
#[derive(Clone)]
pub(crate) struct Tee<S> {
    inner: S,
    /// 上行（写）线上字节。
    pub(crate) sent: Arc<Mutex<Vec<u8>>>,
    /// 下行（读）线上字节。
    pub(crate) received: Arc<Mutex<Vec<u8>>>,
}

impl<S> Tee<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner,
            sent: Arc::new(Mutex::new(Vec::new())),
            received: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl<S> AsyncWrite for Tee<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = &mut *self;
        let poll = Pin::new(&mut me.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &poll {
            me.sent.lock().unwrap().extend_from_slice(&buf[..*written]);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S> AsyncRead for Tee<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = &mut *self;
        let poll = Pin::new(&mut me.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let filled = buf.filled().len();
            if filled > 0 {
                me.received.lock().unwrap().extend_from_slice(&buf.filled());
            }
        }
        poll
    }
}

/// 从 tee 记录的上行字节里切出**首个** padding 块，并校验块自洽。
///
/// 块布局（参考 `XtlsPadding`）：`[16 字节 UUID][command(1)][contentLen BE16]
/// [paddingLen BE16][content][padding]` ⇒ 块长 = `21 + content_len + padding_len`。
pub(crate) fn first_block_of(sent: &[u8], header_len: usize) -> Vec<u8> {
    assert!(
        sent.len() > header_len + 21,
        "tee 记录的上行字节不足以切出首块（header={header_len}, total={}）",
        sent.len()
    );
    let block = &sent[header_len..];
    assert_eq!(&block[..16], &KEY[..], "首个 padding 块必须携带 UUID");
    let content_len = usize::from(u16::from_be_bytes([block[17], block[18]]));
    let padding_len = usize::from(u16::from_be_bytes([block[19], block[20]]));
    assert!(
        block.len() >= 21 + content_len + padding_len,
        "首块长度必须覆盖 21 + content + padding"
    );
    block[..21 + content_len + padding_len].to_vec()
}

/// 解析首个上行 padding 块的 padding 长度并校验块自洽。
pub(crate) fn first_block_lengths(block: &[u8]) -> (u8, usize, usize) {
    assert!(block.len() >= 21, "首块至少 21 字节，实际 {}", block.len());
    assert_eq!(&block[..16], &KEY[..], "首个 padding 块必须携带 UUID");
    let command = block[16];
    let content_len = usize::from(u16::from_be_bytes([block[17], block[18]]));
    let padding_len = usize::from(u16::from_be_bytes([block[19], block[20]]));
    assert_eq!(
        block.len(),
        21 + content_len + padding_len,
        "块自洽：21 + content + padding"
    );
    (command, content_len, padding_len)
}

/// 完整互通：参考 Xray 入站 + 回环 echo，本仓用**新 API** `VisionSession` 走
/// 完整上行（VLESS 头 + vision 块）**并自己解下行**（响应头 + vision 块）。
///
/// 返回 `(首个 padding 块, 本仓解包后的下行明文, tee 记录的下行线上字节)`。
pub(crate) async fn run_wire_echo(
    payload: &[u8],
    first: Option<&[u8]>,
    chunk: usize,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = listener.local_addr().unwrap().port();
    let port = free_port();
    let reference = launch(vision_config(port, &cert), port).await;

    // 目标回环：读满 payload 精确回写（不依赖 EOF 判定回程边界）。
    let echo_payload = payload.to_vec();
    let echo = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = vec![0u8; echo_payload.len()];
        socket.read_exact(&mut received).await.unwrap();
        assert_eq!(received, echo_payload, "目标收到的上行明文必须逐字节一致");
        socket.write_all(&received).await.unwrap();
        socket.shutdown().await.unwrap();
    });

    let client = TlsClient::new("localhost", [cert.cert.der().clone()], WAIT).unwrap();
    let tls = client.connect(([127, 0, 0, 1], port).into()).await.unwrap();

    // VLESS 请求头（参考 `postRequest`：头与首个 padding 块**同一次**写出）。
    let request = Request {
        command: Command::Tcp,
        target: TargetAddr::V4([127, 0, 0, 1], target_port),
    };
    let header = lengsuo_vless::header::encode_with_flow(
        &request,
        &KEY,
        lengsuo_vless::header::Flow::XtlsRprxVision,
    )
    .unwrap();

    // 本卡新 API：`VisionSession`（VLESS 头 + vision 流量层，自己解响应头）。
    let tee = Tee::new(tls);
    let sent = Arc::clone(&tee.sent);
    let received = Arc::clone(&tee.received);
    let mut session = VisionSession::new(
        tee,
        VisionWireConfig {
            uuid: KEY,
            testseed: None,
        },
    );

    // 首包决策：有数据 ⇒ 首包随请求头同一次写出；无数据 ⇒ 0 内容长 padding 块。
    let mut offset = 0usize;
    match first {
        Some(first) => {
            let take = chunk.min(first.len());
            session.start(&request, Some(&first[..take])).await.unwrap();
            offset = take;
        }
        None => {
            session.start(&request, None).await.unwrap();
        }
    }
    while offset < payload.len() {
        let take = chunk.min(payload.len() - offset);
        session
            .write_all(&payload[offset..offset + take])
            .await
            .unwrap();
        offset += take;
    }
    session.finish().await.unwrap();

    let recorded = sent.lock().unwrap().clone();
    assert_eq!(
        &recorded[..header.len()],
        &header[..],
        "前导必须是 VLESS 请求头"
    );
    let first_block = first_block_of(&recorded, header.len());

    // 回程：**新 API** 自己解响应头 + vision 块。
    let mut got = Vec::with_capacity(payload.len());
    let mut raw = [0u8; 16384];
    loop {
        if got.len() >= payload.len() {
            break;
        }
        match timeout(LIMIT, session.read(&mut raw)).await {
            Err(_) => break,
            Ok(Ok(0)) => break,
            Ok(Ok(read)) => got.extend_from_slice(&raw[..read]),
            Ok(Err(error))
                if matches!(
                    &error,
                    lengsuo_vless::vision_wire::VisionWireError::Io(inner)
                        if inner.kind() == std::io::ErrorKind::UnexpectedEof
                ) =>
            {
                break
            }
            Ok(Err(error)) => panic!("读回程失败 {error}"),
        }
    }
    // 参考的响应 addons 恒为空（`responseAddons := &encoding.Addons{}`）。
    let response = session
        .response_header()
        .expect("下行 VLESS 响应头必须已解出");
    assert_eq!(response.version, 0, "响应版本必须是 0");
    assert!(response.addons.is_empty(), "响应 addons 必须为空");
    session.shutdown().await.unwrap();
    echo.await.unwrap();
    let inbound = received.lock().unwrap().clone();
    drop(reference);
    (first_block, got, inbound)
}

/// 未设置 `LENGSUO_XRAY` 时打印跳过原因并返回 `true`（跳过**不是**互通通过）。
pub(crate) fn skip_without_binary() -> bool {
    if std::env::var("LENGSUO_XRAY").is_err() {
        eprintln!("跳过：未设置 LENGSUO_XRAY（未连接参考二进制，不算互通通过）");
        return true;
    }
    false
}
