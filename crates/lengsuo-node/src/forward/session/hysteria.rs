//! hysteria 出站会话：QUIC/H3 认证 → TCP 承载请求 → 独立的发送 / 接收两半。
//!
//! ## 为什么不用 `proxy::TcpProxyStream`
//!
//! `TcpProxyStream` 把 `quinn::SendStream` 与 `quinn::RecvStream` **私有地**绑在
//! 一个对象里，只暴露 `&mut self` 方法（`read` / `write_all` / `finish`），
//! **没有** `AsyncRead` / `AsyncWrite` 实现、**没有**拆分成两半的 API。
//! 转发循环需要「读侧与写侧并发」（`relay.rs` 的 `tokio::join!`），同一个对象
//! 上的两个 `&mut self` 借用无法共存 ⇒ 拆不开。
//!
//! 「不可跨线程」的旧说法经查证**不成立**：`quinn::SendStream` /
//! `quinn::RecvStream` 都是 `Send`，真正障碍只是**缺少拆分 API**。
//! `HysteriaClient::open_tcp()` 直接返回**两个独立的** QUIC 半流，而 quinn 0.11
//! 为它们实现了 `tokio::io::AsyncRead` / `AsyncWrite`（`recv_stream.rs:512` /
//! `send_stream.rs:326`，无 `cfg`），因此两半天然可并发读写。
//!
//! **不用 `unsafe`、不用 `Arc<Mutex<>>`**：拆的是对象，不是共享可变状态。
//!
//! ## 协议步骤（对齐参考 Xray `transport/internet/hysteria/`）
//!
//! 1. QUIC + TLS1.3（ALPN=h3）握手，H3 认证（服务端回 HTTP 状态码 233 表示通过）。
//! 2. 开一条 QUIC 双向流，写 `varint(0x401) + TCPRequest`（含目标地址）。
//! 3. 读 `TCPResponse`；`status == 0` 才可转发（对齐 `proxy/tcp_client.rs`）。
//! 4. 之后该流上的字节就是目标数据；写侧 FIN = 半关闭。
//!
//! 注意 `HysteriaClient` **必须随会话保活**：它持有 H3 的三条控制流
//! （`H3ControlStreams`），drop 即 FIN，对端会判 `H3_CLOSED_CRITICAL_STREAM`。
//! 因此它被挂到读侧对象上，与读侧同生命周期。
//!
//! 偏离：`outbound_hysteria.rs` 的连接装配（`ClientConfig` / `roots_der`）在
//! 本卡边界内不可改，故此处按同一语义复刻一份；协议原语仍全部来自协议 crate。

use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;

use lengsuo_hysteria::h3_auth;
use lengsuo_hysteria::padding::Range;
use lengsuo_hysteria::quic::{ClientConfig, HysteriaClient};
use lengsuo_hysteria::tcp::{Status, TcpRequest, TcpResponse};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::CertificateDer;
use ss_core::target::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{LiveSession, OutboundReader, OutboundWriter, SessionError};
use crate::config::NodeConfig;
use crate::outbound::{resolve_public, DialError};

/// TCPResponse 增量读取的缓冲上限（对齐 `proxy/tcp_client.rs` 的同名上限）。
const MAX_RESPONSE_BUFFER: usize = 8192;
/// 单次读取的目标字节数（对齐 `proxy/tcp_client.rs`）。
const READ_CHUNK: usize = 2048;

/// 建立 hysteria 出站会话并返回可转发的读 / 写两半。
pub(super) async fn open(
    node: &NodeConfig,
    target: &TargetAddr,
    wait: Duration,
) -> Result<LiveSession, SessionError> {
    let client = connect(node, wait).await?;
    // `HysteriaClient::open_tcp(&self)` 会在 await 期间持有 `&HysteriaClient`，
    // 而它是 `Send` 但**不是 `Sync`**（H3 控制流里有 `Box<dyn FnMut + Send>`），
    // 于是那个 future 不是 `Send`，无法进入本仓的转发任务。改为先取它内部的
    // `quinn::Connection`（`Arc`，`Send + Sync`）再开流：借用不跨 await，
    // 语义与 `open_tcp` 完全相同（`open_bi` 就是它唯一做的事）。
    let conn = client.connection().clone();
    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|err| DialError::HysteriaConnect(err.into()))?;
    // 先擦成 trait object：`Box<dyn AsyncWrite ..>` 上没有 quinn 的**固有**
    // `read` / `write_all`（它们返回 `Option<usize>` / `WriteError`，会盖掉
    // `tokio::io` 的同名扩展方法），这里要的是 tokio 的 `AsyncRead`/`AsyncWrite`。
    let mut send = boxed_writer(send);
    let mut recv = boxed_reader(recv);

    // 步骤 2：写 TCPRequest（`TcpRequest::encode` 已含帧类型 0x401）。
    let padding = h3_auth::random_padding(Range::TCP_REQUEST).into_bytes();
    let request = TcpRequest {
        address: target_text(target),
        padding,
    }
    .encode()?;
    send.write_all(&request).await?;

    // 步骤 3：读 TCPResponse（可能跨包），响应帧之后的字节是目标数据。
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; READ_CHUNK];
    let response = loop {
        match TcpResponse::decode(&buf) {
            Ok((response, consumed)) => {
                buf.drain(..consumed);
                break response;
            }
            Err(lengsuo_hysteria::Error::Truncated { .. }) => {
                if buf.len() >= MAX_RESPONSE_BUFFER {
                    return Err(DialError::Rejected(
                        "hysteria 的 TCPResponse 超过缓冲上限".to_owned(),
                    )
                    .into());
                }
                let read = recv.read(&mut chunk).await?;
                if read == 0 {
                    return Err(DialError::Rejected(
                        "hysteria 的 TCPResponse 未读完即遇流结束".to_owned(),
                    )
                    .into());
                }
                buf.extend_from_slice(&chunk[..read]);
            }
            Err(err) => return Err(SessionError::Hysteria(err)),
        }
    };
    if !matches!(response.status, Status::Ok) {
        return Err(DialError::Rejected(format!("hysteria 承载被拒：{}", response.message)).into());
    }

    Ok(LiveSession {
        reader: Box::new(HysteriaReader {
            inner: recv,
            pending: buf,
            // H3 控制流保活（见模块文档）。
            _client: client,
        }),
        writer: Box::new(HysteriaWriter { inner: send }),
    })
}

/// hysteria 出站：QUIC/H3 认证（连接建立即认证通过）。
async fn connect(node: &NodeConfig, wait: Duration) -> Result<HysteriaClient, DialError> {
    let Some(tls) = node.tls.as_ref() else {
        return Err(DialError::InvalidTls(
            "hysteria 要求 tls 配置（QUIC 的 TLS1.3 承载）".to_owned(),
        ));
    };
    if tls.insecure {
        return Err(DialError::InvalidTls(
            "tls.insecure 对 hysteria 尚未接通：lengsuo-hysteria 的 ClientConfig 无跳过校验开关（需跨 crate 改动，见本卡报告）；自签场景请用 tls.ca_pem 固定信任锚".to_owned(),
        ));
    }
    let pem = tls.ca_pem.as_deref().unwrap_or_default();
    let roots_der: Vec<Vec<u8>> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| DialError::InvalidTls(format!("ca_pem 解析失败：{err}")))?
        .into_iter()
        .map(|der| der.to_vec())
        .collect();
    if roots_der.is_empty() {
        return Err(DialError::InvalidTls(
            "tls.ca_pem 未包含任何证书（本卡不加载系统根）".to_owned(),
        ));
    }
    let server_name = tls
        .server_name
        .clone()
        .unwrap_or_else(|| node.endpoint.host.clone());
    let server_addr: SocketAddr =
        resolve_public(&node.endpoint.host, node.endpoint.port, wait).await?;
    Ok(HysteriaClient::connect(ClientConfig {
        server_addr,
        server_name,
        auth: node.auth.password.clone(),
        roots_der,
        brutal_down: 0,
        brutal_up: 0,
        congestion: String::new(),
        peer_cc_rx: None,
    })
    .await?)
}

/// 目标地址 ⇒ TCPRequest 里的 `host:port` 文本。
fn target_text(target: &TargetAddr) -> String {
    match target {
        TargetAddr::V4(octets, port) => format!("{}:{}", Ipv4Addr::from(*octets), port),
        TargetAddr::V6(octets, port) => format!("[{}]:{}", Ipv6Addr::from(*octets), port),
        TargetAddr::Domain(host, port) => format!("{host}:{port}"),
    }
}

/// 把具体读流擦成 trait object（避免在本 crate 里点名 `quinn` 类型）。
fn boxed_reader<R: AsyncRead + Unpin + Send + 'static>(
    inner: R,
) -> Box<dyn AsyncRead + Unpin + Send> {
    Box::new(inner)
}

/// 把具体写流擦成 trait object。
fn boxed_writer<W: AsyncWrite + Unpin + Send + 'static>(
    inner: W,
) -> Box<dyn AsyncWrite + Unpin + Send> {
    Box::new(inner)
}

/// hysteria 读侧：QUIC 接收流上的目标数据。
struct HysteriaReader {
    inner: Box<dyn AsyncRead + Unpin + Send>,
    /// 响应帧之后与响应帧同包到达的目标数据，先交付。
    pending: Vec<u8>,
    /// H3 控制流保活：drop 即 FIN，对端判协议错误。
    _client: HysteriaClient,
}

impl OutboundReader for HysteriaReader {
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
        _wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<usize, SessionError>> + Send + 'a>> {
        Box::pin(async move {
            if !self.pending.is_empty() {
                let take = self.pending.len().min(buf.len());
                buf[..take].copy_from_slice(&self.pending[..take]);
                self.pending.drain(..take);
                return Ok(take);
            }
            self.inner.read(buf).await.map_err(SessionError::Io)
        })
    }
}

/// hysteria 写侧：QUIC 发送流；半关闭 = QUIC 流 FIN（`poll_shutdown` → `finish()`）。
struct HysteriaWriter {
    inner: Box<dyn AsyncWrite + Unpin + Send>,
}

impl OutboundWriter for HysteriaWriter {
    fn send<'a>(
        &'a mut self,
        payload: &'a [u8],
        _wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), SessionError>> + Send + 'a>> {
        Box::pin(async move {
            self.inner
                .write_all(payload)
                .await
                .map_err(SessionError::Io)?;
            self.inner.flush().await.map_err(SessionError::Io)
        })
    }

    fn half_close<'a>(
        &'a mut self,
        _wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), SessionError>> + Send + 'a>> {
        Box::pin(async move { self.inner.shutdown().await.map_err(SessionError::Io) })
    }
}
