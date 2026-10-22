//! REALITY 承载上的 UDP（XUDP）入口。
//!
//! 参考基线：Xray v26.3.27 `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。
//! - `proxy/vless/outbound/outbound.go`：VLESS 出站的 XUDP 接线
//!   （`xudp.NewPacketWriter` / `xudp.NewPacketReader`，以及
//!   `request.Command = protocol.RequestCommandMux` + `v1.mux.cool` 选择器）；
//! - `common/xudp/xudp.go`：XUDP 包封格式本身；
//! - `common/protocol/address.go`：目标地址编码（XUDP 用 `PortThenAddress`，
//!   即**端口在前**，与本仓 [`crate::header`] 的地址编码一致）；
//! - `transport/internet/reality/reality.go`：REALITY 传输层（**只有 TCP 承载**，
//!   UDP 业务由同一条已认证连接上的包封承载）。
//!
//! # 分工
//!
//! - **长度前缀**（两字节大端）直接复用 [`crate::stream`] 的
//!   [`send_datagram`] / [`receive_datagram`]，本模块**不另写一套编解码**；
//! - **XUDP 包封**（session id + 新旧标志 + 选项 + 目标地址 + 载荷长度 + 载荷）
//!   直接复用 [`crate::xudp::Session`]，本模块只补两件事：
//!   1. 把承载流显式接到 REALITY 已认证字节流上；
//!   2. 回程归属校验（见 [`UdpSession::receive`]）。
//!
//! # 承载流
//!
//! 本模块的入口按「已认证字节流」泛型给出，因为 REALITY 的两端拿到的不是同一种
//! 载体：客户端侧是 [`crate::reality_link::RealityStream`]（REALITY + TLS 1.3
//! 握手后的字节流），服务端侧是 `reality::server` 握手后摊平的字节流。两者都
//! 实现 `AsyncRead + AsyncWrite`，语义一致。
//!
//! # fail-closed
//!
//! 包封解析失败一律返回错误：既不把残缺字节当成普通载荷继续处理，也不在目标
//! 解析失败时回落成 TCP 拨号或静默直连。

use std::time::Duration;

use ss_core::target::TargetAddr;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    header::{Command, Request},
    stream, xudp,
};

/// REALITY UDP 入口的错误。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// 底层数据报／包封层失败（超时、帧过长、协议字段非法、I/O 错误）。
    #[error(transparent)]
    Stream(#[from] stream::Error),
    /// 回程目标与会话目标不一致（目标归属串包）。
    #[error("回程目标与会话目标不一致")]
    TargetMismatch,
}

/// 发送一个 UDP 数据报（两字节大端长度前缀 + 载荷）。
///
/// 承载流必须**已完成 REALITY 认证**：客户端侧传
/// [`crate::reality_link::RealityStream`]，服务端侧传 `reality::server`
/// 握手后摊平的字节流。
pub async fn send_datagram<W: AsyncWrite + Unpin>(
    stream: &mut W,
    packet: &[u8],
    deadline: Duration,
) -> Result<(), Error> {
    stream::send_datagram(stream, packet, deadline).await?;
    Ok(())
}

/// 接收一个 UDP 数据报。`limit` 是载荷上限，超过即
/// [`stream::Error::FrameTooLarge`]（不截断后静默发出）。
pub async fn receive_datagram<R: AsyncRead + Unpin>(
    stream: &mut R,
    limit: u16,
    deadline: Duration,
) -> Result<Vec<u8>, Error> {
    let packet = stream::receive_datagram(stream, limit, deadline).await?;
    Ok(packet)
}

/// 客户端在 REALITY 连接上发起 XUDP 会话的前置步骤：发 VLESS 请求头并等响应头。
///
/// 请求头用参考的 XUDP 选择器：`Command::Mux` + `v1.mux.cool` 哨兵
/// （参考 `proxy/vless/outbound/outbound.go` 的
/// `request.Command = protocol.RequestCommandMux` 与
/// `request.Address = net.DomainAddress("v1.mux.cool")`）。
///
/// 参考的 VLESS 请求头在 `Command::Mux` 下**不写目标地址**（`encoding.go`
/// 的 `EncodeRequestHeader` 只在 `Command != RequestCommandMux` 时写地址），
/// 与本仓 [`crate::header::encode`] 的行为一致。
pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    credential: &[u8; 16],
    deadline: Duration,
) -> Result<(), Error> {
    let request = Request {
        command: Command::Mux,
        target: TargetAddr::Domain("v1.mux.cool".to_owned(), 0),
    };
    stream::send_request(stream, &request, credential, deadline).await?;
    stream::receive_response(stream, deadline).await?;
    Ok(())
}

/// XUDP 单会话在 REALITY 承载上的入口。
///
/// 一个会话绑定一条已认证连接（参考 `common/xudp` 的单会话模型）：客户端在首个
/// 包封里带目标地址，服务端从对端首个包封取目标地址。
pub struct UdpSession {
    /// 包封编解码（复用 [`crate::xudp::Session`]，不重复实现包封格式）。
    session: xudp::Session,
    /// 客户端会话：构造时给定；服务端会话：由对端首个包封给出。
    target: Option<TargetAddr>,
    /// 是否客户端会话（决定是否做回程归属校验）。
    client: bool,
}

impl UdpSession {
    /// 客户端会话：目标地址随首个 XUDP 包封发出。
    pub fn client(target: TargetAddr) -> Self {
        Self {
            session: xudp::Session::client(target.clone()),
            target: Some(target),
            client: true,
        }
    }

    /// 服务端会话：目标地址由对端的首个 XUDP 包封给出。
    pub fn server() -> Self {
        Self {
            session: xudp::Session::server(),
            target: None,
            client: false,
        }
    }

    /// 已确认的目标地址（客户端：构造时给定；服务端：收到首个包封后才有）。
    pub fn target(&self) -> Option<&TargetAddr> {
        self.target.as_ref()
    }

    /// 发送一个 UDP 数据报（XUDP 包封）。
    pub async fn send<W: AsyncWrite + Unpin>(
        &mut self,
        stream: &mut W,
        packet: &[u8],
        deadline: Duration,
    ) -> Result<(), Error> {
        self.session.send(stream, packet, deadline).await?;
        Ok(())
    }

    /// 接收一个 UDP 数据报（XUDP 包封），返回目标地址与载荷。
    ///
    /// **回程归属**：客户端会话的目标在构造时即固定，回程目标必须与之相同，
    /// 否则返回 [`Error::TargetMismatch`]——fail-closed，宁可拒绝，也不把归属
    /// 不符的回程交给上层。服务端会话允许逐包目标（参考 `common/xudp` 的
    /// `PacketWriter` 对 `b.UDP != nil` 的处理），故不做单一归属约束。
    pub async fn receive<R: AsyncRead + Unpin>(
        &mut self,
        stream: &mut R,
        limit: u16,
        deadline: Duration,
    ) -> Result<(TargetAddr, Vec<u8>), Error> {
        let (target, packet) = self.session.receive(stream, limit, deadline).await?;
        if self.client && self.target.as_ref().is_some_and(|want| want != &target) {
            return Err(Error::TargetMismatch);
        }
        self.target = Some(target.clone());
        Ok((target, packet))
    }
}
