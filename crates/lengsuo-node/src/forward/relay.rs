//! 单条本地连接的处理：SOCKS5 CONNECT → 选节点 → 建出站会话 → 双向转发。
//!
//! ## 本地协议
//!
//! 本地监听是 **SOCKS5 CONNECT**（`RFC 1928`）：客户端先发
//! `VER(0x05) | CMD(0x01) | RSV(0x00) | ATYP | ADDR | PORT`，转发器回
//! `VER(0x05) | REP | RSV | ATYP | BND.ADDR | BND.PORT`。
//! 地址部分复用 `ss_core::TargetAddr` 的线格式（`ATYP | ADDR | PORT`，
//! 与 shadowsocks / trojan 请求头同一套），因此**不新增第二套地址类型**。
//!
//! `REP` 取值：`0x00` = 成功（转发器已建好出站会话），非 0 = 失败
//! （`0x01` 一般失败 / `0x02` 不允许 / `0x03` 网络不可达 / `0x04` 主机不可达 /
//! `0x05` 连接拒绝）。**失败即断开本地连接，绝不直连**。
//!
//! ## 转发循环语义（对齐参考）
//!
//! 参考基线 Xray v26.3.27（`d2758a02`）：
//! - `app/proxyman/outbound/handler.go` 的 `Dispatch` → `h.proxy.Process`：
//!   转发循环由各协议的 `Process` 承担（`proxy/trojan/client.go`、
//!   `proxy/shadowsocks/client.go`），参考用 `task.Run(ctx, postRequest,
//!   responseDoneAndCloseWriter)` **并发**跑两个方向，`postRequest` 干净结束
//!   后对上游做写半关闭（`task.Close(link.Writer)`），回程方向继续跑到自己的
//!   EOF。
//! - `common/buf/copy.go` 的 `Copy` + `common/buf/buffer.go` 的 `Size = 8192`：
//!   读写都是 8 KiB 粒度。
//! - `features/policy/policy.go` 的 `SessionDefault`：`ConnectionIdle = 300s`。
//!
//! 本端的对应：
//! - 两个方向**同时**进行，用 `tokio::join!`（**不是** `select!`——`select!` 会在
//!   一侧 EOF 时取消另一侧，回程会被丢掉；`w4-ss-relay-addr` 当年就是这个坑）。
//! - 一侧 EOF ⇒ **半关闭**另一侧写侧（发 FIN），**不等于**立刻断连；两侧都结束
//!   才真正关闭。
//! - 空闲上限：每个单次读/写都受 `idle_timeout` 约束（等价于参考
//!   `CancelAfterInactivity` 的效果：静默超过上限即断连）。
//! - 整体上限：整条连接受 `session_timeout` 约束。
//! - 缓冲：每方向固定 8 KiB（对齐参考 `buf.Size`）。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ss_core::target::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::config::ForwardConfig;
use super::session::{
    open, LiveSession, Opened, OutboundReader, OutboundWriter, SessionError, COPY_BUF,
};
use super::NodePool;
use crate::route::{RouteError, RouteTable};

/// SOCKS5 版本号。
const SOCKS5_VERSION: u8 = 0x05;
/// SOCKS5 CONNECT 命令。
const SOCKS5_CONNECT: u8 = 0x01;
/// SOCKS5 成功回复码。
const SOCKS5_REP_OK: u8 = 0x00;
/// SOCKS5 一般失败回复码。
const SOCKS5_REP_GENERAL: u8 = 0x01;
/// SOCKS5「连接被拒绝」回复码（节点不可达 / 认证被拒）。
const SOCKS5_REP_REFUSED: u8 = 0x05;
/// SOCKS5 回复里的 BND.ADDR（绑定地址未知，固定 0.0.0.0）。
const SOCKS5_BND_ADDR: [u8; 4] = [0, 0, 0, 0];

/// 单条连接的处理结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayOutcome {
    /// 双向转发正常结束（两侧都 EOF）。
    Completed,
    /// 失败并 fail-closed 断开（原因见诊断，不含凭据）。
    Failed,
    /// 目标未命中任何路由且无默认节点 ⇒ fail-closed。
    NoRoute,
    /// 路由规则冲突 ⇒ fail-closed（配置加载阶段本应已报错）。
    RouteConflict,
    /// 节点不可达 / 认证被拒 ⇒ fail-closed。
    DialFailed,
    /// 协议本卡未实现转发 ⇒ fail-closed。
    UnsupportedProtocol,
}

/// 中继错误。Display 不含口令、密钥或明文载荷。
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("路由未命中任何规则且未配置默认节点")]
    NoRoute(#[from] RouteError),
    #[error("出站建连失败：{0}")]
    Dial(#[from] crate::outbound::DialError),
    #[error("中继失败：{0}")]
    Session(#[from] SessionError),
    #[error("本地连接 I/O 失败：{0}")]
    Io(#[from] std::io::Error),
    #[error("空闲超时")]
    Idle,
    #[error("整条连接超过生命周期上限")]
    SessionTimeout,
}

/// 处理一条本地连接。
///
/// 全程 fail-closed：任何失败都只断开本地连接，**没有直连回退路径**。
pub async fn handle(
    stream: TcpStream,
    peer: SocketAddr,
    pool: Arc<NodePool>,
    routes: Arc<RouteTable>,
    config: Arc<ForwardConfig>,
) -> RelayOutcome {
    match run(stream, peer, pool, routes, config).await {
        Ok(()) => RelayOutcome::Completed,
        Err(error) => match error {
            RelayError::NoRoute(RouteError::NoRoute) => RelayOutcome::NoRoute,
            RelayError::NoRoute(RouteError::Conflict(_)) => RelayOutcome::RouteConflict,
            RelayError::NoRoute(_) => RelayOutcome::NoRoute,
            RelayError::Dial(_) => RelayOutcome::DialFailed,
            // 结构性不可转发的协议（wireguard）在建会话时显式拒绝。
            RelayError::Session(SessionError::Unsupported(_)) => RelayOutcome::UnsupportedProtocol,
            RelayError::Session(SessionError::Io(err))
                if err.kind() == std::io::ErrorKind::Unsupported =>
            {
                RelayOutcome::UnsupportedProtocol
            }
            RelayError::Session(_) | RelayError::Io(_) | RelayError::Idle => RelayOutcome::Failed,
            RelayError::SessionTimeout => RelayOutcome::Failed,
        },
    }
}

/// 一条连接的完整处理流程。
async fn run(
    stream: TcpStream,
    _peer: SocketAddr,
    pool: Arc<NodePool>,
    routes: Arc<RouteTable>,
    config: Arc<ForwardConfig>,
) -> Result<(), RelayError> {
    let idle = config.idle_timeout();
    let session_limit = config.session_timeout();
    // 整条连接的生命周期上限（fail-closed：超时即断开）。
    let whole = timeout(session_limit, forward(stream, pool, routes, idle));
    match whole.await {
        Ok(result) => result,
        Err(_) => Err(RelayError::SessionTimeout),
    }
}

/// 转发主体：SOCKS5 握手 → 选节点 → 建会话 → 双向转发。
async fn forward(
    stream: TcpStream,
    pool: Arc<NodePool>,
    routes: Arc<RouteTable>,
    idle: Duration,
) -> Result<(), RelayError> {
    let (mut local_read, mut local_write) = tokio::io::split(stream);

    // SOCKS5 请求头 + 目标地址。解析失败 ⇒ 回失败码并断开（不得当作业务载荷）。
    let target = match read_request(&mut local_read, idle).await {
        Ok(target) => target,
        Err(error) => {
            let _ = write_reply(&mut local_write, SOCKS5_REP_GENERAL).await;
            return Err(error);
        }
    };

    // 选节点：最具体优先；未命中且无默认节点 ⇒ fail-closed。
    let selection = match routes.select(&target) {
        Ok(selection) => selection,
        Err(RouteError::NoRoute) => {
            let _ = write_reply(&mut local_write, SOCKS5_REP_GENERAL).await;
            return Err(RelayError::NoRoute(RouteError::NoRoute));
        }
        Err(error) => {
            let _ = write_reply(&mut local_write, SOCKS5_REP_GENERAL).await;
            return Err(RelayError::NoRoute(error));
        }
    };
    let Some(node) = pool.get(&selection.node) else {
        // 路由引用的节点不存在（配置加载阶段应已报错）⇒ fail-closed。
        let _ = write_reply(&mut local_write, SOCKS5_REP_GENERAL).await;
        return Err(RelayError::NoRoute(RouteError::UnknownNode(
            selection.node.clone(),
        )));
    };

    // 建出站会话。失败（不可达 / 认证被拒）⇒ fail-closed。
    let observe = idle.min(Duration::from_millis(500));
    let session = match open(node, &target, idle, observe).await {
        Ok(Opened::Relay(session)) => session,
        Err(error) => {
            let _ = write_reply(&mut local_write, SOCKS5_REP_REFUSED).await;
            return Err(RelayError::Session(error));
        }
    };

    // 出站会话已建立 ⇒ 回 SOCKS5 成功。
    write_reply(&mut local_write, SOCKS5_REP_OK).await?;

    relay_both_ways(local_read, local_write, *session, idle).await
}

/// 读 SOCKS5 请求头并解析目标地址。
///
/// 读满 `VER | CMD | RSV` 三字节后按 `ATYP` 精确读地址与端口
/// （`TargetAddr` 的线格式），**不多读**业务载荷。
async fn read_request(
    reader: &mut tokio::io::ReadHalf<TcpStream>,
    idle: Duration,
) -> Result<TargetAddr, RelayError> {
    let header = read_exact(reader, &mut [0u8; 3], idle).await?;
    if header[0] != SOCKS5_VERSION {
        return Err(RelayError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SOCKS5 版本号非法",
        )));
    }
    if header[1] != SOCKS5_CONNECT {
        return Err(RelayError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SOCKS5 只支持 CONNECT",
        )));
    }
    let atyp = read_exact(reader, &mut [0u8; 1], idle).await?;
    // 地址体长度按 ATYP 精确决定：IPv4 = 4+2，域名 = 1+len+2，IPv6 = 16+2。
    let body = match atyp[0] {
        0x01 => read_exact(reader, &mut [0u8; 6], idle).await?,
        0x03 => {
            let length = read_exact(reader, &mut [0u8; 1], idle).await?;
            let len = usize::from(length[0]);
            let mut body = read_exact(reader, &mut vec![0u8; len + 2], idle).await?;
            body.insert(0, length[0]);
            body
        }
        0x04 => read_exact(reader, &mut [0u8; 18], idle).await?,
        other => {
            return Err(RelayError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("SOCKS5 地址类型非法：{other:#04x}"),
            )))
        }
    };
    // 组回 `ATYP | ADDR | PORT` 交给 `TargetAddr::decode` 解析（复用同一套地址类型）。
    let mut raw = Vec::with_capacity(body.len() + 1);
    raw.push(atyp[0]);
    raw.extend_from_slice(&body);
    let (target, used) = TargetAddr::decode(&raw).map_err(|err| {
        RelayError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("SOCKS5 目标地址非法：{err}"),
        ))
    })?;
    debug_assert_eq!(used, raw.len(), "地址字节必须被完整消费");
    Ok(target)
}

/// 精确读满 `buf.len()` 字节。
async fn read_exact(
    reader: &mut tokio::io::ReadHalf<TcpStream>,
    buf: &mut [u8],
    idle: Duration,
) -> Result<Vec<u8>, RelayError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let read = timeout(idle, reader.read(&mut buf[filled..]))
            .await
            .map_err(|_| RelayError::Idle)?
            .map_err(RelayError::Io)?;
        if read == 0 {
            return Err(RelayError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "读取 SOCKS5 请求头时连接已关闭",
            )));
        }
        filled += read;
    }
    Ok(buf.to_vec())
}

/// 写 SOCKS5 回复（`VER | REP | RSV | ATYP | BND.ADDR | BND.PORT`）。
async fn write_reply(
    writer: &mut tokio::io::WriteHalf<TcpStream>,
    rep: u8,
) -> Result<(), RelayError> {
    let mut reply = Vec::with_capacity(10);
    reply.push(SOCKS5_VERSION);
    reply.push(rep);
    reply.push(0x00);
    reply.push(0x01);
    reply.extend_from_slice(&SOCKS5_BND_ADDR);
    reply.extend_from_slice(&0u16.to_be_bytes());
    writer.write_all(&reply).await.map_err(RelayError::Io)?;
    writer.flush().await.map_err(RelayError::Io)?;
    Ok(())
}

/// 双向转发。
///
/// 两个方向**并发**跑（`tokio::join!`）：请求方向干净结束 → 出站侧写半关闭
/// （参考 `task.OnSuccess(postRequest, task.Close(link.Writer))`），但**绝不能**
/// 因此取消回程方向——回程可能尚未写出（echo 场景就是先收到请求才回）。
/// 因此用 `join` 而非 `select!`。
async fn relay_both_ways(
    local_read: tokio::io::ReadHalf<TcpStream>,
    mut local_write: tokio::io::WriteHalf<TcpStream>,
    mut session: LiveSession,
    idle: Duration,
) -> Result<(), RelayError> {
    let to_upstream = copy_request(local_read, session.writer.as_mut(), idle);
    let to_client = copy_response(session.reader.as_mut(), &mut local_write, idle);
    let (request_result, response_result) = tokio::join!(to_upstream, to_client);
    request_result?;
    response_result?;
    Ok(())
}

/// 请求方向：本地 → 出站。
///
/// 读不到更多字节 ⇒ 对出站侧**半关闭**（FIN），回程方向继续。
async fn copy_request(
    mut local_read: tokio::io::ReadHalf<TcpStream>,
    upstream: &mut dyn OutboundWriter,
    idle: Duration,
) -> Result<(), RelayError> {
    let mut buffer = vec![0u8; COPY_BUF];
    loop {
        let read = timeout(idle, local_read.read(&mut buffer))
            .await
            .map_err(|_| RelayError::Idle)?
            .map_err(RelayError::Io)?;
        if read == 0 {
            // 请求方向干净结束 ⇒ 半关闭出站写侧（FIN），仍可读回程。
            upstream.half_close(idle).await?;
            return Ok(());
        }
        upstream.send(&buffer[..read], idle).await?;
    }
}

/// 回程方向：出站 → 本地。
///
/// 读不到更多字节 ⇒ 对本地侧**半关闭**（FIN）。
async fn copy_response(
    upstream: &mut dyn OutboundReader,
    local: &mut tokio::io::WriteHalf<TcpStream>,
    idle: Duration,
) -> Result<(), RelayError> {
    let mut buffer = vec![0u8; COPY_BUF];
    loop {
        let read = timeout(idle, upstream.recv(&mut buffer, idle))
            .await
            .map_err(|_| RelayError::Idle)?
            .map_err(RelayError::Session)?;
        if read == 0 {
            local.shutdown().await.map_err(RelayError::Io)?;
            return Ok(());
        }
        timeout(idle, local.write_all(&buffer[..read]))
            .await
            .map_err(|_| RelayError::Idle)?
            .map_err(RelayError::Io)?;
    }
}
