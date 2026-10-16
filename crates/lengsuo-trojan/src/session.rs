//! Trojan 会话与 fail-closed 载荷转发（原语，不是完整代理运行时）。
//!
//! 语义基线：Xray v26.3.27，完整 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，`proxy/trojan/protocol.go`、
//! `client.go`、`server.go` 与 `common/drain/drainer.go`。
//!
//! ## 命令分支核对结果（不发明参考没有的东西）
//!
//! - `protocol.go` 只定义 `commandTCP = 1` 与 `commandUDP = 3`（本仓 `Command`
//!   与之完全一致），**没有**第三种命令、没有“应答/心跳”命令分支。
//!   参考 `ConnReader.ParseHeader` 把任何非 3 的命令字节都按 TCP 处理；本仓
//!   `codec::decode` 更严格——非 1/3 直接 `InvalidCommand` 拒绝（保持既有行为，
//!   不新增分支）。
//! - **Trojan 没有响应首字节/状态码**：`client.go` 的 `getResponse` 直接把连接
//!   交给 `buf.NewReader(conn)` 转发，从不先读一个状态字节；`server.go` 在接受
//!   成功后也不向客户端写任何状态码。`server.go` 里出现的 `PROXY …\r\n` 与
//!   `\x0D\x0A…` 字节只在 `fallback` 分支写出，方向是**转发给被 fallback 的目标**，
//!   不是对 Trojan 客户端的应答，且仅在服务端配置了 fallbacks 时才发生。
//! - 空闲期也没有心跳：客户端与服务端都用
//!   `signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)`，
//!   即空闲超时后**直接断连**，不发任何探测帧。
//!
//! ## 因此 fail-closed 用顺序 + 类型表达
//!
//! 参考里“握手是否被接受”只能由顺序与连接存活表达（客户端写完头部后立刻继续写
//! 载荷；服务端认证/解析失败时直接结束连接）。本模块把该约束变成编译期不可绕过的
//! API：应用载荷**只能**经 `Session` 读写，而 `Session` 只能由 `Session::connect`
//! （客户端：请求头已完整写出并 flush）或 `Session::accept`（服务端：密码哈希
//! 常量时间校验通过且头部解析成功）构造。两条握手路径失败都只返回 `Err`，调用方
//! 拿不到 `Session`，因此拿不到任何转发能力，也不会静默回退明文；`Session` 字段
//! 私有，外部无法伪造。命令分支同样受检：TCP 会话不能发数据报帧，UDP 会话不能发
//! 字节流，混用即失败并 poison。
//!
//! 任何读写失败让会话永久 poison：后续操作不触碰流、直接 `Err(Poisoned)`，调用方
//! 必须关闭连接。收尾统一走 `stream::close_stream`（drain + 写半关闭，共用同一个
//! 截止时间）；`Drainer::default()` 即参考 trojan 的默认（不读残留，只半关闭写侧）。
//! TLS 由上层负责，本模块只在完成认证 TLS 之后使用。

use std::time::Duration;

use ss_core::target::TargetAddr;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::codec::{Command, Request};
use crate::credential::Credential;
use crate::drain::{DrainOutcome, Drainer};
use crate::stream::{self, CloseReport, Error};

/// 一个已完成握手的 Trojan 会话，持有流的两半与关闭策略。
///
/// 字段全部私有，只有 `connect` / `accept` 的成功路径能构造它——这就是
/// “未通过认证/未写出请求头前不得转发载荷”的类型级表达。
#[derive(Debug)]
pub struct Session<R, W> {
    read: R,
    write: W,
    command: Command,
    drainer: Drainer,
    wait: Duration,
    /// 数据报载荷上限；默认取参考 `protocol.go` 服务端 `maxLength = 8192`。
    max_datagram: usize,
    poisoned: bool,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> Session<R, W> {
    /// 客户端侧握手：写出请求头（含 flush）之后才交回会话。
    ///
    /// 写头失败（编码拒绝、I/O、超时）返回 `Err` 且**没有**会话，调用方无法转发
    /// 任何载荷，只能关闭连接。`read` / `write` 通常是 `tokio::io::split` 的两半，
    /// 或已完成认证 TLS 的读写句柄。
    pub async fn connect(
        read: R,
        write: W,
        request: &Request,
        credential: &Credential,
        wait: Duration,
    ) -> Result<Self, Error> {
        let mut write = write;
        // 头部完整上线并被确认写出之后，本函数才返回 Session。
        stream::send_request(&mut write, request, credential, wait).await?;
        Ok(Self::new(read, write, request.command, wait))
    }

    /// 服务端侧握手：读取并常量时间校验请求头之后才交回会话与请求。
    ///
    /// 认证失败、格式失败、截断或超时都返回 `Err`（不返回会话）；调用方据此直接
    /// 关闭连接——这正是参考服务端表达“拒绝”的唯一方式（它没有失败码可写）。
    pub async fn accept(
        read: R,
        write: W,
        credential: &Credential,
        wait: Duration,
    ) -> Result<(Self, Request), Error> {
        let mut read = read;
        let request = stream::receive_request(&mut read, credential, wait).await?;
        Ok((Self::new(read, write, request.command, wait), request))
    }

    /// 两条握手成功路径共用的构造：只有这里能把会话建起来，poison 恒为 false。
    fn new(read: R, write: W, command: Command, wait: Duration) -> Self {
        Session {
            read,
            write,
            command,
            drainer: Drainer::default(),
            wait,
            max_datagram: stream::REFERENCE_MAX_DATAGRAM_PAYLOAD,
            poisoned: false,
        }
    }

    /// 会话命令分支（TCP 字节流 / UDP 数据报帧）。
    #[must_use]
    pub fn command(&self) -> Command {
        self.command
    }

    /// 是否已经 poison（曾失败）。poison 后只能关闭连接。
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// 替换关闭前的残留丢弃策略；默认 `Drainer::nop()`（参考 trojan 行为）。
    pub fn set_drainer(&mut self, drainer: Drainer) {
        self.drainer = drainer;
    }

    /// 当前关闭策略。
    #[must_use]
    pub fn drainer(&self) -> &Drainer {
        &self.drainer
    }

    /// 替换数据报载荷上限（`0` 表示禁止任何数据报）；不改变线上帧格式。
    pub fn set_max_datagram_payload(&mut self, limit: usize) {
        self.max_datagram = limit;
    }

    /// 转发一段 TCP 载荷（头部之后的字节流）。非 TCP 分支拒绝并 poison。
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), Error> {
        self.ready()?;
        if self.command != Command::Tcp {
            return Err(self.fail(Error::CommandMismatch(self.command)));
        }
        match stream::forward_payload(&mut self.write, payload, self.wait).await {
            Ok(()) => Ok(()),
            Err(error) => Err(self.fail(error)),
        }
    }

    /// 读取 TCP 载荷到 `buf`，返回读到的字节数；非 TCP 分支拒绝并 poison。
    ///
    /// 与 `AsyncRead` 一致：正常 EOF 返回 `Ok(0)`，不 poison。读到的字节计入
    /// `AcknowledgeReceive`，抵消关闭前要丢弃的长度（参考读侧同样的累加）。
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.ready()?;
        if self.command != Command::Tcp {
            return Err(self.fail(Error::CommandMismatch(self.command)));
        }
        match stream::receive_payload(&mut self.read, buf, self.wait).await {
            Ok(read) => {
                self.drainer.acknowledge_receive(read);
                Ok(read)
            }
            Err(error) => Err(self.fail(error)),
        }
    }

    /// 转发一个 UDP 数据报帧。载荷超过 `max_datagram`（默认参考 8192）时在写任何
    /// 字节前拒绝并 poison。非 UDP 分支拒绝并 poison。
    pub async fn send_datagram(&mut self, target: &TargetAddr, packet: &[u8]) -> Result<(), Error> {
        self.ready()?;
        if self.command != Command::Udp {
            return Err(self.fail(Error::CommandMismatch(self.command)));
        }
        if packet.len() > self.max_datagram {
            return Err(self.fail(Error::FrameTooLarge));
        }
        match stream::send_datagram(&mut self.write, target, packet, self.wait).await {
            Ok(()) => Ok(()),
            Err(error) => Err(self.fail(error)),
        }
    }

    /// 读取一个 UDP 数据报帧；非 UDP 分支拒绝并 poison。
    ///
    /// 分配载荷缓冲前使用的上限是 `max_datagram` 与 `capacity` 中较小者。
    pub async fn recv_datagram(&mut self, capacity: u16) -> Result<(TargetAddr, Vec<u8>), Error> {
        self.ready()?;
        if self.command != Command::Udp {
            return Err(self.fail(Error::CommandMismatch(self.command)));
        }
        let limit = u16::try_from(self.max_datagram)
            .unwrap_or(u16::MAX)
            .min(capacity);
        match stream::receive_datagram(&mut self.read, limit, self.wait).await {
            Ok(frame) => {
                self.drainer.acknowledge_receive(frame.1.len());
                Ok(frame)
            }
            Err(error) => Err(self.fail(error)),
        }
    }

    /// 只丢弃读侧残留、不关写侧（例如还要观察对端是否继续发送）。
    pub async fn drain(&mut self) -> Result<DrainOutcome, Error> {
        self.drainer
            .drain(&mut self.read, self.wait)
            .await
            .map_err(Error::Drain)
    }

    /// 按当前策略收尾：先丢弃读侧残留，再写半关闭（flush + SHUT_WR）。
    ///
    /// poison 的会话**跳过 drain**（帧状态已不可信，不再从流上读任何字节，
    /// `CloseReport.drain` 记为 `Err(Poisoned)`），但仍尝试写半关闭——避免把
    /// 失败连接直接 RST。两阶段结果都在返回值里，调用方仍须最终关闭整条连接。
    pub async fn close(mut self) -> CloseReport {
        if self.poisoned {
            let write_shutdown = stream::shutdown_write(&mut self.write, self.wait).await;
            return CloseReport {
                drain: Err(Error::Poisoned),
                write_shutdown,
            };
        }
        stream::close_stream(
            &mut self.read,
            &mut self.write,
            &mut self.drainer,
            self.wait,
        )
        .await
    }

    /// 未 poison 才允许操作。
    fn ready(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }

    /// 记录失败并永久 poison；返回给调用方的仍是原始错误（不吞原因）。
    fn fail(&mut self, error: Error) -> Error {
        self.poisoned = true;
        error
    }
}
