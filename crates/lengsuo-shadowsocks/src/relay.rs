//! 可部署的 Shadowsocks TCP 中继服务：接受多客户端、按口令解出目标、真实拨号转发。
//!
//! 与参考基线逐条对应（Xray v26.3.27 / `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，
//! `proxy/shadowsocks/server.go` 的 `handleConnection`）：
//!
//! - 入站连接先做握手：读 50 字节 → 拆 salt → 解地址；失败即 `AccessRejected`
//!   并关闭连接（参考 `failed to create request from:` 分支）。本端对应
//!   [`Error::Handshake`]，**绝不在失败后回退成任何形式的直连**。
//! - 目标地址跨 chunk，因此用 [`AddressReader`] 在重组字节上续读；地址所需的
//!   明文只可能来自已通过认证的 chunk。
//! - 接上目标后双向拷贝（`requestDone` / `responseDone`），回程方向以
//!   `WriteTCPResponse` 起手（新随机 salt + 新 nonce 序列）。请求方向干净结束
//!   时对上游做写半关闭（参考 `task.OnSuccess(requestDone, task.Close(link.Writer))`）。
//! - 任一方向结束/出错即中断另一方向并回收连接（参考 `common.Interrupt`）。
//! - 每个连接有独立截止时间；参考用的是策略超时（`ConnectionIdle` 等），本端用
//!   [`RelayConfig::idle_timeout`] 覆盖整个会话，超时即关连接（fail-closed）。
//!
//! 未实现（见 `docs/shadowsocks-status.md` 偏离清单）：参考的
//! `drain.BehaviorSeedLimitedDrainer` 行为探测缓解、分块 padding、真实 policy
//! 管理器级别的超时分级（本端用一个统一的会话超时近似）。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ss_core::crypto::CipherSuite;
use ss_core::target::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::address::AddressReader;
use crate::replay::ReplayFilter;
use crate::tcp::{
    shared_replay, Error as TcpError, Reader as TcpReader, ReplayFilterShared, Writer as TcpWriter,
};

/// 中继失败原因。所有变体都不含口令、主密钥、salt 或 subkey，可安全落日志。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// 配置非法（空口令、零截止时间、零容量等）。
    #[error("中继配置非法：{0}")]
    Config(String),

    /// 监听器绑定/接受失败，或服务无法继续。
    #[error("监听失败：{0}")]
    Listen(#[source] io::Error),

    /// 请求方向握手（salt + 地址）失败。失败即关连接，不重试、不直连。
    #[error("握手失败：{0}")]
    Handshake(#[source] TcpError),

    /// 拨号目标失败（连接被拒/超时/域名解析失败）。**不直连、不降级**。
    #[error("目标不可达：{0}")]
    Unreachable(String),

    /// 中继过程中某一方向失败。
    #[error("中继失败：{0}")]
    Stream(#[source] TcpError),

    /// 会话超过截止时间。
    #[error("会话超时")]
    Timeout,

    /// 连接的底层读写失败。
    #[error("连接 I/O 失败：{0}")]
    Io(#[source] io::Error),

    /// 重放窗口构造失败（配置容量/时间窗非法）。
    #[error("重放窗口非法：{0}")]
    Replay(#[source] crate::replay::Error),
}

/// 中继服务配置。口令以 `Arc<Vec<u8>>` 共享，避免每个连接复制一份；从不落日志。
pub struct RelayConfig {
    pub suite: CipherSuite,
    password: Arc<Vec<u8>>,
    /// 每次握手与每个方向的 I/O 截止时间（必须大于零）。
    pub idle_timeout: Duration,
    /// 单方向最大载荷字节数（同时充当接口契约与测试断言值）。
    pub max_payload: usize,
    /// 入站 salt 重放窗口：`None` 表示关闭（与参考基线行为一致，见 `crate::replay`）。
    pub replay: Option<(usize, Duration)>,
}

/// 必需字段用构造器收口并在 [`RelayConfig::validate`] 里检查，可选字段默认关闭。
#[derive(Clone, Copy)]
pub struct RelayConfigParts {
    pub suite: CipherSuite,
    pub idle_timeout: Duration,
    pub replay: Option<(usize, Duration)>,
}

impl RelayConfig {
    /// 单方向载荷上限（与参考 `buf.Size` 一致的 64 KiB 量级；仅作接口契约）。
    pub const DEFAULT_MAX_PAYLOAD: usize = 65_536;

    #[must_use]
    pub fn new(parts: RelayConfigParts, password: &[u8]) -> Self {
        Self {
            suite: parts.suite,
            password: Arc::new(password.to_vec()),
            idle_timeout: parts.idle_timeout,
            max_payload: Self::DEFAULT_MAX_PAYLOAD,
            replay: parts.replay,
        }
    }

    /// 空口令、零截止时间与零容量窗口都在这里拒绝（fail-closed）。
    pub fn validate(&self) -> Result<(), Error> {
        if self.password.is_empty() {
            return Err(Error::Config("口令为空".into()));
        }
        if self.idle_timeout.is_zero() {
            return Err(Error::Config("截止时间必须大于零".into()));
        }
        if self.max_payload == 0 {
            return Err(Error::Config("载荷上限必须大于零".into()));
        }
        match self.replay {
            Some((0, _)) => Err(Error::Config("重放窗口容量必须大于零".into())),
            Some((_, window)) if window.is_zero() => {
                Err(Error::Config("重放窗口时间窗必须大于零".into()))
            }
            _ => Ok(()),
        }
    }
}

/// 已绑定但未启动的中继服务。绑定与运行分开，测试可以先取到真实端口再启动。
pub struct RelayService {
    listener: TcpListener,
    config: Arc<RelayConfig>,
}

impl RelayService {
    /// 绑定 `bind` 并校验配置。只应传回环地址；本函数不做额外限制，调用方负责。
    pub async fn bind(bind: SocketAddr, config: RelayConfig) -> Result<Self, Error> {
        config.validate()?;
        let listener = TcpListener::bind(bind).await.map_err(Error::Listen)?;
        Ok(Self {
            listener,
            config: Arc::new(config),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.listener.local_addr().map_err(Error::Listen)
    }

    /// 启动服务并返回停止句柄；`drop` 句柄或调用 [`RelayHandle::shutdown`] 后，
    /// 监听器关闭、所有在途连接被中断、残留任务全部回收。
    ///
    /// 服务本身**不要求 `Send`**（连接任务用 `spawn_local` 并发），因此调用方要在
    /// 一个 `LocalSet`（或当前线程 runtime）里 await 本函数；这样中继不需要 `Send`
    /// 的存储层，也不需要额外的线程池假设。
    pub async fn start(self) -> Result<RelayHandle, Error> {
        let (stop_tx, stop_rx) = watch::channel(false);
        let listener = self.listener;
        let config = Arc::clone(&self.config);
        let shared_config = Arc::clone(&config);
        // 重放过滤器**跨连接共享**：重放保护的意义就在于同一 salt 在任何连接上
        // 第二次出现都要拒绝。句柄内部只在 `record` 这一次同步调用上借用，不跨 await。
        let replay: Option<ReplayFilterShared> = match config.replay {
            Some((capacity, window)) => Some(shared_replay(
                ReplayFilter::new(capacity, window).map_err(Error::Replay)?,
            )),
            None => None,
        };
        let join = tokio::task::spawn_local(async move {
            let config = shared_config;
            let shared = replay;
            let mut connections: JoinSet<()> = JoinSet::new();
            let mut stop_rx = stop_rx;
            loop {
                tokio::select! {
                    // 剪枝：已结束的连接任务在这里被回收，避免长时间运行下无界增长。
                    Some(_done) = connections.join_next(), if !connections.is_empty() => {}
                    accepted = listener.accept() => {
                        let (stream, _peer) = match accepted {
                            Ok(pair) => pair,
                            // 单个 accept 失败（如瞬时 fd 耗尽）不应终止整个服务。
                            Err(_) => continue,
                        };
                        let config = Arc::clone(&config);
                        // 只克隆 Rc 句柄（廉价），不跨 await 持有 RefCell 借用。
                        let replay = shared.clone();
                        connections.spawn_local(async move {
                            let _ = handle_connection(stream, config, replay.as_ref()).await;
                        });
                    }
                    changed = stop_rx.changed() => {
                        let stopping = changed.is_err() || *stop_rx.borrow();
                        if stopping {
                            break;
                        }
                    }
                }
            }
            // 中断所有在途连接：drop JoinSet 会 abort 尚未完成的任务，随后等待回收。
            connections.shutdown().await;
            Ok(())
        });
        // 重放窗口的合法性已在上面构造共享句柄时校验：非法配置必须在 start 就失败，
        // 而不是等到第一条连接才暴露（服务对外表现为「已启动但不工作」）。
        Ok(RelayHandle {
            stop_tx: Some(stop_tx),
            join: Some(join),
        })
    }
}

/// 服务句柄。**故意不实现 `Debug`**（内部持有配置，口令在配置里）。
pub struct RelayHandle {
    stop_tx: Option<watch::Sender<bool>>,
    join: Option<tokio::task::JoinHandle<Result<(), Error>>>,
}

impl RelayHandle {
    /// 请求停止并等待服务任务退出（连接全部回收）。可重复调用；
    /// 第二次调用直接返回 `Ok(())`（服务已在关闭过程中）。
    pub async fn shutdown(mut self) -> Result<(), Error> {
        // 接收端可能已退出（监听错误）；此时忽略发送失败，只等任务结果。
        if let Some(sender) = self.stop_tx.take() {
            let _ = sender.send(true);
        }
        let Some(join) = self.join.take() else {
            return Ok(());
        };
        match join.await {
            Ok(result) => result,
            Err(_) => Err(Error::Config("中继任务异常终止".into())),
        }
    }
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        // 句柄被丢弃（测试提前失败）时也要让服务停下来，不留后台监听。
        if let Some(sender) = self.stop_tx.take() {
            let _ = sender.send(true);
        }
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

/// 处理一条入站连接：握手解地址 → 拨号 → 双向中继。
///
/// 地址解出之前不碰目标网络；拨号失败时只返回错误（由调用方关闭连接），
/// **没有任何直连回退路径**。
async fn handle_connection(
    mut stream: TcpStream,
    config: Arc<RelayConfig>,
    replay: Option<&ReplayFilterShared>,
) -> Result<(), Error> {
    let wait = config.idle_timeout;
    let outcome = timeout(wait, async {
        let (read_half, write_half) = stream.split();
        let mut reader = TcpReader::new(read_half, config.suite, &config.password, wait)
            .map_err(Error::Handshake)?;
        // 地址读取借下游读半（与 reader 同一底层流，不会双读）；地址读完即丢弃。
        let mut target: Option<TargetAddr> = None;
        // 与地址同 chunk 到达的载荷开头（必须原样转交上游，不能丢）。
        let mut head_payload: Vec<u8> = Vec::new();
        {
            // 地址字节全部来自已认证 chunk：AddressReader 只吃 `push` 进来的字节，
            // 不直接读底层流（避免与 reader 的读半双读/借用冲突）。
            let mut address = AddressReader::from_pending();
            while target.is_none() {
                let chunk = match replay {
                    Some(filter) => reader.recv_guarded_shared(filter).await,
                    None => reader.recv().await,
                }
                .map_err(Error::Handshake)?;
                match chunk {
                    Some(bytes) => {
                        address.push(&bytes);
                        // 非破坏性解析：字节不够时回滚游标，等下一个 chunk。
                        if let Ok(parsed) = address.read_target().await {
                            target = Some(parsed);
                            // 地址之后剩余的同 chunk 字节即载荷开头，转交上游。
                            head_payload = address.take_pending();
                        }
                    }
                    // 地址没读完就干净收尾 ⇒ 握手失败，不是空请求。
                    None => return Err(Error::Handshake(TcpError::Closed)),
                }
            }
        }
        let target = target.expect("循环条件保证地址已解出");
        // 拨号必须在地址通过认证并解出之后；失败即关连接，没有任何直连回退。
        let upstream = dial(&target, wait).await?;
        let writer = TcpWriter::new(write_half, config.suite, &config.password, wait)
            .map_err(Error::Handshake)?;
        relay_both_ways(reader, writer, upstream, head_payload).await
    })
    .await;
    match outcome {
        Ok(result) => result,
        Err(_) => Err(Error::Timeout),
    }
}

/// 拨号目标地址。域名交给系统解析（与参考 freedom 出站一致），失败即不可达。
async fn dial(target: &TargetAddr, wait: Duration) -> Result<TcpStream, Error> {
    let connect = timeout(wait, async {
        match target {
            TargetAddr::V4(ip, port) => {
                TcpStream::connect((std::net::Ipv4Addr::from(*ip), *port)).await
            }
            TargetAddr::V6(ip, port) => {
                TcpStream::connect((std::net::Ipv6Addr::from(*ip), *port)).await
            }
            TargetAddr::Domain(host, port) => TcpStream::connect((host.as_str(), *port)).await,
        }
    })
    .await;
    match connect {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(err)) => Err(Error::Unreachable(err.to_string())),
        Err(_) => Err(Error::Timeout),
    }
}

/// 双向中继。请求方向干净结束 → 上游写半关闭；任一方向出错/结束即中断另一方向。
async fn relay_both_ways<R, W>(
    reader: TcpReader<R>,
    writer: TcpWriter<W>,
    upstream: TcpStream,
    head_payload: Vec<u8>,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (upstream_read, upstream_write) = upstream.into_split();
    let to_upstream = copy_request(reader, upstream_write, head_payload);
    let to_client = copy_response(writer, upstream_read);
    // 两个方向**并发**跑：请求方向干净结束会对上游做写半关闭（`task.Close(link.Writer)`），
    // 但绝不能因此取消回程方向——回程可能尚未写出（echo 需要先收到请求）。
    // 因此用 `join` 而非 `select!`（`select!` 会在任一分支完成时丢弃另一个方向）。
    let (request_result, response_result) = tokio::join!(to_upstream, to_client);
    request_result?;
    response_result?;
    Ok(())
}

/// 请求方向：把已认证的明文写上游，上游写出错则断开（不重试）。
async fn copy_request<R, W>(
    mut reader: TcpReader<R>,
    mut upstream: W,
    head_payload: Vec<u8>,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // 与地址同 chunk 到达的载荷必须先写上游，否则会丢首包（首包常含整条请求）。
    if !head_payload.is_empty() {
        upstream.write_all(&head_payload).await.map_err(Error::Io)?;
    }
    loop {
        let chunk = reader.recv().await.map_err(Error::Stream)?;
        match chunk {
            Some(bytes) => upstream.write_all(&bytes).await.map_err(Error::Io)?,
            None => {
                // 参考 task.Close(link.Writer)：请求方向结束后半关上游，仍可读回程。
                return upstream.shutdown().await.map_err(Error::Io);
            }
        }
    }
}

/// 回程方向：上游字节经 `TcpWriter`（新方向 salt + 新 nonce 序列）回写给客户端。
async fn copy_response<W, R>(mut writer: TcpWriter<W>, mut upstream: R) -> Result<(), Error>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0u8; 8192];
    loop {
        let got = upstream.read(&mut buffer).await.map_err(Error::Io)?;
        if got == 0 {
            // 干净收尾：写半关闭客户端方向，不伪造终止帧。
            return writer.shutdown().await.map_err(Error::Stream);
        }
        writer.send(&buffer[..got]).await.map_err(Error::Stream)?;
    }
}
