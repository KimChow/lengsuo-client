//! 外层传输矩阵的**共享骨架**：外层档位、动作、测试身份、回环业务目标、
//! 有界 IO 与客户端动作。
//!
//! 与外层无关的 trojan 侧逻辑（写头、写载荷、关写端、读回程）全部集中在这里；
//! 逐外层的差异只体现在两处：
//!
//! 1. **怎么建流**：TLS 之后套 `ws` / `httpupgrade` 升级，或直接用裸 TLS 流；
//! 2. **怎么关写端**：WS 走 `Close` 帧（`ws::Connection::poll_shutdown`），
//!    TCP / HTTPUpgrade 走底层 FIN（`AsyncWriteExt::shutdown`）。
//!
//! 观测面只有一个：**回环业务目标的 accept 计数**。它证明“trojan 头部与载荷
//! 确实穿过外层传输抵达了业务”，也是所有拒绝类用例的唯一“未泄漏”判据。
//! 不用“我方读操作超时”当拒绝证据（沿用 `tests/exception_matrix.rs` 的纪律）。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lengsuo_tls::{PrivatePkcs8KeyDer, TlsClient, TlsServer};
use lengsuo_trojan::server::Error as ServerError;
use lengsuo_trojan::stream::send_request;
use lengsuo_trojan::{Command, Credential, Request, TargetAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

pub use super::support::WAIT;

/// 测试专用假凭据；不打印、不进日志。
pub const PASSWORD: &str = "transport-matrix-good-password";
pub const BAD_PASSWORD: &str = "transport-matrix-wrong-password";
/// 请求载荷：回环业务目标按此长度读满后回写。
pub const PAYLOAD: &[u8] = b"transport-matrix-request-payload";
/// 正常往返的回程（小）。
pub const REPLY: &[u8] = b"transport-matrix-reply-payload";
/// 半关闭用例的回程（大，跨多个 TLS 记录）。
pub const REPLY_BULK_LEN: usize = 64 * 1024;
/// 外层升级路径（WS / HTTPUpgrade 共用）。
pub const PATH: &str = "/lengsuo-trojan-matrix";
/// 握手截止：截断用例据此得到**有界**拒绝（对齐参考 policy 的 `handshake`）。
pub const HANDSHAKE: Duration = Duration::from_secs(2);
/// 单次写入/flush 的有限预算。
pub const WRITE_BOUND: Duration = Duration::from_secs(3);
/// 观察对端结束连接的上限。
pub const CLOSE_BOUND: Duration = Duration::from_secs(8);
/// 单个用例的总预算。
pub const TOTAL: Duration = Duration::from_secs(90);

/// 截断点：覆盖参考 `proxy/trojan/server.go:176` 首块协议判定线的两侧。
///
/// - `30` 字节：不足 58 字节 ⇒ 落在判定线**之前**（`NotTrojanProtocol`）。
/// - `60` 字节：跨过判定线、头部仍不全 ⇒ 由握手截止给出有界拒绝。
pub const TRUNCATION_CUTS: [(usize, &str); 2] =
    [(30, "首块判定线之前"), (60, "跨过判定线、头部不全")];

/// 外层传输档位。`Tcp` 是**基线行**（raw，无任何升级层），其余两档是
/// TLS 之上的 HTTP/1.1 Upgrade 系列。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outer {
    /// raw / tcp：TLS 之后直接是 trojan 字节流。
    Tcp,
    /// websocket：TLS 之后是 RFC 6455 帧。
    Ws,
    /// httpupgrade：TLS 之后是裸字节流（只有 HTTP 升级握手）。
    HttpUpgrade,
}

impl Outer {
    /// 全部档位（矩阵的列）。
    pub const ALL: [Outer; 3] = [Outer::Tcp, Outer::Ws, Outer::HttpUpgrade];

    /// 档位名（同时用于用例名与文档表格）。
    pub fn name(self) -> &'static str {
        match self {
            Outer::Tcp => "tcp",
            Outer::Ws => "ws",
            Outer::HttpUpgrade => "httpupgrade",
        }
    }
}

/// 客户端动作：与外层无关的 trojan 侧动作。
#[derive(Debug, Clone, Copy)]
pub enum Action {
    /// 正常往返：写完整头部与载荷，**不**关写端，读满小回程。
    Normal,
    /// 错密码：写完整头部（错误口令），不得有任何回程。
    WrongPassword,
    /// 截断：只写头部的前 `cut` 字节，写端保持打开，等对端有界拒绝。
    Truncated { cut: usize },
    /// 半关闭：写完整头部与载荷后**关写端**，随后必须收完整个大回程。
    HalfClose,
}

impl Action {
    /// 用例名片段。
    pub fn name(self) -> &'static str {
        match self {
            Action::Normal => "normal",
            Action::WrongPassword => "wrong_password",
            Action::Truncated { .. } => "truncated",
            Action::HalfClose => "half_close",
        }
    }

    /// 该动作期望的回程长度。
    pub fn reply_len(self) -> usize {
        match self {
            Action::HalfClose => REPLY_BULK_LEN,
            _ => REPLY.len(),
        }
    }
}

/// 客户端观测到的结果。
#[derive(Debug, Default)]
pub struct Outcome {
    /// 读到的回程字节。
    pub reply: Vec<u8>,
    /// 读侧是否观察到对端正常结束连接（`Ok(0)`）。
    pub peer_closed: bool,
    /// 读侧是否观察到错误。
    pub peer_error: bool,
    /// 读侧是否读到了**不应出现**的数据（拒绝类用例里读到数据即失败）。
    pub unexpected_data: bool,
}

impl Outcome {
    /// 拒绝类用例的判据：必须观察到结束或错误，且**没有**任何数据字节。
    pub fn rejected_cleanly(&self) -> bool {
        (self.peer_closed || self.peer_error) && !self.unexpected_data
    }
}

/// 测试身份：运行时自签证书（叶子 `localhost`），客户端与服务端共用。
pub struct Identity {
    cert: rcgen::CertifiedKey,
    client: TlsClient,
}

impl Identity {
    /// 生成自签身份；证书只在回环测试里使用。
    pub fn new() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let client = TlsClient::new("localhost", [cert.cert.der().clone()], WAIT).unwrap();
        Self { cert, client }
    }

    /// 已配置信任锚的 TLS 客户端。
    pub fn client(&self) -> &TlsClient {
        &self.client
    }

    /// TLS 服务端接入器（供本仓服务端侧使用）。
    pub fn server(&self) -> TlsServer {
        TlsServer::new(
            vec![self.cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(self.cert.key_pair.serialize_der()).into(),
            WAIT,
        )
        .unwrap()
    }

    /// 证书 PEM（供参考服务端配置使用）。
    pub fn cert_pem(&self) -> String {
        self.cert.cert.pem()
    }

    /// 私钥 PEM（供参考服务端配置使用）。
    pub fn key_pem(&self) -> String {
        self.cert.key_pair.serialize_pem()
    }
}

/// 回环业务目标：读满请求载荷后回写固定回程并关写端。
///
/// accept 计数是“是否抵达业务”的**唯一**观测面；每条连接的处理任务登记在
/// `workers` 里，回收时逐个 await，不留悬挂任务。
pub struct Target {
    port: u16,
    accepted: Arc<AtomicUsize>,
    accept_task: Option<JoinHandle<()>>,
    workers: Arc<Mutex<JoinSet<()>>>,
}

impl Target {
    /// 绑定一个回环业务目标；`reply` 是回写内容。
    pub async fn bind(reply: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let workers = Arc::new(Mutex::new(JoinSet::new()));
        let counter = accepted.clone();
        let body = Arc::new(reply);
        let pool = workers.clone();
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let body = body.clone();
                let worker = serve(socket, body);
                pool.lock().unwrap().spawn(worker);
            }
        });
        Self {
            port,
            accepted,
            accept_task: Some(accept_task),
            workers,
        }
    }

    /// 业务目标端口。
    pub fn port(&self) -> u16 {
        self.port
    }

    /// 已 accept 的连接数（“抵达业务”的计数）。
    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// 显式回收：断 accept 循环并 await 每连接任务。
    pub async fn stop(mut self) {
        if let Some(task) = self.accept_task.take() {
            task.abort();
            let _ = timeout(CLOSE_BOUND, task).await;
        }
        let mut batch = std::mem::take(&mut *self.workers.lock().unwrap());
        loop {
            match timeout(CLOSE_BOUND, batch.join_next()).await {
                Ok(None) => break,
                Ok(Some(_)) => {}
                Err(_) => panic!("业务目标任务未在回收预算内退出，任务泄漏"),
            }
        }
    }
}

/// 单条业务连接：读满请求载荷 → 回写 → flush → 关写端。
async fn serve(mut socket: TcpStream, reply: Arc<Vec<u8>>) {
    let mut request = vec![0u8; PAYLOAD.len()];
    if !matches!(
        timeout(WAIT, socket.read_exact(&mut request)).await,
        Ok(Ok(_))
    ) {
        return;
    }
    if request != PAYLOAD {
        return;
    }
    let _ = bounded_write(&mut socket, &reply).await;
    let _ = bounded_flush(&mut socket).await;
    let _ = bounded_shutdown(&mut socket).await;
}

/// trojan 请求（CONNECT 到回环业务目标）。
pub fn tcp_request(port: u16) -> Request {
    Request {
        command: Command::Tcp,
        target: TargetAddr::V4([127, 0, 0, 1], port),
    }
}

/// trojan 头部的线上字节（用于截断用例）。
pub fn header_bytes(target_port: u16, password: &str) -> Vec<u8> {
    lengsuo_trojan::codec::encode(&tcp_request(target_port), &Credential::new(password)).unwrap()
}

/// 有界写入。
pub async fn bounded_write<S: AsyncWrite + Unpin>(
    stream: &mut S,
    data: &[u8],
) -> std::io::Result<()> {
    match timeout(WRITE_BOUND, stream.write_all(data)).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "写入超时",
        )),
    }
}

/// 有界 flush。
pub async fn bounded_flush<S: AsyncWrite + Unpin>(stream: &mut S) -> std::io::Result<()> {
    match timeout(WRITE_BOUND, stream.flush()).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "flush 超时",
        )),
    }
}

/// 有界关写端（半关闭）。WS 下这一层会先发 `Close` 帧再关底层写端。
pub async fn bounded_shutdown<S: AsyncWrite + Unpin>(stream: &mut S) -> std::io::Result<()> {
    match timeout(WRITE_BOUND, stream.shutdown()).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "关写端超时",
        )),
    }
}

/// 客户端一次动作（与外层无关）。`stream` 必须是已完成外层升级的流。
pub async fn client_action<S>(stream: &mut S, action: Action, target_port: u16) -> Outcome
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match action {
        Action::Normal => {
            send_request(
                stream,
                &tcp_request(target_port),
                &Credential::new(PASSWORD),
                WAIT,
            )
            .await
            .expect("写 trojan 头失败");
            bounded_write(stream, PAYLOAD).await.expect("写载荷超时");
            bounded_flush(stream).await.expect("flush 超时");
            read_exact_outcome(stream, action.reply_len()).await
        }
        Action::WrongPassword => {
            send_request(
                stream,
                &tcp_request(target_port),
                &Credential::new(BAD_PASSWORD),
                WAIT,
            )
            .await
            .expect("写 trojan 头失败");
            bounded_write(stream, PAYLOAD).await.expect("写载荷超时");
            bounded_flush(stream).await.expect("flush 超时");
            observe_rejection(stream).await
        }
        Action::Truncated { cut } => {
            let header = header_bytes(target_port, PASSWORD);
            assert!(cut < header.len(), "截断点必须落在头部之内");
            bounded_write(stream, &header[..cut])
                .await
                .expect("写截断头超时");
            bounded_flush(stream).await.expect("flush 超时");
            // 写端**保持打开**：等对端按握手截止给出有界拒绝。
            observe_rejection(stream).await
        }
        Action::HalfClose => {
            send_request(
                stream,
                &tcp_request(target_port),
                &Credential::new(PASSWORD),
                WAIT,
            )
            .await
            .expect("写 trojan 头失败");
            bounded_write(stream, PAYLOAD).await.expect("写载荷超时");
            bounded_flush(stream).await.expect("flush 超时");
            // 关写端：WS 下发 Close 帧，其余走底层 FIN。
            bounded_shutdown(stream).await.expect("关写端超时");
            read_exact_outcome(stream, action.reply_len()).await
        }
    }
}

/// 读满定长回程；读不足或出错都如实记录**实际读到的字节数**。
///
/// 这里不用 `read_exact`：它在出错时不报告已读字节数，若把缓冲区整体当作
/// 回程，长度断言会变成空转（缓冲区是零填充的）。改成自己累加，得到的
/// `reply.len()` 就是线上真实回程长度。
async fn read_exact_outcome<S: AsyncRead + Unpin>(stream: &mut S, len: usize) -> Outcome {
    let mut reply = vec![0u8; len];
    let mut filled = 0usize;
    let mut peer_error = false;
    while filled < len {
        let read = match timeout(WAIT, stream.read(&mut reply[filled..])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(read)) => read,
            Ok(Err(_)) => {
                peer_error = true;
                break;
            }
            Err(_) => break,
        };
        filled += read;
    }
    reply.truncate(filled);
    Outcome {
        reply,
        peer_error,
        ..Outcome::default()
    }
}

/// 观察对端结束连接：读到 0 字节 = 正常结束；读到错误 = 异常结束；
/// 读到数据 = 不该发生（记录为 `unexpected_data`）。
async fn observe_rejection<S: AsyncRead + Unpin>(stream: &mut S) -> Outcome {
    let mut buf = [0u8; 64];
    match timeout(CLOSE_BOUND, stream.read(&mut buf)).await {
        Ok(Ok(0)) => Outcome {
            peer_closed: true,
            ..Outcome::default()
        },
        Ok(Ok(read)) => Outcome {
            reply: buf[..read].to_vec(),
            unexpected_data: true,
            ..Outcome::default()
        },
        Ok(Err(_)) => Outcome {
            peer_error: true,
            ..Outcome::default()
        },
        Err(_) => Outcome::default(),
    }
}

/// 本仓服务端一条连接的处理**判定**。
///
/// `server::Error` 不实现 `PartialEq`（它包着 `ss_core::Error` 等非可比类型），
/// 因此这里把可判别的失败归一成一组**互斥**的变体，用 `matches!` 断言，
/// 既不依赖 `PartialEq`，也不放宽判据。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// 处理成功结束（正常往返、半关闭后的服务端侧收尾）。
    Completed,
    /// 首块协议判定线之前（参考 `proxy/trojan/server.go:176` 的
    /// `firstLen < 58 || first.Byte(56) != '\r'`）。
    NotTrojanProtocol,
    /// 认证失败（哈希不匹配）。
    Authentication,
    /// 握手截止内头部未读全。
    Timeout,
    /// 非法命令字节。
    InvalidCommand,
    /// 外层传输升级失败（路径/头不匹配）——发生在 trojan 协议层之前。
    UpgradeFailed,
    /// 其它错误。
    Other,
}

impl Verdict {
    /// 把 `server::Error` 归一成判定变体。
    pub fn of(error: &ServerError) -> Self {
        match error {
            ServerError::NotTrojanProtocol => Verdict::NotTrojanProtocol,
            ServerError::Authentication => Verdict::Authentication,
            ServerError::Timeout => Verdict::Timeout,
            ServerError::InvalidCommand(_) => Verdict::InvalidCommand,
            _ => Verdict::Other,
        }
    }
}
