//! 错误认证与收尾验收的**共享测试骨架**：固定基线身份、假凭据与有限时间常量、
//! 可显式回收的回环业务目标壳与 fallback 信标壳，以及“每一处 socket 写入都有超时”的
//! 有界 IO 助手。判定用的观测面（accept 计数、读侧结束）都在这里定义。
use super::support::*;
use lengsuo_tls::TlsClient;
use lengsuo_trojan::stream::send_request;
pub use lengsuo_trojan::{Command, Credential, Request, TargetAddr};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

/// 测试专用假凭据。
pub const GOOD: &str = "trojan-error-good-test-password";
pub const BAD: &str = "trojan-error-wrong-test-password";
pub const PAYLOAD: &[u8] = b"business-request-payload";
pub const REPLY: &[u8] = b"business-reply-payload";
/// 等待参考端主动结束连接的上限，必须明显小于参考默认的 60 秒握手截止，
/// 否则“观察超时”与“被拒绝”无法区分。
pub const CLOSE_BOUND: Duration = Duration::from_secs(8);
/// 单个用例的有限总预算（含参考进程启动与对照组）。
pub const TOTAL: Duration = Duration::from_secs(60);
/// 大回程载荷：跨多个 TLS 记录，验证半关闭之后的回程仍被完整收到。
pub const BULK_LEN: usize = 64 * 1024;
/// 普通 socket 写入与 flush 的有限预算（回环上远够用，仅用于兜住失控等待）。
pub const WRITE_BOUND: Duration = Duration::from_secs(3);
/// 64 KiB 回程写入的有限预算（仍远小于总预算）。
pub const WRITE_BULK: Duration = Duration::from_secs(10);
/// 回收一个自建任务（abort 后等待其真正退出）的预算。
pub const RECYCLE_BOUND: Duration = Duration::from_secs(12);

/// 把 policy 握手截止压到 2 秒，用于观测“头部写了一半之后静默”的有界拒绝。
pub fn policy() -> Value {
    json!({"levels":{"0":{"handshake":2}}})
}

pub struct Identity {
    client: TlsClient,
    cert: rcgen::CertifiedKey,
}

impl Identity {
    pub fn new() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        Self {
            client: TlsClient::new("localhost", [cert.cert.der().clone()], WAIT).unwrap(),
            cert,
        }
    }
    /// 已完成认证 TLS 的流；具体类型由 `lengsuo-tls` 决定，本文件不命名它。
    pub async fn connect(&self, port: u16) -> impl AsyncRead + AsyncWrite + Unpin {
        self.client
            .connect(([127, 0, 0, 1], port).into())
            .await
            .unwrap()
    }
    pub fn server_settings(&self) -> Value {
        json!({"security":"tls","tlsSettings":{"certificates":[{
            "certificate":self.cert.cert.pem().lines().collect::<Vec<_>>(),
            "key":self.cert.key_pair.serialize_pem().lines().collect::<Vec<_>>() }]}})
    }
}

/// 有界轮询一个观测面：命中返回 true；调用方用 timeout 给出观察上限。
pub async fn wait_until(predicate: impl Fn() -> bool) -> bool {
    loop {
        if predicate() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// 自管理的回环 TCP 壳的**测试 owner**：拥有端口与监听句柄（回收完成前端口不
/// 提前释放，`free_port` 也不会把它再发给参考服务）、accept 计数（唯一的“是否
/// 抵达业务”观测面）、FIN 观测计数，以及可显式回收的 accept 句柄 + 每连接任务
/// 集。连接处理登记在同一个任务集里，不再产生无人回收的嵌套 spawn；每条连接的
/// 读、写、flush、关写端全部受有限超时约束。测试结束必须调用 `recycle()`。
pub struct TcpShell {
    listener: Option<Arc<TcpListener>>,
    accepted: Arc<AtomicUsize>,
    fin_seen: Arc<AtomicUsize>,
    accept: Option<JoinHandle<()>>,
    workers: Arc<Mutex<JoinSet<()>>>,
}

impl TcpShell {
    /// `reply` 为回程载荷；`hold_until_fin` 决定是否先保留读侧直到收到我方 FIN
    /// 再回写（半关闭验收），否则读满请求立刻回写、不依赖 FIN 传播。
    pub async fn bind(reply: Vec<u8>, hold_until_fin: bool) -> Self {
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let accepted = Arc::new(AtomicUsize::new(0));
        let fin_seen = Arc::new(AtomicUsize::new(0));
        let workers = Arc::new(Mutex::new(JoinSet::new()));
        // 共享监听句柄：owner 与 accept 循环各持一份，端口只在双方都释放后回收。
        let accept = tokio::spawn(accept_loop(
            listener.clone(),
            accepted.clone(),
            workers.clone(),
            Arc::new(reply),
            fin_seen.clone(),
            hold_until_fin,
        ));
        TcpShell {
            listener: Some(listener),
            accepted,
            fin_seen,
            accept: Some(accept),
            workers,
        }
    }

    pub fn port(&self) -> u16 {
        self.listener.as_ref().unwrap().local_addr().unwrap().port()
    }

    pub fn counter(&self) -> Arc<AtomicUsize> {
        self.accepted.clone()
    }

    /// 半关闭验收壳：回写大载荷之后继续观测读侧直到结束（FIN 观测）。
    pub async fn fin_shell(bulk: Vec<u8>) -> Self {
        Self::bind(bulk, true).await
    }

    /// 回程写完之后观测到的“读侧结束”次数。固定基线在收到我方写半关闭后会直接
    /// 结束到目标的连接，因此这里既可能是我方 FIN、也可能是参考端关闭，只作为
    /// 记录性观测，不参与拒绝判定。
    pub fn fin_count(&self) -> usize {
        self.fin_seen.load(Ordering::SeqCst)
    }

    /// 显式回收：abort accept 循环并 await 其真正退出，再 await 全部每连接任务。
    /// 每一步都有有限预算；worker 未在预算内退出直接失败，不静默泄漏。
    pub async fn recycle(mut self) {
        if let Some(accept) = self.accept.take() {
            accept.abort();
            let _ = timeout(RECYCLE_BOUND, accept).await;
        }
        // 循环已断，再放掉 owner 这份监听句柄，端口随之释放。
        self.listener = None;
        // 先在锁内整批取出，再在锁外逐个 await，绝不持锁跨 await。
        let mut batch = std::mem::take(&mut *self.workers.lock().unwrap());
        loop {
            match timeout(RECYCLE_BOUND, batch.join_next()).await {
                Ok(None) => break,
                Ok(Some(_)) => {}
                Err(_) => panic!("自建连接任务未在回收预算内退出，任务泄漏"),
            }
        }
    }
}

/// fallback 信标的 owner：由测试拥有端口与监听句柄，取连接走**有界 accept**，
/// 不启动任何后台循环，因此不存在永不回收的任务；句柄 drop 即回收端口。
pub struct BeaconShell {
    listener: Option<TcpListener>,
    accepted: Arc<AtomicUsize>,
}

impl BeaconShell {
    pub async fn bind() -> Self {
        BeaconShell {
            listener: Some(TcpListener::bind("127.0.0.1:0").await.unwrap()),
            accepted: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn port(&self) -> u16 {
        self.listener.as_ref().unwrap().local_addr().unwrap().port()
    }

    pub fn counter(&self) -> Arc<AtomicUsize> {
        self.accepted.clone()
    }

    /// 取走 fallback 转来的第一条连接（含 xver=1 头部）；等待有界，
    /// 取不到即失败，不靠超时推断。
    pub async fn take_one(&self) -> TcpStream {
        let accepted = timeout(CLOSE_BOUND, self.listener.as_ref().unwrap().accept())
            .await
            .expect("认证失败应由 fallback 接住，而不是既不拒绝也不分流")
            .unwrap();
        self.accepted.fetch_add(1, Ordering::SeqCst);
        accepted.0
    }

    /// 回收：释放监听句柄（端口随之归还）。没有后台循环，因此没有悬挂任务。
    pub fn recycle(self) {
        drop(self.listener.expect("信标监听器由 owner 持有至回收"));
    }
}

/// 每接受一条连接就计数，并登记一条读满请求后回写载荷的处理任务。
async fn accept_loop(
    listener: Arc<TcpListener>,
    counter: Arc<AtomicUsize>,
    pool: Arc<Mutex<JoinSet<()>>>,
    reply: Arc<Vec<u8>>,
    fin_seen: Arc<AtomicUsize>,
    hold_until_fin: bool,
) {
    loop {
        // accept 不设整体超时（等待拨号不算失控）：abort 会取消这条 await，
        // 这一份监听句柄随之丢弃，端口在 owner 也放掉后释放。
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };
        counter.fetch_add(1, Ordering::SeqCst);
        let worker = serve(socket, reply.clone(), fin_seen.clone(), hold_until_fin);
        pool.lock().unwrap().spawn(worker);
    }
}

/// 单条业务连接：读满请求 → 回写载荷 → flush → 关写端；`observe_fin` 时再观测
/// 我方 FIN 是否传到目标端。
///
/// 回写**不**吊在 FIN 之后：实测固定基线（Xray 26.3.27/d2758a0，freedom 出口）在
/// 收到我方写半关闭后会直接结束到目标的连接，若等 FIN 才回写就会把回程一起切断，
/// 那属于“外层传输行为”，不是本用例要验收的协议结论。本用例验收的是：我方半关闭
/// 之后，回程 64 KiB 仍能完整收到。FIN 观测因此放在回程写完之后，且只作记录。
async fn serve(
    mut socket: TcpStream,
    reply: Arc<Vec<u8>>,
    fin_seen: Arc<AtomicUsize>,
    observe_fin: bool,
) {
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
    if bounded_write(&mut socket, &reply, WRITE_BULK)
        .await
        .is_err()
    {
        return;
    }
    let _ = bounded_flush(&mut socket).await;
    let _ = bounded_shutdown(&mut socket).await;
    if observe_fin {
        // 读侧到结束（Ok(0)）或错误/超时为止，记录 FIN 是否真的抵达目标端。
        let mut tail = [0u8; 1];
        if matches!(timeout(WAIT, socket.read(&mut tail)).await, Ok(Ok(0))) {
            fin_seen.fetch_add(1, Ordering::SeqCst);
        }
    }
}

pub fn tcp_request(port: u16) -> Request {
    Request {
        command: Command::Tcp,
        target: TargetAddr::V4([127, 0, 0, 1], port),
    }
}

pub fn trojan_inbound(port: u16, settings: Value, identity: &Identity) -> Value {
    json!({"listen":"127.0.0.1","port":port,"protocol":"trojan",
        "settings":settings,"streamSettings":identity.server_settings()})
}

/// 单次 socket 写入的有限预算：返回 `Result` 而非 `bool`，调用方既要知道是否
/// 超时，也要知道写失败的原因。文件内**每一处** socket 写入/flush/关写端都走
/// 这三个函数，不出现裸 `write_all(...).await.unwrap()`。
pub async fn bounded_write<S: AsyncWrite + Unpin>(
    stream: &mut S,
    payload: &[u8],
    within: Duration,
) -> Result<(), std::io::Error> {
    match timeout(within, stream.write_all(payload)).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "回环写入超时",
        )),
    }
}

pub async fn bounded_flush<S: AsyncWrite + Unpin>(stream: &mut S) -> Result<(), std::io::Error> {
    match timeout(WRITE_BOUND, stream.flush()).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "回环 flush 超时",
        )),
    }
}

pub async fn bounded_shutdown<S: AsyncWrite + Unpin>(stream: &mut S) -> Result<(), std::io::Error> {
    match timeout(WAIT, stream.shutdown()).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "回环关写端超时",
        )),
    }
}

/// 正向对照：认证请求头 + 载荷 + 写半关闭，然后收到回程应答。/// 证明同一套观测面确实能抓到“抵达目标”的连接，拒绝断言不是空转。
pub async fn control_round_trip(identity: &Identity, port: u16, target: u16) {
    let mut stream = identity.connect(port).await;
    send_request(
        &mut stream,
        &tcp_request(target),
        &Credential::new(GOOD),
        WAIT,
    )
    .await
    .unwrap();
    // 我方每一处 socket 写入同样受有限超时约束，不出现裸 await。
    bounded_write(&mut stream, PAYLOAD, WRITE_BOUND)
        .await
        .expect("对照写入请求载荷超时");
    bounded_flush(&mut stream).await.expect("对照 flush 超时");
    // tokio 在 TCP 上的 shutdown 只关写半（SHUT_WR），读侧仍须能收回程。
    bounded_shutdown(&mut stream).await.expect("对照关写端超时");
    let mut reply = vec![0; REPLY.len()];
    timeout(WAIT, stream.read_exact(&mut reply))
        .await
        .expect("对照回程超时")
        .unwrap();
    assert_eq!(reply, REPLY);
}

/// 拒绝用例的写侧：完整头部 + 载荷，但用错误密码。不关闭写端，把连接的
/// 结局完全交给参考端决定（要么主动结束，要么被 fallback 接走）。
pub async fn wrong_password_offer(
    identity: &Identity,
    port: u16,
    target: u16,
) -> impl AsyncRead + Unpin {
    let mut stream = identity.connect(port).await;
    send_request(
        &mut stream,
        &tcp_request(target),
        &Credential::new(BAD),
        WAIT,
    )
    .await
    .unwrap();
    bounded_write(&mut stream, PAYLOAD, WRITE_BOUND)
        .await
        .expect("失败分支写入请求载荷超时");
    bounded_flush(&mut stream)
        .await
        .expect("失败分支 flush 超时");
    stream
}

/// 读一侧直到参考端结束连接。`expect` 触发说明只拿到观察超时；
/// 本文件不把超时单独当作拒绝证据。
pub async fn await_close<S: AsyncRead + Unpin>(
    stream: &mut S,
    within: Duration,
) -> std::io::Result<usize> {
    timeout(within, stream.read(&mut [0u8; 32]))
        .await
        .expect("参考端必须在观察上限内主动结束连接（超时本身不算拒绝证据）")
}
