//! 显式上游异步 UDP 请求-响应测试：`dns::upstream::exchange`。
//!
//! 覆盖：两个并发上游各返回不同响应（验证独占 socket）、同一 peer 先错 ID
//! 再合法、错误 qname、无响应超时、上游来源伪造不接受、查询非法时不发包、
//! 零期限拒绝。全部走 loopback + 随机端口，绝不碰公网 DNS；每个用例都套总
//! 超时兜底，结束时 join 自建任务。这些测试只证明本原语的语义，不代表整个
//! TUN/DNS 转发链路验收完成。

use lengsuo_tun::dns::upstream::{self, Error};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// 用例兜底总超时：本模块只在 loopback 上收发，正常应远低于此。
const WAIT: Duration = Duration::from_secs(5);
/// 传给 exchange 的正常期限（会真正收到响应的用例）。
const OPEN: Duration = Duration::from_millis(800);
/// 给超时类用例的内部期限：应早于外层 WAIT 触发，证明 deadline 生效。
const TIGHT: Duration = Duration::from_millis(300);

/// 编码一个未压缩名字（长度八位组 + 标签 + 结尾零）。
fn encode_name(labels: &[&str], out: &mut Vec<u8>) {
    for label in labels {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// 构造一条合法 A 记录查询：QR=0、opcode=0、QDCOUNT=1、后续三区为空。
fn query(id: u16, labels: &[&str]) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&0x0100u16.to_be_bytes()); // RD，其余标志 0
    m.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    m.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    m.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    m.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(labels, &mut m);
    m.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    m.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    m
}

/// 构造一条回显 `labels` 问题区的响应：QR=1、单问题；可选携带一条 A 记录。
fn response(id: u16, labels: &[&str], answer: Option<[u8; 4]>) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&0x8180u16.to_be_bytes()); // QR|RD|RA，rcode 0
    m.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    m.extend_from_slice(&u16::from(answer.is_some()).to_be_bytes()); // ANCOUNT
    m.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    m.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(labels, &mut m);
    m.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    m.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    if let Some(rdata) = answer {
        m.extend_from_slice(&0xC00C_u16.to_be_bytes()); // 指针回指偏移 12 的问题名字
        m.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        m.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        m.extend_from_slice(&60u32.to_be_bytes()); // TTL
        m.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        m.extend_from_slice(&rdata);
    }
    m
}

/// 绑定一个 loopback 随机端口 UDP socket，返回 socket 与其本地地址。
async fn bind() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .expect("loopback 绑定随机端口");
    let addr = socket.local_addr().expect("读取本地地址");
    (socket, addr)
}

/// 调用被测函数：每次现取一份期限，其余原样透传。
async fn exchange(
    q: &[u8],
    upstream_addr: SocketAddr,
    deadline: Duration,
) -> Result<Vec<u8>, Error> {
    upstream::exchange(q, upstream_addr, deadline).await
}

async fn join(handles: impl IntoIterator<Item = JoinHandle<()>>) {
    for handle in handles {
        // 自建任务多数已自然结束；兜底 abort 避免悬挂。
        if !handle.is_finished() {
            handle.abort();
        }
        let _ = handle.await;
    }
}

/// 两个并发上游各返回不同响应：验证每次调用独占 socket、互不串扰。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_upstreams_are_independent() {
    let labels = ["example", "com"];
    let id = 0x1234u16;
    let q = query(id, &labels);
    let a = response(id, &labels, Some([1, 1, 1, 1]));
    let b = response(id, &labels, Some([2, 2, 2, 2]));

    let (sock_a, addr_a) = bind().await;
    let (sock_b, addr_b) = bind().await;
    let handles = vec![
        tokio::spawn(answer_once(sock_a, a.clone())),
        tokio::spawn(answer_once(sock_b, b.clone())),
    ];

    let (ra, rb) = timeout(WAIT, {
        let qa = q.clone();
        let qb = q.clone();
        async move { tokio::try_join!(exchange(&qa, addr_a, OPEN), exchange(&qb, addr_b, OPEN)) }
    })
    .await
    .expect("并发交换总超时")
    .expect("两个上游均应各自拿到响应");

    assert_eq!(ra, a);
    assert_eq!(rb, b);
    assert_ne!(a, b, "两份响应应可区分，证明未串扰");

    join(handles).await;
}

/// 收到一条查询后原样回一份响应，然后结束（用于正常/并发用例）。
async fn answer_once(socket: UdpSocket, reply: Vec<u8>) {
    let mut buf = [0u8; 512];
    let (_, peer) = socket.recv_from(&mut buf).await.expect("收到查询");
    socket.send_to(&reply, peer).await.expect("发出响应");
}

/// 收到一条查询后回两份响应：先一份 ID 错的，再一份合法的（同一 peer）。
async fn answer_wrong_then_right(socket: UdpSocket, wrong: Vec<u8>, right: Vec<u8>) {
    let mut buf = [0u8; 512];
    let (_, peer) = socket.recv_from(&mut buf).await.expect("收到查询");
    socket.send_to(&wrong, peer).await.expect("发出错 ID 响应");
    socket.send_to(&right, peer).await.expect("发出合法响应");
}

/// 同一 peer 先错 ID、后合法：丢弃不匹配包并继续等待合法响应。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_id_then_valid_is_accepted() {
    let labels = ["example", "com"];
    let id = 0x00ffu16;
    let q = query(id, &labels);
    let right = response(id, &labels, Some([9, 9, 9, 9]));
    // ID 漂移一位以上，结构合法但与查询 ID 不符，应被丢弃。
    let wrong = response(id ^ 0x5a5a, &labels, Some([8, 8, 8, 8]));

    let (sock, addr) = bind().await;
    let handles = vec![tokio::spawn(answer_wrong_then_right(
        sock,
        wrong,
        right.clone(),
    ))];

    let got = timeout(WAIT, exchange(&q, addr, OPEN))
        .await
        .expect("单次交换超过兜底")
        .expect("应最终拿到合法响应");
    assert_eq!(got, right);
    join(handles).await;
}

/// 错误 qname：ID 相符但问题名字不同 → 丢弃 → 内部期限超时（不回注错会话）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_qname_times_out() {
    let labels = ["example", "com"];
    let id = 0x2222u16;
    let q = query(id, &labels);
    // 同一 ID，但问题区名字改成 example.net，结构合法却与查询 qname 不符。
    let bad = response(id, &["example", "net"], Some([7, 7, 7, 7]));

    let (sock, addr) = bind().await;
    let handles = vec![tokio::spawn(answer_once(sock, bad))];

    let result = timeout(WAIT, exchange(&q, addr, TIGHT))
        .await
        .expect("单次交换超过兜底");
    assert!(matches!(result, Err(Error::Timeout)), "得到 {result:?}");
    join(handles).await;
}

/// 上游完全不回应：内部 deadline 生效，返回超时错误。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_response_times_out() {
    let labels = ["dnstest", "example"];
    let q = query(0x3333, &labels);
    let (sock, addr) = bind().await;
    // 只收查询、永不回应。
    let handles = vec![tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let _ = sock.recv_from(&mut buf).await;
        tokio::time::sleep(WAIT).await;
    })];

    let started = tokio::time::Instant::now();
    let result = timeout(WAIT, exchange(&q, addr, TIGHT))
        .await
        .expect("交换超过兜底")
        .expect_err("应超时");
    assert!(matches!(result, Error::Timeout), "得到 {result:?}");
    assert!(started.elapsed() < WAIT, "超时未受内部 deadline 约束");
    join(handles).await;
}

/// 收到查询后不回应，仅把客户端源地址报出（用于来源伪造用例），随后保活静默。
async fn silent_but_report(socket: UdpSocket, tx: tokio::sync::mpsc::Sender<SocketAddr>) {
    let mut buf = [0u8; 512];
    let (_, peer) = socket.recv_from(&mut buf).await.expect("收到查询");
    let _ = tx.send(peer).await;
    // exchange 连接的是这个地址：保持 socket 存活并始终不回。
    tokio::time::sleep(WAIT).await;
}

/// 上游来源伪造：合法响应从非连接 peer 的地址发来，连接式 socket 不收 → 超时。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_source_is_not_accepted() {
    let labels = ["example", "com"];
    let id = 0x4444u16;
    let q = query(id, &labels);
    let good = response(id, &labels, Some([5, 5, 5, 5]));

    // 合法上游：静默、仅报出客户端源地址（exchange 连接的正是它）。
    let (legit, legit_addr) = bind().await;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SocketAddr>(1);
    let legit_handle = tokio::spawn(silent_but_report(legit, tx));

    // 交换在后台运行，等待那份永远不会从合法上游到达的响应。
    let exchange_handle = tokio::spawn({
        let q = q.clone();
        async move { exchange(&q, legit_addr, TIGHT).await }
    });

    // 拿到客户端源地址后，由另一个地址（伪造方）发来一份逐字节合法的响应。
    let client = timeout(WAIT, rx.recv())
        .await
        .expect("等待查询来源总超时")
        .expect("合法上游应收到查询并报出源地址");
    let (forger, forger_addr) = bind().await;
    assert_ne!(forger_addr, legit_addr, "伪造方源地址须与连接 peer 不同");
    let sent = forger.send_to(&good, client).await.expect("伪造方发出响应");
    assert_eq!(sent, good.len(), "伪造响应应完整发出");

    let result = timeout(WAIT, exchange_handle)
        .await
        .expect("交换任务未结束")
        .expect("任务不应 panic")
        .expect_err("伪造来源不应被接受");
    assert!(matches!(result, Error::Timeout), "得到 {result:?}");

    legit_handle.abort();
    let _ = legit_handle.await;
}

/// 收到查询就报出源地址；用于验证非法查询根本不会发包。
async fn report_if_queried(socket: UdpSocket, tx: tokio::sync::mpsc::Sender<SocketAddr>) {
    let mut buf = [0u8; 512];
    if let Ok(Ok((_, peer))) = timeout(OPEN, socket.recv_from(&mut buf)).await {
        let _ = tx.send(peer).await;
    }
}

/// 查询本身非法：拒绝且不发送任何报文。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_query_sends_nothing() {
    let (sock, addr) = bind().await;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SocketAddr>(1);
    let handles = vec![tokio::spawn(report_if_queried(sock, tx))];

    // 短到无法构成合法查询的载荷。
    let bad_query = vec![0u8, 1, 2];
    let result = exchange(&bad_query, addr, OPEN)
        .await
        .expect_err("非法查询应被拒绝");
    assert!(matches!(result, Error::BadQuery(_)), "得到 {result:?}");

    // 上游不应收到任何查询：report_if_queried 在内部超时后静默结束，通道为空。
    assert!(
        !matches!(timeout(OPEN, rx.recv()).await, Ok(Some(_))),
        "非法查询却发出了报文"
    );
    join(handles).await;
}

/// 零期限直接拒绝，绝不进入绑定/收发。
#[tokio::test]
async fn zero_deadline_rejected() {
    let labels = ["example", "com"];
    let q = query(0x5555, &labels);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
    let result = upstream::exchange(&q, addr, Duration::ZERO)
        .await
        .expect_err("零期限应被拒绝");
    assert!(matches!(result, Error::InvalidDeadline), "得到 {result:?}");
}
