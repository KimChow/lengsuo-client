//! 显式上游隔离测试的回环桩与任务回收。

use super::*;

/// 单个 await 的最外层兜底总超时：正常路径远低于此，触顶即判失败。
pub(super) const WAIT: Duration = Duration::from_secs(10);
/// 传给 `exchange` 的正常期限：会真正收到响应的用例预算。
pub(super) const OPEN: Duration = Duration::from_millis(900);
/// 期限类用例的内部预算：应早于外层 `WAIT` 触发，证明 deadline 生效。
pub(super) const TIGHT: Duration = Duration::from_millis(250);
/// 制造交错用的小延迟：远小于 `OPEN`，只用于让两条交换的收发窗口明确重叠。
pub(super) const STAGGER: Duration = Duration::from_millis(80);
/// 断言收包计数前的观察窗：让「本不该到达」的报文有机会被计入。
pub(super) const SETTLE: Duration = Duration::from_millis(150);
/// 假上游单次接收的缓冲区上限。
pub(super) const MAX_DATAGRAM: usize = 512;

/// 编码一个未压缩名字（长度八位组 + 标签 + 结尾零）。
pub(super) fn encode_name(labels: &[&str], out: &mut Vec<u8>) {
    for label in labels {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// 12 字节头部 + 问题区名字。`reply` 决定 QR 位，`answers` 决定 ANCOUNT。
pub(super) fn framing(id: u16, labels: &[&str], reply: bool, answers: u16) -> Vec<u8> {
    // 查询：RD=1；响应：QR|RD|RA，rcode 0。
    let flags: u16 = if reply { 0x8180 } else { 0x0100 };
    let mut message = Vec::new();
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&flags.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    message.extend_from_slice(&answers.to_be_bytes()); // ANCOUNT
    message.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    message.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(labels, &mut message);
    message
}

/// 构造一条 A 记录查询：QR=0、opcode=0、QDCOUNT=1、后续三区为空。
pub(super) fn query(id: u16, labels: &[&str]) -> Vec<u8> {
    let mut message = framing(id, labels, false, 0);
    message.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    message.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    message
}

/// 构造一条回显 `labels` 问题区、带一条 A 记录的响应；`answer` 为 4 字节 rdata。
pub(super) fn response(id: u16, labels: &[&str], answer: [u8; 4]) -> Vec<u8> {
    let mut message = framing(id, labels, true, 1);
    message.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    message.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    message.extend_from_slice(&0xC00C_u16.to_be_bytes()); // 指针回指偏移 12 的名字
    message.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    message.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    message.extend_from_slice(&60u32.to_be_bytes()); // TTL
    message.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    message.extend_from_slice(&answer);
    message
}

/// 构造一条 AAAA 问题区的响应：与 A 查询的 qtype 不符，用于问题区错配用例。
pub(super) fn response_qtype_aaaa(id: u16, labels: &[&str]) -> Vec<u8> {
    let mut message = framing(id, labels, true, 0);
    message.extend_from_slice(&28u16.to_be_bytes()); // qtype AAAA
    message.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    message
}

/// 取响应末尾的 4 字节 A 记录 rdata，作为「哪条上游答的」可区分标记。
pub(super) fn answer_of(message: &[u8]) -> Option<[u8; 4]> {
    let tail = message.len().checked_sub(4)?;
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&message[tail..]);
    Some(bytes)
}

/// 失败描述只报「第几号失败种类」，绝不把报文原始字节写进断言输出。
pub(super) fn shape(result: &Result<Vec<u8>, Error>) -> String {
    match result {
        Ok(bytes) => format!("Ok({} 字节)", bytes.len()),
        Err(error) => format!("Err({error:?})"),
    }
}

/// 一个假上游：loopback 随机端口 + 服务端实际收包计数。
pub(super) struct Upstream {
    pub(super) socket: UdpSocket,
    pub(super) addr: SocketAddr,
    pub(super) seen: Arc<AtomicUsize>,
}

impl Upstream {
    /// 在 `127.0.0.1` 随机端口绑定；初始收包计数为 0。
    pub(super) async fn bind() -> Self {
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("loopback 绑定随机端口");
        let addr = socket.local_addr().expect("读取假上游地址");
        Self {
            socket,
            addr,
            seen: Arc::new(AtomicUsize::new(0)),
        }
    }
}

/// 收包计数的只读句柄；把上游本体 move 进任务后仍能在主体里断言。
pub(super) struct Seen(Arc<AtomicUsize>);

impl Seen {
    pub(super) fn of(upstream: &Upstream) -> Self {
        Self(Arc::clone(&upstream.seen))
    }

    pub(super) fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// 收到一条查询计数一次，回一份预制载荷，只服务一次。
pub(super) async fn answer_once(upstream: Upstream, reply: Vec<u8>) {
    let Upstream {
        socket,
        seen,
        addr: _,
    } = upstream;
    let mut buffer = [0u8; MAX_DATAGRAM];
    if let Ok(Ok((_, peer))) = timeout(WAIT, socket.recv_from(&mut buffer)).await {
        seen.fetch_add(1, Ordering::SeqCst);
        let _ = socket.send_to(&reply, peer).await;
    }
}

/// 收到一条查询计数一次；等 `gate` 放行后才回载荷，用于把两条交换的收发窗口
/// 拉成明确重叠。等待本身也受 `WAIT` 兜底，绝不无限悬挂。
pub(super) async fn answer_when_gated(
    upstream: Upstream,
    reply: Vec<u8>,
    gate: oneshot::Receiver<()>,
) {
    let Upstream {
        socket,
        seen,
        addr: _,
    } = upstream;
    let mut buffer = [0u8; MAX_DATAGRAM];
    let Ok(Ok((_, peer))) = timeout(WAIT, socket.recv_from(&mut buffer)).await else {
        return;
    };
    seen.fetch_add(1, Ordering::SeqCst);
    let _ = timeout(WAIT, gate).await;
    let _ = socket.send_to(&reply, peer).await;
}

/// 晚一拍放行：让被门控的上游在另一条交换已完成收发之后才发话。
pub(super) async fn release_after(gate: oneshot::Sender<()>, delay: Duration) {
    tokio::time::sleep(delay).await;
    let _ = gate.send(());
}

/// 收到一条查询计数一次，连发 `times` 份非法载荷后保持沉默。
pub(super) async fn flood_invalid(upstream: Upstream, junk: Vec<u8>, times: usize) {
    let Upstream {
        socket,
        seen,
        addr: _,
    } = upstream;
    let mut buffer = [0u8; MAX_DATAGRAM];
    if let Ok(Ok((_, peer))) = timeout(WAIT, socket.recv_from(&mut buffer)).await {
        seen.fetch_add(1, Ordering::SeqCst);
        for _ in 0..times {
            let _ = socket.send_to(&junk, peer).await;
        }
    }
}

/// 只计数不回应：冒充「系统 DNS 替身 / 另一出口」，任何到达它的查询都算回退泄漏。
pub(super) async fn only_count(upstream: Upstream) {
    let Upstream {
        socket,
        seen,
        addr: _,
    } = upstream;
    let mut buffer = [0u8; MAX_DATAGRAM];
    // 静默监听，直到内部窗口结束才退出；期间每条到达的查询都计入计数。
    while let Ok(Ok(_)) = timeout(OPEN, socket.recv_from(&mut buffer)).await {
        seen.fetch_add(1, Ordering::SeqCst);
    }
}

/// 回收自建任务：已结束就 await 取结果，未结束先 abort 再 await，不留悬挂任务。
pub(super) async fn reap(handles: impl IntoIterator<Item = JoinHandle<()>>) {
    for handle in handles {
        if !handle.is_finished() {
            handle.abort();
        }
        let _ = handle.await;
    }
}
