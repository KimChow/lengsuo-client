//! 「清理」矩阵的**观测手段**（上游事件、端口占用、salt 记忆池条目）。
//!
//! 这些手段存在的理由：本仓的会话资源是**不可见**的（`RelayService` 只暴露
//! `shutdown`，没有「当前连接数」这类计数器），因此「资源被回收」必须从
//! **外部可观测的事实**推断：
//!
//! - **上游侧**：中继是否关闭了它拨出去的那条连接（上游看到 EOF / 错误）。
//! - **端口侧**：listener 是否真的关了（`/proc/net/tcp` 的 LISTEN 状态 + 同端口
//!   重新 bind）。
//! - **记忆池侧**：salt 记录是否按实现的真实语义留在窗口里。
//!
//! 全部只读回环与临时路径，不碰生产资源。

use std::path::Path;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::common::{OBSERVE, WAIT};

/// 上游目标的可观测事件。
#[derive(Debug, PartialEq, Eq)]
pub enum TargetEvent {
    /// 上游接受了中继拨来的连接（证明中继真的连上了上游）。
    Accepted,
    /// 上游读到了字节（只记长度，**不记内容**，避免日志带出载荷）。
    Received(usize),
    /// 上游看到对端 EOF（**中继**关闭了上游连接的读半 ⇒ 上游资源被回收）。
    PeerEof,
    /// 上游读到错误（RST / 其它）。
    Failed,
}

/// 一个回环上游目标：接受连接并按 flavor 行事。
pub struct Target {
    pub addr: std::net::SocketAddr,
    pub events: mpsc::UnboundedReceiver<TargetEvent>,
}

/// 上游目标的行事方式。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    /// 回声：把收到的字节原样写回，然后等对端 EOF。
    Echo,
    /// 立刻 RST：接受后 `SO_LINGER=0` 直接 drop（发 RST，不是 FIN）。
    Reset,
    /// 持住：接受后既不读也不写，连接一直开着（用于「relay 关闭时在途连接」）。
    Hold,
    /// **分段**回声：每读到一段就**单独**写回并 flush，不等后续字节。
    ///
    /// 与 [`Flavor::Echo`] 的关键区别：`Echo` 把读到的字节原样写回，但**读**的粒度
    /// 由 TCP 决定（多段可能被**合并**成一次读）⇒ 回程方向看到的是「合并后」的
    /// 字节流，无法区分「上游发了几段」。`Segmented` 每次读到就立刻写回并 flush，
    /// 让**回程方向**的每次读对应上游的**每一次写**——这样「回程方向漏掉了某一段」
    /// 这类缺陷才会暴露成可观测的**字节数缺失**。
    Segmented,
}

/// 起一个回环上游目标。
pub async fn spawn_target(flavor: Flavor) -> Target {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("target 地址");
    let (tx, events) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let _ = tx.send(TargetEvent::Accepted);
                match flavor {
                    Flavor::Reset => {
                        let _ = stream.set_zero_linger();
                        drop(stream);
                        let _ = tx.send(TargetEvent::Failed);
                    }
                    Flavor::Hold => {
                        // 持住连接：直到对端关闭才继续。
                        let mut sink = vec![0u8; 4096];
                        loop {
                            match stream.read(&mut sink).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                        let _ = tx.send(TargetEvent::PeerEof);
                    }
                    Flavor::Echo | Flavor::Segmented => {
                        let mut buffer = vec![0u8; 8192];
                        loop {
                            let got = match stream.read(&mut buffer).await {
                                Ok(0) => {
                                    let _ = tx.send(TargetEvent::PeerEof);
                                    break;
                                }
                                Err(_) => {
                                    let _ = tx.send(TargetEvent::Failed);
                                    break;
                                }
                                Ok(got) => got,
                            };
                            let _ = tx.send(TargetEvent::Received(got));
                            if stream.write_all(&buffer[..got]).await.is_err() {
                                let _ = tx.send(TargetEvent::Failed);
                                break;
                            }
                            // `Segmented`：每次写完立刻 flush，不等后续字节 ⇒ 回程
                            // 方向的每次读对应上游的每次写（段不会被合并）。
                            if flavor == Flavor::Segmented {
                                let _ = stream.flush().await;
                            }
                        }
                        let _ = stream.shutdown().await;
                    }
                }
            });
        }
    });
    Target { addr, events }
}

/// 取出目标在期限内产生的下一个事件（超时 ⇒ `None`）。
pub async fn next_event(target: &mut Target, limit: Duration) -> Option<TargetEvent> {
    timeout(limit, target.events.recv()).await.ok().flatten()
}

/// 收集目标在**总期限**内产生的全部事件（期限内不再有新事件即结束）。
///
/// 逐事件用 `gap` 的短轮询间隔判断「暂时没有新事件」，整体不超过 `limit`；
/// 这样「上游只被连了一次」这类计数断言不会因为把 `Accepted` 事件提前消费掉
/// 而误判。
pub async fn drain_events(target: &mut Target, limit: Duration, gap: Duration) -> Vec<TargetEvent> {
    let deadline = Instant::now() + limit;
    let mut events = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let step = gap.min(remaining);
        match timeout(step, target.events.recv()).await {
            Ok(Some(event)) => events.push(event),
            Ok(None) => break,
            Err(_) => {
                // 本次轮询窗口内没有新事件：若总期限还没到，再多等一个窗口。
                if Instant::now() >= deadline {
                    break;
                }
            }
        }
    }
    events
}

/// 等上游**本次调用期间**累计收到的字节数达到 `expected`（在期限内），返回该累计值。
///
/// 返回值是**增量**（从本次调用开始算起），不是历史总和：调用方据此判断
/// 「这一批 chunk 是否已被完整转发到上游」。用于「先确认上游已收到 N 字节，
/// 再制造异常」的同步点：否则 RST 可能与转发并发，断言就变成竞态。
///
/// **超时不会被当成通过**——返回最后一次读到的累计值，调用方据此断言失败。
pub async fn wait_received_delta(target: &mut Target, expected: usize, limit: Duration) -> usize {
    let deadline = Instant::now() + limit;
    let mut total = 0usize;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(
            remaining.min(Duration::from_millis(200)),
            target.events.recv(),
        )
        .await
        {
            Ok(Some(TargetEvent::Received(len))) => {
                total += len;
                if total >= expected {
                    return total;
                }
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {}
        }
    }
    total
}

/// 事件序列里 `Received` 事件的字节数总和。
pub fn received_bytes(events: &[TargetEvent]) -> usize {
    events
        .iter()
        .filter_map(|event| match event {
            TargetEvent::Received(len) => Some(*len),
            _ => None,
        })
        .sum()
}

/// 读**原始字节**（不解帧）到 EOF 或首次错误。
///
/// `Ok(bytes)` = 对端干净关闭（FIN）；`Err(err)` = RST / 其它错误；超时按「对端
/// 还没关」处理（返回 `Ok(空)`，调用方用时限区分）。
pub async fn read_raw_until_end(mut stream: TcpStream) -> std::io::Result<Vec<u8>> {
    let mut got = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match timeout(WAIT, stream.read(&mut buffer)).await {
            Ok(Ok(0)) => return Ok(got),
            Ok(Ok(count)) => got.extend_from_slice(&buffer[..count]),
            Ok(Err(err)) => return Err(err),
            Err(_) => return Ok(got),
        }
    }
}

/// 端口上是否还有 **LISTEN** 状态的套接字（仅 Linux；找不到 `/proc/net/tcp` ⇒ `None`）。
///
/// 只看 LISTEN（状态 `0A`）：`TIME_WAIT` 之类的残留套接字**不**代表端口仍被
/// listener 占用，混进来会把「端口已释放」误判成「端口仍被占用」。
pub fn port_has_listener(port: u16) -> Option<bool> {
    let mut found = false;
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let mut fields = line.split_whitespace();
            let _sl = fields.next()?;
            let local = fields.next()?;
            let _remote = fields.next()?;
            let state = fields.next()?;
            if state != "0A" {
                continue;
            }
            if let Some((_, hex_port)) = local.rsplit_once(':') {
                if hex_port.eq_ignore_ascii_case(&format!("{port:04X}")) {
                    found = true;
                }
            }
        }
    }
    Some(found)
}

/// 在 [`OBSERVE`] 内等对端关闭（干净 EOF 或错误都算「关闭了」）。
///
/// 返回 `true` = 在期限内观察到对端关闭；`false` = 期限内没关（说明中继没及时
/// 感知断开）。**超时**与「没关」都返回 `false`，绝不把超时当成通过。
pub async fn closed_within(mut stream: TcpStream) -> bool {
    let mut buffer = [0u8; 4096];
    match timeout(OBSERVE, stream.read(&mut buffer)).await {
        Ok(Ok(0)) => true,
        Ok(Ok(_)) => {
            // 读到了字节：继续读到真正结束。
            match timeout(OBSERVE, read_raw_until_end(stream)).await {
                Ok(Ok(_)) | Ok(Err(_)) => true,
                Err(_) => false,
            }
        }
        Ok(Err(_)) => true,
        Err(_) => false,
    }
}

/// 等 salt 记忆池状态文件里的条目数**达到** `expected`（在期限内）。
///
/// 中继的收尾回写发生在**连接任务结束**时，而客户端看到干净 EOF 只说明回程
/// 方向已半关闭——两者之间有一个很短的窗口。因此这里用**有界轮询**而不是
/// 立刻读：到达 `expected` 即返回实际值；期限内没到达则返回最后一次读到的值
/// （调用方据此断言失败）。**超时不会被当成通过**。
pub async fn wait_pool_entries(path: &Path, expected: usize, limit: Duration) -> usize {
    let deadline = Instant::now() + limit;
    let mut last = salt_pool_entries(path).unwrap_or(0);
    loop {
        last = salt_pool_entries(path).unwrap_or(last);
        if last == expected {
            return last;
        }
        if Instant::now() >= deadline {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// salt 记忆池状态文件里**当前仍记在窗口内**的条目数。
///
/// `None` = 文件不存在（记忆池还没回写过 ⇒ 窗口从未被记入任何已认证连接）。
///
/// 文件布局（`crate::persist`）：`magic(8) | version(4) | body_len(8) | body | mac(32)`；
/// body 布局（`crate::replay::encode_body`）：
/// `capacity(8) | window_ms(8) | [salt_len(1) | salt | seen(8)]*`。
/// 状态体本身**不加密**（只有 HMAC 标签保护完整性），所以测试可以直接数条目。
pub fn salt_pool_entries(path: &Path) -> Option<usize> {
    let bytes = std::fs::read(path).ok()?;
    const BODY_OFFSET: usize = 8 + 4 + 8;
    if bytes.len() < BODY_OFFSET + 16 {
        return None;
    }
    let body_len = u64::from_le_bytes(bytes[12..20].try_into().expect("长度字段在界内")) as usize;
    let body_end = BODY_OFFSET.checked_add(body_len)?;
    if bytes.len() < body_end {
        return None;
    }
    let body = &bytes[BODY_OFFSET..body_end];
    let mut cursor = 16usize; // capacity(8) + window_ms(8)
    let mut count = 0usize;
    while cursor < body.len() {
        let salt_len = body[cursor] as usize;
        cursor += 1;
        if cursor + salt_len + 8 > body.len() {
            return None;
        }
        cursor += salt_len + 8;
        count += 1;
    }
    Some(count)
}
