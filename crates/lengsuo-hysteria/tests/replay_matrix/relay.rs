//! `replay_matrix` 支撑代码的**网络转发与轮询**部分。
//!
//! 与 `support.rs` 同属本卡自带副本（**不**依赖仓库级的
//! `tests/support/mod.rs`，那是其它卡独占的共享支撑文件）。
//!
//! 提供：
//! - `UdpRelay`：UDP 中继，抓取「客户端 → 服务端」方向的数据报，供
//!   **包级重放**逐字节重发；
//! - `json_escape`：把任意字符串安全地嵌进 JSON 字符串字面量
//!   （参考 Xray 的配置是 JSON 文本）；
//! - `wait_until`：轮询等待条件成立（禁止「固定 sleep 后直接断言」）；
//! - `CASE_DEADLINE` / `case_within`：用例级的**总墙钟上限**兜底。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ===========================================================================
// 用例级墙钟上限
// ===========================================================================

/// 单条用例的**总**墙钟上限。
///
/// 内部每一步都有各自的超时（建连 / 写 / 读），但用例整体还要留一道
/// 兜底：万一某个等待路径没套超时，用例也不能挂死整个测试进程。
pub(crate) const CASE_DEADLINE: Duration = Duration::from_secs(90);

/// 把一条异步用例包进「总墙钟上限」里。
///
/// 用法：`case_within(CASE_DEADLINE, async { ... }).await;`
///
/// 超时 ⇒ **panic**（不是静默通过）：挂死的用例必须暴露成失败。
pub(crate) async fn case_within<F>(deadline: Duration, fut: F)
where
    F: std::future::Future<Output = ()>,
{
    match tokio::time::timeout(deadline, fut).await {
        Ok(()) => {}
        Err(_) => panic!("用例超过总墙钟上限 {deadline:?}（挂死）"),
    }
}

// ===========================================================================
// UDP 中继（包级重放用）
// ===========================================================================

/// UDP 中继：客户端连到中继，中继把流量转发到真实服务端，并把
/// **客户端 → 服务端**方向的每个数据报原样记录下来，供「包级重放」使用。
///
/// 关键：中继**用同一个 socket** 收发两个方向 ⇒
/// - 服务端看到的客户端源地址恒为中继 socket；
/// - 重放时用同一 socket、同一字节、同一源地址 ⇒ 是**逐字节精确重放**。
///
/// **多客户端**：中继可能同时挂着若干条客户端连接（跨连接重放用例）。
/// 服务端 → 客户端方向的数据报**广播**给所有已知客户端 —— 这是安全的：
/// QUIC 用连接 ID 寻址，客户端只会处理属于自己连接的包（quinn 对未知
/// CID 的短头包静默丢弃）。
pub(crate) struct UdpRelay {
    /// 客户端应当连接的地址。
    pub(crate) addr: SocketAddr,
    /// 真实服务端地址。
    server: SocketAddr,
    sock: Arc<tokio::net::UdpSocket>,
    captured: Arc<Mutex<Vec<Vec<u8>>>>,
    #[allow(dead_code)]
    task: tokio::task::JoinHandle<()>,
}

impl UdpRelay {
    /// 起一个中继，把流量转发到 `server`。
    pub(crate) async fn start(server: SocketAddr) -> Self {
        let sock = Arc::new(
            tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("绑定 UDP 中继"),
        );
        let addr = sock.local_addr().expect("中继地址");
        let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let clients: Arc<Mutex<Vec<SocketAddr>>> = Arc::new(Mutex::new(Vec::new()));
        let task_sock = Arc::clone(&sock);
        let task_captured = Arc::clone(&captured);
        let task_clients = Arc::clone(&clients);
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let Ok((n, from)) = task_sock.recv_from(&mut buf).await else {
                    return;
                };
                let payload = buf[..n].to_vec();
                if from == server {
                    // 服务端 → 客户端：广播给所有已知客户端（QUIC 按连接
                    // ID 寻址，非本连接的数据报被对端丢弃）。
                    let peers = task_clients.lock().expect("中继客户端锁中毒").clone();
                    for peer in peers {
                        let _ = task_sock.send_to(&payload, peer).await;
                    }
                } else {
                    // 客户端 → 服务端：记住客户端地址、转发并记录（供重放）。
                    //
                    // ⚠️ 锁的作用域必须**在** `await` 之前结束：`MutexGuard`
                    // 不是 `Send`，跨 `await` 存活会让 `tokio::spawn` 的
                    // future 失去 `Send`（`future cannot be sent between
                    // threads safely`）。用独立代码块把守卫圈住，而不是
                    // `drop(slot)` —— 后者在 async 生成器里仍被判为
                    // 「maybe used later」。
                    {
                        let mut slots = task_clients.lock().expect("中继客户端锁中毒");
                        if !slots.contains(&from) {
                            slots.push(from);
                        }
                    }
                    task_captured
                        .lock()
                        .expect("中继捕获锁中毒")
                        .push(payload.clone());
                    let _ = task_sock.send_to(&payload, server).await;
                }
            }
        });
        Self {
            addr,
            server,
            sock,
            captured,
            task,
        }
    }

    /// 已捕获的「客户端 → 服务端」数据报（按到达顺序）。
    pub(crate) fn captured(&self) -> Vec<Vec<u8>> {
        self.captured.lock().expect("中继捕获锁中毒").clone()
    }

    /// 重放第 `index` 个捕获的数据报（逐字节、原源地址、原 socket）。
    ///
    /// 返回是否确实发出。
    pub(crate) async fn replay(&self, index: usize) -> bool {
        let Some(bytes) = self.captured().get(index).cloned() else {
            return false;
        };
        self.sock.send_to(&bytes, self.server).await.is_ok()
    }
}

// ===========================================================================
// JSON 转义（参考 Xray 的配置是 JSON 文本）
// ===========================================================================

/// 把任意字符串安全地嵌进 **JSON 字符串字面量**。
///
/// 规则（RFC 8259）：`\` → `\\`，`"` → `\"`，其余 U+0000..U+001F 控制字符
/// → `\u00XX`。
pub(crate) fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

// ===========================================================================
// 轮询等待
// ===========================================================================

/// 轮询等待条件成立：总时长不超过 `deadline`。
///
/// 禁止「固定 sleep 后直接断言」：条件不成立就等到总截止时间。
/// 条件本身是**同步**闭包（观测点都是同步可读的，如 `target.received()`），
/// 因此不会把外部变量 move 进 `async move` 块。
///
/// ⚠️ **只能用于肯定断言**（等某个状态**出现**）。否定断言（等某个状态
/// **不出现**）必须用 [`observe_never`]：本函数在条件**恒不成立**时会一直
/// 轮询到超时才返回 `false`，用它做否定断言会把「没观察到」和「超时」
/// 混为一谈，而且条件写成 `<= before` 这类**恒真**形式时会在第一次轮询
/// 就返回 `true` ⇒ 断言**恒成立**、形同虚设。
pub(crate) async fn wait_until<F>(deadline: Duration, mut cond: F) -> bool
where
    F: FnMut() -> bool,
{
    let end = tokio::time::Instant::now() + deadline;
    loop {
        let left = end.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return false;
        }
        if cond() {
            return true;
        }
        let left = end.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return false;
        }
        tokio::time::sleep(left.min(crate::support::POLL_INTERVAL)).await;
    }
}

/// 否定断言的观测窗：在 `window` 内**持续**观察 `cond`，一旦条件成立
/// 就**立刻**返回 `false`（说明发生了不该发生的事）。
///
/// 与 [`wait_until`] 的区别：
/// - `wait_until` 等条件**出现**（肯定断言）；
/// - `observe_never` 等条件**不出现**（否定断言）—— 条件一旦成立立刻
///   失败并给出**成立时刻**，而不是等到超时才发现。
///
/// 语义：返回 `true` = 整个观测窗内条件**始终不成立**（符合预期）。
///
/// ⚠️ 观测窗是**有限**的：本函数只能证明「在 `window` 内没发生」，
/// 不能证明「永远不会发生」。这是「重放不得污染后续会话」这类断言的
/// 合理上限 —— 传输层的丢弃是**立即**发生的，不需要更长的窗。
pub(crate) async fn observe_never<F>(window: Duration, mut cond: F) -> bool
where
    F: FnMut() -> bool,
{
    let end = tokio::time::Instant::now() + window;
    loop {
        if cond() {
            return false;
        }
        let left = end.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return true;
        }
        tokio::time::sleep(left.min(crate::support::POLL_INTERVAL)).await;
    }
}

// ===========================================================================
// 轮询原语的自检
// ===========================================================================

/// 自检：`observe_never` 必须**真的能失败**。
///
/// 这条不是「凑数测试」—— 否定断言的整个有效性都建立在
/// `observe_never` 能观察到「不该发生的事发生了」之上。若这个原语恒返回
/// `true`，本卡所有「重放**不得**污染新会话 / **不得**重复交付 /
/// **不得**新建连接」的断言都会**形同虚设**却仍然显示通过。
///
/// 判据：
/// - 条件**恒真** ⇒ 必须返回 `false`（立刻失败，不是等满窗）；
/// - 条件**恒假** ⇒ 必须返回 `true`（整个观测窗都没发生）。
#[tokio::test]
async fn observe_never_detects_a_violation() {
    // 恒真条件：必须**立刻**失败。
    let started = tokio::time::Instant::now();
    let detected = !observe_never(Duration::from_secs(30), || true).await;
    assert!(
        detected,
        "observe_never 对**恒真**条件必须返回 false（检测到违规）"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "observe_never 必须**立刻**发现违规，而不是等满观测窗（耗时 {:?}）",
        started.elapsed()
    );

    // 恒假条件：整个观测窗内都没发生 ⇒ 返回 true。
    let never = observe_never(Duration::from_millis(120), || false).await;
    assert!(
        never,
        "observe_never 对**恒假**条件必须返回 true（观测窗内始终未发生）"
    );
}

/// 自检：`wait_until` 的**恒真**条件是**陷阱**（它第一次轮询就返回），
/// 而 `observe_never` 的恒真条件是**正确**的（它必须失败）。
///
/// 这条把「为什么否定断言不能用 `wait_until`」钉成可执行的事实：
/// `wait_until(|| true)` 立刻返回 `true` ⇒ 用它做否定断言等于**恒真**、
/// 形同虚设。
#[tokio::test]
async fn wait_until_true_is_trivially_satisfied_but_observe_never_is_not() {
    // `wait_until` 对恒真条件：立刻成功 ⇒ 拿它做否定断言毫无意义。
    let trivially = wait_until(Duration::from_millis(50), || true).await;
    assert!(trivially, "wait_until 对恒真条件应立刻成功");

    // `observe_never` 对同一个恒真条件：必须失败。
    let flagged = !observe_never(Duration::from_millis(50), || true).await;
    assert!(
        flagged,
        "observe_never 对恒真条件必须失败（这正是它与 wait_until 的区别）"
    );
}
