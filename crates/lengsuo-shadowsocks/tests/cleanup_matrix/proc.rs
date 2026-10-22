//! 「清理」格的**进程级资源回收观测窗**（独占锁 + 基线读数 + 回落断言）。
//!
//! 范式来源：`crates/lengsuo-wireguard/tests/half_close_matrix/fixture.rs`
//! —— `open_fd_count()`（`:239`，读 `/proc/self/fd`）、`thread_count()`（`:252`，
//! 读 `/proc/self/task`）、以及「进程级读数观测窗」的独占锁（`:275-287`）。
//! 本卡**照抄**那套做法（对那个文件只读引用，未改动），不另造「等价」实现。
//!
//! 观测点本体在同目录的 [`super::probe`]（`open_fd_count` / `thread_count`）；
//! 本模块负责「读数窗口」：
//!
//! 1. **独占锁**：fd 数与线程数都是**进程级**读数，同一测试二进制里并行执行的
//!    其它用例会污染观测窗（其它用例的回环 socket、libtest 的用例线程）⇒ 假红。
//!    因此本二进制的**全部**用例都取同一把锁 ⇒ 整轮串行执行 ⇒ 观测窗内读数
//!    只反映被测用例自身的行为。
//! 2. **同构基线**：基线与收尾读数**都在同一个 runtime 里**取 ⇒ runtime 自身的
//!    epoll/eventfd 句柄在两边同时出现、同时抵消。
//! 3. **有界轮询**：「连接任务结束」与「内核释放 fd」之间有一个很短的窗口
//!    （连接任务被 drop 时 socket 才关闭），用有界轮询把**时序**噪声与真正的
//!    **泄漏**区分开——泄漏时读数永远不回落，轮询到期限即失败。
//!
//! ⚠️ 平台口径：非 Linux 平台**没有**这两个可观测点（无 `/proc`）⇒ 返回
//! `None` ⇒ 调用方**如实报告「该平台无法断言」**，绝不编造一个假数字。

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use lengsuo_shadowsocks::{
    RelayConfig, RelayConfigParts, RelayHandle, RelayService, TargetAddr, TcpReader, TcpWriter,
};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::common::{IDLE_TIMEOUT, SUITE, WAIT};
use super::probe::{open_fd_count, thread_count};

/// fd 数的允许抖动：基线 + 0。
///
/// 论证：基线与收尾读数**取自同一个 runtime**（runtime 自身的 epoll/eventfd
/// 句柄在两边同时出现、同时抵消），因此两者之差**恰为**被测连接残留的 fd 数。
/// 本仓的中继在 `RelayHandle::shutdown` 里 `JoinSet::shutdown` ⇒ abort 并**等待**
/// 全部连接任务 ⇒ 连接 socket 随之 drop ⇒ 不留常驻句柄 ⇒ 容忍度取 **0**。
///
/// （`/proc/self/fd` 的读取本身会占用一个目录句柄，但它在**每一次**读数里都
/// 出现 ⇒ 同样抵消，不影响差值。）
pub const FD_SLACK: usize = 0;

/// 线程数的允许抖动：基线 + 0。
///
/// 论证：本仓的 SS 实现**不创建任何线程**（`src/` 内无 `thread::spawn` /
/// `spawn_blocking`；连接任务用 `spawn_local` 跑在当前线程 runtime 上）⇒
/// 一次「连接 → 关闭 → 会话结束」**不得**留下任何线程 ⇒ 容忍度取 **0**。
///
/// 线程读数会受 **libtest 自身**影响：libtest 为每个用例派发一个线程
/// （`/proc/self/task/<tid>/comm` 就是用例名），这些线程随用例结束而**退出**。
/// 观测窗被独占锁保护 ⇒ 窗口内没有别的用例在跑 ⇒ 读数**只减不增**；基线取
/// 「派发突发结束后的稳定值」，收尾读数因此不会更大 ⇒ 容忍度 0 可稳定成立。
pub const THREAD_SLACK: usize = 0;

/// 回落观察窗口的期限：与 `common::OBSERVE` 同量级（连接收尾应在观察窗口内
/// 完成；期限内不回落 ⇒ 判失败，**绝不**把超时当成通过）。
pub const RECLAIM_WINDOW: Duration = Duration::from_secs(3);

/// 基线的稳定窗口：轮询到读数**连续三次不变**为止（上限本值）。
///
/// 为什么需要：libtest 在启动时**一次性**派发本二进制的全部用例线程 ⇒ 头几
/// 毫秒内线程数**爬升**。基线若落在爬升途中，收尾读数就会「比基线大」——那是
/// libtest 的线程，不是被测代码的。稳定窗口把基线取在爬升结束之后。
pub const SETTLE_WINDOW: Duration = Duration::from_millis(1000);

/// 稳定窗口与回落轮询的轮询间隔。
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// 「进程级读数观测窗」的独占锁。
///
/// 理由见模块头：fd/线程数是**进程级**读数，必须把并行执行的其它用例挡在
/// 观测窗外，否则读数随机漂移 ⇒ 假红。
///
/// 用 `tokio::sync::Mutex`（异步感知）：`std::sync::MutexGuard` 跨 `.await`
/// 持有是 clippy 明令禁止的错误（`await_holding_lock`）。
static SERIAL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// 取得串行执行锁（**同步**用例用：必须在进入 runtime **之前**取）。
///
/// `blocking_lock` 内部用 tokio 自己的 `block_on` 阻塞等待 ⇒ 必须在**同步**
/// 上下文（本仓的 `#[test]` 函数体开头）调用：若在 runtime 上下文里调用，
/// tokio 会 panic（`Cannot block the current thread from within a runtime`）。
pub fn serial_guard() -> tokio::sync::MutexGuard<'static, ()> {
    SERIAL_LOCK.blocking_lock()
}

/// 一份进程级资源读数快照。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resources {
    /// 打开的文件描述符数（`/proc/self/fd`）。
    pub fds: usize,
    /// 线程数（`/proc/self/task`）。
    pub threads: usize,
}

impl Resources {
    /// 取当前快照。
    ///
    /// 任一观测点缺失 ⇒ `None`：该平台**不宣称**「资源已回收」（如实报告
    /// 「无法断言」），不得用假数字凑一个「通过」。
    pub fn snapshot() -> Option<Self> {
        Some(Self {
            fds: open_fd_count()?,
            threads: thread_count()?,
        })
    }
}

/// 取**稳定基线**：轮询到读数**连续三次不变**为止，取观测到的**线程数最大值**
/// 与**末次 fd 数**。
///
/// - 线程数取最大值：窗口内任何一次读数偏高都可能是「派发爬升」的一部分，
///   把它算进基线才不会误判成被测代码的线程泄漏。
/// - fd 数取末次值：fd 读数没有「爬升」语义，取瞬时值最贴近「此刻开了几个
///   fd」这个事实。
///
/// 调用时机约定：必须在「**中继已启动、尚无本用例的连接**」时调用——这样基线
/// 里的 fd 就是「常驻的那些」，差值才是「这条连接残留了多少」。
pub async fn baseline() -> Option<Resources> {
    let deadline = tokio::time::Instant::now() + SETTLE_WINDOW;
    let mut threads = thread_count()?;
    let mut last = Resources {
        fds: open_fd_count()?,
        threads,
    };
    let mut stable = 0usize;
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        let now = Resources::snapshot()?;
        threads = threads.max(now.threads);
        stable = if now == last { stable + 1 } else { 0 };
        last = now;
        if stable >= 3 || tokio::time::Instant::now() >= deadline {
            break;
        }
    }
    Some(Resources {
        fds: last.fds,
        threads,
    })
}

/// 断言「资源已回收」：fd 数与线程数都回落到「基线 + 抖动」以内。
///
/// **调用方约定**（三条，缺一则断言无效）：
///
/// 1. 基线与本断言**在同一个 runtime 里**：runtime 自身的句柄在两边抵消，且
///    读数**不包含**已被场景释放的句柄。
/// 2. 基线取自「中继已启动、尚无本用例的连接」；本断言做于「**连接已结束、
///    会话已被回收**」——这样差值才是「这条连接残留了多少 fd / 线程」，而不是
///    「进程退出后当然没有 fd」那种无效断言。
/// 3. 必须持有 [`serial_guard`]，把并行用例挡在观测窗外。
///
/// - 观测点缺失（`None`）⇒ **跳过并打印说明**（不宣称通过），不伪造数字。
/// - 期限内未回落 ⇒ 断言失败，消息里带上基线、上限与最后一次读数。
pub async fn assert_reclaimed(baseline: Option<Resources>, context: &str) {
    let Some(baseline) = baseline else {
        eprintln!(
            "[ss-cleanup] 本平台无 /proc/self/fd 或 /proc/self/task 观测点 ⇒ \
             进程级资源回收**未断言**（{context}）：该平台按「不宣称」口径处理"
        );
        return;
    };
    let deadline = tokio::time::Instant::now() + RECLAIM_WINDOW;
    // 末次读数（失败时进断言消息）。
    let last = loop {
        let Some(now) = Resources::snapshot() else {
            eprintln!("[ss-cleanup] 读数中途失去观测点 ⇒ 进程级资源回收**未断言**（{context}）");
            return;
        };
        let reclaimed =
            now.fds <= baseline.fds + FD_SLACK && now.threads <= baseline.threads + THREAD_SLACK;
        if reclaimed || tokio::time::Instant::now() >= deadline {
            break now;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    };
    let fds = last.fds;
    let threads = last.threads;
    assert!(
        fds <= baseline.fds + FD_SLACK,
        "{context}：连接结束 {RECLAIM_WINDOW:?} 内 fd 数未回落到基线 {} + 抖动 {FD_SLACK} \
         （最后一次读数 {fds}，线程读数 {threads}）",
        baseline.fds
    );
    assert!(
        threads <= baseline.threads + THREAD_SLACK,
        "{context}：连接结束 {RECLAIM_WINDOW:?} 内线程数未回落到基线 {} + 抖动 {THREAD_SLACK} \
         （最后一次读数 {threads}，fd 读数 {fds}）",
        baseline.threads
    );
}

/// 运行时生成的**假口令**（与任何生产凭据无关）。
///
/// 任务书要求「运行时生成的假口令」：每个用例用**当场生成**的随机口令 ⇒ 用例
/// 之间不可能因为「口令相同」而互相干扰。口令**从不**进日志或断言消息。
pub fn runtime_password() -> Vec<u8> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("生成随机假口令");
    bytes.to_vec()
}

/// 起一个**回环**中继，用给定口令与**临时端口**（端口 0 ⇒ 由内核分配）。
///
/// 不挂 salt 记忆池状态文件（本组只观测进程级资源回收，不需要记忆池语义）。
pub async fn start_relay_with_password(password: &[u8]) -> (SocketAddr, RelayHandle) {
    let config = RelayConfig::new(
        RelayConfigParts {
            suite: SUITE,
            idle_timeout: IDLE_TIMEOUT,
            replay: None,
        },
        password,
    );
    let service = RelayService::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), config)
        .await
        .expect("中继绑定");
    let addr = service.local_addr().expect("中继地址");
    let handle = service.start().await.expect("中继启动");
    (addr, handle)
}

/// 客户端方向的一次「写请求 → 半关闭写端 → 读回程到干净 EOF」，返回回程字节。
///
/// 读端用 [`TcpReader`] 解帧；**写端必须先半关闭**（否则回程方向不会结束）。
pub async fn roundtrip_with_password(
    relay: SocketAddr,
    target: &TargetAddr,
    payload: &[u8],
    password: &[u8],
) -> Vec<u8> {
    let mut stream = timeout(WAIT, TcpStream::connect(relay))
        .await
        .expect("连接中继超时")
        .expect("连接中继");
    let mut request: Vec<u8> = Vec::new();
    target.encode_checked(&mut request).expect("回环目标可编码");
    request.extend_from_slice(payload);
    let mut writer = TcpWriter::new(&mut stream, SUITE, password, WAIT).expect("构造写端");
    timeout(WAIT, writer.send(&request))
        .await
        .expect("send 未被外层超时")
        .expect("send 成功");
    timeout(WAIT, writer.shutdown())
        .await
        .expect("shutdown 未被外层超时")
        .expect("写半关闭应成功");
    drop(writer);

    let (read_half, _write_half) = stream.split();
    let mut reader = TcpReader::new(read_half, SUITE, password, WAIT).expect("构造读端");
    let mut got = Vec::new();
    for _ in 0..16 {
        match timeout(WAIT, reader.recv()).await.expect("recv 超时") {
            Ok(Some(chunk)) => got.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(err) => panic!("回程读取失败（应等到干净 EOF）：{err}"),
        }
    }
    got
}

/// 客户端方向的一次「**连发多个 chunk** → 半关闭写端 → 读回程到干净 EOF」。
///
/// 覆盖 `copy_request` 的「**后续 chunk** 转发」分支：同一条连接上连发 N 个
/// chunk（salt 只在第一个 chunk 前上线，nonce 序列连续）⇒ 与 `common.rs` 的
/// `send_request_chunks` 同构，只是口令改为运行时传入。
///
/// 返回回程字节（各 chunk 的回显按发送顺序拼接）。
pub async fn multichunk_roundtrip_with_password(
    relay: SocketAddr,
    target: &TargetAddr,
    payloads: &[&[u8]],
    password: &[u8],
) -> Vec<u8> {
    let mut stream = timeout(WAIT, TcpStream::connect(relay))
        .await
        .expect("连接中继超时")
        .expect("连接中继");
    let mut writer = TcpWriter::new(&mut stream, SUITE, password, WAIT).expect("构造写端");
    for (index, payload) in payloads.iter().enumerate() {
        let mut request: Vec<u8> = Vec::new();
        if index == 0 {
            target.encode_checked(&mut request).expect("回环目标可编码");
        }
        request.extend_from_slice(payload);
        timeout(WAIT, writer.send(&request))
            .await
            .expect("send 未被外层超时")
            .expect("send 成功");
    }
    timeout(WAIT, writer.shutdown())
        .await
        .expect("shutdown 未被外层超时")
        .expect("写半关闭应成功");
    drop(writer);

    let (read_half, _write_half) = stream.split();
    let mut reader = TcpReader::new(read_half, SUITE, password, WAIT).expect("构造读端");
    let mut got = Vec::new();
    for _ in 0..16 {
        match timeout(WAIT, reader.recv()).await.expect("recv 超时") {
            Ok(Some(chunk)) => got.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(err) => panic!("回程读取失败（应等到干净 EOF）：{err}"),
        }
    }
    got
}

/// 客户端方向的一次「写请求」（**不半关闭**写端，连接保持打开）。
pub async fn write_request_with_password(
    stream: &mut TcpStream,
    target: &TargetAddr,
    payload: &[u8],
    password: &[u8],
) {
    let mut request: Vec<u8> = Vec::new();
    target.encode_checked(&mut request).expect("回环目标可编码");
    request.extend_from_slice(payload);
    let mut writer = TcpWriter::new(&mut *stream, SUITE, password, WAIT).expect("构造写端");
    timeout(WAIT, writer.send(&request))
        .await
        .expect("send 未被外层超时")
        .expect("send 成功");
    drop(writer);
}
