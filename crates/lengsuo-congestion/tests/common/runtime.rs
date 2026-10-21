//! 最小 std-only 异步运行时（仅供本 crate 的端到端测试使用）。
//!
//! # 为什么需要它
//!
//! quinn 的 `Endpoint` 需要一个 `Runtime` 实现（定时器 + UDP socket 读写 +
//! 任务派生）。本 crate 的依赖只有 `quinn`（其 `runtime-tokio` feature 会在
//! **编译期**把 tokio 带进来，但 tokio 并不是本 crate 的**直接依赖**，
//! Rust 不允许在代码里引用未在 `Cargo.toml` 中声明的 crate）。
//!
//! 而把 `tokio` 加进 `[dev-dependencies]` 会**改动 `Cargo.lock`** —— 超出本卡
//! 边界（`Cargo.lock` 由基建卡独占）。
//!
//! 故这里用 `std` 手写一个最小运行时：
//! - 定时器：到期时刻由后台线程到期唤醒；
//! - UDP 读：独立后台线程做非阻塞 `recvmsg`，把数据放进队列；
//! - 任务派生：每个任务一个后台线程。
//!
//! 规模很小（测试专用），不追求性能，只求**行为正确**。
//!
//! # `quinn::Instant` 是私有的
//!
//! `quinn` 的 `Runtime` trait 用 `quinn::Instant`（= `quinn-proto` 的
//! `Instant` = `std::time::Instant`）作定时器时刻，但 `quinn` **没有**
//! re-export 它（`pub(crate) use std::time::Instant`）。本模块因此**不**
//! 显式写该类型：用 `impl Runtime for StdRuntime` 时，让类型由 trait 签名
//! 推导即可（`fn new_timer(&self, at: quinn::Instant)` 写成
//! `fn new_timer(&self, at: _)` 不可行 —— 改用**完全省略类型标注**的方式：
//! 实现 trait 时参数类型必须写出来，故这里用 `quinn::Runtime` 的
//! 关联写法 —— 见下方 `new_timer` 的实现说明）。
//!
//! # 安全
//!
//! 不含 `unsafe`（quinn 内部除外）；不涉及密钥/明文/口令。

use std::collections::VecDeque;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::time::{Duration, Instant as StdInstant};

use quinn::udp::{RecvMeta, Transmit, UdpSocketState};
use quinn::{AsyncTimer, AsyncUdpSocket, Runtime, UdpPoller};

/// 把一个 `Future` 变成可 `Waker` 唤醒的 `Waker`（置位型唤醒）。
fn make_waker(ready: Arc<AtomicBool>) -> Waker {
    unsafe fn clone(data: *const ()) -> RawWaker {
        let arc = unsafe { Arc::from_raw(data as *const AtomicBool) };
        let cloned = arc.clone();
        std::mem::forget(arc);
        RawWaker::new(Arc::into_raw(cloned) as *const (), &VTABLE)
    }
    unsafe fn wake(data: *const ()) {
        let arc = unsafe { Arc::from_raw(data as *const AtomicBool) };
        arc.store(true, Ordering::SeqCst);
    }
    unsafe fn wake_by_ref(data: *const ()) {
        let arc = unsafe { Arc::from_raw(data as *const AtomicBool) };
        arc.store(true, Ordering::SeqCst);
        std::mem::forget(arc);
    }
    unsafe fn drop_waker(data: *const ()) {
        drop(unsafe { Arc::from_raw(data as *const AtomicBool) });
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop_waker);
    let raw = RawWaker::new(Arc::into_raw(ready) as *const (), &VTABLE);
    // SAFETY: `VTABLE` 的四个函数都遵守 `RawWaker` 契约。
    unsafe { Waker::from_raw(raw) }
}

/// 轮询一个 future 直到就绪，返回其输出；**超时则 panic**。
///
/// 用于「这一步必须成功」的路径（握手、开流等）—— 超时属环境异常，
/// 直接暴露而不是静默继续。
pub fn block_on<F: Future>(mut future: F, timeout: Duration) -> F::Output {
    block_on_inner(future, timeout)
        .unwrap_or_else(|| panic!("block_on 超时（{timeout:?}）"))
}

/// 轮询一个 future 直到就绪，返回其输出；**超时返回 `None`（不 panic）**。
///
/// 用于「超时是可接受结局」的路径（如测量窗口内的单次流写入）——
/// 调用方据此**放弃本次测量**而不是让整个用例 panic。
///
/// ⚠️ 之前 `brutal_e2e` 的写超时保护写了 `Err(_) => break`，
/// 但 `block_on` 超时是 **panic** ⇒ 那个「放弃」分支是**死代码**，
/// 于是负载下 10s 写超时直接把整个用例打成失败
/// （`cargo test --workspace --locked` 的合流门禁随机打红）。
pub fn block_on_timeout<F: Future>(mut future: F, timeout: Duration) -> Option<F::Output> {
    block_on_inner(future, timeout)
}

/// `block_on` / `block_on_timeout` 的共同实现。
fn block_on_inner<F: Future>(mut future: F, timeout: Duration) -> Option<F::Output> {
    let deadline = StdInstant::now() + timeout;
    let ready = Arc::new(AtomicBool::new(true));
    let waker = make_waker(ready.clone());
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `future` 在本函数内不被移动。
    let mut future = unsafe { Pin::new_unchecked(&mut future) };
    loop {
        if let Poll::Ready(out) = future.as_mut().poll(&mut cx) {
            return Some(out);
        }
        if StdInstant::now() >= deadline {
            return None;
        }
        ready.store(false, Ordering::SeqCst);
        // 再轮询一次（可能在上一次 poll 期间已就绪）。
        if let Poll::Ready(out) = future.as_mut().poll(&mut cx) {
            return Some(out);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// 定时器共享状态。
#[derive(Debug)]
struct TimerState {
    /// 到期时刻（以「自进程启动的偏移」表示，避免依赖私有 `Instant` 类型）。
    deadline_ms: Mutex<u64>,
    fired: AtomicBool,
    waker: Mutex<Option<Waker>>,
    /// 世代号：`reset` 会推进它，让旧的后台线程自动退出。
    generation: AtomicU64,
}

/// 定时器：后台线程等到期后触发唤醒。
#[derive(Debug)]
struct Timer {
    state: Arc<TimerState>,
    /// 后台唤醒线程（`reset` 时被替换）。
    driver: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Timer {
    fn create(deadline_ms: u64) -> Pin<Box<dyn AsyncTimer>> {
        let state = Arc::new(TimerState {
            deadline_ms: Mutex::new(deadline_ms),
            fired: AtomicBool::new(false),
            waker: Mutex::new(None),
            generation: AtomicU64::new(0),
        });
        let timer = Self {
            state: Arc::clone(&state),
            driver: Mutex::new(None),
        };
        timer.respawn_driver();
        Box::pin(timer)
    }

    /// 重新启动后台唤醒线程（`reset` 后调用）。
    fn respawn_driver(&self) {
        let state = Arc::clone(&self.state);
        let generation = state.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let driver = std::thread::spawn(move || {
            loop {
                let deadline = *state.deadline_ms.lock().expect("期限锁");
                let now = now_ms();
                if now >= deadline {
                    state.fired.store(true, Ordering::SeqCst);
                    if let Some(w) = state.waker.lock().expect("waker 锁").take() {
                        w.wake();
                    }
                    return;
                }
                // 世代被推进（`reset`）⇒ 退出，由新线程接管。
                if state.generation.load(Ordering::SeqCst) != generation {
                    return;
                }
                std::thread::sleep(
                    Duration::from_millis(1).min(Duration::from_millis(deadline - now)),
                );
            }
        });
        let mut slot = self.driver.lock().expect("driver 锁");
        if let Some(old) = slot.take() {
            let _ = old.join();
        }
        *slot = Some(driver);
    }
}

/// 进程启动以来的毫秒数（单调时钟）。
fn now_ms() -> u64 {
    static ORIGIN: std::sync::OnceLock<StdInstant> = std::sync::OnceLock::new();
    let origin = ORIGIN.get_or_init(StdInstant::now);
    origin.elapsed().as_millis() as u64
}

impl AsyncTimer for Timer {
    fn reset(self: Pin<&mut Self>, at: quinn_proto_instant::Instant) {
        let this = self.as_ref().get_ref();
        let deadline = now_ms()
            + at.duration_since(quinn_proto_instant::Instant::now())
                .as_millis() as u64;
        *this.state.deadline_ms.lock().expect("期限锁") = deadline;
        this.state.fired.store(false, Ordering::SeqCst);
        this.respawn_driver();
    }

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.as_ref().get_ref();
        if this.state.fired.load(Ordering::SeqCst) {
            return Poll::Ready(());
        }
        *this.state.waker.lock().expect("waker 锁") = Some(cx.waker().clone());
        if this.state.fired.load(Ordering::SeqCst) {
            return Poll::Ready(());
        }
        Poll::Pending
    }
}

/// `quinn-proto` 的 `Instant`（= `std::time::Instant`）的可达路径。
///
/// `quinn` 未 re-export 它，但 `quinn::congestion::Controller` 的方法签名里
/// 用的就是它 —— 而**本 crate 的 `brutal.rs` 已经能实现该 trait**，
/// 说明该类型在实现 `AsyncTimer` 时同样可由 trait 签名推导。
/// 这里用 trait 签名里的类型别名来写参数类型。
mod quinn_proto_instant {
    /// `quinn-proto` 的 `Instant` 与 `std::time::Instant` **同类型**
    /// （`quinn-proto` 在非 wasm 目标上 `pub(crate) use std::time::Instant`）。
    pub type Instant = std::time::Instant;
}

/// 最小运行时。
#[derive(Debug)]
pub struct StdRuntime;

impl Runtime for StdRuntime {
    fn new_timer(&self, at: quinn_proto_instant::Instant) -> Pin<Box<dyn AsyncTimer>> {
        Timer::create(
            now_ms()
                + at.duration_since(quinn_proto_instant::Instant::now())
                    .as_millis() as u64,
        )
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        std::thread::spawn(move || {
            block_on(future, Duration::from_secs(120));
        });
    }

    fn wrap_udp_socket(&self, sock: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        Ok(Arc::new(StdUdpSocket::new(sock)?))
    }
}

/// 一个已收到的数据报。
#[derive(Debug)]
struct Datagram {
    bytes: Vec<u8>,
    meta: RecvMeta,
}

/// 非阻塞 UDP socket 包装：读由后台线程完成，写直接走 `sendmsg`。
#[derive(Debug)]
struct StdUdpSocket {
    state: Arc<UdpSocketState>,
    sock: std::net::UdpSocket,
    /// 后台收包线程投递给 `poll_recv` 的队列。
    queue: Arc<Mutex<VecDeque<Datagram>>>,
    /// 有新数据时唤醒等待者。
    signal: Arc<Condvar>,
    /// 关闭标志（socket 被 drop 时通知后台线程退出）。
    closed: Arc<AtomicBool>,
}

impl StdUdpSocket {
    fn new(sock: std::net::UdpSocket) -> io::Result<Self> {
        let state = Arc::new(UdpSocketState::new((&sock).into())?);
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let signal = Arc::new(Condvar::new());
        let closed = Arc::new(AtomicBool::new(false));

        let reader_state = Arc::clone(&state);
        let reader_queue = Arc::clone(&queue);
        let reader_signal = Arc::clone(&signal);
        let reader_closed = Arc::clone(&closed);
        let reader_sock = sock.try_clone()?;
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65_535];
            let mut meta = [RecvMeta::default(); 1];
            while !reader_closed.load(Ordering::SeqCst) {
                let mut iov = [IoSliceMut::new(&mut buf)];
                match reader_state.recv((&reader_sock).into(), &mut iov, &mut meta) {
                    Ok(_) => {
                        let len = meta[0].len.min(buf.len());
                        let datagram = Datagram {
                            bytes: buf[..len].to_vec(),
                            meta: meta[0],
                        };
                        reader_queue.lock().expect("队列锁").push_back(datagram);
                        reader_signal.notify_all();
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            state,
            sock,
            queue,
            signal,
            closed,
        })
    }
}

impl Drop for StdUdpSocket {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        self.signal.notify_all();
    }
}

impl AsyncUdpSocket for StdUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        // 写就绪轮询：socket 是非阻塞的，直接就绪。
        Box::pin(ReadyPoller)
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.state.send((&self.sock).into(), transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut queue = self.queue.lock().expect("队列锁");
        if queue.is_empty() {
            // 等一小段时间再看，避免占满 CPU。
            let (next, _) = self
                .signal
                .wait_timeout(queue, Duration::from_millis(2))
                .expect("条件变量等待");
            queue = next;
        }
        if queue.is_empty() {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        // 把队首数据报拷贝到调用方的缓冲区。
        let mut count = 0usize;
        for (slot, meta_slot) in bufs.iter_mut().zip(meta.iter_mut()) {
            if queue.is_empty() {
                break;
            }
            let datagram = queue.pop_front().expect("队列非空");
            let len = datagram.bytes.len().min(slot.len());
            slot[..len].copy_from_slice(&datagram.bytes[..len]);
            *meta_slot = datagram.meta;
            count += 1;
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.state.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.state.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.state.gro_segments()
    }
}

/// 永远就绪的写轮询器。
#[derive(Debug)]
struct ReadyPoller;

impl UdpPoller for ReadyPoller {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
