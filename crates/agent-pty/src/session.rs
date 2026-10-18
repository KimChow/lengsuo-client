//! 单个 PTY 会话的构造与内部句柄。
//!
//! 线程模型（无 `unsafe`）：
//! - `portable-pty` 的 master reader 是阻塞 `std::io::Read`，因此放在**专用 OS 线程**读；
//! - 每个 chunk 先写入历史环形缓冲，再经 `tokio::runtime::Handle::block_on(tx.send(..))`
//!   投递到**有界 mpsc**；通道满时该线程挂起 ⇒ 背压回传到内核 tty 缓冲，内存有界；
//! - `alive` 与历史放在 `Arc<Mutex<SessionState>>`，由 reader 线程与管理器共享；
//! - master/writer/child 放在 `Arc<Mutex<SessionCtl>>`，因为规格里 `write`/`resize`
//!   的签名是 `&self`，需要内部可变性。
//!
//! 会话存活依赖两个事实：reader 线程随子进程退出得到 EOF 而结束；
//! 最后一路 slave fd 关闭后内核销毁 pty，子进程收到 SIGHUP。

use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use tokio::sync::mpsc;

use crate::config::PtyConfig;
use crate::error::PtyError;
use crate::ring::ByteRing;

/// 输出通道容量（chunk 个数）。足以吸收突发输出，又保证背压成立。
pub(crate) const OUTPUT_CHANNEL_CAPACITY: usize = 256;

/// 单次 PTY 读取缓冲大小。
const READ_CHUNK_BYTES: usize = 8 * 1024;

/// reader 线程与管理器共享的会话状态。
#[derive(Debug)]
pub(crate) struct SessionState {
    /// 历史回滚缓冲（≤1 MiB）。
    pub history: ByteRing,
    /// 子进程是否仍活动（reader EOF/读错误后为 false）。
    pub alive: bool,
}

impl SessionState {
    fn new() -> Self {
        Self {
            history: ByteRing::with_default_capacity(),
            alive: true,
        }
    }
}

/// 只有持锁者能碰的 PTY 句柄。
pub(crate) struct SessionCtl {
    /// master 端：resize / get_size。
    pub master: Box<dyn MasterPty + Send>,
    /// 输入写入端；`None` 表示不再可写（已 kill）。
    pub writer: Option<Box<dyn std::io::Write + Send>>,
    /// 子进程句柄；`None` 表示已终止并回收（不留僵尸）。
    pub child: Option<Box<dyn Child + Send + Sync>>,
}

/// 一次成功 `spawn` 的产物。
pub(crate) struct Spawned {
    pub command: String,
    pub cwd: Option<PathBuf>,
    pub started_at_ms: u64,
    pub pid: Option<u32>,
    pub ctl: Arc<Mutex<SessionCtl>>,
    pub state: Arc<Mutex<SessionState>>,
    pub output_rx: mpsc::Receiver<Vec<u8>>,
}

/// 按配置打开 PTY、启动子进程并起 reader 线程。
///
/// 须在 `spawn_blocking` 内调用（openpty 与 fork/exec 都是阻塞系统调用）。
pub(crate) fn spawn(cfg: &PtyConfig) -> Result<Spawned, PtyError> {
    let argv = cfg
        .argv()
        .ok_or_else(|| PtyError::Io("shell 命令行未配置或无法解析".to_string()))?;

    // portable-pty 对不存在的工作目录会**静默回退到家目录**（见其 `as_command`），
    // 与项目「失败必须 fail-closed，不得静默回退」的规则冲突，因此先行校验。
    if let Some(dir) = &cfg.cwd {
        if !dir.is_dir() {
            return Err(PtyError::Io(format!("工作目录不存在: {}", dir.display())));
        }
    }

    let pair = native_pty_system()
        .openpty(PtySize {
            rows: cfg.rows,
            cols: cfg.cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(PtyError::io)?;

    let mut cmd = CommandBuilder::new(&argv[0]);
    cmd.args(&argv[1..]);
    if let Some(dir) = &cfg.cwd {
        cmd.cwd(dir);
    }
    for (key, value) in &cfg.env {
        cmd.env(key, value);
    }

    let child = pair.slave.spawn_command(cmd).map_err(PtyError::io)?;
    let pid = child.process_id();

    let writer = pair.master.take_writer().map_err(PtyError::io)?;
    let mut reader = pair.master.try_clone_reader().map_err(PtyError::io)?;

    let (tx, output_rx) = mpsc::channel(OUTPUT_CHANNEL_CAPACITY);
    let state = Arc::new(Mutex::new(SessionState::new()));

    // 输出泵线程：只借用 `Handle` 投递，不持有管理器引用，随 EOF 自然退出。
    let handle = tokio::runtime::Handle::current();
    let pump_state = Arc::clone(&state);
    std::thread::Builder::new()
        .name(format!("agent-pty-pump-{}", pid.unwrap_or(0)))
        .spawn(move || pump_loop(&mut reader, tx, &pump_state, &handle))
        .map_err(PtyError::io)?;

    Ok(Spawned {
        command: cfg.shell.clone(),
        cwd: cfg.cwd.clone(),
        started_at_ms: now_ms(),
        pid,
        ctl: Arc::new(Mutex::new(SessionCtl {
            master: pair.master,
            writer: Some(writer),
            child: Some(child),
        })),
        state,
        output_rx,
    })
}

/// reader 线程主体。
///
/// - EOF / 读错误 ⇒ `alive = false` 并 drop 发送端，使接收端 `recv()` 得到 `None`；
/// - 通道满 ⇒ `block_on(send)` 挂起本线程，形成背压；
/// - 接收端被丢弃（`send` 失败）⇒ 停止投递但**继续读到 EOF**：既保证历史完整，
///   也避免 tty 缓冲写满后反过来阻塞子进程。
fn pump_loop(
    reader: &mut Box<dyn Read + Send>,
    tx: mpsc::Sender<Vec<u8>>,
    state: &Arc<Mutex<SessionState>>,
    handle: &tokio::runtime::Handle,
) {
    // 持有发送端直到线程退出；结束时显式 drop ⇒ 接收端 recv() 得到 None。
    let mut buf = vec![0u8; READ_CHUNK_BYTES];
    let mut delivering = true;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let chunk = buf[..n].to_vec();
        {
            let Ok(mut st) = state.lock() else { break };
            st.history.push(&chunk);
        }
        if delivering && handle.block_on(tx.send(chunk)).is_err() {
            delivering = false;
        }
    }
    if let Ok(mut st) = state.lock() {
        st.alive = false;
    }
    drop(tx);
}

/// 当前 unix 毫秒时间戳。
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// 锁定共享状态；中毒只可能来自 panic 传播，转成 `Io` 而不静默继续。
pub(crate) fn lock<T>(m: &Mutex<T>, id: u64) -> Result<std::sync::MutexGuard<'_, T>, PtyError> {
    m.lock()
        .map_err(|_| PtyError::Io(format!("会话 {id} 内部状态锁已损坏")))
}

/// 非阻塞回收已退出的子进程，避免遗留僵尸。
///
/// 返回 `true` 表示子进程已确认退出（顺带把 `alive` 落定为 false）。
/// 若句柄已被 `kill` 摘走则视为已退出。
pub(crate) fn reap_if_exited(
    ctl: &Arc<Mutex<SessionCtl>>,
    state: &Arc<Mutex<SessionState>>,
) -> bool {
    let Ok(mut guard) = ctl.lock() else {
        return false;
    };
    let reaped = match guard.child.as_mut() {
        None => true,
        Some(child) => matches!(child.try_wait(), Ok(Some(_))),
    };
    if reaped {
        guard.child = None;
        if let Ok(mut st) = state.lock() {
            st.alive = false;
        }
    }
    reaped
}

/// 终止子进程并尽力回收：`Child::kill` 在 unix 上是 SIGHUP → 约 200 ms 宽限 →
/// SIGKILL；随后再做一次非阻塞 `try_wait`。会短暂阻塞（≤ 宽限期），
/// 因此只在 `spawn_blocking` 或析构路径上调用。
pub(crate) fn kill_child(ctl: &Arc<Mutex<SessionCtl>>, id: u64) -> Result<(), PtyError> {
    let mut guard = lock(ctl, id)?;
    // 输入端不再可用：并发 write 立刻看到 AlreadyDead。
    guard.writer = None;
    let Some(mut child) = guard.child.take() else {
        return Err(PtyError::AlreadyDead(id));
    };
    let killed = child.kill().map_err(PtyError::io);
    let _ = child.try_wait();
    drop(child);
    killed
}
