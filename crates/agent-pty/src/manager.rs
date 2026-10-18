//! `PtyManager`：会话表与对外 API（签名按波次 1 卡 4 冻结规格）。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::config::PtyConfig;
use crate::error::PtyError;
use crate::session::{self, SessionCtl, SessionState};

/// 会话句柄与状态的一对共享引用。
type SessionHandles = (Arc<Mutex<SessionCtl>>, Arc<Mutex<SessionState>>);

/// 会话面板条目（对照 参考客户端 的 `sidecar:list` 进程面板）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// 终端会话 id。
    pub id: u64,
    /// 启动的命令行（原样回显，供 UI 展示）。
    pub shell: String,
    /// 工作目录；`None` 表示沿用家目录。
    pub cwd: Option<PathBuf>,
    /// 子进程 pid；平台未报告时为 `None`。
    pub pid: Option<u32>,
    /// 创建时间（unix 毫秒）。
    pub started_at_ms: u64,
    /// 是否仍活动（子进程退出或被 kill 后为 false）。
    pub alive: bool,
}

/// 管理器内部的一条会话记录。
struct Entry {
    id: u64,
    shell: String,
    cwd: Option<PathBuf>,
    started_at_ms: u64,
    pid: Option<u32>,
    ctl: Arc<Mutex<SessionCtl>>,
    state: Arc<Mutex<SessionState>>,
    /// 输出流接收端；`take_output` 取走后置 `None`。
    output_rx: Option<mpsc::Receiver<Vec<u8>>>,
}

impl Entry {
    fn alive(&self) -> bool {
        self.state.lock().map(|st| st.alive).unwrap_or(false)
    }

    fn info(&self) -> SessionInfo {
        SessionInfo {
            id: self.id,
            shell: self.shell.clone(),
            cwd: self.cwd.clone(),
            pid: self.pid,
            started_at_ms: self.started_at_ms,
            alive: self.alive(),
        }
    }
}

/// PTY 会话管理器。
///
/// 生命周期动作（`create`/`kill`/`take_output`）取 `&mut self`，数据面
/// （`write`/`resize`/`list`/`replay`）取 `&self`，与冻结规格一致；后者靠每会话
/// 的 `Arc<Mutex<..>>` 达成，因此 UI 高频键入/尺寸变更不争用管理器本身。
/// 阻塞系统调用一律放 `spawn_blocking`，不占用工作线程。
pub struct PtyManager {
    sessions: HashMap<u64, Entry>,
    next_id: u64,
}

impl Default for PtyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PtyManager {
    /// 新建空管理器。
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_id: 1,
        }
    }

    /// 创建终端会话，返回 terminal id。
    pub async fn create(&mut self, cfg: PtyConfig) -> Result<u64, PtyError> {
        let spawned = tokio::task::spawn_blocking(move || session::spawn(&cfg))
            .await
            .map_err(|e| PtyError::Io(format!("create 任务被中止: {e}")))??;

        let id = self.next_id;
        self.next_id += 1;
        self.sessions.insert(
            id,
            Entry {
                id,
                shell: spawned.command,
                cwd: spawned.cwd,
                started_at_ms: spawned.started_at_ms,
                pid: spawned.pid,
                ctl: spawned.ctl,
                state: spawned.state,
                output_rx: Some(spawned.output_rx),
            },
        );
        Ok(id)
    }

    /// 向会话 stdin 写入原始字节（UI 键入 → PTY）。
    pub async fn write(&self, id: u64, data: &[u8]) -> Result<(), PtyError> {
        let (ctl, state) = self.handles(id)?;
        let data = data.to_vec();
        tokio::task::spawn_blocking(move || {
            if !state_alive(&state) {
                // 已退出：顺带回收，避免僵尸堆积。
                session::reap_if_exited(&ctl, &state);
                return Err(PtyError::AlreadyDead(id));
            }
            let mut ctl_guard = session::lock(&ctl, id)?;
            let Some(writer) = ctl_guard.writer.as_mut() else {
                return Err(PtyError::AlreadyDead(id));
            };
            writer.write_all(&data).map_err(|err| match err.kind() {
                // tty 已无 slave 端：按「已死」报告，与状态机保持一致。
                std::io::ErrorKind::BrokenPipe => PtyError::AlreadyDead(id),
                _ => PtyError::io(err),
            })?;
            writer.flush().map_err(PtyError::io)
        })
        .await
        .map_err(|e| PtyError::Io(format!("write 任务被中止: {e}")))?
    }

    /// 调整窗口尺寸（UI resize → `TIOCSWINSZ`，内核向子进程投递 SIGWINCH）。
    pub async fn resize(&self, id: u64, cols: u16, rows: u16) -> Result<(), PtyError> {
        let (ctl, state) = self.handles(id)?;
        tokio::task::spawn_blocking(move || {
            if !state_alive(&state) {
                session::reap_if_exited(&ctl, &state);
                return Err(PtyError::AlreadyDead(id));
            }
            let ctl_guard = session::lock(&ctl, id)?;
            ctl_guard
                .master
                .resize(portable_pty::PtySize {
                    rows,
                    cols,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .map_err(PtyError::io)
        })
        .await
        .map_err(|e| PtyError::Io(format!("resize 任务被中止: {e}")))?
    }

    /// 终止会话：SIGHUP → 超时升级 SIGKILL；会话记录保留，`replay` 仍可读历史。
    ///
    /// 复用 `portable-pty` 的 `Child::kill`（unix：发 SIGHUP，给信号处理约 200 ms
    /// 宽限，仍存活则升级 SIGKILL 并回收进程，不留僵尸）。
    /// 对已死会话再次 `kill` ⇒ `AlreadyDead`；未知 id ⇒ `NotFound`。
    pub async fn kill(&mut self, id: u64) -> Result<(), PtyError> {
        let (ctl, state) = self.handles(id)?;
        if state_alive(&state) {
            tokio::task::spawn_blocking(move || session::kill_child(&ctl, id))
                .await
                .map_err(|e| PtyError::Io(format!("kill 任务被中止: {e}")))??;
        } else {
            // 自然退出的会话：回收后即可报告「已死」，与 kill 活会话的错误一致。
            session::reap_if_exited(&ctl, &state);
            return Err(PtyError::AlreadyDead(id));
        }
        // reader 线程通常已因 EOF 置 alive=false；显式落定，保证返回即可见。
        if let Ok(mut st) = state.lock() {
            st.alive = false;
        }
        Ok(())
    }

    /// 会话面板：按 id 升序返回全部会话（含已退出，供 UI 展示历史终端）。
    ///
    /// 顺带惰性回收已退出会话的子进程句柄（面板刷新是常态动作，也是僵尸的收敛点）。
    pub fn list(&self) -> Vec<SessionInfo> {
        let mut out: Vec<SessionInfo> = Vec::with_capacity(self.sessions.len());
        for entry in self.sessions.values() {
            if !entry.alive() {
                session::reap_if_exited(&entry.ctl, &entry.state);
            }
            out.push(entry.info());
        }
        out.sort_by_key(|s| s.id);
        out
    }

    /// 取回会话输出流；每会话仅一条、只能取走一次。
    ///
    /// `None` 表示会话不存在或流已被取走（不区分二者：调用方只需知道拿不到流，
    /// 应先 `replay` 补历史，再复用已持有的接收端）。
    pub async fn take_output(&mut self, id: u64) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.sessions.get_mut(&id)?.output_rx.take()
    }

    /// 历史回放：返回该会话最近 ≤1 MiB 的原始输出（重开 UI 时喂给终端仿真器）。
    /// 未知会话返回空。
    pub fn replay(&self, id: u64) -> Vec<u8> {
        let Some(entry) = self.sessions.get(&id) else {
            return Vec::new();
        };
        entry
            .state
            .lock()
            .map(|st| st.history.snapshot())
            .unwrap_or_default()
    }

    fn entry(&self, id: u64) -> Result<&Entry, PtyError> {
        self.sessions.get(&id).ok_or(PtyError::NotFound(id))
    }

    /// 一次查表取回（句柄, 状态）两个 Arc，避免 `&self` 方法里的重复查找。
    fn handles(&self, id: u64) -> Result<SessionHandles, PtyError> {
        let entry = self.entry(id)?;
        Ok((Arc::clone(&entry.ctl), Arc::clone(&entry.state)))
    }
}

impl Drop for PtyManager {
    /// 管理器销毁 ⇒ 终止全部仍在运行的会话。
    ///
    /// 不这么做的话，`bash` 之类不依赖 stdin 的进程会一直活着，reader 线程
    /// 因阻塞在 `read` 上而永不退出（线程与进程双泄漏）。`Child::kill` 最坏
    /// 阻塞约 200 ms 的宽限期，每个活动会话一次；已退出的会话只做非阻塞回收。
    fn drop(&mut self) {
        for entry in self.sessions.values() {
            let ctl = Arc::clone(&entry.ctl);
            let state = Arc::clone(&entry.state);
            let id = entry.id;
            if !entry.alive() {
                session::reap_if_exited(&ctl, &state);
                continue;
            }
            // Drop 路径可能是同步的，这里不调用 spawn_blocking：直接同步终止。
            let _ = session::kill_child(&ctl, id);
            let Some(mut st) = state.lock().ok() else {
                continue;
            };
            st.alive = false;
        }
    }
}

fn state_alive(state: &Arc<Mutex<SessionState>>) -> bool {
    state.lock().map(|st| st.alive).unwrap_or(false)
}
