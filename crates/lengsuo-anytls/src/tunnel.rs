//! 隧道生命周期：客户端 Settings、冷启动流（编号 1）、SYNACK 看门狗与恢复判据。
//! 基线 anytls-go fd6167acd6d73b9fa3e607659951847fbc9e6c50
//! `proxy/session/session.go` 的 `Session.Run`/`OpenStream`/`recvLoop`。
//!
//! 参考的两条不变量，本模块逐字对齐：
//! 1. **编号 1 是握手流**：`streamId` 从 0 起累加，第一条流恒为 1；看门狗条件
//!    `sid >= 2 && peerVersion >= 2` 使编号 1 永不武装看门狗，第二条流才武装。
//! 2. **未就绪状态不承认流已打开**：带错误文本的 SYNACK 走 `stream.closeWithError`
//!    （删除该流，`Rejected`），而非空载荷 SYNACK 才 `Ready`。在 v2 下，
//!    未收到 `Ready` 前 `push` 一律视为违规。
//!
//! 「SYNACK 迟到」不是状态机接受的状态（迟到 = 该流已被回收，编号不复用），
//! 因此本模块把迟到定义为**看门狗已触发后的到达**：隧道进入 `Dead`，
//! 后续任何帧都被拒绝。恢复只能靠调用方重建隧道，与参考的回调 `s.Close()` 一致。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::client_state::{ClientError, ClientState, Event};
use crate::frame::{Command, Frame};

/// 参考 `NewDeadlineWatcher(time.Second*3, …)` 的看门狗时长。
pub const SYNACK_TIMEOUT: Duration = Duration::from_secs(3);

/// 参考 `writeControlFrame` 的单次写出上限（5 秒），记录于此供测试与文档对照。
pub const WRITE_DEADLINE: Duration = Duration::from_secs(5);

/// 看门狗期限（单位由调用方与 `Expiry::Clock` 的粒度约定，本模块用 UNIX 毫秒）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    /// 由调用方的时钟驱动；参考用 `time.Timer`（挂钟）。
    Clock(Instant),
    /// 由调用方显式触发（测试与「丢包」模拟用），不依赖真实时间。
    Manual,
}

impl Expiry {
    /// 是否已到期；`Manual` 永不自动到期，须调用 `expire_synack_watchdog`。
    pub fn is_due(&self, now: Instant) -> bool {
        match self {
            Self::Clock(deadline) => now >= *deadline,
            Self::Manual => false,
        }
    }
}

/// 看门狗是否需要整条隧道加锁，还是可以按流裁决。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watchdog {
    /// 武装时正在等待 SYNACK 的流（永不等于 1）。
    pub stream_id: u32,
    pub expiry: Expiry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TunnelError {
    #[error("客户端 Settings 尚未发送")]
    SettingsNotSent,
    #[error("客户端 Settings 只发送一次")]
    SettingsAlreadySent,
    #[error("看门狗未武装，无可解除")]
    NoWatchdog,
    #[error("流编号 1 是握手流，不得武装看门狗")]
    ColdStartIsNotWatchdogged,
    #[error("隧道已因看门狗到期而终止")]
    Dead,
    #[error("状态机拒绝：{0}")]
    State(#[from] ClientError),
    #[error("流编号分配失败")]
    StreamExhausted,
}

/// 隧道判定：客户端会话状态机 + SYNACK 看门狗。
/// 不派生 `Debug`：内部持有 `ClientState`，且隧道状态可映射到应用数据。
pub struct Tunnel {
    state: ClientState,
    watchdog: Option<Watchdog>,
    /// 看门狗触发次数；非零表示隧道已死。
    expired: bool,
    /// 已就绪流编号集合，用于「未就绪不得发送」的判据。
    ready: HashMap<u32, bool>,
    /// 固定时钟：`Manual` 模式下调用方通过 `now` 自行推进时间。
    injected: Option<Instant>,
}

impl Tunnel {
    pub fn new(max_streams: usize) -> Result<Self, TunnelError> {
        Ok(Self {
            state: ClientState::new(max_streams)?,
            watchdog: None,
            expired: false,
            ready: HashMap::new(),
            injected: None,
        })
    }

    /// 注入固定时钟：`expire_at` 之后看门狗按此时间判定，便于确定性测试。
    pub fn with_clock(mut self, now: Instant) -> Self {
        self.injected = Some(now);
        self
    }

    pub fn peer_version(&self) -> u8 {
        self.state.peer_version()
    }

    pub fn is_dead(&self) -> bool {
        self.expired
    }

    /// 参考 `Session.Run`：先写出 `cmdSettings`，之后才允许 SYN 等控制帧。
    pub fn send_settings(&mut self) -> Result<Frame, TunnelError> {
        self.check_alive()?;
        if self.state.settings_sent() {
            return Err(TunnelError::SettingsAlreadySent);
        }
        self.state.mark_settings_sent()?;
        Ok(Frame {
            command: Command::Settings,
            stream_id: 0,
            data: settings_text().into_bytes(),
        })
    }

    /// Settings 文本字节（供测试与调用方核对）。
    pub fn settings_text_bytes() -> Vec<u8> {
        settings_text().into_bytes()
    }

    /// 打开一条流（参考 `Session.OpenStream`）：分配编号 → 视条件武装看门狗 →
    /// 产出 SYN 帧。`peer_version >= 2 且 sid >= 2` 才武装。
    pub fn open_stream(&mut self, now: Instant) -> Result<(u32, Frame), TunnelError> {
        self.check_alive()?;
        let stream_id = self.state.open_stream()?;
        if stream_id >= 2 && self.state.peer_version() >= 2 {
            // 参考在覆盖 synDone 前先触发旧看门狗。
            if let Some(previous) = self.watchdog.take() {
                debug_assert!(previous.stream_id < stream_id);
            }
            self.watchdog = Some(Watchdog {
                stream_id,
                expiry: Expiry::Clock(now + SYNACK_TIMEOUT),
            });
        }
        self.ready.insert(stream_id, false);
        Ok((
            stream_id,
            Frame {
                command: Command::Syn,
                stream_id,
                data: Vec::new(),
            },
        ))
    }

    /// 当前看门狗；`None` 表示无待决握手。
    pub fn watchdog(&self) -> Option<Watchdog> {
        self.watchdog
    }

    /// 参考看门狗回调 `func() { s.Close() }`：到期即关闭整条隧道。
    /// 返回 `true` 表示本次调用真的触发了终止（幂等，重复调用返回 `false`）。
    pub fn expire_synack_watchdog(&mut self) -> bool {
        if self.expired || self.watchdog.is_none() {
            return false;
        }
        self.watchdog = None;
        self.expired = true;
        true
    }

    /// 「丢包」路径：看门狗到期但调用方希望保留一条新隧道继续——
    /// 本方法把旧隧道标记为死并返回需要重建的信号，与参考
    /// 「回调里只能 Close，重建由 Client 在下次 CreateStream 完成」一致。
    pub fn recover_needs_new_tunnel(&mut self, now: Instant) -> Result<u32, TunnelError> {
        self.check_alive()?;
        if let Some(watchdog) = self.watchdog {
            if watchdog.expiry.is_due(now) {
                self.expired = true;
                self.watchdog = None;
                return Err(TunnelError::Dead);
            }
        }
        // 隧道仍存活：直接开新流即可，无需重建。
        self.open_stream(now).map(|(id, _)| id)
    }

    /// 接收一个服务器帧，维护看门狗与就绪集合（参考 `recvLoop`）。
    pub fn accept(&mut self, frame: &Frame) -> Result<Event, TunnelError> {
        self.check_alive()?;
        let event = self.state.accept(frame)?;
        match &event {
            Event::Ready(stream_id) => {
                self.ready.insert(*stream_id, true);
                // 参考：任一 SYNACK（无论是否带错误）都解除看门狗。
                if let Some(watchdog) = self.watchdog {
                    if watchdog.stream_id == *stream_id {
                        self.watchdog = None;
                    }
                }
            }
            Event::Rejected(stream_id) => {
                if let Some(watchdog) = self.watchdog {
                    if watchdog.stream_id == *stream_id {
                        self.watchdog = None;
                    }
                }
            }
            Event::Closed(stream_id) => {
                self.ready.remove(stream_id);
            }
            _ => {}
        }
        Ok(event)
    }

    /// 该流是否可发送数据：版本 1 活跃即就绪；版本 2 必须收到成功 SYNACK。
    pub fn stream_sendable(&self, stream_id: u32) -> bool {
        self.ready.contains_key(&stream_id) && self.state.is_ready(stream_id)
    }

    /// 主动关闭某条流（参考 `streamClosed`：写 FIN 并删除本地流）。
    pub fn close_stream(&mut self, stream_id: u32) -> Result<Frame, TunnelError> {
        self.check_alive()?;
        self.state.close_stream(stream_id)?;
        self.ready.remove(&stream_id);
        if self
            .watchdog
            .is_some_and(|watchdog| watchdog.stream_id == stream_id)
        {
            self.watchdog = None;
        }
        Ok(Frame {
            command: Command::Fin,
            stream_id,
            data: Vec::new(),
        })
    }

    fn check_alive(&self) -> Result<(), TunnelError> {
        if self.expired {
            return Err(TunnelError::Dead);
        }
        Ok(())
    }
}

/// 参考 `Session.Run` 的 Settings 文本：`v=2`、`client=<ProgramVersionName>`、
/// `padding-md5=<默认方案 md5>`。键序在参考里由 Go map 迭代决定（不确定），
/// 故此处固定为 `v`、`client`、`padding-md5` 顺序；对端按 `key=value` 行解析，
/// 不依赖顺序——`crates/lengsuo-anytls/src/server_state.rs::parse_settings` 亦然。
fn settings_text() -> String {
    use crate::padding::DEFAULT_PADDING_MD5;
    format!(
        "v=2\nclient={}\npadding-md5={DEFAULT_PADDING_MD5}",
        env!("CARGO_PKG_VERSION")
    )
}
