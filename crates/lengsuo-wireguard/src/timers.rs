//! WireGuard 定时器状态机（对照 wireguard-go `device/timers.go`，commit 2631ce99）。
//!
//! 参考实现用 `time.AfterFunc` + goroutine，本 crate 不启动后台线程、不睡眠：
//! 每个 `TimerState` 只保存「到期时刻」，由调用方用注入的 `Instant` 调用
//! [`TimerState::tick`] 推进。`tick` 返回按参考语义排列的 [`TimerAction`] 序列，
//! 调用方负责真正发包与置位；`tick` 自身不改动「外部状态」字段
//! （`handshake_complete` / `handshake_attempts` / `sent_last_minute_handshake`），
//! 这些由 [`TimerState::on_handshake_initiated`] 等事件方法驱动，
//! 与参考里 `timersHandshakeComplete` 等入口一一对应。
//!
//! 时间单位一律为「自 peer 启动以来的秒数」(`f64`)，因此测试可以精确断言
//! t=0/1/5/90/120/180… 各点的动作序列，不需要真实等待。
//!
//! 抖动（`RekeyTimeoutJitterMaxMs`）：参考用 `fastrandn(334)` 毫秒均匀随机。
//! 本 crate 不引入随机源，改为调用方通过 [`TimerState::set_jitter`] 注入一个
//! 确定性值；见 `docs/wireguard-status.md` 的偏离清单。

use std::time::Instant;

/// 协议常量，数值与 wireguard-go `device/constants.go` 对齐。
pub mod constants {
    /// 数据报文计数器超过该值时主动重握手。
    pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
    /// 计数器达到该值时 keypair 失效（拒绝继续收发）。
    pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13) - 1;
    /// 发起方 keypair 超过该年龄后主动重握手。
    pub const REKEY_AFTER_TIME: f64 = 120.0;
    /// 重试窗口总长。
    pub const REKEY_ATTEMPT_TIME: f64 = 90.0;
    /// 单次重发 initiation 的最小间隔。
    pub const REKEY_TIMEOUT: f64 = 5.0;
    /// 重试上限 `REKEY_ATTEMPT_TIME / REKEY_TIMEOUT`。
    pub const MAX_TIMER_HANDSHAKES: u32 = 18;
    /// 重发抖动上限（毫秒），参考为 334ms 均匀随机。
    pub const REKEY_TIMEOUT_JITTER_MAX_MS: u64 = 334;
    /// keypair 硬寿命：超过该年龄的 keypair 立即失效。
    pub const REJECT_AFTER_TIME: f64 = 180.0;
    /// 静默多久之后发送 keepalive。
    pub const KEEPALIVE_TIMEOUT: f64 = 10.0;
    /// `REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT`：
    /// 发起方在 keypair 的最后 165 秒起只发起一次新握手。
    pub const LAST_MINUTE_HANDSHAKE_AGE: f64 =
        REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT;
    /// `newHandshake` 定时器的基础超时。
    pub const NEW_HANDSHAKE_TIMEOUT: f64 = KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;
}

use constants::*;

/// `tick` 产出的动作。顺序即为参考中回调的触发顺序。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerAction {
    /// `retransmitHandshake` 到期：重试次数未超上限，重发 initiation。
    RetransmitHandshake,
    /// `retransmitHandshake` 到期且重试次数已超上限（`> MaxTimerHandshakes`）：
    /// 放弃握手、清空暂存包，并武装 `zeroKeyMaterial`。
    HandshakeGaveUp,
    /// `sendKeepalive` 到期：发一条 keepalive。
    SendKeepalive,
    /// `newHandshake` 到期：静默过久，重新发起握手。
    NewHandshake,
    /// `zeroKeyMaterial` 到期：擦除全部密钥。
    ZeroKeyMaterial,
    /// `persistentKeepalive` 到期且配置了间隔：发一条 keepalive。
    PersistentKeepalive,
}

/// 到期待处理条目。
struct Pending {
    /// `None` 表示该定时器未武装。
    deadline: Option<f64>,
}

impl Pending {
    const fn new() -> Self {
        Self { deadline: None }
    }

    /// 对照参考 `Timer.Mod`：武装并在到期时触发回调（`isPending` 置 true）。
    fn mod_at(&mut self, now: f64, after: f64) {
        self.deadline = Some(now + after);
    }

    /// 对照参考 `Timer.Del`：取消且不再触发。
    fn del(&mut self) {
        self.deadline = None;
    }

    /// 对照参考 `Timer.IsPending`。
    fn is_pending(&self) -> bool {
        self.deadline.is_some()
    }

    fn take_if_due(&mut self, now: f64) -> bool {
        match self.deadline {
            Some(deadline) if deadline <= now => {
                self.deadline = None;
                true
            }
            _ => false,
        }
    }
}

/// 单个 peer 的定时器状态机。
///
/// 除五个定时器外还保存参考 `peer.handshake.lastSentHandshake` / `keypair.created`
/// 的注入读数——本 crate 不用真实时钟，这些值由调用方通过事件方法提供。
pub struct TimerState {
    /// 调用方注入的时间原点；所有 `now` 均以其为基准的秒数。
    epoch: Instant,
    running: bool,
    persistent_keepalive_secs: u64,
    jitter_secs: f64,

    retransmit_handshake: Pending,
    send_keepalive: Pending,
    new_handshake: Pending,
    zero_key_material: Pending,
    persistent_keepalive: Pending,

    handshake_attempts: u32,
    need_another_keepalive: bool,
    sent_last_minute_handshake: bool,

    handshake_sent: bool,
    handshake_complete: bool,
    last_sent_handshake: f64,
    current_keypair_created: Option<f64>,
    current_keypair_is_initiator: bool,
}

impl TimerState {
    /// 新建：五个定时器默认均未武装（对照参考 `timersInit` 后 `timer.Stop()`）。
    #[must_use]
    pub fn new(now: Instant) -> Self {
        Self {
            epoch: now,
            running: false,
            persistent_keepalive_secs: 0,
            jitter_secs: 0.0,
            retransmit_handshake: Pending::new(),
            send_keepalive: Pending::new(),
            new_handshake: Pending::new(),
            zero_key_material: Pending::new(),
            persistent_keepalive: Pending::new(),
            handshake_attempts: 0,
            need_another_keepalive: false,
            sent_last_minute_handshake: false,
            handshake_sent: false,
            handshake_complete: false,
            // 参考 `Peer.Start`：`lastSentHandshake = now - (RekeyTimeout + 1s)`。
            last_sent_handshake: -(REKEY_TIMEOUT + 1.0),
            current_keypair_created: None,
            current_keypair_is_initiator: false,
        }
    }

    /// 以 `epoch` 为原点换算的秒数。
    #[must_use]
    pub fn now_secs(&self, now: Instant) -> f64 {
        now.duration_since(self.epoch).as_secs_f64()
    }

    /// 注入重发抖动秒数（对应参考的 `fastrandn(RekeyTimeoutJitterMaxMs)` 毫秒）。
    /// 超过上限则截断到 `REKEY_TIMEOUT_JITTER_MAX_MS/1000`。
    pub fn set_jitter(&mut self, secs: f64) {
        let max = REKEY_TIMEOUT_JITTER_MAX_MS as f64 / 1000.0;
        self.jitter_secs = secs.clamp(0.0, max);
    }

    /// 配置 `PersistentKeepalive`（秒）；0 表示关闭。
    pub fn set_persistent_keepalive(&mut self, secs: u64) {
        self.persistent_keepalive_secs = secs;
    }

    /// 对照参考 `timersActive`：仅当 peer 在运行时定时器才生效。
    pub fn set_running(&mut self, running: bool) {
        self.running = running;
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// 对照参考 `timersStop`：全部取消。
    pub fn stop(&mut self) {
        self.retransmit_handshake.del();
        self.send_keepalive.del();
        self.new_handshake.del();
        self.zero_key_material.del();
        self.persistent_keepalive.del();
    }

    // ---- 事件入口（对照 timers.go 下半部分的 timersXxx） ----

    /// 对照 `timersHandshakeInitiated`。
    pub fn on_handshake_initiated(&mut self, now_secs: f64) {
        self.handshake_sent = true;
        self.last_sent_handshake = now_secs;
        if self.running {
            self.retransmit_handshake
                .mod_at(now_secs, REKEY_TIMEOUT + self.jitter_secs);
        }
    }

    /// 对照 `timersHandshakeComplete`。
    pub fn on_handshake_complete(&mut self, now_secs: f64) {
        if self.running {
            self.retransmit_handshake.del();
        }
        self.handshake_attempts = 0;
        self.sent_last_minute_handshake = false;
        self.handshake_complete = true;
        // 参考写 `lastHandshakeNano`，本 crate 只记录注入时钟读数。
        self.last_sent_handshake = now_secs;
    }

    /// 对照 `timersSessionDerived`。
    pub fn on_session_derived(&mut self, now_secs: f64) {
        if self.running {
            self.zero_key_material
                .mod_at(now_secs, REJECT_AFTER_TIME * 3.0);
        }
    }

    /// 对照 `timersAnyAuthenticatedPacketSent`。
    pub fn on_authenticated_sent(&mut self) {
        if self.running {
            self.send_keepalive.del();
        }
    }

    /// 对照 `timersAnyAuthenticatedPacketReceived`。
    pub fn on_authenticated_received(&mut self) {
        if self.running {
            self.new_handshake.del();
        }
    }

    /// 对照 `timersAnyAuthenticatedPacketTraversal`。
    pub fn on_authenticated_traversal(&mut self, now_secs: f64) {
        if self.persistent_keepalive_secs > 0 && self.running {
            self.persistent_keepalive
                .mod_at(now_secs, self.persistent_keepalive_secs as f64);
        }
    }

    /// 对照 `timersDataSent`。
    pub fn on_data_sent(&mut self, now_secs: f64) {
        if self.running && !self.new_handshake.is_pending() {
            self.new_handshake
                .mod_at(now_secs, NEW_HANDSHAKE_TIMEOUT + self.jitter_secs);
        }
    }

    /// 对照 `timersDataReceived`。
    pub fn on_data_received(&mut self, now_secs: f64) {
        if !self.running {
            return;
        }
        if !self.send_keepalive.is_pending() {
            self.send_keepalive.mod_at(now_secs, KEEPALIVE_TIMEOUT);
        } else {
            self.need_another_keepalive = true;
        }
    }

    // ---- 只读查询（供 Device 组装层判定，不改动状态） ----

    #[must_use]
    pub fn handshake_attempts(&self) -> u32 {
        self.handshake_attempts
    }

    /// 对照参考 `handshake.sentLastMinuteHandshake`。
    #[must_use]
    pub fn sent_last_minute_handshake(&self) -> bool {
        self.sent_last_minute_handshake
    }

    /// 对照参考 `handshake.lastSentHandshake`；`None` 表示尚未发过任何握手包。
    #[must_use]
    pub fn last_sent_handshake(&self) -> Option<f64> {
        if self.handshake_sent {
            Some(self.last_sent_handshake)
        } else {
            None
        }
    }

    /// 注入当前 keypair 的生成时刻与发起方标志（参考 `keypair.created` / `isInitiator`）。
    pub fn set_current_keypair(&mut self, created_secs: Option<f64>, is_initiator: bool) {
        self.current_keypair_created = created_secs;
        self.current_keypair_is_initiator = is_initiator;
    }

    /// 对照参考 `keepKeyFreshSending` 的第二个条件：
    /// 当前 keypair 是发起方且年龄超过 `RekeyAfterTime` 时应主动重握手。
    #[must_use]
    pub fn keypair_send_needs_rekey(&self, now_secs: f64) -> bool {
        match self.current_keypair_created {
            Some(created) => {
                self.current_keypair_is_initiator && now_secs - created > REKEY_AFTER_TIME
            }
            None => false,
        }
    }

    /// 对照参考 `keepKeyFreshReceiving`：发起方 keypair 进入「最后一分钟」且本端
    /// 尚未发过这轮新握手时，应发一次新握手（且只发一次）。
    #[must_use]
    pub fn keypair_receive_needs_last_minute_handshake(&self, now_secs: f64) -> bool {
        if self.sent_last_minute_handshake {
            return false;
        }
        match self.current_keypair_created {
            Some(created) => {
                self.current_keypair_is_initiator && now_secs - created > LAST_MINUTE_HANDSHAKE_AGE
            }
            None => false,
        }
    }

    /// 记录「已发出最后一分钟握手」，使上面的查询不再重复触发。
    pub fn mark_last_minute_handshake_sent(&mut self) {
        self.sent_last_minute_handshake = true;
    }

    // ---- 到期推进 ----

    /// 推进到注入时刻 `now`，返回本刻到期的动作序列。
    ///
    /// 顺序固定为参考中回调的等价顺序：先 `retransmitHandshake`（可能派生出
    /// `HandshakeGaveUp` / `ZeroKeyMaterial` 的武装），再 `sendKeepalive`（可能
    /// 因 `needAnotherKeepalive` 重新武装），再 `newHandshake`、`zeroKeyMaterial`、
    /// `persistentKeepalive`。后三重检查保证同刻先重发的场景不会误触发。
    pub fn tick(&mut self, now: Instant) -> Vec<TimerAction> {
        let now_secs = self.now_secs(now);
        let mut actions = Vec::new();
        if !self.running {
            return actions;
        }

        if self.retransmit_handshake.take_if_due(now_secs) {
            if self.handshake_attempts > MAX_TIMER_HANDSHAKES {
                // 对照 expiredRetransmitHandshake 的放弃分支。
                self.send_keepalive.del();
                if !self.zero_key_material.is_pending() {
                    self.zero_key_material
                        .mod_at(now_secs, REJECT_AFTER_TIME * 3.0);
                }
                actions.push(TimerAction::HandshakeGaveUp);
            } else {
                self.handshake_attempts += 1;
                // 对照 markEndpointSrcForClearing + SendHandshakeInitiation(true)。
                self.on_handshake_initiated(now_secs);
                actions.push(TimerAction::RetransmitHandshake);
            }
        }

        if self.send_keepalive.take_if_due(now_secs) {
            actions.push(TimerAction::SendKeepalive);
            if self.need_another_keepalive {
                self.need_another_keepalive = false;
                self.send_keepalive.mod_at(now_secs, KEEPALIVE_TIMEOUT);
            }
        }

        if self.new_handshake.take_if_due(now_secs) {
            // 对照 expiredNewHandshake：清 endpoint src 后 SendHandshakeInitiation(false)。
            self.on_handshake_initiated(now_secs);
            actions.push(TimerAction::NewHandshake);
        }

        if self.zero_key_material.take_if_due(now_secs) {
            // 对照 expiredZeroKeyMaterial：ZeroAndFlushAll。
            self.handshake_sent = false;
            self.handshake_complete = false;
            self.current_keypair_created = None;
            actions.push(TimerAction::ZeroKeyMaterial);
        }

        if self.persistent_keepalive.take_if_due(now_secs) && self.persistent_keepalive_secs > 0 {
            actions.push(TimerAction::PersistentKeepalive);
        }

        actions
    }
}
