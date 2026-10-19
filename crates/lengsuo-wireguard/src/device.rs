//! 设备运行时的**纯逻辑子集**：把定时器、keypair 轮换、allowedIPs 路由三者
//! 组装成一个 `Device` 状态对象，暴露「喂一个报文 → 返回待发送字节 + 待投递明文」。
//!
//! **不做任何真实 socket / TUN / 线程**：不建网络设备、不睡眠、不启后台任务，
//! 所有时间由调用方注入。握手/传输报文的密码学复用既有 `handshake` / `transport`
//! 模块，本模块只做分类与路由，不复制任何实现。
//!
//! 未实现（不在本卡范围，见 `docs/wireguard-status.md`）：TUN 读写、真实
//! endpoint 收发、握手报文的构造/校验（`handshake` 模块存在但本模块只做转发）。

use std::time::Instant;

use crate::allowedips::AllowedIps;
use crate::keypair::KeypairSet;
use crate::timers::{TimerAction, TimerState};
use crate::wire::{self, Message};

/// 本端在 allowedIPs 表里对应的 peer 标识（当前只支持单个 peer）。
pub const LOCAL_PEER: usize = 0;

/// `receive` 之后的待办输出。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// 投递给本机协议栈的明文载荷（已认证解密）。
    Deliver { peer: usize, payload: Vec<u8> },
    /// 该报文命中一个已过期/不存在的 keypair，已丢弃（fail-closed）。
    DroppedExpiredKeypair { local_index: u32 },
    /// 报文格式非法或认证失败，已丢弃（fail-closed）。
    DroppedUnparsable,
}

/// 事件驱动的纯逻辑设备。
pub struct Device {
    timers: TimerState,
    keypairs: KeypairSet,
    allowed_ips: AllowedIps,
    /// 本端对所有 peer 的配置（本卡只装配单 peer）。
    persistent_keepalive: Option<u64>,
}

impl Device {
    /// 以注入的时间原点建设备。
    #[must_use]
    pub fn new(epoch: Instant) -> Self {
        Self {
            timers: TimerState::new(epoch),
            keypairs: KeypairSet::new(),
            allowed_ips: AllowedIps::new(),
            persistent_keepalive: None,
        }
    }

    /// 启动/停止本端定时器（对照 `peer.Start` / `peer.Stop`）。
    pub fn set_running(&mut self, running: bool) {
        self.timers.set_running(running);
        if !running {
            self.timers.stop();
        }
    }

    #[must_use]
    pub fn allowed_ips(&self) -> &AllowedIps {
        &self.allowed_ips
    }

    pub fn allowed_ips_mut(&mut self) -> &mut AllowedIps {
        &mut self.allowed_ips
    }

    #[must_use]
    pub fn keypairs(&self) -> &KeypairSet {
        &self.keypairs
    }

    pub fn keypairs_mut(&mut self) -> &mut KeypairSet {
        &mut self.keypairs
    }

    #[must_use]
    pub fn timers(&self) -> &TimerState {
        &self.timers
    }

    pub fn timers_mut(&mut self) -> &mut TimerState {
        &mut self.timers
    }

    /// 配置 `PersistentKeepalive` 并同步到定时器。
    pub fn set_persistent_keepalive(&mut self, secs: u64, now: Instant) {
        self.persistent_keepalive = Some(secs);
        let now_secs = self.timers.now_secs(now);
        self.timers.set_persistent_keepalive(secs);
        if secs > 0 {
            self.timers.on_authenticated_traversal(now_secs);
        }
    }

    /// 对照 `RoutineReceiveIncoming` 的分类与 `RoutineSequentialReceiver` 的处理：
    /// 返回待投递的明文，并顺带推进 keepalive/新握手定时器。
    pub fn receive(&mut self, now: Instant, packet: &[u8]) -> Output {
        let now_secs = self.timers.now_secs(now);
        let receiver = match wire::parse(packet) {
            Ok(Message::Transport(transport)) => transport.receiver,
            // 握手与 cookie 报文的处理属握手层（本卡不装配），此处 fail-closed 丢弃。
            Ok(_) => return Output::DroppedUnparsable,
            Err(_) => return Output::DroppedUnparsable,
        };

        // 先按参考 receive.go 的到期检查筛掉过期 keypair，再尝试认证解密。
        let expired = match self.keypairs.for_receive_mut(now_secs, receiver) {
            Some(keypair) => {
                let result = keypair.open(packet);
                match result {
                    Ok(decrypted) => Output::Deliver {
                        peer: LOCAL_PEER,
                        payload: decrypted.plaintext,
                    },
                    Err(_) => Output::DroppedUnparsable,
                }
            }
            None => Output::DroppedExpiredKeypair {
                local_index: receiver,
            },
        };

        if let Output::Deliver { payload, .. } = &expired {
            // 对照 RoutineSequentialReceiver：认证通过即完成握手定时器语义。
            self.timers.on_authenticated_received();
            self.timers.on_authenticated_traversal(now_secs);
            self.timers.on_handshake_complete(now_secs);
            if payload.is_empty() {
                // keepalive：无载荷，不触发 keepKeyFreshReceiving 的数据路径。
            } else {
                self.timers.on_data_received(now_secs);
            }
            // 对照 ReceivedWithKeypair：next 收到数据后晋升为 current。
            self.keypairs.received_with_keypair(receiver);
        }
        expired
    }

    /// 推进定时器并返回到期的动作（调用方据此真正发包 / 擦除密钥）。
    pub fn tick(&mut self, now: Instant) -> Vec<TimerAction> {
        self.timers.tick(now)
    }
}
