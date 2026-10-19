//! keypair 轮换与生命周期（对照 wireguard-go `device/keypair.go` +
//! `device/noise-protocol.go` 的 `BeginSymmetricSession` / `ReceivedWithKeypair`
//! + `device/receive.go` 的到期检查，commit 2631ce99）。
//!
//! 参考用 `sync.RWMutex` + `atomic.Pointer`，本 crate 是单线程状态对象：
//! 用普通 `Option<K>` 字段保存 current/previous/next 三元组，语义一一对应。
//!
//! 三条硬不变量（fail-closed）：
//! 1. **接收**：keypair 年龄 `>= RejectAfterTime` 时不再接受（对照 receive.go
//!    `keypair.created.Add(RejectAfterTime).Before(now) -> continue`）；
//! 2. **发送**：current 不可用（已过期）时**绝不**回落到 previous——宁可返回
//!    「无可用 keypair」让上层重新握手，也不复用旧密钥；
//! 3. **计数器**：`RejectAfterMessages` 达到后 keypair 失效，接收侧由重放窗口
//!    上限截断，发送侧在推进前拒绝。
//!
//! 时间用「自 peer 启动以来的秒数」(`f64`)，由调用方注入，与 `timers` 模块一致。

use crate::timers::constants::{
    REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME, REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME,
};
use crate::transport::{Receiver, Sender, TransportKey};

/// keypair 失效/重握手判定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeypairStatus {
    /// 可正常收发。
    Ok,
    /// 发送侧需要重握手：计数器超过 `RekeyAfterMessages`，或发起方 keypair
    /// 年龄超过 `RekeyAfterTime`（对照 send.go `keepKeyFreshSending`）。
    RekeyAdvised,
    /// 已过期：年龄 `>= RejectAfterTime` 或计数器达到 `RejectAfterMessages`。
    Expired,
}

/// 一个 keypair：发送/接收上下文 + 元数据。
pub struct Keypair {
    /// 本端索引（报文中接收者字段用的值）。
    pub local_index: u32,
    /// 对端索引。
    pub remote_index: u32,
    /// 本端是否为发起方（决定 nonce 与人生周期判定）。
    pub is_initiator: bool,
    /// 生成时刻（自 peer 启动以来的秒数）。
    pub created: f64,
    /// 发送上下文；`None` 表示对端索引/密钥不可用（例如只做接收的 next keypair）。
    sender: Option<Sender>,
    /// 接收上下文。
    receiver: Option<Receiver>,
    /// 发送计数器读数，与 `sender` 同步；用于生命周期判定。
    send_counter: u64,
}

impl Keypair {
    /// 构造一对收发上下文。`send_key` / `recv_key` 由调用方（握手层）提供，
    /// 本模块只负责生命周期，不生成密钥。
    #[must_use]
    pub fn new(
        local_index: u32,
        remote_index: u32,
        is_initiator: bool,
        created: f64,
        send_key: &[u8],
        recv_key: &[u8],
    ) -> Option<Self> {
        let send = TransportKey::new(send_key).ok()?;
        let recv = TransportKey::new(recv_key).ok()?;
        Some(Self {
            local_index,
            remote_index,
            is_initiator,
            created,
            sender: Some(Sender::new(send, remote_index, 0)),
            // 接收侧上限取 `RejectAfterMessages`：到点后重放窗口直接拒绝。
            receiver: Some(Receiver::new(recv, local_index, REJECT_AFTER_MESSAGES)),
            send_counter: 0,
        })
    }

    /// 只带接收上下文的 keypair（对照参考 `next` 在 responder 分支下的用法：
    /// 密钥已派生但尚未晋升为 current，不用于发送）。
    #[must_use]
    pub fn receive_only(
        local_index: u32,
        remote_index: u32,
        is_initiator: bool,
        created: f64,
        recv_key: &[u8],
    ) -> Option<Self> {
        let recv = TransportKey::new(recv_key).ok()?;
        Some(Self {
            local_index,
            remote_index,
            is_initiator,
            created,
            sender: None,
            receiver: Some(Receiver::new(recv, local_index, REJECT_AFTER_MESSAGES)),
            send_counter: 0,
        })
    }

    /// 对照 `receive.go` 的到期检查：年龄 `>= RejectAfterTime` 即拒收。
    #[must_use]
    pub fn age_expired(&self, now_secs: f64) -> bool {
        now_secs - self.created >= REJECT_AFTER_TIME
    }

    /// 计数器是否已达 `RejectAfterMessages`。
    #[must_use]
    pub fn counter_exhausted(&self) -> bool {
        self.send_counter >= REJECT_AFTER_MESSAGES
    }

    /// 当前生命周期判定（对照 `keepKeyFreshSending` + receive 的到期检查）。
    #[must_use]
    pub fn status(&self, now_secs: f64) -> KeypairStatus {
        if self.age_expired(now_secs) || self.counter_exhausted() {
            return KeypairStatus::Expired;
        }
        if self.send_counter > REKEY_AFTER_MESSAGES
            || (self.is_initiator && now_secs - self.created > REKEY_AFTER_TIME)
        {
            return KeypairStatus::RekeyAdvised;
        }
        KeypairStatus::Ok
    }

    /// 能否用于**发送**：未过期且有发送上下文。
    #[must_use]
    pub fn can_send(&self, now_secs: f64) -> bool {
        self.sender.is_some() && self.status(now_secs) != KeypairStatus::Expired
    }

    /// 能否用于**接收**：未过期且有接收上下文。
    #[must_use]
    pub fn can_receive(&self, now_secs: f64) -> bool {
        self.receiver.is_some() && !self.age_expired(now_secs)
    }

    /// 封装一条数据报文并推进计数器。
    pub fn seal(&mut self, payload: &[u8]) -> Result<Vec<u8>, crate::transport::Error> {
        let sender = match self.sender.as_mut() {
            Some(sender) => sender,
            None => return Err(crate::transport::Error::Poisoned),
        };
        let packet = sender.seal(payload)?;
        self.send_counter = sender.next_counter();
        Ok(packet)
    }

    /// 解封一条数据报文。
    pub fn open(
        &mut self,
        packet: &[u8],
    ) -> Result<crate::transport::Decrypted, crate::transport::Error> {
        match self.receiver.as_mut() {
            Some(receiver) => receiver.open(packet),
            None => Err(crate::transport::Error::NotTransport(
                "该 keypair 无接收上下文",
            )),
        }
    }

    /// 使 keypair 立即失效（对照 `ExpireCurrentKeypairs` 把 sendNonce 顶到上限）。
    pub fn expire(&mut self) {
        self.send_counter = REJECT_AFTER_MESSAGES;
    }

    /// 当前重生放窗口的最高计数器（便于测试断言）。
    #[must_use]
    pub fn highest_received(&self) -> Option<u64> {
        self.receiver.as_ref().and_then(Receiver::highest)
    }
}

/// current / previous / next 三元组（对照参考 `Keypairs`）。
///
/// - `current`：唯一可用于发送的 keypair；
/// - `previous`：只收不发，用于吸收对端仍用旧密钥发出的在途包；
/// - `next`：本端作为 responder 刚派生的 keypair，等第一个用它的数据报文确认后晋升。
#[derive(Default)]
pub struct KeypairSet {
    current: Option<Keypair>,
    previous: Option<Keypair>,
    next: Option<Keypair>,
}

impl KeypairSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn current(&self) -> Option<&Keypair> {
        self.current.as_ref()
    }

    /// 选择用于**发送**的 keypair：只有 current，且必须未过期。
    /// 过期时返回 `None`——绝不回落到 previous（fail-closed）。
    #[must_use]
    pub fn for_send(&self, now_secs: f64) -> Option<&Keypair> {
        self.current.as_ref().filter(|k| k.can_send(now_secs))
    }

    /// 可变版本。过期时不返回任何 keypair。
    pub fn for_send_mut(&mut self, now_secs: f64) -> Option<&mut Keypair> {
        self.current.as_mut().filter(|k| k.can_send(now_secs))
    }

    /// 按本端索引查找可用于**接收**的 keypair（对照 `device.indexTable.Lookup`）。
    /// 三个槽位都参与查找，但已过期的一律拒绝（fail-closed）。
    pub fn for_receive_mut(&mut self, now_secs: f64, local_index: u32) -> Option<&mut Keypair> {
        for slot in [&mut self.current, &mut self.previous, &mut self.next] {
            if let Some(keypair) = slot {
                if keypair.local_index == local_index && keypair.can_receive(now_secs) {
                    return slot.as_mut();
                }
            }
        }
        None
    }

    /// 对照 `BeginSymmetricSession` 的轮换分支（`isInitiator == true`）：
    /// 新 keypair 上位为 current，原 current 降为 previous，原 next 与更早的
    /// previous 一并丢弃。
    pub fn install_as_initiator(&mut self, keypair: Keypair) {
        // 参考 noise-protocol.go `BeginSymmetricSession`：
        //   if next != nil { next = nil; previous = next; DeleteKeypair(current) }
        //   else           { previous = current }
        // 两个分支的差别在于 **旧的 current 是否被丢弃**：next 存在时它直接
        // 被删除（不入 previous），否则它降级保留为 previous。Rust 侧用 Drop
        // 承担 `device.DeleteKeypair`（Keypair 持有密钥材料，析构即清零），
        // 因此「丢弃 current」等价于在此处让它被 `take()` 后随即析构。
        self.previous = match self.next.take() {
            Some(next) => Some(next), // take() 已把 next 置空；current 由下面 drop
            None => self.current.take(),
        };
        self.current = Some(keypair);
    }

    /// 对照 `BeginSymmetricSession` 的 responder 分支（`isInitiator == false`）：
    /// 新 keypair 只进 next，previous 清空，current 保持不变。
    pub fn install_as_responder(&mut self, keypair: Keypair) {
        self.next = Some(keypair);
        self.previous = None;
    }

    /// 对照 `ReceivedWithKeypair`：收到第一个用 next 加密的数据包后，
    /// next 晋升为 current，原 current 降为 previous。
    /// 返回是否发生了晋升（只有该 keypair 仍是 next 时才晋升一次）。
    pub fn received_with_keypair(&mut self, local_index: u32) -> bool {
        let is_next = self
            .next
            .as_ref()
            .is_some_and(|k| k.local_index == local_index);
        if !is_next {
            return false;
        }
        self.previous = self.current.take();
        self.current = self.next.take();
        true
    }

    /// 对照 `ZeroAndFlushAll`：清空三元组并擦除密钥材料。
    pub fn zero_and_flush(&mut self) {
        self.current = None;
        self.previous = None;
        self.next = None;
    }

    /// 对照 `ExpireCurrentKeypairs`：把 current 与 next 的发送计数器顶到上限。
    pub fn expire_current(&mut self) {
        if let Some(keypair) = self.current.as_mut() {
            keypair.expire();
        }
        if let Some(keypair) = self.next.as_mut() {
            keypair.expire();
        }
    }
}
