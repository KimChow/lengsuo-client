//! 全局 index 表：本端为每个 peer 的握手/密钥对分配一个 32 位 `localIndex`，
//! 接收侧按报文里的 `receiver` 字段反查「这个包属于哪个 peer 的哪个 keypair」。
//!
//! 对照 wireguard-go `device/indextable.go`：
//! - `IndexTableEntry{peer, handshake, keypair}` 三态：
//!   仅握手阶段 `keypair == None`，密钥派生完成后 `SwapIndexForKeypair` 把同一
//!   index 的条目换成 `keypair`（对照 `noise-protocol.go:677`）。
//! - 分配用 **随机 uint32 + 冲突重试**（`NewIndexForHandshake`），
//!   移除用 `Delete`，查找用 `Lookup`。
//!
//! 与参考的差异写在偏离清单里：
//! - 参考是无上限的随机重试；本实现为**事件驱动纯逻辑**，随机源由调用方注入
//!   （可复现测试），并加**容量上限 / 耗尽 fail-closed**（参考靠 map 无界，
//!   本实现按任务书要求封顶）。
//! - `Delete` 在参考里静默；本实现对**不存在的 index 也静默**（与参考一致），
//!   但 `NewIndex` 冲突时**绝不覆盖既有条目**（fail-closed）。

use std::collections::HashMap;

/// 单条 index 记录，对照 `IndexTableEntry`。
///
/// `handshake` 与 `keypair` 互斥：握手期为 `handshake`，密钥派生后换成
/// `keypair`（`SwapIndexForKeypair`）。两者不应同时为 `None`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// 归属的 peer 标识（本 crate 内部编号，非公钥）。
    pub peer: usize,
    /// 握手进行中时绑定，密钥派生后清空。
    pub handshake: Option<u64>,
    /// 密钥派生完成后绑定。
    pub keypair: Option<u64>,
}

impl IndexEntry {
    fn handshake(peer: usize, handshake: u64) -> Self {
        Self {
            peer,
            handshake: Some(handshake),
            keypair: None,
        }
    }
}

/// 分配失败的原因（fail-closed，不静默覆盖）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexError {
    /// 表已达容量上限，无法再分配。
    TableFull,
    /// 随机源连续冲突次数超过上限（正常随机下几乎不可能）。
    Exhausted,
}

/// 全局 index 表。对照 `IndexTable`。
///
/// 一次分配最多重试 [`MAX_ALLOC_ATTEMPTS`] 次（对照参考的 `for {}` 无限循环，
/// 本实现为可终止性封顶）。容量上限 [`DEFAULT_CAPACITY`]。
pub struct IndexTable {
    table: HashMap<u32, IndexEntry>,
    capacity: usize,
    /// 已分配 index 的下一个随机种子（确定性 PRNG，便于测试复现）。
    rng_state: u64,
    /// 分配尝试计数（用于 Exhausted 判定，也是可观测的诊断量）。
    attempts_total: u64,
}

/// 默认容量上限：每 peer 最多 3 个 index（对照 keypair 三槽位 + 握手）已足够，
/// 参考 `MaxPeers = 1<<16`，这里按 index 条目数封顶为 4×peers 更宽松。
pub const DEFAULT_CAPACITY: usize = 1 << 18;
/// 单次分配的随机重试上限，超过即判 `Exhausted`（参考无上限，见偏离清单）。
pub const MAX_ALLOC_ATTEMPTS: u32 = 1 << 20;

impl Default for IndexTable {
    fn default() -> Self {
        Self::new()
    }
}

impl IndexTable {
    /// 空表 + 默认容量。对照 `IndexTable.Init`。
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// 指定容量上限的空表。
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            table: HashMap::new(),
            capacity,
            rng_state: 0x243f_6a88_85a3_08d3,
            attempts_total: 0,
        }
    }

    /// 以固定种子建设备（测试可复现）。
    #[must_use]
    pub fn with_seed(capacity: usize, seed: u64) -> Self {
        let mut table = Self::with_capacity(capacity);
        table.rng_state = seed;
        table
    }

    /// 当前条目数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[must_use]
    pub fn attempts_total(&self) -> u64 {
        self.attempts_total
    }

    /// 下一个确定性伪随机 uint32（对照 `randUint32`；此处非密码学随机，
    /// 仅用于事件驱动的可复现分配，见偏离清单）。
    fn next_rand(&mut self) -> u32 {
        // splitmix64：确定性、分布均匀，便于测试固定种子复现。
        self.rng_state = self.rng_state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.rng_state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        (z ^ (z >> 31)) as u32
    }

    /// 为一次新握手分配 index。对照 `NewIndexForHandshake`：
    /// 随机取一个未被占用的 index，绑定 `peer`/`handshake`。
    ///
    /// **fail-closed**：容量耗尽返回 `TableFull`，冲突重试超限返回 `Exhausted`，
    /// 任何情况下都不覆盖既有条目。
    pub fn new_index_for_handshake(
        &mut self,
        peer: usize,
        handshake: u64,
    ) -> Result<u32, IndexError> {
        if self.table.len() >= self.capacity {
            return Err(IndexError::TableFull);
        }
        for _ in 0..MAX_ALLOC_ATTEMPTS {
            self.attempts_total += 1;
            let index = self.next_rand();
            // 冲突检测：绝不覆盖（对照参考 `if ok { continue }` + 加锁二次确认）。
            if self.table.contains_key(&index) {
                continue;
            }
            self.table
                .insert(index, IndexEntry::handshake(peer, handshake));
            return Ok(index);
        }
        Err(IndexError::Exhausted)
    }

    /// 密钥派生完成后，把该 index 的条目从 handshake 换成 keypair。
    /// 对照 `SwapIndexForKeypair`：index 不存在时静默返回（与参考一致）。
    pub fn swap_index_for_keypair(&mut self, index: u32, keypair: u64) {
        if let Some(entry) = self.table.get_mut(&index) {
            entry.handshake = None;
            entry.keypair = Some(keypair);
        }
    }

    /// 按 index 查找。对照 `Lookup`：不存在返回 `None`（对应 Go 的零值条目，
    /// 其 `peer==nil && keypair==nil`，调用方据此丢弃报文）。
    #[must_use]
    pub fn lookup(&self, index: u32) -> Option<&IndexEntry> {
        self.table.get(&index)
    }

    /// 释放 index。对照 `Delete`：不存在时静默（幂等）。
    /// peer 移除或 keypair 过期时调用，回收后该 index 可被再次分配，
    /// 且在途旧包因查不到条目而被丢弃（不串到新 peer）。
    pub fn delete(&mut self, index: u32) {
        self.table.remove(&index);
    }

    /// 回收某 peer 的全部 index（peer 移除）。返回回收数量。
    /// 参考靠在 `peer.Stop` 里逐个 `Delete`；此处按 peer 聚合回收。
    pub fn delete_peer(&mut self, peer: usize) -> usize {
        let before = self.table.len();
        self.table.retain(|_, entry| entry.peer != peer);
        before - self.table.len()
    }

    /// 该 index 是否已分配。
    #[must_use]
    pub fn contains(&self, index: u32) -> bool {
        self.table.contains_key(&index)
    }
}
