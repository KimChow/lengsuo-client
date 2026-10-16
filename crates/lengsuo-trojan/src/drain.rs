//! 关闭前残留读取（drain）原语（不是完整协议服务）。
//!
//! 语义基线：Xray v26.3.27，完整 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，`common/drain/drainer.go`：
//!
//! ```text
//! BehaviorSeedLimitedDrainer{DrainSize}
//!   NewBehaviorSeedLimitedDrainer(seed, foundation, maxBase, maxRand):
//!     dice       = NewDeterministicDice(seed)
//!     Base       = dice.Roll(maxBase)
//!     RandMax    = dice.Roll(maxRand) + 1
//!     RandRolled = dice.Roll(RandMax)
//!     DrainSize  = foundation + Base + RandRolled
//!   AcknowledgeReceive(size): DrainSize -= size      // 可减成负数
//!   Drain(reader): DrainSize > 0 时读满 DrainSize 字节并丢弃；
//!                  读满 → "drained connection"；提前 EOF/出错 → "unable to drain"；
//!                  DrainSize <= 0 → 完全不读，返回 nil。
//! ```
//!
//! 对应关系与**偏差**（不隐瞒）：
//!
//! - `DrainSize` 用 `i64`（参考是 Go `int`，`AcknowledgeReceive` 可把它减为负数），
//!   负数一律按"无需再读"处理，与参考 `if d.DrainSize > 0` 判据一致。
//! - 参考把"读满"与"读不满"**都**当失败上报（再由 `drain.WithError` 叠加原始错误），
//!   本仓用 `DrainOutcome` 表达同一区分：调用方两种结果都必须关闭连接，只是拿到
//!   可判别的枚举而不是被压扁的字符串。
//! - `Drain` 与参考一样**不**自己抵消 `DrainSize`；抵消只由 `AcknowledgeReceive`
//!   表达（上层在正常转发路径上逐次累加已读字节）。
//! - 参考末端 `dice.Roll(RandMax)` 走 Go **全局**随机（`common/dice.Roll`），因此
//!   那一项在参考里本身不可复现。本仓把末端 roll 也接同一颗种子化骰子，使整条
//!   派生在固定种子下逐字节可复现；取值域与参考公式一致（`[0, RandMax)`），没有
//!   新增或收窄分支。`DeterministicDice` 只对齐参考的**结构与取值域**
//!   （`roll(n)` ∈ `[0,n)`，`n <= 1` 恒为 0），**不宣称**与 Go `math/rand` 逐位相同：
//!   基线环境无 Go 工具链可核对（见 `docs/trojan-status.md` 未验证项），且该数值
//!   只影响本地关闭前的丢弃长度，不上线、不改变任何帧字节。
//! - 所有读取由调用方给的**单个正数截止时间**包住（零时长拒绝），超时即失败。
//!
//! 默认行为按参考：`proxy/trojan/{client,server}.go` 自身**不**安装 drainer
//! （只有 `proxy/shadowsocks` 与 `proxy/vmess` 的读取侧用
//! `NewBehaviorSeedLimitedDrainer(seed, 16+38, 3266, 64)`），因此 `Drainer::default()`
//! 等价于参考 `NopDrainer`；种子化丢弃是部署显式开启的策略。

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

/// 参考各调用点的固定参数之一：`NewBehaviorSeedLimitedDrainer(seed, 16+38, 3266, 64)`
/// 的 `drainFoundation`（`proxy/shadowsocks/protocol.go`、
/// `proxy/vmess/encoding/{client,server}.go`）。
pub const DRAIN_FOUNDATION: usize = 16 + 38;
/// 参考 `maxBaseDrainSize`。
pub const MAX_BASE_DRAIN_SIZE: usize = 3266;
/// 参考 `maxRandDrain`。
pub const MAX_RAND_DRAIN: usize = 64;

/// 丢弃读的单次缓冲上限：只是内部读盘粒度，不影响线上字节，也不改变结果计数。
const DISCARD_CHUNK: usize = 4096;

/// drain 失败原因。Display/Debug 不含凭据。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("drain 截止时间必须大于零")]
    InvalidDeadline,

    #[error("drain 超时")]
    Timeout,

    #[error("drain 读取失败：{0}")]
    Io(#[from] std::io::Error),
}

/// 把 `Error` 压成 `std::io::Error`，用于与参考 `drain.WithError` 一样把 drain
/// 结果叠加在原始错误之上（关闭路径不因 drain 失败而丢失原始失败原因）。
impl From<Error> for std::io::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::InvalidDeadline | Error::Timeout => {
                std::io::Error::new(std::io::ErrorKind::TimedOut, error.to_string())
            }
            Error::Io(inner) => inner,
        }
    }
}

/// 对齐参考 `Drain` 的三条分支（含 `DrainSize <= 0` 的不读分支）。
/// 非 `NothingToDrain` 都表示对端仍有残留或已提前结束，调用方必须关闭连接。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainOutcome {
    /// `DrainSize <= 0`（被 `AcknowledgeReceive` 抵消，或本就不需要）：不读任何字节。
    NothingToDrain,
    /// 目标字节全部读到并丢弃（参考把它报为 `drained connection` 失败）。
    FullyDrained { bytes: usize },
    /// 提前 EOF 或读错误（参考 `unable to drain connection`），`bytes` 为已丢弃数。
    Short { bytes: usize },
}

impl DrainOutcome {
    /// 本次实际丢弃的字节数。
    #[must_use]
    pub const fn bytes(&self) -> usize {
        match self {
            DrainOutcome::NothingToDrain => 0,
            DrainOutcome::FullyDrained { bytes } | DrainOutcome::Short { bytes } => *bytes,
        }
    }
}

/// 种子化确定性骰子，对齐 `common/dice.DeterministicDice` 的结构与取值域。
#[derive(Debug, Clone, Copy)]
pub struct DeterministicDice {
    state: u64,
}

impl DeterministicDice {
    /// 由 `i64` 种子构造（参考 `dice.NewDeterministicDice(behaviorSeed)`）。
    #[must_use]
    pub fn new(seed: i64) -> Self {
        // 先做一次混合，避免 seed = 0 时状态退化。
        DeterministicDice {
            state: mix(seed as u64),
        }
    }

    /// `[0,n)`；`n <= 1` 恒为 0，与参考 `DeterministicDice.Roll` / `dice.Roll` 一致。
    pub fn roll(&mut self, n: usize) -> usize {
        if n <= 1 {
            return 0;
        }
        let bound = n as u64;
        // 拒绝采样去掉取模偏置：只接受 [0, limit) 内的原始值。
        let limit = u64::MAX - (u64::MAX % bound);
        loop {
            let value = self.next_u64();
            if value < limit {
                return (value % bound) as usize;
            }
        }
    }

    /// 对齐 `dice.RollDeterministic(n, seed)`：一次性种子化取值。
    #[must_use]
    pub fn rolled(n: usize, seed: i64) -> usize {
        Self::new(seed).roll(n)
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E_37_79_B9_7F_4A_7C_15);
        self.state = mix(self.state);
        self.state
    }
}

fn mix(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xBF_58_47_6D_1C_E4_E5_B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94_D0_49_BB_13_31_11_EB);
    value ^ (value >> 31)
}

/// 对齐参考 `BehaviorSeedLimitedDrainer`：有界的关闭前残留丢弃。
#[derive(Debug, Clone, Copy)]
pub struct BehaviorSeedLimitedDrainer {
    drain_size: i64,
}

impl BehaviorSeedLimitedDrainer {
    /// 参考 `NewBehaviorSeedLimitedDrainer` 的公式；末端 roll 同样接种子化骰子
    /// （偏差见模块注释）。`max_base_drain_size` / `max_rand_drain` 为 0 时不 panic，
    /// 按参考骰子取值域退化为 0。
    #[must_use]
    pub fn new(
        behavior_seed: i64,
        drain_foundation: usize,
        max_base_drain_size: usize,
        max_rand_drain: usize,
    ) -> Self {
        let mut dice = DeterministicDice::new(behavior_seed);
        let base = dice.roll(max_base_drain_size);
        let rand_max = dice.roll(max_rand_drain) + 1;
        let rand_rolled = dice.roll(rand_max);
        let drain_size = drain_foundation
            .saturating_add(base)
            .saturating_add(rand_rolled);
        BehaviorSeedLimitedDrainer {
            drain_size: i64::try_from(drain_size).unwrap_or(i64::MAX),
        }
    }

    /// 用参考调用点的三个固定常量派生。
    #[must_use]
    pub fn with_reference_limits(behavior_seed: i64) -> Self {
        Self::new(
            behavior_seed,
            DRAIN_FOUNDATION,
            MAX_BASE_DRAIN_SIZE,
            MAX_RAND_DRAIN,
        )
    }

    /// 直接指定丢弃长度（上层已有确定策略，或测试固定边界）。
    #[must_use]
    pub const fn from_drain_size(bytes: usize) -> Self {
        BehaviorSeedLimitedDrainer {
            drain_size: bytes as i64,
        }
    }

    /// 参考 `AcknowledgeReceive(size)`：已读字节抵消后续要丢弃的长度，可减为负数。
    pub fn acknowledge_receive(&mut self, size: usize) {
        self.drain_size = self
            .drain_size
            .saturating_sub(i64::try_from(size).unwrap_or(i64::MAX));
    }

    /// 覆盖剩余目标，供测试或上层确定策略使用。
    pub fn set_drain_size(&mut self, bytes: usize) {
        self.drain_size = i64::try_from(bytes).unwrap_or(i64::MAX);
    }

    /// 还需丢弃的字节数；`DrainSize <= 0` 时为 0，与参考 `Drain` 的判据一致。
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.drain_size.max(0) as usize
    }

    /// 参考 `Drain(reader)`：`remaining() == 0` 时**不触碰流**；否则在单个截止时间
    /// 包住下读满并丢弃，不向调用方交还任何字节。与参考一致，本方法不改 `DrainSize`。
    pub async fn drain<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
        wait: Duration,
    ) -> Result<DrainOutcome, Error> {
        let want = self.remaining();
        if want == 0 {
            return Ok(DrainOutcome::NothingToDrain);
        }
        if wait.is_zero() {
            return Err(Error::InvalidDeadline);
        }
        timeout(wait, async {
            let mut scratch = vec![0u8; DISCARD_CHUNK.min(want)];
            let mut total = 0usize;
            while total < want {
                let take = (want - total).min(scratch.len());
                let read = reader.read(&mut scratch[..take]).await?;
                if read == 0 {
                    // 正常 EOF：参考在这里把错误上抛为 "unable to drain"。
                    return Ok(DrainOutcome::Short { bytes: total });
                }
                total += read;
            }
            Ok(DrainOutcome::FullyDrained { bytes: total })
        })
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(Error::Io)
    }
}

/// 对齐参考 `NopDrainer`：从不读取、从不抵消。
#[derive(Debug, Clone, Copy, Default)]
pub struct NopDrainer;

impl NopDrainer {
    #[must_use]
    pub const fn new() -> Self {
        NopDrainer
    }

    pub fn acknowledge_receive(&mut self, _size: usize) {}

    #[must_use]
    pub const fn remaining(&self) -> usize {
        0
    }

    /// 不触碰流，直接返回 `NothingToDrain`；`wait` 仍被校验，便于上层统一策略。
    pub async fn drain<R: AsyncRead + Unpin>(
        &mut self,
        _reader: &mut R,
        wait: Duration,
    ) -> Result<DrainOutcome, Error> {
        if wait.is_zero() {
            return Err(Error::InvalidDeadline);
        }
        Ok(DrainOutcome::NothingToDrain)
    }
}

/// 关闭前残留丢弃策略。`Default` 等价参考 `NopDrainer`（trojan 不安装 drainer）。
#[derive(Debug, Clone, Copy)]
pub enum Drainer {
    Nop(NopDrainer),
    BehaviorSeeded(BehaviorSeedLimitedDrainer),
}

impl Default for Drainer {
    fn default() -> Self {
        Drainer::Nop(NopDrainer)
    }
}

impl Drainer {
    /// 参考 trojan 的默认：不丢弃任何残留，只保证写侧半关闭。
    #[must_use]
    pub fn nop() -> Self {
        Drainer::default()
    }

    /// 用行为种子与参考调用点常量开启种子化丢弃。
    #[must_use]
    pub fn behavior_seeded(behavior_seed: i64) -> Self {
        Drainer::BehaviorSeeded(BehaviorSeedLimitedDrainer::with_reference_limits(
            behavior_seed,
        ))
    }

    /// 用已构造好的种子化 drainer。
    #[must_use]
    pub fn limited(drainer: BehaviorSeedLimitedDrainer) -> Self {
        Drainer::BehaviorSeeded(drainer)
    }

    /// 上层在正常转发路径上每收到 `size` 字节就调用一次（参考 `AcknowledgeReceive`）。
    pub fn acknowledge_receive(&mut self, size: usize) {
        match self {
            Drainer::Nop(inner) => inner.acknowledge_receive(size),
            Drainer::BehaviorSeeded(inner) => inner.acknowledge_receive(size),
        }
    }

    /// 还需丢弃的字节数。
    #[must_use]
    pub fn remaining(&self) -> usize {
        match self {
            Drainer::Nop(inner) => inner.remaining(),
            Drainer::BehaviorSeeded(inner) => inner.remaining(),
        }
    }

    /// 在单个正数截止时间包住下丢弃残留；零时长立即拒绝，超时即失败。
    pub async fn drain<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
        wait: Duration,
    ) -> Result<DrainOutcome, Error> {
        match self {
            Drainer::Nop(inner) => inner.drain(reader, wait).await,
            Drainer::BehaviorSeeded(inner) => inner.drain(reader, wait).await,
        }
    }
}
