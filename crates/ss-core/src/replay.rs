//! 接收侧重放窗口：每个 peer / key epoch 独占一个 8192 位窗口。
//!
//! 共享的计数器窗口原语；窗口大小是本项目策略，不是任何协议的完整实现。
//!
//! 规则（全部在 `accept_authenticated` 一次调用内完成，不做任何到时重置）：
//!
//! - 只能由调用方在 **MAC 认证成功后** 调用；本模块不提供 MAC，也不判断报文可信。
//! - 初始窗口为空，首包 `counter = 0` 可用；上限 `max_counter` 由构造时注入。
//! - 窗口内未见过的乱序计数器接受；重复计数器拒绝。
//! - 比最高计数器旧 8192 位以上（`highest - counter >= 8192`）落在窗口外，拒绝。
//! - `counter > max_counter` 拒绝。该上限来自未来的密钥生命周期策略
//!   （一个 key epoch 内允许的最大计数器），不是 WireGuard 规定的固定阈值。
//! - 向前大跨度跳跃（`counter - highest >= 8192`）清空窗口并以该计数器重新起窗。
//!   此时所有旧已收计数器与新最高的距离本身就已 >= 8192，全部落在新窗口之外，
//!   因此清空不削弱任何重放保护，而是窗口位数的自然结果。
//! - 所有减法用 `checked_`/已确认大小关系，不存在算术溢出。
//!
//! 窗口状态只在显式调用时改变：没有到时自动重置，也不会在拒绝后修改内部状态。
//! **禁止跨 peer 或跨 key epoch 复用同一个 `Window`**：新建对端或轮换密钥时必须
//! `Window::new(...)` 取得独立窗口，否则会把旧 epoch 的已收位误当作本 epoch 的历史。

/// 窗口位数：本项目使用的固定 8192 位。
pub const WINDOW_BITS: usize = 8192;
/// 位图字数（每字 64 位）。
const WORDS: usize = WINDOW_BITS / 64;
/// 位图每字的位数。
const BITS_PER_WORD: usize = 64;

/// 重放判定失败原因。三类都是拒绝，且拒绝不改变窗口状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// 重复计数器：该值已在窗口内收下（或与当前最高计数器相同）。
    #[error("重放：计数器 {counter} 已收下")]
    Duplicate { counter: u64 },
    /// 计数器比窗口最高可收位置更旧，落在 8192 位窗口之外。
    #[error("重放：计数器 {counter} 比最高计数器 {highest} 旧出窗口范围")]
    TooOld { counter: u64, highest: u64 },
    /// 计数器超过构造时注入的密钥生命周期上限。
    #[error("重放：计数器 {counter} 超过注入上限 {max_counter}")]
    ExceedsMaxCounter { counter: u64, max_counter: u64 },
}

/// 单个 peer / 单个 key epoch 的接收重放窗口。
///
/// `Debug` 只输出最高计数器与是否已起窗，不输出位图内容，
/// 避免把与流量模式相关的时间序列细节带进日志。
#[derive(Clone)]
pub struct Window {
    /// 构造时注入的计数器上限（密钥生命周期策略），不是协议常量。
    max_counter: u64,
    /// 已接受的最大计数器；`None` 表示窗口为空，尚无任何认证通过的报文。
    highest: Option<u64>,
    /// 位 `delta` 表示 `highest - counter == delta`；`delta = 0` 即最高计数器本身。
    words: [u64; WORDS],
}

impl core::fmt::Debug for Window {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Window")
            .field("window_bits", &WINDOW_BITS)
            .field("max_counter", &self.max_counter)
            .field("highest", &self.highest)
            // 故意不输出 words 位图。
            .finish_non_exhaustive()
    }
}

impl Window {
    /// 新建空窗口，`max_counter` 是本 key epoch 内允许的最大计数器。
    ///
    /// 每个新 peer 或新 key epoch 都必须调用本函数取得独占窗口。
    #[must_use]
    pub fn new(max_counter: u64) -> Self {
        Window {
            max_counter,
            highest: None,
            words: [0; WORDS],
        }
    }

    /// 注入的上限，便于上层做密钥轮换决策。
    #[must_use]
    pub fn max_counter(&self) -> u64 {
        self.max_counter
    }

    /// 当前最高已接受计数器；空窗口为 `None`。
    #[must_use]
    pub fn highest(&self) -> Option<u64> {
        self.highest
    }

    /// 窗口内是否已记录某个计数器（仅供测试与诊断；不改变状态）。
    #[must_use]
    pub fn contains(&self, counter: u64) -> bool {
        let Some(highest) = self.highest else {
            return false;
        };
        if counter > highest {
            return false;
        }
        // highest >= counter，减法不溢出；超出窗口范围一律视为未记录。
        match highest.checked_sub(counter) {
            Some(delta) => delta < WINDOW_BITS as u64 && self.bit(delta as usize),
            None => false,
        }
    }

    /// **仅在 MAC 认证成功后调用**：判定 `counter` 是否可收下并更新窗口。
    ///
    /// 返回 `Ok(())` 表示该计数器此前在本窗口未被收下且在允许范围内；
    /// 返回 `Err` 表示拒绝，且窗口状态保持不变。
    /// 本函数不做任何与时间相关的重置，也不验证报文真伪。
    pub fn accept_authenticated(&mut self, counter: u64) -> Result<(), Error> {
        if counter > self.max_counter {
            return Err(Error::ExceedsMaxCounter {
                counter,
                max_counter: self.max_counter,
            });
        }
        let Some(highest) = self.highest else {
            // 空窗口：首包直接起窗，counter = 0 天然可用。
            self.highest = Some(counter);
            self.words[0] = 1;
            return Ok(());
        };
        match counter.cmp(&highest) {
            core::cmp::Ordering::Equal => Err(Error::Duplicate { counter }),
            core::cmp::Ordering::Greater => {
                // counter > highest，减法不会溢出。
                let delta = counter - highest;
                self.highest = Some(counter);
                if delta >= WINDOW_BITS as u64 {
                    // 向前大跨度跳跃：整窗清空。此时所有旧已收计数器的距离都
                    // >= 8192，本就落在新窗口之外，因此清空不削弱任何保护。
                    self.words = [0; WORDS];
                } else {
                    self.shift_bitmap(delta as usize);
                }
                // 移位后字 0 的最低位必为 0，用 |= 保留随移位保留的旧位。
                self.words[0] |= 1;
                Ok(())
            }
            core::cmp::Ordering::Less => {
                // highest > counter，减法不会溢出。
                let delta = highest - counter;
                if delta >= WINDOW_BITS as u64 {
                    return Err(Error::TooOld { counter, highest });
                }
                let index = delta as usize;
                if self.bit(index) {
                    return Err(Error::Duplicate { counter });
                }
                self.set_bit(index);
                Ok(())
            }
        }
    }

    /// 位图整体向“更旧”方向移动 `shift` 位（最高计数器前移 `shift`）。
    /// 位移量由调用方保证 `1..WINDOW_BITS`。
    fn shift_bitmap(&mut self, shift: usize) {
        debug_assert!((1..WINDOW_BITS).contains(&shift));
        let word_shift = shift / BITS_PER_WORD;
        let bit_shift = shift % BITS_PER_WORD;
        // 倒序写入：每个目的字只读取下标不大于自身、且尚未被覆盖的源字。
        for index in (0..WORDS).rev() {
            let source = index.checked_sub(word_shift);
            let moved = source.map_or(0, |source| self.words[source] << bit_shift);
            let carry = source
                .and_then(|source| source.checked_sub(1))
                .map_or(0, |source| {
                    // bit_shift == 0 时右移 64 位无定义，此处显式给零。
                    if bit_shift == 0 {
                        0
                    } else {
                        self.words[source] >> (BITS_PER_WORD - bit_shift)
                    }
                });
            self.words[index] = moved | carry;
        }
    }

    fn bit(&self, index: usize) -> bool {
        let word_index = index / BITS_PER_WORD;
        let offset = index % BITS_PER_WORD;
        match self.words.get(word_index) {
            Some(word) => word & (1u64 << offset) != 0,
            None => false,
        }
    }

    fn set_bit(&mut self, index: usize) {
        let word_index = index / BITS_PER_WORD;
        let offset = index % BITS_PER_WORD;
        if let Some(word) = self.words.get_mut(word_index) {
            *word |= 1u64 << offset;
        }
    }
}
