//! 关闭前残留丢弃（drain）测试，对齐参考 `common/drain/drainer.go`。
//!
//! 覆盖：N 字节边界（正好丢满 / 提前 EOF 只丢部分 / 目标为 0 不触碰流）、
//! `AcknowledgeReceive` 抵消、超时包住静默对端、零时长拒绝、
//! 固定种子逐字节可复现、种子骰子取值域退化，以及 drain + 写半关闭组合
//! （参考默认 Nop 行为、种子化行为、两阶段共用一个截止时间）。
//! 所有异步读写都被 `tokio::time::timeout` 包住；`read_to_end` 前先关写端。
//! 密码为测试专用假凭据。
//!
//! 结构：本文件是**入口**，只留共享的导入、常量与 `pattern` 辅助；
//! 用例按语义分两个文件 —— drain 语义（`drain_cases.rs`）与
//! half_close / close 语义（`close_cases.rs`）。两个文件都以 `include!`
//! 拼回**本模块**（而不是另起子模块），因此用例的全限定名与拆分前完全一致
//! （`drain_discards_exactly_n_bytes` 等，不带任何模块前缀）。

use std::time::Duration;

use lengsuo_trojan::drain::{
    BehaviorSeedLimitedDrainer, DeterministicDice, DrainOutcome, Drainer, DRAIN_FOUNDATION,
    MAX_BASE_DRAIN_SIZE, MAX_RAND_DRAIN,
};
use lengsuo_trojan::stream::{close_stream, shutdown_write};
use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(2);
const SILENT: Duration = Duration::from_millis(30);

/// 固定可复现的伪随机字节型样（不依赖随机源，便于逐字节比较）。
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u32 * 7 + 11) as u8).collect()
}

include!("close_drain/drain_cases.rs");
include!("close_drain/close_cases.rs");
