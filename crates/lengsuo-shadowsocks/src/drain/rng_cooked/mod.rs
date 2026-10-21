//! `rngCooked` 常量表，逐字节转写自 Go `math/rand` 的 `rng.go`。
//!
//! Go 在 seed 时把 `seedrand` LCG 的输出与这些固定常量做 XOR，用来初始化
//! 607 项的滞后 Fibonacci 反馈寄存器。要让 Xray 的
//! `dice.NewDeterministicDice` 逐位复现，这张表不可省略。
//! 共 607 项（`rngLen`），类型 `int64`。
//!
//! 表本身按 203 / 202 / 202 三段落在 [`part_a`] / [`part_b`] / [`part_c`]，
//! 由下面的 `concat` 在**编译期**拼回 [`RNG_COOKED`]——顺序与数值均未改变，
//! 只是把一张超长的字面量表拆到多个文件里。

mod part_a;
mod part_b;
mod part_c;

/// `rngCooked` 的第 1 段（203 项）。
const PART_A_LEN: usize = 203;
/// `rngCooked` 的第 2 段（202 项）。
const PART_B_LEN: usize = 202;
/// `rngCooked` 的第 3 段（202 项）。
const PART_C_LEN: usize = 202;

/// 编译期把三段常量表按顺序拼成完整的 607 项表。
const fn concat() -> [i64; PART_A_LEN + PART_B_LEN + PART_C_LEN] {
    let mut out = [0i64; PART_A_LEN + PART_B_LEN + PART_C_LEN];
    let mut i = 0;
    while i < PART_A_LEN {
        out[i] = part_a::RNG_COOKED_A[i];
        i += 1;
    }
    let mut i = 0;
    while i < PART_B_LEN {
        out[PART_A_LEN + i] = part_b::RNG_COOKED_B[i];
        i += 1;
    }
    let mut i = 0;
    while i < PART_C_LEN {
        out[PART_A_LEN + PART_B_LEN + i] = part_c::RNG_COOKED_C[i];
        i += 1;
    }
    out
}

/// Go `math/rand` 的 `rngCooked` 表，共 607 项，类型 `int64`。
pub(crate) const RNG_COOKED: [i64; 607] = concat();
