//! VLESS Vision 握手 padding 参数：对齐 `common.go` 的 `ParsePadding` /
//! `CreatPadding`（纯函数，独立复算）。
//!
//! 参考语义：
//! - `ParsePadding(padding, &lens, &gaps)` 解析 `a-b-c.d-e-f.g-h-i` 形式的字符串：
//!   每段用 `-` 拆成 `[a, b, c]`，第 0、2、4… 段（偶数下标）进入 `lens`（同时累加
//!   `max(b, c)`），第 1、3、5… 段（奇数下标）进入 `gaps`。
//! - 首段必须满足 `a >= 100` 且 `b, c >= 18 + 17`（参考把常量写作 `18+17`）。
//! - 所有偶数段的 `max(b, c)` 之和不得超过 `18 + 65535`。
//! - `CreatPadding(lens, gaps)`：`lens` 为空时使用参考默认表
//!   `{100,111,1111}` + `{50,0,3333}`（gaps 同时替换为 `{75,0,111}`）；每段
//!   按 `y[0] >= rand(0..100)` 判定是否取值，取值为 `rand(y[1]..y[2])`（gap 单位毫秒）。
//!
//! 随机数以 `impl RngCore` 注入，便于确定性单测；解析不含随机，只依赖输入。

use aes_gcm::aead::rand_core::RngCore;

use super::rand_below;

/// 参考 `ParsePadding` 首段下限：`y[1]` / `y[2]` 必须不小于 `18 + 17`。
const MIN_SEGMENT: i32 = 18 + 17;
/// 参考 `ParsePadding` 首段概率下限。
const FIRST_CHANCE_MIN: i32 = 100;
/// 参考 `ParsePadding` 总长上限：`18 + 65535`。
const MAX_TOTAL: i64 = 18 + 65535;
/// 参考 `CreatPadding` 的默认 padding lens 表（lens 为空时启用）。
const DEFAULT_LENS: [[i32; 3]; 2] = [[100, 111, 1111], [50, 0, 3333]];
/// 参考 `CreatPadding` 的默认 padding gaps 表（lens 为空时与 lens 一并启用）。
const DEFAULT_GAPS: [[i32; 3]; 1] = [[75, 0, 111]];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PaddingError {
    /// 某段无法拆成 `a-b-c`（缺项、空项或整数解析失败）。
    #[error("非法 padding 长度/间隔参数：{0}")]
    InvalidSegment(String),
    /// 首段不满足 `a>=100 && b,c>=18+17`。
    #[error("首个 padding 长度不得小于 35")]
    FirstPaddingTooSmall,
    /// 偶数段 `max(b,c)` 之和超过上限。
    #[error("padding 总长度不得大于 65553")]
    TotalPaddingTooLarge,
}

/// 参考 `crypto.RandBetween`（区间 `[,)`；`from == to` 直接返回；`from > to` 交换）。
fn rand_between(rng: &mut impl RngCore, from: i64, to: i64) -> i64 {
    if from == to {
        return from;
    }
    let (lo, hi) = if from > to { (to, from) } else { (from, to) };
    lo + rand_below(rng, (hi - lo) as u64) as i64
}

/// 参考 `ParsePadding`：把 `padding` 解析进 `padding_lens` / `padding_gaps`。
///
/// 空字符串直接成功（不追加任何条目）。
pub fn parse_padding(
    padding: &str,
    padding_lens: &mut Vec<[i32; 3]>,
    padding_gaps: &mut Vec<[i32; 3]>,
) -> Result<(), PaddingError> {
    if padding.is_empty() {
        return Ok(());
    }
    let mut max_len: i64 = 0;
    for (i, segment) in padding.split('.').enumerate() {
        let parts: Vec<&str> = segment.split('-').collect();
        if parts.len() < 3 || parts[0].is_empty() || parts[1].is_empty() || parts[2].is_empty() {
            return Err(PaddingError::InvalidSegment(segment.to_owned()));
        }
        let mut entry = [0i32; 3];
        // 参考只取前三段，多余的 `-` 轮廓不校验（`len(x) < 3` 才失败）。
        for (k, part) in parts.iter().take(3).enumerate() {
            entry[k] = part
                .parse::<i32>()
                .map_err(|_| PaddingError::InvalidSegment(segment.to_owned()))?;
        }
        if i == 0
            && (entry[0] < FIRST_CHANCE_MIN || entry[1] < MIN_SEGMENT || entry[2] < MIN_SEGMENT)
        {
            return Err(PaddingError::FirstPaddingTooSmall);
        }
        if i % 2 == 0 {
            padding_lens.push(entry);
            max_len += i64::from(entry[1].max(entry[2]));
        } else {
            padding_gaps.push(entry);
        }
    }
    if max_len > MAX_TOTAL {
        return Err(PaddingError::TotalPaddingTooLarge);
    }
    Ok(())
}

/// 参考 `CreatPadding`：由 len/gap 表与随机源生成单握手 padding。
///
/// 返回 `(总字节数, 每段长度, 每段间隔毫秒)`。`padding_lens` 为空时按参考替换
/// 默认表（同时替换 gaps）。
pub fn create_padding(
    padding_lens: &[[i32; 3]],
    padding_gaps: &[[i32; 3]],
    rng: &mut impl RngCore,
) -> (usize, Vec<usize>, Vec<u64>) {
    let (lens_table, gaps_table): (&[[i32; 3]], &[[i32; 3]]) = if padding_lens.is_empty() {
        (&DEFAULT_LENS, &DEFAULT_GAPS)
    } else {
        (padding_lens, padding_gaps)
    };

    let mut length: usize = 0;
    let mut lens = Vec::with_capacity(lens_table.len());
    for entry in lens_table {
        let mut value: i64 = 0;
        if i64::from(entry[0]) >= rand_between(rng, 0, 100) {
            value = rand_between(rng, i64::from(entry[1]), i64::from(entry[2]));
        }
        lens.push(value as usize);
        length += value as usize;
    }

    let mut gaps = Vec::with_capacity(gaps_table.len());
    for entry in gaps_table {
        let mut value: i64 = 0;
        if i64::from(entry[0]) >= rand_between(rng, 0, 100) {
            value = rand_between(rng, i64::from(entry[1]), i64::from(entry[2]));
        }
        gaps.push(value as u64);
    }

    (length, lens, gaps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vision::test_util::CounterRng;

    #[test]
    fn parse_builds_the_reference_default_tables() {
        // 三者正是参考 `CreatPadding` 默认表的常量（逐项比对，非自造）。
        let mut lens = Vec::new();
        let mut gaps = Vec::new();
        parse_padding("100-111-1111.75-0-111.50-0-3333", &mut lens, &mut gaps).unwrap();
        assert_eq!(lens, vec![[100, 111, 1111], [50, 0, 3333]]);
        assert_eq!(gaps, vec![[75, 0, 111]]);
    }

    #[test]
    fn parse_empty_string_and_single_segment() {
        let mut lens = Vec::new();
        let mut gaps = Vec::new();
        parse_padding("", &mut lens, &mut gaps).unwrap();
        assert!(lens.is_empty() && gaps.is_empty());

        let mut lens = Vec::new();
        let mut gaps = Vec::new();
        parse_padding("100-35-35", &mut lens, &mut gaps).unwrap();
        assert_eq!(lens, vec![[100, 35, 35]]);
        assert!(gaps.is_empty());
    }

    #[test]
    fn parse_rejects_malformed_segments() {
        for spec in ["100", "100-35", "-35-35", "100--35", "100-35-", "a-b-c"] {
            let mut lens = Vec::new();
            let mut gaps = Vec::new();
            assert!(
                matches!(
                    parse_padding(spec, &mut lens, &mut gaps),
                    Err(PaddingError::InvalidSegment(_))
                ),
                "{spec} 应判为非法段"
            );
        }
        // 参考忽略第 4 段以后；第 3 段存在即合法。
        let mut lens = Vec::new();
        let mut gaps = Vec::new();
        parse_padding("100-35-35-999", &mut lens, &mut gaps).unwrap();
        assert_eq!(lens, vec![[100, 35, 35]]);
    }

    #[test]
    fn parse_enforces_first_segment_and_total_bounds() {
        for spec in ["99-35-35", "100-34-35", "100-35-34"] {
            let mut lens = Vec::new();
            let mut gaps = Vec::new();
            assert_eq!(
                parse_padding(spec, &mut lens, &mut gaps),
                Err(PaddingError::FirstPaddingTooSmall),
                "{spec} 首段下限"
            );
        }
        // 首段合法，但偶数段 max(b,c) 之和超上限。
        let mut lens = Vec::new();
        let mut gaps = Vec::new();
        assert_eq!(
            parse_padding("100-70000-35", &mut lens, &mut gaps),
            Err(PaddingError::TotalPaddingTooLarge)
        );
    }

    #[test]
    fn create_padding_uses_reference_default_tables() {
        // CounterRng 依次产出 0,1,2,3,4,5：
        // lens[0]=[100,111,1111]：0>=rand(0,100)=0 → l=rand(111,1111)=111+1=112
        // lens[1]=[50,0,3333]： 50>=rand(0,100)=2 → l=rand(0,3333)=0+3=3
        // gaps[0]=[75,0,111]：  75>=rand(0,100)=4 → g=rand(0,111)=5
        let (length, lens, gaps) = create_padding(&[], &[], &mut CounterRng(0));
        assert_eq!(length, 115);
        assert_eq!(lens, vec![112, 3]);
        assert_eq!(gaps, vec![5]);
    }

    #[test]
    fn create_padding_respects_explicit_tables_and_empty_gaps() {
        // 显式表不为空时不得注入默认表；gaps 为空就产生空 gaps。
        let (length, lens, gaps) = create_padding(&[[100, 0, 9]], &[], &mut CounterRng(0));
        assert_eq!(length, 1); // 0>=0 → rand(0,9)=0+1=1
        assert_eq!(lens, vec![1]);
        assert!(gaps.is_empty());
    }

    #[test]
    fn create_padding_skips_when_chance_fails() {
        // CounterRng 首个值为 99：lens[0]=[0,111,1111] 时 0 >= rand(0,100)=99 失败 → l=0。
        let (length, lens, gaps) = create_padding(&[[0, 111, 1111]], &[], &mut CounterRng(99));
        assert_eq!(length, 0);
        assert_eq!(lens, vec![0]);
        assert!(gaps.is_empty());
    }
}
