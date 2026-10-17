//! 精确度（规格 §2.4「精确规则 > 通配规则；同精度时按规则序」）。
//!
//! 分级即冻结的优先级：`Exact > HostAnchored > HostWildcard > AllPages`。
//! 同级之间再比字面锚点长度（长者优先），长度相同才交给规则序裁决——
//! 因此 [`more_specific`] 对同精度同长度的两条模式必须返回 `None`，
//! 否则排序不稳定、规则序失效。

use super::compiled::Pattern;

/// 精确度分级。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Specificity {
    /// 「所有网页」通配兜底（`*`、`**`、`*/**`、`**/**`）：最低精度。
    AllPages = 0,
    /// 主机是通配写法（`*.example.com/*`、`*/x`、`**/*.js`）：有域锚点但主机不固定。
    HostWildcard = 1,
    /// 主机固定、路径含通配（`example.com/*`、`example.com/**`、`example.com/{1..}`）。
    HostAnchored = 2,
    /// 纯字面量模式（`example.com/login`）：最高精度。
    Exact = 3,
}

impl Specificity {
    /// 全部分级，按优先级**从高到低**排列（策略作者核对覆盖序时按此顺序读）。
    pub const ALL: [Self; 4] = [
        Self::Exact,
        Self::HostAnchored,
        Self::HostWildcard,
        Self::AllPages,
    ];
}

/// `a` 是否比 `b` **更精确**（可作规则序的覆盖依据）。
///
/// 跨级比较只看级别，字面锚点长度不得反超；同级比较才比长度。
/// 同精度同长度返回 `false`——两条模式互不优先，交给规则序裁决；
/// 自反比较（同一条模式）因此也必须是 `false`，否则排序不稳定。
#[must_use]
pub fn more_specific(a: &Pattern, b: &Pattern) -> bool {
    use std::cmp::Ordering;
    match a.specificity().cmp(&b.specificity()) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => a.literal_len().cmp(&b.literal_len()) == Ordering::Greater,
    }
}
