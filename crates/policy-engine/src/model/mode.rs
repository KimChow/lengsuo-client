//! 规格 §1 数据模型分片：`mode`。
//!
//! 统一从 [`crate::model`] 再导出，字段名/数值契约见本目录各文件。
//! 模式与兜底枚举（规格 §1）：线上格式是**冻结数值**，未知数值直接报错。

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

/// 数值枚举的 serde 契约：线上只接受冻结的 `u8`，未知数值直接报错——
/// 既不接受字符串写法，也不回退到任何默认变体（fail-closed，AGENTS.md §3）。
fn parse_numeric<'de, D, T>(
    deserializer: D,
    type_name: &str,
    from_number: fn(u8) -> Option<T>,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
{
    let number = u8::deserialize(deserializer)?;
    from_number(number).ok_or_else(|| {
        de::Error::custom(format!(
            "未知的 {type_name} 数值 {number}，只接受已冻结数值"
        ))
    })
}

/// 策略模式（数值冻结：ALL=1、SomeBlack=2、SomeWhite=3、SpecialCase=4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyMode {
    /// 1：全放行（策略生效对象内的一切访问都允许）。
    All = 1,
    /// 2：部分黑名单（默认可访问，命中黑名单规则则拒绝）。
    SomeBlack = 2,
    /// 3：部分白名单（默认不可访问，命中白名单规则才允许）。
    SomeWhite = 3,
    /// 4：特殊案例（最高优先级，命中即以其结论为准，覆盖黑白名单）。
    SpecialCase = 4,
}

impl PolicyMode {
    /// 全部冻结变体（顺序即优先级从低到高）。
    pub const ALL_VARIANTS: [Self; 4] = [
        Self::All,
        Self::SomeBlack,
        Self::SomeWhite,
        Self::SpecialCase,
    ];

    /// 冻结的线上数值。
    #[must_use]
    pub const fn number(self) -> u8 {
        self as u8
    }

    /// 由线上数值解析；未知数值返回 `None`。
    #[must_use]
    pub const fn from_number(number: u8) -> Option<Self> {
        Some(match number {
            1 => Self::All,
            2 => Self::SomeBlack,
            3 => Self::SomeWhite,
            4 => Self::SpecialCase,
            _ => return None,
        })
    }
}

impl Serialize for PolicyMode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(Self::number(*self))
    }
}

impl<'de> Deserialize<'de> for PolicyMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        parse_numeric(deserializer, "PolicyMode", Self::from_number)
    }
}

/// `strategy` 为空时的兜底模式。实证结论：只有黑名单一种兜底（规格 §1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmptyStrategyDefault {
    /// 1：strategy 为空 ⇒ 按黑名单模式处理（唯一实现值，不预留 White）。
    Black = 1,
}

impl EmptyStrategyDefault {
    /// 冻结的线上数值。
    #[must_use]
    pub const fn number(self) -> u8 {
        self as u8
    }

    /// 由线上数值解析；未知数值返回 `None`。
    #[must_use]
    pub const fn from_number(number: u8) -> Option<Self> {
        match number {
            1 => Some(Self::Black),
            _ => None,
        }
    }
}

impl Default for EmptyStrategyDefault {
    /// 缺省即实证结论：黑名单。
    fn default() -> Self {
        Self::Black
    }
}

impl Serialize for EmptyStrategyDefault {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(Self::number(*self))
    }
}

impl<'de> Deserialize<'de> for EmptyStrategyDefault {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        parse_numeric(deserializer, "EmptyStrategyDefault", Self::from_number)
    }
}
