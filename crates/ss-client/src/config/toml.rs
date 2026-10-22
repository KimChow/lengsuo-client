//! TOML 子集读取器。
//!
//! **为什么自带读取器**：`crates/ss-client/Cargo.toml` 的依赖表里没有 `toml`
//!（也没有 `serde`），而 `Cargo.toml` 由基建卡独占、本卡不得新增依赖。
//! 为让配置模块**真的能被编译与测试**，本目录用 std 手写一个 TOML 读取器，
//! 覆盖本配置格式用到的全部语法：注释、裸键 / 引号键 / 点分键、表头
//! `[a.b]`、表数组头 `[[a.b]]`、基本串 / 字面串 / 多行串、整数、布尔、
//! 数组（可跨行）、内联表。
//!
//! **错误信息不回显源行**：TOML 源行可能含 `ss://` 口令，`toml` crate 的
//! 解析错误会带上出错行原文，本读取器只报**行号 + 描述**（fail-closed 且不泄漏）。
//!
//! **不���持浮点**：本配置格式没有浮点字段，浮点一律按语法错拒绝
//! （fail-closed），免得「读进来了但没人用」的值被静默丢弃。
//!
//! 偏离与「换回官方 `toml` crate」的计划见 `docs/ss-client-config-activate.md`。

mod parser;
mod scalar;

use std::collections::BTreeMap;
use std::fmt;

use crate::error::{ConfigError, Error, Result};

/// 配置值。
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    Array(Vec<Value>),
    Table(BTreeMap<String, Value>),
}

impl Value {
    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(text) => Some(text),
            _ => None,
        }
    }

    pub(crate) fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(number) => Some(*number),
            _ => None,
        }
    }

    pub(crate) fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(flag) => Some(*flag),
            _ => None,
        }
    }

    pub(crate) fn as_table(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Self::Table(entries) => Some(entries),
            _ => None,
        }
    }

    pub(crate) fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// 取字符串字段；类型不符即 `Err`（fail-closed，不做隐式转换）。
    pub(crate) fn str_field(&self, field: &'static str) -> Result<&str> {
        self.as_str()
            .ok_or_else(|| type_error(field, "must be a string"))
    }

    /// 取整数字段；类型不符即 `Err`（fail-closed）。
    pub(crate) fn int_field(&self, field: &'static str) -> Result<i64> {
        self.as_int()
            .ok_or_else(|| type_error(field, "must be an integer"))
    }

    /// 取布尔字段；类型不符即 `Err`（fail-closed）。
    pub(crate) fn bool_field(&self, field: &'static str) -> Result<bool> {
        self.as_bool()
            .ok_or_else(|| type_error(field, "must be a boolean"))
    }

    /// 取表字段；类型不符即 `Err`（fail-closed）。
    pub(crate) fn table_field(&self, field: &'static str) -> Result<&BTreeMap<String, Value>> {
        self.as_table()
            .ok_or_else(|| type_error(field, "must be a table"))
    }

    /// 取数组字段；类型不符即 `Err`（fail-closed）。
    pub(crate) fn array_field(&self, field: &'static str) -> Result<&[Value]> {
        self.as_array()
            .ok_or_else(|| type_error(field, "must be an array"))
    }
}

/// 取字符串列表；标量也当作单元素列表。
pub(crate) fn string_list(value: Option<&Value>, field: &'static str) -> Result<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    match value {
        Value::Str(single) => Ok(vec![single.clone()]),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Str(text) => Ok(text.clone()),
                _ => Err(type_error(field, "must be a string array")),
            })
            .collect(),
        _ => Err(type_error(field, "must be a string or string array")),
    }
}

/// 解析错误：只带行号与描述，**不回显源行**（源行可能含凭据）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParseError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

/// 解析一份 TOML 文档，返回顶层表。
pub(crate) fn parse(text: &str) -> std::result::Result<BTreeMap<String, Value>, ParseError> {
    parser::Parser::new(text).parse_document()
}

/// 类型不符的错误：只说字段与形状，**不回显取值**（取值可能是凭据）。
fn type_error(field: &'static str, reason: &str) -> Error {
    ConfigError::Invalid {
        field,
        reason: reason.to_owned(),
    }
    .into()
}
