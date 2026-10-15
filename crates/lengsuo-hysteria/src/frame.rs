//! 帧解析共享辅助（crate 内部，不对外导出）。
//!
//! `tcp.rs` 与 `connect_udp.rs` 共用同一套 fail-closed 原语：varint 读取
//! （截断长度归一为绝对偏移）、按长度取字节、长度范围检查、文本字段校验。
//! 任一失败都要求调用方丢弃该流：不得在未对齐的字节流上继续读取，也不得
//! 回退到明文。本模块不定义帧格式，也不生成 padding。
//!
//! 从 `tcp.rs` 抽出（同一套字节级语义），避免 CONNECT-UDP 帧复制实现。

use crate::varint;
use crate::Error;

/// 在 `offset` 处读取 varint，返回（取值，其后绝对偏移）。
pub(crate) fn read_varint(input: &[u8], offset: usize) -> Result<(u64, usize), Error> {
    let rest = input.get(offset..).ok_or(Error::Truncated {
        need: offset.saturating_add(1),
        got: input.len(),
    })?;
    let (value, used) = varint::decode(rest).map_err(|error| match error {
        Error::Truncated { need, .. } => Error::Truncated {
            need: offset.saturating_add(need),
            got: input.len(),
        },
        other => other,
    })?;
    Ok((value, offset + used))
}

/// 取 `input[offset..offset+len]`，返回（切片，其后绝对偏移）。
///
/// 长度上限已在上游按协议常量校验，这里只处理输入不足。相加溢出归一为
/// `usize::MAX`，仍按截断失败，不因大长度字段 panic。
pub(crate) fn take_bytes(input: &[u8], offset: usize, len: u64) -> Result<(&[u8], usize), Error> {
    let len = usize::try_from(len).unwrap_or(usize::MAX);
    let end = offset.saturating_add(len);
    input
        .get(offset..end)
        .map(|slice| (slice, end))
        .ok_or(Error::Truncated {
            need: end,
            got: input.len(),
        })
}

/// 长度范围检查；`min` 为 1 时为空视为协议违规。
pub(crate) fn check_len(field: &'static str, len: u64, min: u64, max: u64) -> Result<(), Error> {
    if len < min {
        return Err(Error::EmptyField { field });
    }
    if len > max {
        return Err(Error::TooLong { field, len, max });
    }
    Ok(())
}

/// NUL 先于 UTF-8 报告：NUL 本身是合法 UTF-8，但地址与消息一律禁止。
pub(crate) fn text_bytes(field: &'static str, bytes: &[u8]) -> Result<(), Error> {
    if bytes.contains(&0) {
        return Err(Error::ContainsNul { field });
    }
    std::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8 { field })?;
    Ok(())
}

/// 校验为文本后转 `String`。
pub(crate) fn text(field: &'static str, bytes: &[u8]) -> Result<String, Error> {
    text_bytes(field, bytes)?;
    Ok(String::from_utf8(bytes.to_vec()).expect("上文已确认字节是合法 UTF-8"))
}
