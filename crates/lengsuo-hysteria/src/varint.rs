//! QUIC (RFC 9000) 变长整数。
//!
//! 编码使用规范最短形式；解码按首两位的长度前缀读取，允许非最短编码
//! （长度前缀决定有效位数，与 QUIC 文本一致）。这与参考实现的写入
//! `varintPut` + `quicvarint.Len`（最短）以及 `quicvarint.Read`（接受
//! 非最短）行为一致，见 `core/internal/protocol/proxy.go`，完整 commit
//! `ca8fbd874fd6ca82413948de6dc5924405e103e1`。
//!
//! 只覆盖 varint 原语本身：不涉及 QUIC 帧、连接或流。测试见
//! `tests/varint.rs`。

use crate::Error;

/// 可表示的最大值：2^62 - 1。
pub const MAX_VALUE: u64 = (1 << 62) - 1;

/// 规范最短编码所需字节数（1/2/4/8）；超出 `MAX_VALUE` 返回 `None`。
#[must_use]
pub fn encoded_len(value: u64) -> Option<usize> {
    if value <= 63 {
        Some(1)
    } else if value <= 16_383 {
        Some(2)
    } else if value < (1 << 30) {
        Some(4)
    } else if value <= MAX_VALUE {
        Some(8)
    } else {
        None
    }
}

/// 规范最短编码所需字节数；取值超限时报错，供调用方预分配使用。
pub fn size(value: u64) -> Result<usize, Error> {
    encoded_len(value).ok_or(Error::VarIntOutOfRange { value })
}

/// 首字节对应的编码长度（1/2/4/8）。
#[must_use]
pub const fn prefix_len(first: u8) -> usize {
    1 << (first >> 6)
}

/// 编码为规范最短形式并写入 `buf`，返回写入字节数。
///
/// 取值超限或缓冲区不足时报错，且不会部分写入。
pub fn encode(value: u64, buf: &mut [u8]) -> Result<usize, Error> {
    let len = size(value)?;
    if buf.len() < len {
        return Err(Error::Truncated {
            need: len,
            got: buf.len(),
        });
    }
    match len {
        1 => buf[0] = value as u8,
        2 => {
            buf[0] = (value >> 8) as u8 | 0x40;
            buf[1] = value as u8;
        }
        4 => {
            let bytes = (value as u32).to_be_bytes();
            buf[0] = bytes[0] | 0x80;
            buf[1..4].copy_from_slice(&bytes[1..]);
        }
        _ => {
            // len == 8：首字节高两位是前缀，其余 62 位大端展开。
            let bytes = value.to_be_bytes();
            buf[0] = bytes[0] | 0xC0;
            buf[1..8].copy_from_slice(&bytes[1..]);
        }
    }
    Ok(len)
}

/// 追加规范最短编码到 `Vec`，返回追加字节数；失败时不追加任何字节。
pub fn append(value: u64, buf: &mut Vec<u8>) -> Result<usize, Error> {
    let mut scratch = [0_u8; 8];
    let len = encode(value, &mut scratch)?;
    buf.extend_from_slice(&scratch[..len]);
    Ok(len)
}

/// 从字节流头部解码，返回（取值，消耗字节数）。
///
/// 接受非最短编码（例如 `0x40 0x00` 表示 0，`0x80 0x00 0x00 0x0F` 表示 15），
/// 由长度前缀决定读取位数；截断时报告该前缀所需的完整字节数。
/// 按前缀规则解出的值恒 `<= MAX_VALUE`，因此越界只可能来自调用方自己的
/// 长度字段上限检查。
pub fn decode(input: &[u8]) -> Result<(u64, usize), Error> {
    let first = *input.first().ok_or(Error::Truncated { need: 1, got: 0 })?;
    let len = prefix_len(first);
    if input.len() < len {
        return Err(Error::Truncated {
            need: len,
            got: input.len(),
        });
    }
    let mut value = u64::from(first & 0x3F);
    for byte in &input[1..len] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, len))
}
