//! QPACK 的底层原语：`prefix-int` 编解码、Huffman 解码、字符串字面量解码。

use super::error::QpackError;
use super::tables::HUFFMAN;

/// `prefix-int` 解码（RFC 7541 §5.1，QPACK 沿用）。
/// 返回（值，消耗字节数）；`prefix_bits` 为 1..=8。
pub(crate) fn prefix_int(input: &[u8], prefix_bits: u32) -> Result<(u64, usize), QpackError> {
    debug_assert!((1..=8).contains(&prefix_bits));
    let mask: u64 = (1 << prefix_bits) - 1;
    let first = *input
        .first()
        .ok_or(QpackError::Truncated { need: 1, got: 0 })?;
    let mut value = (first as u64) & mask;
    if value < mask {
        return Ok((value, 1));
    }
    let mut pos = 1usize;
    let mut shift = 0u32;
    loop {
        let byte = *input.get(pos).ok_or(QpackError::Truncated {
            need: pos + 1,
            got: pos,
        })?;
        pos += 1;
        value += ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, pos));
        }
        shift += 7;
        if shift > 56 {
            return Err(QpackError::Truncated {
                need: pos,
                got: pos,
            });
        }
    }
}

/// `prefix-int` 编码：模式位占首字节高 `8 - prefix_bits` 位。
pub(crate) fn append_prefix_int(value: u64, prefix_bits: u32, pattern: u8, out: &mut Vec<u8>) {
    let mask: u64 = (1 << prefix_bits) - 1;
    if value < mask {
        out.push(pattern | (value as u8));
        return;
    }
    out.push(pattern | (mask as u8));
    let mut rest = value - mask;
    while rest >= 0x80 {
        out.push(((rest as u8) & 0x7f) | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

/// Huffman 解码（RFC 7541 §5.2，码表见 `tables.rs`）。
/// 尾部填充位必须少于 8 位且全为 1；EOS（30 个 1）视为错误。
pub(crate) fn huffman_decode(input: &[u8]) -> Result<Vec<u8>, QpackError> {
    let mut out = Vec::with_capacity(input.len() * 2);
    let mut code = 0u32;
    let mut len = 0u32;
    for &byte in input {
        for i in (0..8).rev() {
            code = (code << 1) | ((byte >> i) & 1) as u32;
            len += 1;
            if let Ok(idx) = HUFFMAN.binary_search_by(|(c, l, _)| (*l as u32, *c).cmp(&(len, code)))
            {
                out.push(HUFFMAN[idx].2);
                code = 0;
                len = 0;
                continue;
            }
            if len == 30 {
                return Err(QpackError::Huffman {
                    reason: "码长达到 30 位仍未匹配（EOS 或非法码）",
                });
            }
        }
    }
    if len >= 8 {
        return Err(QpackError::Huffman {
            reason: "尾部填充位达到或超过 8 位",
        });
    }
    if len > 0 && code != (1 << len) - 1 {
        return Err(QpackError::Huffman {
            reason: "尾部填充位含 0",
        });
    }
    Ok(out)
}

/// 字符串字面量解码：H 位 + 7 位前缀长度 + 字节（或 Huffman 码流）。
pub(crate) fn string_literal(input: &[u8]) -> Result<(Vec<u8>, usize), QpackError> {
    let first = *input
        .first()
        .ok_or(QpackError::Truncated { need: 1, got: 0 })?;
    let huffman = first & 0x80 != 0;
    let (len, mut pos) = prefix_int(input, 7)?;
    let rest = input.len() - pos;
    if len > rest as u64 {
        return Err(QpackError::StringTooLong {
            declared: len,
            rest,
        });
    }
    let raw = &input[pos..pos + len as usize];
    pos += len as usize;
    let value = if huffman {
        huffman_decode(raw)?
    } else {
        raw.to_vec()
    };
    Ok((value, pos))
}
