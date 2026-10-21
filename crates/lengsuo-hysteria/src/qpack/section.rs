//! 字段区块（Field Section）解码：前缀（RIC / Base）与字段行模式。

use super::decoder::static_lookup;
use super::error::QpackError;
use super::header::HeaderField;
use super::primitives::{huffman_decode, prefix_int, string_literal};

/// 解码字段区块前缀：RIC（8 位前缀）+ S 位 + Delta Base（7 位前缀）。
///
/// 返回（Base 绝对索引基准，前缀结束后的字节偏移）。
/// RIC 按 RFC 9204 §4.5.1.1 相对 `2*max_entries` 回绕解出。
pub(super) fn decode_section_prefix(
    block: &[u8],
    insert_count: u64,
    capacity: u64,
) -> Result<(u64, usize), QpackError> {
    let (encoded_ric, mut pos) = prefix_int(block, 8)?;
    // S 位在 7 位前缀整数的模式区（首字节最高位），prefix_int 的返回值
    // 不含它，需从原始字节读取
    let s_raw = *block.get(pos).ok_or(QpackError::Truncated {
        need: pos + 1,
        got: pos,
    })?;
    let (delta, n) = prefix_int(&block[pos..], 7)?;
    pos += n;
    let sign_negative = s_raw & 0x80 != 0;

    let total = insert_count;
    let required = if encoded_ric == 0 {
        0
    } else {
        if capacity == 0 {
            return Err(QpackError::InsertCount {
                required: encoded_ric,
                known: total,
            });
        }
        let max_entries = capacity / 32;
        let mut count = encoded_ric - 1;
        let mut wrapped = total % (2 * max_entries);
        if wrapped >= count + max_entries {
            count += 2 * max_entries;
        } else if wrapped + max_entries < count {
            wrapped += 2 * max_entries;
        }
        let required = count + total - wrapped;
        if required > total {
            return Err(QpackError::InsertCount {
                required,
                known: total,
            });
        }
        required
    };
    let base = if required == 0 {
        0
    } else if sign_negative {
        if delta + 1 > required {
            return Err(QpackError::InvalidBase {
                ric: required,
                delta,
            });
        }
        required - delta - 1
    } else {
        required + delta
    };
    Ok((base, pos))
}

/// 解码一个字段区块（RFC 9204 §4.5），返回字段列表。
pub(super) fn decode_field_lines(
    block: &[u8],
    pos: &mut usize,
    base: u64,
    dyn_table: &super::header::DynamicTable,
) -> Result<Vec<HeaderField>, QpackError> {
    let mut out = Vec::new();
    while *pos < block.len() {
        let first = block[*pos];
        let rest = &block[*pos..];
        let (field, consumed) = if first & 0b1000_0000 != 0 {
            // 4.5.2 Indexed：1T + u6；T=1 静态，T=0 动态相对（abs = base-1-rel）
            let t_static = first & 0b0100_0000 != 0;
            let (index, n) = prefix_int(rest, 6)?;
            let (name, value) = if t_static {
                let (n_, v_) = static_lookup(index)?;
                (n_.to_vec(), v_.to_vec())
            } else {
                let abs = base
                    .checked_sub(1)
                    .and_then(|b| b.checked_sub(index))
                    .ok_or(QpackError::DynamicIndex {
                        abs: u64::MAX,
                        count: base,
                    })?;
                let f = dyn_table.get(abs)?.clone();
                (f.name, f.value)
            };
            (HeaderField { name, value }, n)
        } else if first & 0b1111_0000 == 0b0001_0000 {
            // 4.5.3 Indexed With Post-Base：0001 + u4（abs = base + idx）
            let (index, n) = prefix_int(rest, 4)?;
            let f = dyn_table.get(base + index)?.clone();
            (
                HeaderField {
                    name: f.name,
                    value: f.value,
                },
                n,
            )
        } else if first & 0b1100_0000 == 0b0100_0000 {
            // 4.5.4 Literal With Name Reference：01NT + u4
            let t_static = first & 0b0001_0000 != 0;
            let (index, n1) = prefix_int(rest, 4)?;
            let (value, n2) = string_literal(&rest[n1..])?;
            let name = if t_static {
                static_lookup(index)?.0.to_vec()
            } else {
                let abs = base
                    .checked_sub(1)
                    .and_then(|b| b.checked_sub(index))
                    .ok_or(QpackError::DynamicIndex {
                        abs: u64::MAX,
                        count: base,
                    })?;
                dyn_table.get(abs)?.name.clone()
            };
            (HeaderField { name, value }, n1 + n2)
        } else if first & 0b1111_0000 == 0 {
            // 4.5.5 Literal With Post-Base Name Reference：0000N + u3（abs = base + idx）
            let (index, n1) = prefix_int(rest, 3)?;
            let (value, n2) = string_literal(&rest[n1..])?;
            let name = dyn_table.get(base + index)?.name.clone();
            (HeaderField { name, value }, n1 + n2)
        } else if first & 0b1110_0000 == 0b0010_0000 {
            // 4.5.6 Literal With Literal Name：001NH + u3 名字长度
            let huffman = first & 0b0000_1000 != 0;
            let (len, n1) = prefix_int(rest, 3)?;
            let name_end = n1 + len as usize;
            if name_end > rest.len() {
                return Err(QpackError::StringTooLong {
                    declared: len,
                    rest: rest.len() - n1,
                });
            }
            let raw = &rest[n1..name_end];
            let name = if huffman {
                huffman_decode(raw)?
            } else {
                raw.to_vec()
            };
            let (value, n2) = string_literal(&rest[name_end..])?;
            (HeaderField { name, value }, name_end + n2)
        } else {
            return Err(QpackError::UnknownPattern { byte: first });
        };
        out.push(field);
        *pos += consumed;
    }
    Ok(out)
}
