//! QPACK（RFC 9204）最小完备实现：仅覆盖 Hysteria2 HTTP/3 认证交换所需。
//!
//! 背景：本 crate 无法新增 `http` 依赖（Cargo.toml 由基建卡独占），`h3` crate
//! 的客户端 API 需要 `http::Request` 且其 QPACK 子模块私有，因此认证交换在
//! quinn 流上手写 HTTP/3 帧，头部块由本模块编解码。
//!
//! - 请求侧编码：全部使用「Literal Field Line with Literal Name」（001 模式，
//!   明文不 Huffman），Required Insert Count=0、Base=0，任何合规解码器可解。
//! - 响应侧解码：完整实现 RFC 9204 字段区块解码（Indexed / Post-Base /
//!   Literal 各模式、动态表、RIC 回绕、Huffman 解码），并消费 encoder 流指令
//!   （SetCapacity / Insert / Duplicate）建表，能解 quic-go/qpack 的任意合规输出。
//! - decoder 流反馈：提供 Section Acknowledgment 与 Insert Count Increment 的
//!   编码，调用方在解完一个区块后发送，避免对端因驱逐阻塞。
//!
//! Huffman 码表与静态表见 `tables.rs`（生成文件，含出处说明）。

mod tables;

use std::collections::VecDeque;
use tables::{HUFFMAN, STATIC_TABLE};

/// QPACK 解码错误。一律 fail-closed：错误后必须重置整条连接的 QPACK 状态。
#[derive(Debug, thiserror::Error)]
pub enum QpackError {
    #[error("输入不足：至少需要 {need} 字节，实际 {got}")]
    Truncated { need: usize, got: usize },
    #[error("Huffman 解码失败：{reason}")]
    Huffman { reason: &'static str },
    #[error("字段区块前缀非法：Required Insert Count 解出 {required}，超出已知插入计数 {known}")]
    InsertCount { required: u64, known: u64 },
    #[error("Base 为负：RIC={ric}，delta={delta}")]
    InvalidBase { ric: u64, delta: u64 },
    #[error("动态表索引越界：绝对索引 {abs}，插入计数 {count}")]
    DynamicIndex { abs: u64, count: u64 },
    #[error("静态表索引越界：{index}（表长 {len}）")]
    StaticIndex { index: u64, len: usize },
    #[error("字符串长度超过剩余字节：声明 {declared}，剩余 {rest}")]
    StringTooLong { declared: u64, rest: usize },
    #[error("动态表容量非法：{capacity}")]
    CapacityInvalid { capacity: u64 },
    #[error("条目大小 {size} 超过动态表容量 {capacity}，编码器违规")]
    EntryTooLarge { size: usize, capacity: usize },
    #[error("未知指令或字段模式：首字节 {byte:#04x}")]
    UnknownPattern { byte: u8 },
}

/// `prefix-int` 解码（RFC 7541 §5.1，QPACK 沿用）。
/// 返回（值，消耗字节数）；`prefix_bits` 为 1..=8。
fn prefix_int(input: &[u8], prefix_bits: u32) -> Result<(u64, usize), QpackError> {
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
fn append_prefix_int(value: u64, prefix_bits: u32, pattern: u8, out: &mut Vec<u8>) {
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
fn huffman_decode(input: &[u8]) -> Result<Vec<u8>, QpackError> {
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
fn string_literal(input: &[u8]) -> Result<(Vec<u8>, usize), QpackError> {
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

/// 头部字段（名字节、值字节；不假设 UTF-8，比较用字节序）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderField {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl HeaderField {
    fn size(&self) -> usize {
        self.name.len() + self.value.len() + 32
    }
}

struct DynEntry {
    field: HeaderField,
    /// 绝对索引（对每次插入 +1）。
    abs: u64,
}

/// 动态表（RFC 9204 §3.2），FIFO 驱逐，最新条目在前。
#[derive(Default)]
struct DynamicTable {
    entries: VecDeque<DynEntry>,
    size: usize,
    capacity: u64,
    insert_count: u64,
}

impl DynamicTable {
    fn set_capacity(&mut self, capacity: u64) -> Result<(), QpackError> {
        if capacity > (1 << 30) - 1 {
            return Err(QpackError::CapacityInvalid { capacity });
        }
        self.capacity = capacity;
        while self.size > self.capacity as usize {
            let entry = self
                .entries
                .pop_back()
                .ok_or(QpackError::CapacityInvalid { capacity })?;
            self.size -= entry.field.size();
        }
        Ok(())
    }

    fn insert(&mut self, field: HeaderField) -> Result<(), QpackError> {
        let size = field.size();
        if size > self.capacity as usize {
            // RFC 9204 §4.3：超过容量的条目编码器不得插入，收到即解码失败。
            return Err(QpackError::EntryTooLarge {
                size,
                capacity: self.capacity as usize,
            });
        }
        while self.size + size > self.capacity as usize {
            let evicted = self.entries.pop_back().ok_or(QpackError::EntryTooLarge {
                size,
                capacity: self.capacity as usize,
            })?;
            self.size -= evicted.field.size();
        }
        let abs = self.insert_count;
        self.insert_count += 1;
        self.entries.push_front(DynEntry { field, abs });
        self.size += size;
        Ok(())
    }

    /// 按绝对索引取条目；被驱逐或未插入过的索引都是错误。
    fn get(&self, abs: u64) -> Result<&HeaderField, QpackError> {
        self.entries
            .iter()
            .find(|e| e.abs == abs)
            .map(|e| &e.field)
            .ok_or(QpackError::DynamicIndex {
                abs,
                count: self.insert_count,
            })
    }

    /// 相对索引（相对 total insert count，encoder 流指令用）→ 绝对索引。
    fn rel_to_abs(&self, rel: u64) -> Result<u64, QpackError> {
        self.insert_count
            .checked_sub(1)
            .and_then(|c| c.checked_sub(rel))
            .ok_or(QpackError::DynamicIndex {
                abs: u64::MAX,
                count: self.insert_count,
            })
    }
}

/// 请求侧字段区块编码：RIC=0、Base=0，全部字段用 001（literal-literal）模式。
/// 伪头部必须排最前（RFC 9114 §4.1），由调用方保证顺序。
pub fn encode_field_block(headers: &[HeaderField]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(0); // Required Insert Count = 0（8 位前缀）
    out.push(0); // S=0，Delta Base = 0（7 位前缀）
    for h in headers {
        // 001 N=0 H=0 + 名字长度（3 位前缀）
        append_prefix_int(h.name.len() as u64, 3, 0b0010_0000, &mut out);
        out.extend_from_slice(&h.name);
        // 值：H=0 + 7 位前缀长度
        append_prefix_int(h.value.len() as u64, 7, 0, &mut out);
        out.extend_from_slice(&h.value);
    }
    out
}

/// QPACK 连接级解码器：动态表 + encoder 流指令状态。
#[derive(Default)]
pub struct Decoder {
    dyn_table: DynamicTable,
}

impl Decoder {
    /// 处理一段 encoder 流字节（可含多条指令），返回消耗长度。
    /// 指令（RFC 9204 §4.3）：Insert NameRef(1T)、Insert Literal(01)、
    /// Duplicate(000)、SetCapacity(001)。
    ///
    /// 尾部不完整的指令（网络分块边界）不算错误：返回已消费的前缀长度，
    /// 调用方保留未消费尾部、读入更多字节后从原偏移重试。真正的解析错误
    /// （未知模式、索引越界、容量非法）仍然 fail-closed。
    pub fn apply_encoder_stream(&mut self, input: &[u8]) -> Result<usize, QpackError> {
        let mut pos = 0usize;
        while pos < input.len() {
            match self.apply_one_encoder_instruction(&input[pos..]) {
                Ok(Some(consumed)) => pos += consumed,
                Ok(None) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(pos)
    }

    /// 解析一条 encoder 流指令。`Ok(None)` 表示输入在指令中间截断。
    fn apply_one_encoder_instruction(&mut self, input: &[u8]) -> Result<Option<usize>, QpackError> {
        macro_rules! try_incomplete {
            ($e:expr) => {
                match $e {
                    Ok(v) => v,
                    Err(QpackError::Truncated { .. }) | Err(QpackError::StringTooLong { .. }) => {
                        return Ok(None)
                    }
                    Err(e) => return Err(e),
                }
            };
        }
        let first = input[0];
        let (field, consumed) = if first & 0b1000_0000 != 0 {
            // 4.3.2 Insert With Name Reference：1T + u6 名字索引 + 值字符串
            let t_static = first & 0b0100_0000 != 0;
            let (index, n1) = try_incomplete!(prefix_int(input, 6));
            let (value, n2) = try_incomplete!(string_literal(&input[n1..]));
            let name = if t_static {
                static_lookup(index)?.0.to_vec()
            } else {
                self.dyn_table
                    .get(self.dyn_table.rel_to_abs(index)?)?
                    .name
                    .clone()
            };
            (Some(HeaderField { name, value }), n1 + n2)
        } else if first & 0b0100_0000 != 0 {
            // 4.3.3 Insert With Literal Name：01H + u5 名字长度 + 名字 + 值
            let huffman = first & 0b0010_0000 != 0;
            let (len, n1) = try_incomplete!(prefix_int(input, 5));
            let name_end = n1 + len as usize;
            if name_end > input.len() {
                return Ok(None);
            }
            let raw = &input[n1..name_end];
            let name = if huffman {
                huffman_decode(raw)?
            } else {
                raw.to_vec()
            };
            let (value, n2) = try_incomplete!(string_literal(&input[name_end..]));
            (Some(HeaderField { name, value }), name_end + n2)
        } else if first & 0b1110_0000 == 0 {
            // 4.3.4 Duplicate：000 + u5 相对索引
            let (rel, n) = try_incomplete!(prefix_int(input, 5));
            let field = self.dyn_table.get(self.dyn_table.rel_to_abs(rel)?)?.clone();
            (Some(field), n)
        } else if first & 0b0010_0000 != 0 {
            // 4.3.1 Set Dynamic Table Capacity：001 + u5
            let (cap, n) = try_incomplete!(prefix_int(input, 5));
            self.dyn_table.set_capacity(cap)?;
            (None, n)
        } else {
            return Err(QpackError::UnknownPattern { byte: first });
        };
        if let Some(f) = field {
            self.dyn_table.insert(f)?;
        }
        Ok(Some(consumed))
    }

    /// 解码一个字段区块（RFC 9204 §4.5），返回字段列表。
    /// RIC 按 RFC 9204 §4.5.1.1 相对 `2*max_entries` 回绕解出。
    pub fn decode_field_section(&mut self, block: &[u8]) -> Result<Vec<HeaderField>, QpackError> {
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

        let total = self.dyn_table.insert_count;
        let required = if encoded_ric == 0 {
            0
        } else {
            if self.dyn_table.capacity == 0 {
                return Err(QpackError::InsertCount {
                    required: encoded_ric,
                    known: total,
                });
            }
            let max_entries = self.dyn_table.capacity / 32;
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

        let mut out = Vec::new();
        while pos < block.len() {
            let first = block[pos];
            let rest = &block[pos..];
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
                    let f = self.dyn_table.get(abs)?.clone();
                    (f.name, f.value)
                };
                (HeaderField { name, value }, n)
            } else if first & 0b1111_0000 == 0b0001_0000 {
                // 4.5.3 Indexed With Post-Base：0001 + u4（abs = base + idx）
                let (index, n) = prefix_int(rest, 4)?;
                let f = self.dyn_table.get(base + index)?.clone();
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
                    self.dyn_table.get(abs)?.name.clone()
                };
                (HeaderField { name, value }, n1 + n2)
            } else if first & 0b1111_0000 == 0 {
                // 4.5.5 Literal With Post-Base Name Reference：0000N + u3（abs = base + idx）
                let (index, n1) = prefix_int(rest, 3)?;
                let (value, n2) = string_literal(&rest[n1..])?;
                let name = self.dyn_table.get(base + index)?.name.clone();
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
            pos += consumed;
        }
        Ok(out)
    }

    /// 当前已知插入计数（用于 Insert Count Increment）。
    pub fn insert_count(&self) -> u64 {
        self.dyn_table.insert_count
    }
}

fn static_lookup(index: u64) -> Result<(&'static [u8], &'static [u8]), QpackError> {
    let (n, v) = STATIC_TABLE
        .get(index as usize)
        .ok_or(QpackError::StaticIndex {
            index,
            len: STATIC_TABLE.len(),
        })?;
    Ok((*n, *v))
}

/// decoder 流：Section Acknowledgment（模式位 1 + u7 流号）。
pub fn append_section_acknowledgment(stream_id: u64, out: &mut Vec<u8>) {
    append_prefix_int(stream_id, 7, 0x80, out);
}

/// decoder 流：Insert Count Increment（模式位 00 + u6）。
pub fn append_insert_count_increment(count: u64, out: &mut Vec<u8>) {
    append_prefix_int(count, 6, 0x00, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hf(name: &str, value: &str) -> HeaderField {
        HeaderField {
            name: name.as_bytes().to_vec(),
            value: value.as_bytes().to_vec(),
        }
    }

    #[test]
    fn prefix_int_roundtrip_boundaries() {
        for &(bits, pattern, val) in &[
            (3u32, 0b0010_0000u8, 6u64),
            (3, 0b0010_0000, 7), // 前缀打满，进入续字节
            (7, 0x00, 126),
            (7, 0x00, 1000),
            (6, 0x80, 63),
            (5, 0b0010_0000, 4000),
        ] {
            let mut buf = Vec::new();
            append_prefix_int(val, bits, pattern, &mut buf);
            assert_eq!(
                buf[0] & !((1 << bits) - 1) as u8,
                pattern & !((1 << bits) - 1) as u8
            );
            let (decoded, used) = prefix_int(&buf, bits).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(used, buf.len());
        }
    }

    #[test]
    fn huffman_known_symbols() {
        // RFC 7541 附录 B：'0'=0/5、'1'=0x1/5、'a'=0x3/5、' '=0x14/6。
        // 码流 "00000"+"00001"+"00011"+"010100" 共 21 位，补 3 个 1：
        // 00000000 01000110 10100111 = 00 46 a7。
        let decoded = huffman_decode(&[0x00, 0x46, 0xa7]).unwrap();
        assert_eq!(decoded, b"01a ".to_vec());
    }

    #[test]
    fn huffman_rejects_bad_padding() {
        assert!(huffman_decode(&[0x00]).is_err()); // 8 位零填充
        assert!(huffman_decode(&[0xff, 0xff, 0xff, 0xff]).is_err()); // 命中 EOS
    }

    #[test]
    fn literal_block_roundtrip() {
        let headers = vec![
            hf(":method", "POST"),
            hf(":scheme", "https"),
            hf(":authority", "hysteria"),
            hf(":path", "/auth"),
            hf("hysteria-auth", "secret-value"),
        ];
        let block = encode_field_block(&headers);
        let mut dec = Decoder::default();
        let decoded = dec.decode_field_section(&block).unwrap();
        assert_eq!(decoded, headers);
    }

    #[test]
    fn decodes_static_indexed_and_dynamic_entries() {
        // encoder 流：SetCapacity(0x100) + Insert With Literal Name（pong/pang，01 模式）
        let mut enc = Vec::new();
        append_prefix_int(0x100, 5, 0b0010_0000, &mut enc);
        append_prefix_int(4, 5, 0b0100_0000, &mut enc);
        enc.extend_from_slice(b"pong");
        append_prefix_int(4, 7, 0x00, &mut enc);
        enc.extend_from_slice(b"pang");

        let mut dec = Decoder::default();
        let consumed = dec.apply_encoder_stream(&enc).unwrap();
        assert_eq!(consumed, enc.len());
        assert_eq!(dec.insert_count(), 1);

        // 区块：required=1 → enc = 1%16+1 = 2（k=8）、S=0 delta=0 → base=1。
        // 字段 1：indexed static 17（:method GET）→ 0xC0|17 = 0xd1。
        // 字段 2：indexed dynamic rel=0 → abs = base-1-0 = 0 → pong/pang → 0x80|0 = 0x80。
        let block = vec![0x02, 0x00, 0xd1, 0x80];
        let fields = dec.decode_field_section(&block).unwrap();
        assert_eq!(fields[0], hf(":method", "GET"));
        assert_eq!(fields[1], hf("pong", "pang"));
    }

    #[test]
    fn post_base_index_resolves() {
        // 插入两条后，base 取 2（RIC=2、S=0、delta=0），post-base idx=0 → abs=2。
        let mut enc = Vec::new();
        append_prefix_int(0x100, 5, 0b0010_0000, &mut enc);
        for name in ["aa", "bb"] {
            append_prefix_int(name.len() as u64, 5, 0b0100_0000, &mut enc);
            enc.extend_from_slice(name.as_bytes());
            append_prefix_int(1, 7, 0x00, &mut enc);
            enc.push(b'v');
        }
        let mut dec = Decoder::default();
        dec.apply_encoder_stream(&enc).unwrap();
        // 区块：required=2 → enc = 2%16+1 = 3；S=1 delta=0 → base = 2-0-1 = 1；
        // post-base idx=0 → abs = base+0 = 1（后插入的 bb/v）。
        let block = vec![0x03, 0x80, 0x10];
        let fields = dec.decode_field_section(&block).unwrap();
        assert_eq!(fields, vec![hf("bb", "v")]);
    }

    #[test]
    fn ric_beyond_known_fails() {
        let mut dec = Decoder::default();
        assert!(matches!(
            dec.decode_field_section(&[0x01, 0x00]),
            Err(QpackError::InsertCount { .. })
        ));
    }

    #[test]
    fn decoder_stream_feedback_encoding() {
        let mut out = Vec::new();
        append_section_acknowledgment(0, &mut out);
        assert_eq!(out, vec![0x80]);
        out.clear();
        append_section_acknowledgment(5, &mut out);
        assert_eq!(out, vec![0x85]);
        out.clear();
        append_insert_count_increment(3, &mut out);
        assert_eq!(out, vec![0x03]);
    }
}
