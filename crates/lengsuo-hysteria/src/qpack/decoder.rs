//! QPACK 连接级解码器：动态表 + encoder 流指令状态。

use super::error::QpackError;
use super::header::{DynamicTable, HeaderField};
use super::primitives::{huffman_decode, prefix_int, string_literal};
use super::section::{decode_field_lines, decode_section_prefix};
use super::tables::STATIC_TABLE;

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

    /// 当前已知插入计数（用于 Insert Count Increment）。
    pub fn insert_count(&self) -> u64 {
        self.dyn_table.insert_count()
    }

    /// 解码一个字段区块（RFC 9204 §4.5），返回字段列表。
    /// RIC 按 RFC 9204 §4.5.1.1 相对 `2*max_entries` 回绕解出。
    pub fn decode_field_section(&mut self, block: &[u8]) -> Result<Vec<HeaderField>, QpackError> {
        let dyn_table = &self.dyn_table;
        let (base, mut pos) =
            decode_section_prefix(block, dyn_table.insert_count(), dyn_table.capacity())?;
        decode_field_lines(block, &mut pos, base, dyn_table)
    }
}

/// 静态表查表（RFC 9204 附录 A）。
pub(super) fn static_lookup(index: u64) -> Result<(&'static [u8], &'static [u8]), QpackError> {
    let (n, v) = STATIC_TABLE
        .get(index as usize)
        .ok_or(QpackError::StaticIndex {
            index,
            len: STATIC_TABLE.len(),
        })?;
    Ok((*n, *v))
}
