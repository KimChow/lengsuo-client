//! 头部字段与**动态表**（RFC 9204 §3.2，FIFO 驱逐，最新条目在前）。

use std::collections::VecDeque;

use super::error::QpackError;

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
pub(super) struct DynamicTable {
    entries: VecDeque<DynEntry>,
    size: usize,
    capacity: u64,
    insert_count: u64,
}

impl DynamicTable {
    pub(super) fn set_capacity(&mut self, capacity: u64) -> Result<(), QpackError> {
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

    pub(super) fn insert(&mut self, field: HeaderField) -> Result<(), QpackError> {
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
    pub(super) fn get(&self, abs: u64) -> Result<&HeaderField, QpackError> {
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
    pub(super) fn rel_to_abs(&self, rel: u64) -> Result<u64, QpackError> {
        self.insert_count
            .checked_sub(1)
            .and_then(|c| c.checked_sub(rel))
            .ok_or(QpackError::DynamicIndex {
                abs: u64::MAX,
                count: self.insert_count,
            })
    }

    /// 当前已知插入计数。
    pub(super) fn insert_count(&self) -> u64 {
        self.insert_count
    }

    /// 当前动态表容量。
    pub(super) fn capacity(&self) -> u64 {
        self.capacity
    }
}
