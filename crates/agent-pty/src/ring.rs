//! 每会话历史回滚缓冲：字节环形，上限 [`HISTORY_BYTES`]（1 MiB）。
//!
//! 语义取舍：环形按**字节**截断，可能从转义序列中间切开。这里不尝试对齐到
//! ANSI 序列边界——重开 UI 回放历史时，前端终端仿真器（xterm.js 等）对
//! 半截序列本身有容错；而对齐需要引入解析器，收益不抵复杂度。
//! 截断只丢弃**最旧**字节，最近输出始终完整保留（回滚缓冲的产品意图）。

/// 历史缓冲上限：1 MiB（规格冻结值）。
pub const HISTORY_BYTES: usize = 1024 * 1024;

/// 定长环形字节缓冲；写入超过容量时覆盖最旧数据。
#[derive(Debug, Clone)]
pub(crate) struct ByteRing {
    buf: Vec<u8>,
    /// 写入位置（始终 `< capacity`）。
    head: usize,
    /// 已写入总字节数（用于判断是否已绕回）。
    written: usize,
    capacity: usize,
}

impl ByteRing {
    fn new(capacity: usize) -> Self {
        Self {
            buf: vec![0; capacity],
            head: 0,
            written: 0,
            capacity,
        }
    }

    /// 新建默认容量的历史缓冲。
    pub(crate) fn with_default_capacity() -> Self {
        Self::new(HISTORY_BYTES)
    }

    pub(crate) fn push(&mut self, data: &[u8]) {
        if self.capacity == 0 {
            return;
        }
        // 单次写入超过容量：只保留尾部（最新的 capacity 字节）。
        let mut src = data;
        if src.len() >= self.capacity {
            src = &src[src.len() - self.capacity..];
            self.buf.copy_from_slice(src);
            self.head = 0;
            self.written = self.capacity;
            return;
        }
        let first = (self.capacity - self.head).min(src.len());
        self.buf[self.head..self.head + first].copy_from_slice(&src[..first]);
        if first < src.len() {
            self.buf[..src.len() - first].copy_from_slice(&src[first..]);
        }
        self.head = (self.head + src.len()) % self.capacity;
        self.written += src.len();
    }

    /// 当前缓冲内容，按时间顺序（最旧 → 最新）。
    pub(crate) fn snapshot(&self) -> Vec<u8> {
        let len = self.written.min(self.capacity);
        if len == 0 {
            return Vec::new();
        }
        if self.written < self.capacity {
            // 尚未绕回：有效数据是 [0, head)。
            return self.buf[..self.head].to_vec();
        }
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(&self.buf[self.head..]);
        out.extend_from_slice(&self.buf[..self.head]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_returns_in_time_order_before_wrap() {
        let mut r = ByteRing::new(8);
        r.push(b"abc");
        r.push(b"de");
        assert_eq!(r.snapshot(), b"abcde".to_vec());
        assert_eq!(r.snapshot().len(), 5);
    }

    #[test]
    fn snapshot_returns_in_time_order_after_wrap() {
        let mut r = ByteRing::new(8);
        r.push(b"12345678");
        r.push(b"AB");
        assert_eq!(r.snapshot(), b"345678AB".to_vec());
        assert_eq!(r.snapshot().len(), 8);
    }

    #[test]
    fn oversized_write_keeps_newest_tail() {
        let mut r = ByteRing::new(4);
        r.push(b"abcdefghij");
        // 一次写入超容量：只留最新的 4 字节，head 归零。
        assert_eq!(r.snapshot(), b"ghij".to_vec());
        assert_eq!(r.snapshot().len(), 4);
        r.push(b"XY");
        assert_eq!(r.snapshot(), b"ijXY".to_vec());
    }

    #[test]
    fn exact_capacity_and_empty() {
        let mut r = ByteRing::new(4);
        assert!(r.snapshot().is_empty());
        r.push(b"abcd");
        assert_eq!(r.snapshot(), b"abcd".to_vec());
        r.push(b"");
        assert_eq!(r.snapshot(), b"abcd".to_vec());
    }

    #[test]
    fn split_across_boundary_is_stitched() {
        let mut r = ByteRing::new(8);
        r.push(b"123456");
        r.push(b"789");
        // 共写入 9 字节 > 容量 8：最旧的 "1" 被覆盖，顺序仍为时间序。
        assert_eq!(r.snapshot(), b"23456789".to_vec());
    }

    #[test]
    fn default_capacity_is_one_mebibyte() {
        assert_eq!(HISTORY_BYTES, 1024 * 1024);
        let mut r = ByteRing::with_default_capacity();
        let chunk = vec![b'x'; 64 * 1024];
        for _ in 0..40 {
            r.push(&chunk);
        }
        assert_eq!(r.snapshot().len(), HISTORY_BYTES, "历史不得无界增长");
        assert_eq!(r.snapshot().len(), HISTORY_BYTES);
    }
}
