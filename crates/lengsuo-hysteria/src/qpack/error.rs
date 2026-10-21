//! QPACK 解码错误。一律 fail-closed：错误后必须重置整条连接的 QPACK 状态。

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
