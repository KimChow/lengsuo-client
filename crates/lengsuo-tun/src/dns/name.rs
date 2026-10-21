//! 名字的线上格式常量。

/// 名字总字节上限，含每个标签的长度八位组与结尾零（RFC 1035 3.3.14）。
pub(super) const MAX_NAME: usize = 255;
