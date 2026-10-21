//! DNS 头部、问题区记录与已解码名字。

use super::name::MAX_NAME;

/// [`QuestionName::labels`] 的返回类型。
pub struct Labels<'a> {
    name: &'a QuestionName,
    at: usize,
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let length = usize::from(*self.name.bytes.get(self.at)?);
        if length == 0 {
            return None;
        }
        let start = self.at + 1;
        self.at = start + length;
        Some(&self.name.bytes[start..self.at])
    }
}

/// 头部字段，逐位取自 RFC 1035 4.1.1。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// 查询标识，响应必须原样匹配。
    pub id: u16,
    /// QR：1 表示响应。
    pub response: bool,
    /// 4 位 opcode，本层只接受 QUERY。
    pub opcode: u8,
    /// AA，仅记录，不参与决策。
    pub authoritative: bool,
    /// TC：报文被截断。
    pub truncated: bool,
    /// RD。
    pub recursion_desired: bool,
    /// RA。
    pub recursion_available: bool,
    /// 4 位 RCODE（含扩展 0），仅记录，不代表内容可信。
    pub rcode: u8,
    pub question_count: u16,
    pub answer_count: u16,
    pub name_server_count: u16,
    pub additional_count: u16,
}

impl Header {
    /// 后续三区记录总数。查询报文必须为零。
    pub fn record_count(&self) -> u16 {
        self.answer_count
            .saturating_add(self.name_server_count)
            .saturating_add(self.additional_count)
    }
}

/// 问题区的一条记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: QuestionName,
    pub qtype: u16,
    pub qclass: u16,
}

/// 已解码的名字，以未压缩的线上格式（长度八位组 + 标签内容 + 结尾零）存放。
///
/// 定长数组避免数据面为每条查询堆分配；`PartialEq` 按字节比较，因此跨大小写
/// 相等必须用 [`QuestionName::matches`]（DNS 名字按不区分大小写处理，RFC 1035 2.3.1）。
#[derive(Clone)]
pub struct QuestionName {
    pub(super) bytes: [u8; MAX_NAME],
    pub(super) len: usize,
}

impl PartialEq for QuestionName {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for QuestionName {}

impl core::fmt::Debug for QuestionName {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 只输出点分形式，不打印原始字节，避免把内容写进日志。
        formatter
            .debug_struct("QuestionName")
            .field("name", &self.to_text())
            .finish()
    }
}

impl QuestionName {
    /// 未压缩的线上字节（含结尾零八位组）。
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// 根名字（只有一个零八位组）。
    pub fn is_root(&self) -> bool {
        self.len == 1 && self.bytes[0] == 0
    }

    /// 逐标签比较，ASCII 大小写不敏感（RFC 1035 2.3.1）。
    ///
    /// 只做标签边界比较而不是整串 `eq_ignore_ascii_case`：标签长度字节相同
    /// 但内容不同（如长度字节碰巧等于某个字母）不会被误判为相等。
    pub fn matches(&self, other: &Self) -> bool {
        let mut left = self.labels();
        let mut right = other.labels();
        loop {
            match (left.next(), right.next()) {
                (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => continue,
                (None, None) => return true,
                _ => return false,
            }
        }
    }

    /// 标签迭代器，不含结尾零八位组。
    pub fn labels(&self) -> Labels<'_> {
        Labels { name: self, at: 0 }
    }

    /// 点分形式，用于诊断与测试断言。非可打印字节以 `.` 代替，绝不外泄原始字节。
    pub fn to_text(&self) -> String {
        let mut text = String::new();
        for label in self.labels() {
            if !text.is_empty() {
                text.push('.');
            }
            for byte in label {
                text.push(match byte.is_ascii_graphic() {
                    true => char::from(*byte).to_ascii_lowercase(),
                    false => '.',
                });
            }
        }
        text
    }
}
