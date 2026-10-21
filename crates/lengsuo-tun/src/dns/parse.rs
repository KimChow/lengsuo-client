//! DNS 报文的结构化解析：头部校验、问题区名字读取与后续区跳过。

use super::header::{Header, Question, QuestionName};
use super::name::MAX_NAME;

/// DNS 头部固定 12 字节。
const HEADER: usize = 12;
/// 单个标签的字节上限（RFC 1035 3.3.1，6 位长度字段）。
const MAX_LABEL: usize = 63;
/// 标签数上限：每个标签至少占 2 字节（长度八位组 + 1 字节内容），结尾零已计入
/// [`MAX_NAME`]，因此 1 + 127 × 2 = 255。存在它是为了让任何畸形输入都在有限
/// 步数内结束，而不是宽松放行。
const MAX_LABELS: usize = 127;
/// 单个名字里允许的指针跳转次数上限：合法报文远达不到，存在它只为给指针环
/// 一个硬性上界。
const MAX_POINTER_HOPS: usize = 32;
/// 标签长度字段的低 6 位掩码。
const LABEL_MASK: u8 = 0x3f;
/// 压缩指针标签的两位前缀（11）与偏移掩码。
const POINTER_MASK: u16 = 0x3fff;

/// DNS 解析的全部失败种类。调用方一律丢弃报文并记录原因，不得回退为放行。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// 报文短于所需字段，无法安全继续解析。
    #[error("DNS 报文尚未完整")]
    Incomplete,
    /// 问题区计数不是 1：转发决策只处理单查询报文。
    #[error("DNS 问题区计数为 {0}，本层只接受单问题报文")]
    QuestionCount(u16),
    /// 查询报文携带答案、权威或附加记录。
    #[error("查询报文携带 {0} 条后续记录，拒绝转发")]
    UnexpectedRecords(u16),
    /// TC 置位：报文已被截断，内容不完整。
    #[error("DNS 报文 TC 位置位，内容被截断")]
    Truncated,
    /// QR 与期望方向不符。
    #[error("DNS 报文方向与期望不符（QR={0}）")]
    WrongDirection(bool),
    /// opcode 不是 QUERY。
    #[error("不支持的 DNS opcode {0}")]
    UnsupportedOpcode(u8),
    /// 标签长度超过 63 字节。
    #[error("DNS 标签长度超过 {MAX_LABEL} 字节")]
    LabelTooLong,
    /// 名字总长超过 255 字节或标签数超过上限。
    #[error("DNS 名字超过长度或标签数上限")]
    NameTooLong,
    /// 标签前缀为保留的 01/10，或指针目标越界/前向。
    #[error("DNS 标签或指针非法")]
    BadLabel,
    /// 单个名字的指针跳转次数超过 [`MAX_POINTER_HOPS`]。
    #[error("DNS 名字指针跳转次数超过上限")]
    PointerLimit,
}

/// 一条通过结构校验的 DNS 报文：头部 + 唯一一条问题记录。
///
/// 后续区只在校验「结构完整」时被遍历，内容不保留、不解释，因此这里不暴露它们。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub question: Question,
}

/// 解析任意方向的 DNS 报文，不做 QR 方向判定。
pub fn parse(payload: &[u8]) -> Result<Message, Error> {
    parse_inner(payload, None)
}

/// 解析**查询**报文：QR 必须为 0、后续三区必须为空、TC 必须为 0。
pub fn parse_query(payload: &[u8]) -> Result<Message, Error> {
    let message = parse_inner(payload, Some(false))?;
    if message.header.record_count() != 0 {
        return Err(Error::UnexpectedRecords(message.header.record_count()));
    }
    Ok(message)
}

/// 解析**响应**报文：QR 必须为 1、TC 必须为 0；后续区做结构化跳过后被丢弃。
pub fn parse_response(payload: &[u8]) -> Result<Message, Error> {
    parse_inner(payload, Some(true))
}

/// `expect_response` 为 `None` 时不判定 QR；为 `Some` 时方向不符即拒绝。
fn parse_inner(payload: &[u8], expect_response: Option<bool>) -> Result<Message, Error> {
    let header = parse_header(payload)?;
    if Some(header.response) != expect_response {
        return Err(Error::WrongDirection(header.response));
    }
    // opcode 在两个方向上都限定为 QUERY：INVITE/STATUS 等不属于本数据面要
    // 转发的语义，响应携带非 QUERY opcode 同样说明报文不属于任何已登记的查询。
    if header.opcode != super::OPCODE_QUERY {
        return Err(Error::UnsupportedOpcode(header.opcode));
    }
    if header.truncated {
        return Err(Error::Truncated);
    }
    if header.question_count != 1 {
        return Err(Error::QuestionCount(header.question_count));
    }
    let mut cursor = Cursor::new(payload);
    cursor.position = HEADER;
    let name = read_name(&mut cursor, false)?;
    let qtype = cursor.u16()?;
    let qclass = cursor.u16()?;
    skip_records(&mut cursor, header.record_count())?;
    Ok(Message {
        header,
        question: Question {
            name,
            qtype,
            qclass,
        },
    })
}

fn parse_header(payload: &[u8]) -> Result<Header, Error> {
    if payload.len() < HEADER {
        return Err(Error::Incomplete);
    }
    let flags = be16(payload, 2)?;
    Ok(Header {
        id: be16(payload, 0)?,
        response: flags & 0x8000 != 0,
        opcode: (flags >> 11) as u8 & 0x0f,
        authoritative: flags & 0x0400 != 0,
        truncated: flags & 0x0200 != 0,
        recursion_desired: flags & 0x0100 != 0,
        recursion_available: flags & 0x0080 != 0,
        rcode: (flags & 0x000f) as u8,
        question_count: be16(payload, 4)?,
        answer_count: be16(payload, 6)?,
        name_server_count: be16(payload, 8)?,
        additional_count: be16(payload, 10)?,
    })
}

/// 按 counts 逐条跳过资源记录：名字（允许压缩指针）+ 类型/类别/TTL + rdlength 段。
/// 只验证每条记录是否落在报文内，内容一律不解释。
fn skip_records(cursor: &mut Cursor<'_>, count: u16) -> Result<(), Error> {
    for _ in 0..count {
        read_name(cursor, true)?;
        cursor.skip(4)?; // TYPE + CLASS
        cursor.skip(4)?; // TTL
        let length = usize::from(cursor.u16()?);
        cursor.skip(length)?;
    }
    Ok(())
}

/// 读取一个名字并返回未压缩形式。`allow_pointer` 为 false 时任何指针前缀都拒绝。
///
/// 指针语义按 RFC 1035 4.1.4：指针之后的字节属于**原位置**的记录剩余字段，因此
/// 名字结束后游标回到指针两字节之后（`resume`）。指针目标必须严格靠前且不早于
/// 头部之后，这条单调递减保证指针链有限收敛，加上 [`MAX_POINTER_HOPS`] 双保险。
fn read_name(cursor: &mut Cursor<'_>, allow_pointer: bool) -> Result<QuestionName, Error> {
    let mut name = QuestionName {
        bytes: [0u8; MAX_NAME],
        len: 0,
    };
    let mut labels = 0usize;
    let mut hops = 0usize;
    let mut resume = None;
    loop {
        let prefix = cursor.byte()?;
        match prefix >> 6 {
            0b11 if allow_pointer => {
                let target = usize::from(be16(cursor.raw(2)?, 0)? & POINTER_MASK);
                if target < HEADER || target >= cursor.position {
                    return Err(Error::BadLabel);
                }
                hops += 1;
                if hops > MAX_POINTER_HOPS {
                    return Err(Error::PointerLimit);
                }
                // 只在第一个指针处记录续读位置：指针后的名字尾部共享，记录剩余
                // 字段仍从首个指针之后继续。
                if resume.is_none() {
                    let after = cursor.position.checked_add(2).ok_or(Error::Incomplete)?;
                    resume = Some(after);
                }
                cursor.position = target;
            }
            0b00 => {
                cursor.take(1)?; // 消费标签长度或根名字零八位组。
                let length = usize::from(prefix & LABEL_MASK);
                if length > MAX_LABEL {
                    return Err(Error::LabelTooLong);
                }
                labels += 1;
                if labels > MAX_LABELS {
                    return Err(Error::NameTooLong);
                }
                if length == 0 {
                    name.bytes[name.len] = 0;
                    name.len += 1;
                    if let Some(at) = resume {
                        cursor.position = at;
                    }
                    return Ok(name);
                }
                // 总长必须容得下本标签的长度八位组、内容与结尾零。
                let needed = name
                    .len
                    .checked_add(length + 1 + 1)
                    .ok_or(Error::NameTooLong)?;
                if needed > MAX_NAME {
                    return Err(Error::NameTooLong);
                }
                let bytes = cursor.take(length)?;
                name.bytes[name.len] = length as u8;
                name.bytes[name.len + 1..name.len + length + 1].copy_from_slice(bytes);
                name.len += length + 1;
            }
            _ => return Err(Error::BadLabel),
        }
    }
}

/// 报文游标：所有读取都经 `get` 带检查完成，越界即 [`Error::Incomplete`]。
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// 前瞻一个字节但不移动游标（标签前缀）。
    fn byte(&self) -> Result<u8, Error> {
        Ok(self.range(self.position, 1)?[0])
    }

    /// 前瞻 `len` 字节的原始视图，用于拆指针字段。
    fn raw(&self, len: usize) -> Result<&'a [u8], Error> {
        self.range(self.position, len)
    }

    /// 读取 `len` 字节并前进游标。
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let bytes = self.range(self.position, len)?;
        self.position = self.position.checked_add(len).ok_or(Error::Incomplete)?;
        Ok(bytes)
    }

    fn skip(&mut self, len: usize) -> Result<(), Error> {
        self.take(len).map(|_| ())
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let pair = self.take(2)?;
        Ok(u16::from_be_bytes([pair[0], pair[1]]))
    }

    fn range(&self, start: usize, len: usize) -> Result<&'a [u8], Error> {
        let end = start.checked_add(len).ok_or(Error::Incomplete)?;
        self.bytes.get(start..end).ok_or(Error::Incomplete)
    }
}

fn be16(bytes: &[u8], at: usize) -> Result<u16, Error> {
    let pair = bytes
        .get(at..at.checked_add(2).ok_or(Error::Incomplete)?)
        .ok_or(Error::Incomplete)?;
    Ok(u16::from_be_bytes([pair[0], pair[1]]))
}
