//! DNS 报文解析原语（RFC 1035）：头部、问题区与后续资源记录区的结构校验。
//!
//! 纯内存、只读，不改写报文、不发包、不做缓存，也不判断报文该走哪台出口设备。
//! 入参是 UDP 载荷字节（IP/UDP 头部由 [`crate::packet`] 负责），因此本模块只在
//! 「载荷确实是一个结构完整的 DNS 报文」时返回决策层需要的字段。
//!
//! 安全底线（全部 fail-closed，没有任何宽松回退）：
//! - 任何截断、越界、非法标签长度（高位组合不是 `00`/`11`）、超限名字或标签数量
//!   都返回 [`Error`]，调用方必须丢弃报文。
//! - 问题区不接受压缩指针（RFC 1035 3.3.14 只允许出现在后续区），因此问题区的
//!   名字解析是严格线性的，不可能形成指针环。
//! - 后续区（答案/权威/附加）只做**结构化跳过**：按名字（允许合法指针）+ 8 字节
//!   固定字段 + rdlength 推进，逐条核对是否落在报文内；内容一律不被解释，
//!   也不参与任何决策，因此跳过失败只说明报文结构不完整。
//! - 指针跳转次数与指针目标都有显式上限与方向检查（目标必须严格靠前且不小于
//!   头部长度），环与自指无法无限消耗 CPU。
//!
//! 已知范围限制：本模块不验证 UDP 校验和（见 [`crate::checksum`]），不理解任何
//! 资源记录语义（不判断 RCODE 是否代表伪造），也不做 DNSSEC 校验；它提供的是
//! 「能否安全地把这条报文交给转发决策」的结构门槛。

mod header;
mod name;
mod parse;

pub mod rewrite;
pub mod upstream;

pub use header::{Header, Labels, Question, QuestionName};
pub use parse::{parse, parse_query, parse_response, Error, Message};

/// UDP DNS 的约定端口：转发决策只接受落在该端口上的流。
pub const DNS_PORT: u16 = 53;
/// 查询报文的 opcode 上限：本模块只接受 QUERY(0)。
pub const OPCODE_QUERY: u8 = 0;
/// 类型 A。
pub const TYPE_A: u16 = 1;
/// 类型 AAAA。
pub const TYPE_AAAA: u16 = 28;
/// 类别 IN。
pub const CLASS_IN: u16 = 1;
