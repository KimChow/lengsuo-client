//! 请求侧字段区块编码与 **decoder 流反馈**编码。

use super::header::HeaderField;
use super::primitives::append_prefix_int;

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

/// decoder 流：Section Acknowledgment（模式位 1 + u7 流号）。
pub fn append_section_acknowledgment(stream_id: u64, out: &mut Vec<u8>) {
    append_prefix_int(stream_id, 7, 0x80, out);
}

/// decoder 流：Insert Count Increment（模式位 00 + u6）。
pub fn append_insert_count_increment(count: u64, out: &mut Vec<u8>) {
    append_prefix_int(count, 6, 0x00, out);
}
