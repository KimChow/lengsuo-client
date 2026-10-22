//! 非法帧的向量回放：五类失败条件各有独立向量。
//!
//! | 失败条件 | 向量 |
//! |---|---|
//! | `len` 超 1 MiB | `IL_LEN_OVER_LIMIT` / `IL_LEN_OVER_LIMIT_HUGE` |
//! | `reserved` 非 0 | `IL_RESERVED_0` / `_1` / `_2` / `_ALL`（三个位置各一条） |
//! | `type` 未知 | `IL_TYPE_11` / `IL_TYPE_255` |
//! | 帧头被截断 | `IL_HEADER_TRUNCATED_0` / `_1` / `_4` / `_7` |
//! | 载荷被截断 | `IL_PAYLOAD_TRUNCATED` / `_EMPTY` / `_AT_LIMIT` |
//! | 多余字节（`decode_exact`） | `IL_TRAILING_BYTES` |

use crate::support::assert_illegal;

#[test]
fn illegal_len_over_limit() {
    assert_illegal("IL_LEN_OVER_LIMIT");
}

#[test]
fn illegal_len_over_limit_huge() {
    assert_illegal("IL_LEN_OVER_LIMIT_HUGE");
}

#[test]
fn illegal_reserved_byte_0() {
    assert_illegal("IL_RESERVED_0");
}

#[test]
fn illegal_reserved_byte_1() {
    assert_illegal("IL_RESERVED_1");
}

#[test]
fn illegal_reserved_byte_2() {
    assert_illegal("IL_RESERVED_2");
}

#[test]
fn illegal_reserved_all_bytes() {
    assert_illegal("IL_RESERVED_ALL");
}

#[test]
fn illegal_type_11() {
    assert_illegal("IL_TYPE_11");
}

#[test]
fn illegal_type_255() {
    assert_illegal("IL_TYPE_255");
}

#[test]
fn illegal_header_truncated_to_0_bytes() {
    assert_illegal("IL_HEADER_TRUNCATED_0");
}

#[test]
fn illegal_header_truncated_to_1_byte() {
    assert_illegal("IL_HEADER_TRUNCATED_1");
}

#[test]
fn illegal_header_truncated_to_4_bytes() {
    assert_illegal("IL_HEADER_TRUNCATED_4");
}

#[test]
fn illegal_header_truncated_to_7_bytes() {
    assert_illegal("IL_HEADER_TRUNCATED_7");
}

#[test]
fn illegal_payload_truncated() {
    assert_illegal("IL_PAYLOAD_TRUNCATED");
}

#[test]
fn illegal_payload_truncated_empty() {
    assert_illegal("IL_PAYLOAD_TRUNCATED_EMPTY");
}

#[test]
fn illegal_payload_truncated_at_limit() {
    assert_illegal("IL_PAYLOAD_TRUNCATED_AT_LIMIT");
}

#[test]
fn illegal_trailing_bytes() {
    assert_illegal("IL_TRAILING_BYTES");
}
