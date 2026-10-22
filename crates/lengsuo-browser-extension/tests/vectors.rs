//! ⭐ 固定测试向量回放：**跨仓字节一致性的唯一防漂移手段**。
//!
//! `tests/vectors/credential-wire-v1.json` 是扩展仓 / 客户端仓 / 服务端仓
//! 共享的**同一份**字节定义 ⇒ 字段名用英文、语义自解释。
//!
//! 本套件**只做「实现 ⇒ 与 JSON 字面量逐字节比对」**：
//! JSON 里的每个 hex 都是**独立算出的期望值**（照契约 §5.2 手工推导），
//! ⛔ 绝不是「先编码再解码回来相等」那种自家往返。
//!
//! # 组织方式
//!
//! 原单文件 514 行，按**主题**拆成本目录下的三个子模块：
//! - [`support`]：共享夹具（读向量文件、按名字取条目、逐条断言）。
//! - [`legal`]：合法帧回放（边界长度 5 条 + 11 种消息类型各 1 条）。
//! - [`illegal`]：非法帧回放（五类失败条件 + 多余字节）。
//!
//! 结构性常量与跨仓对照的用例留在本文件。

#[path = "vectors/illegal.rs"]
mod illegal;
#[path = "vectors/legal.rs"]
mod legal;
#[path = "vectors/support.rs"]
mod support;

use lengsuo_browser_extension::frame::{FRAME_HEADER_LEN, MAX_PAYLOAD_LEN};
use lengsuo_browser_extension::message::{MessageType, HOST_NAME, NATIVE_RESPONSE_FALLBACK_TYPE};
use serde_json::Value;

use support::load;

// ---------------------------------------------------------------- 结构性常量

#[test]
fn vector_file_structural_constants_match_the_contract() {
    let frame = load().get("frame").expect("向量文件缺 frame 段");
    assert_eq!(frame["header_len"].as_u64(), Some(8));
    assert_eq!(frame["max_payload_len"].as_u64(), Some(1_048_576));
    // 字节序也钉进向量：⛔ 不能只钉布局不钉字节序。
    assert_eq!(frame["len_field"]["endian"].as_str(), Some("big"));
    assert_eq!(frame["len_field"]["width"].as_u64(), Some(4));
    assert_eq!(frame["len_field"]["offset"].as_u64(), Some(0));
    assert_eq!(
        frame["len_field"]["meaning"].as_str(),
        Some("payload byte count")
    );
    assert_eq!(
        frame["len_field"]["excludes_frame_header"].as_bool(),
        Some(true)
    );
    assert_eq!(frame["type_field"]["offset"].as_u64(), Some(4));
    assert_eq!(frame["type_field"]["width"].as_u64(), Some(1));
    assert_eq!(frame["reserved_field"]["offset"].as_u64(), Some(5));
    assert_eq!(frame["reserved_field"]["width"].as_u64(), Some(3));
    assert_eq!(
        frame["reserved_field"]["must_be_zero"].as_bool(),
        Some(true)
    );
    assert_eq!(frame["payload_offset"].as_u64(), Some(8));
    // 本 crate 的常量必须与向量文件一致。
    assert_eq!(FRAME_HEADER_LEN, 8);
    assert_eq!(MAX_PAYLOAD_LEN, 1_048_576);
}

#[test]
fn vector_file_carries_the_cross_repo_note() {
    let note = load()["note"].as_str().expect("note 必须是字符串");
    assert!(note.contains("三仓"), "note 必须写明改它要三仓同步");
}

// ------------------------------------------------- 扩展侧类型表对照（编号一致）

#[test]
fn extension_side_message_type_table_matches_the_rust_table() {
    let table = load()
        .get("extension_message_types")
        .and_then(Value::as_object)
        .expect("extension_message_types 必须是对象");
    assert_eq!(table.len(), MessageType::ALL.len(), "扩展侧表必须是 11 项");

    // 逐项：扩展侧的「键名 → 编号」必须能由本枚举还原。
    for (key, number) in table {
        let number = number.as_u64().expect("编号必须是数字") as u8;
        let message_type = MessageType::from_u8(number)
            .unwrap_or_else(|| panic!("编号 {} 不是已知消息类型", number));
        assert_eq!(message_type.name(), key, "扩展侧键名与本枚举名称不一致");
    }

    // 反向：11 种类型全部出现在向量文件里。
    for message_type in MessageType::ALL {
        assert!(
            table.contains_key(message_type.name()),
            "向量文件缺 {}",
            message_type.name()
        );
    }

    // 编号恰好是 0..=10。
    let mut numbers: Vec<u64> = table.values().map(|v| v.as_u64().unwrap()).collect();
    numbers.sort_unstable();
    assert_eq!(numbers, (0..=10).collect::<Vec<u64>>());
}

// ---------------------------------------------------------------- 回退语义标记

#[test]
fn native_response_fallback_marker_is_pinned() {
    let fallback = &load()["native_response_fallback"];
    assert_eq!(fallback["type"].as_u64(), Some(10));
    assert_eq!(fallback["name"].as_str(), Some("USE_NATIVE_RESPONSE"));
    assert_eq!(NATIVE_RESPONSE_FALLBACK_TYPE, 10);
    assert!(MessageType::UseNativeResponse.is_native_response_fallback());

    // 其余 10 种都**不是**回退信号。
    for message_type in MessageType::ALL {
        if message_type == MessageType::UseNativeResponse {
            continue;
        }
        assert!(
            !message_type.is_native_response_fallback(),
            "{} 不是回退信号",
            message_type.name()
        );
    }
    let fallbacks = MessageType::ALL
        .iter()
        .filter(|m| m.is_native_response_fallback())
        .count();
    assert_eq!(fallbacks, 1, "回退信号必须唯一");
}

#[test]
fn host_name_constant_is_pinned() {
    assert_eq!(load()["host_name"].as_str(), Some(HOST_NAME));
    assert_eq!(HOST_NAME, "lengsuo.credential");
}
