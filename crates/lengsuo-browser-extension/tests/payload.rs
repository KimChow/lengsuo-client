//! ⭐ 契约 §5.3.1 载荷层的固定向量回放（W3a-2）。
//!
//! `tests/vectors/payload-v1.json` 是本卡专用的**手写**期望值集：
//! 每个 base64url / 转义期望都先手工推导、再经 python 标准库**独立**核对，
//! ⛔ 绝不是「先编码再解码回来相等」的自家往返，也⛔ 不是本仓实现的回灌。
//!
//! # 组织方式（照抄 `tests/vectors.rs` 的主题拆分形状）
//!
//! - [`support`]：共享夹具（读向量文件、按名字取条目、错误变体命名）。
//! - [`cases`]：用例主体（请求解码 / 响应编码 / 转义 / base64url /
//!   clientDataJSON / invalid / nonce 回显 / 自设上限）。
//!
//! 跨端字段名对照（M5）与结构性断言留在本文件。

#[path = "payload/cases.rs"]
mod cases;
#[path = "payload/support.rs"]
mod support;

use lengsuo_browser_extension::json::{MAX_JSON_BYTES, MAX_JSON_DEPTH};

use support::load;

#[test]
fn vector_file_note_pins_the_hand_written_rule() {
    let note = load()["note"].as_str().expect("note 必须是字符串");
    assert!(note.contains("手写"), "note 必须写明期望值是手写");
    assert!(note.contains("5.3.1"), "note 必须指向契约 §5.3.1");
}

#[test]
fn limits_section_matches_self_set_constants() {
    let limits = &load()["limits"];
    assert_eq!(
        limits["max_json_bytes"].as_u64(),
        Some(MAX_JSON_BYTES as u64),
        "向量必须钉住自设输入上限"
    );
    assert_eq!(
        limits["max_json_depth"].as_u64(),
        Some(MAX_JSON_DEPTH as u64),
        "向量必须钉住自设嵌套上限"
    );
}

// ------------------------------------------------- M5 跨端字段名对照（§6.12）

#[test]
fn cross_end_field_names_all_match() {
    let entries = support::section("cross_end");
    assert!(entries.len() >= 11, "对照表至少覆盖任务书点名的 11 项");

    for item in entries {
        let field = item["field"].as_str().expect("field 必须是字符串");
        assert_eq!(
            item["match"].as_bool(),
            Some(true),
            "字段 {field} 跨端不一致（js = {:?}）",
            item["js"].as_str().unwrap_or(""),
        );
        assert!(
            !item["js"].as_str().unwrap_or_default().is_empty(),
            "{field} 缺 js 出处"
        );
        assert!(
            !item["rust"].as_str().unwrap_or_default().is_empty(),
            "{field} 缺 rust 侧说明"
        );
    }

    // 机械半边：type 3 / 4 的请求字面量必须含 JS 侧会发出的**每一个**线上键
    // （字面量若与 `fido2_page_script.js` 的构造形状不符，这里立刻红）。
    let create = support::entry("requests", "passkey_create")["json"]
        .as_str()
        .unwrap();
    for key in [
        "\"nonce\"",
        "\"origin\"",
        "\"rp_id\"",
        "\"challenge\"",
        "\"user\"",
        "\"id\"",
        "\"name\"",
        "\"display_name\"",
    ] {
        assert!(create.contains(key), "passkey_create 字面量缺 {key}");
    }
    let get = support::entry("requests", "passkey_get")["json"]
        .as_str()
        .unwrap();
    for key in [
        "\"nonce\"",
        "\"origin\"",
        "\"rp_id\"",
        "\"challenge\"",
        "\"allow_ids\"",
    ] {
        assert!(get.contains(key), "passkey_get 字面量缺 {key}");
    }
}
