//! 固定向量回放的共享夹具：读向量文件、取条目、解 hex、换字节序。

use lengsuo_native_host::frame::FRAME_HEADER_LEN;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::OnceLock;

/// 向量文件路径。
pub fn vector_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("native-host-transport-v1.json")
}

/// 读向量文件（只读一次）。
///
/// ⛔ 文件缺失或解析失败 ⇒ **测试失败**，绝不 skip。
pub fn load() -> &'static Value {
    static CACHE: OnceLock<Value> = OnceLock::new();
    CACHE.get_or_init(|| {
        let path = vector_path();
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("读不到向量文件 {}：{}", path.display(), e));
        serde_json::from_str(&text).expect("向量文件必须是合法 JSON")
    })
}

/// 取某一段里的全部条目。
pub fn entries(section: &str) -> &'static Vec<Value> {
    load()
        .get(section)
        .unwrap_or_else(|| panic!("向量文件缺段 {}", section))
        .as_array()
        .unwrap_or_else(|| panic!("向量文件段 {} 必须是数组", section))
}

/// 按名字取某一段里的条目。
pub fn entry(section: &str, name: &str) -> &'static Value {
    entries(section)
        .iter()
        .find(|item| item.get("name").and_then(Value::as_str) == Some(name))
        .unwrap_or_else(|| panic!("向量文件段 {} 里没有名为 {} 的条目", section, name))
}

/// 取字符串字段。
pub fn str_field(item: &Value, key: &str) -> String {
    item[key]
        .as_str()
        .unwrap_or_else(|| panic!("字段 {} 必须是字符串", key))
        .to_owned()
}

/// 取 u64 字段。
pub fn u64_field(item: &Value, key: &str) -> u64 {
    item[key]
        .as_u64()
        .unwrap_or_else(|| panic!("字段 {} 必须是数字", key))
}

/// 解 hex。
pub fn from_hex(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap_or_else(|e| panic!("非法 hex {}：{}", text, e))
}

/// ⭐ 把向量文件里的**小端**参考字节换成本机字节序。
///
/// 只换帧头那 4 字节（长度前缀），载荷原样保留。
/// 本机是小端时是恒等变换。
pub fn to_native(reference_frame: &[u8]) -> Vec<u8> {
    let mut out = reference_frame.to_vec();
    if cfg!(target_endian = "big") {
        out[..FRAME_HEADER_LEN].reverse();
    }
    out
}

/// ⭐ 把向量文件里的**小端**长度头换成本机字节序。
pub fn header_to_native(reference_header: &[u8]) -> Vec<u8> {
    let mut out = reference_header.to_vec();
    if cfg!(target_endian = "big") {
        out.reverse();
    }
    out
}

/// 断言某一段里存在这些名字的条目。
pub fn assert_has_entries(section: &str, required: &[&str]) {
    let names: Vec<String> = entries(section)
        .iter()
        .map(|item| str_field(item, "name"))
        .collect();
    for name in required {
        assert!(
            names.contains(&(*name).to_owned()),
            "向量文件段 {} 缺 {}",
            section,
            name
        );
    }
}
