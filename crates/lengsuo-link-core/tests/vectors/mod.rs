//! 跨端测试向量（L2 会话 + L3 帧会话侧扩展）的**模块入口**、极小 JSON 取值器
//! 与**共享的会话构造助手**。
//!
//! # 范式沿用 `tests/frame_vectors.rs`（既有 L3 向量）
//!
//! | 既有做法 | 本模块 |
//! |---|---|
//! | JSON **内嵌**在 Rust 测试文件里（移动端只读一份 Rust 文件即可取到向量） | 同 |
//! | 纯 JSON 文本（无注释、无尾逗号） | 同 |
//! | 手写**极小 JSON 取值器**，**不引入 `serde`/`serde_json`** | 同 |
//! | 三重校验（规范化 / 重算字节 / 期望字节能解回） | 同 |
//! | 测试专用密钥（**不得**用于真实会话） | 同 |
//!
//! ⛔ 本模块**不新增任何依赖**（`Cargo.toml` 属共享区，本卡不许改）。
//!
//! # 为什么是「子目录 + 按层分文件」
//!
//! 既有 `tests/frame_vectors.rs` 是「单文件内嵌」（394 行）。本卡体量更大
//! （会话握手 + 收发帧 + 重连 + 错误路径），单文件会顶破 400 行软目标 ⇒ 改用
//! **子目录 + 按层分文件**。**三条范式完全不变**（见上表），
//! 移动端读取方式也仍是「取 JSON 文本 → 解析」。
//!
//! # 文件分工
//!
//! - 本文件：极小 JSON 取值器、十六进制/区间工具、**稳定错误标签**、
//!   共享常量、**会话构造助手**（错误向量与会话向量都要用）。
//! - [`session_vectors`]：L2 会话握手 / 收发帧 / 重连的**字节级向量**。
//! - [`error_vectors`]：错误路径的确定性输入 → **稳定标签**映射。
//! - [`consistency`]：一致性测试（向量能复现、向量自洽、跨向量不矛盾）。

pub mod consistency;
pub mod error_vectors;
pub mod generator;
pub mod json;
pub mod labels;
pub mod rebuild;
pub mod scenarios;
pub mod session_data;
pub mod session_vectors;

pub use labels::{frame_error_label, frame_label, session_error_label, session_label};

use std::time::{Duration, Instant};

use lengsuo_link_core::frame::FrameType;
use lengsuo_link_core::session::{Session, SessionConfig, SessionRole};

// ---------------------------------------------------------------- 极小 JSON 取值器
//
// 与 `tests/frame_vectors.rs` 的取值器**同源同语义**（移动端读的是 JSON 文本，
// 本模块只是仓内自检用的读取器）。刻意手写：不引入 `serde`/`serde_json`
// （本卡不新增依赖），且移动端因此也不必把 JSON 解析器塞进静态库。
//
// ⚠️ 取值器按**作用域**工作：先切出对象的内部文本（[`array_items`] /
// [`object_item`]），再在**该作用域内**取字段 ⇒ 同名字段不会串。

/// 定位 `"<key>":` 之后的位置（键不存在即 panic）。
fn value_start(text: &str, key: &str) -> usize {
    let needle = format!("\"{key}\":");
    let at = text
        .find(&needle)
        .unwrap_or_else(|| panic!("缺少字段 {key}"));
    at + needle.len()
}

/// 取字符串字段的值。
pub fn str_field(text: &str, key: &str) -> String {
    let rest = text[value_start(text, key)..].trim_start();
    assert!(rest.starts_with('"'), "字段 {key} 不是字符串");
    let end = rest[1..].find('"').expect("字符串未闭合") + 1;
    rest[1..end].to_string()
}

/// 取无符号整数字段的值。
pub fn num_field(text: &str, key: &str) -> u64 {
    let rest = text[value_start(text, key)..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    assert!(end > 0, "字段 {key} 不是整数");
    rest[..end].parse().expect("整数")
}

/// 切出数组字段里每个对象的文本（花括号配平，跳过字符串内的花括号）。
pub fn array_items(text: &str, key: &str) -> Vec<String> {
    let rest = text[value_start(text, key)..].trim_start();
    assert!(rest.starts_with('['), "字段 {key} 不是数组");
    let mut items = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, ch) in rest.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => {
                if depth == 0 {
                    start = index + 1;
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    items.push(rest[start..index].to_string());
                }
            }
            // 数组的收尾括号：数组内不再有对象，停止扫描
            // （否则会扫进外层对象，把它的 '}' 当成数组元素的一部分）。
            ']' if depth == 0 => break,
            _ => {}
        }
    }
    assert_eq!(depth, 0, "字段 {key} 的数组里花括号不配平");
    items
}

/// 切出**嵌套对象**字段的内部文本（不含最外层花括号）。
///
/// 用于「对象里再套对象」：先取出内层文本，再在**该作用域内**取字段。
pub fn object_item(text: &str, key: &str) -> String {
    let rest = text[value_start(text, key)..].trim_start();
    assert!(rest.starts_with('{'), "字段 {key} 不是对象");
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, ch) in rest.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return rest[1..index].to_string();
                }
            }
            _ => {}
        }
    }
    panic!("字段 {key} 的对象未闭合");
}

/// 切出对象字段的**全部键值对**（键与值都是字符串）。
///
/// 只处理「值是字符串」的对象字段（够本卡用：参数表都是字符串）。
pub fn object_entries(text: &str, key: &str) -> Vec<(String, String)> {
    let inner = object_item(text, key);
    let mut entries = Vec::new();
    let mut rest = inner.as_str();
    while let Some(at) = rest.find('"') {
        let after = &rest[at + 1..];
        let key_end = after.find('"').expect("键未闭合");
        let name = after[..key_end].to_string();
        let after_key = &after[key_end + 1..];
        let colon = after_key.find(':').expect("键后缺冒号");
        let after_colon = after_key[colon + 1..].trim_start();
        assert!(after_colon.starts_with('"'), "参数 {name} 的值必须是字符串");
        let value_end = after_colon[1..].find('"').expect("值未闭合");
        let value = after_colon[1..1 + value_end].to_string();
        entries.push((name, value));
        // 跳到下一个键。
        let tail = &after_colon[1 + value_end..];
        match tail.find(',') {
            Some(comma) => rest = &tail[comma + 1..],
            None => break,
        }
    }
    entries
}

// ---------------------------------------------------------------- 十六进制 / 区间工具

/// 十六进制小写编码。
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("写字符串");
    }
    out
}

/// 十六进制解码（拒绝奇数长度与非法字符）。
pub fn from_hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "十六进制长度必须是偶数：{text}");
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    pairs
        .iter()
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("十六进制字符");
            let low = (pair[1] as char).to_digit(16).expect("十六进制字符");
            ((high << 4) | low) as u8
        })
        .collect()
}

/// 把 32 字节十六进制解码成定长数组。
pub fn key32(text: &str) -> [u8; 32] {
    let bytes = from_hex(text);
    assert_eq!(bytes.len(), 32, "密钥字段必须是 32 字节");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// 把 `start-end` 形式的区间表解析成 `(usize, usize)` 列表（半开区间）。
pub fn parse_ranges(spec: &str) -> Vec<(usize, usize)> {
    spec.split(',')
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (start, end) = part.split_once('-').expect("区间格式必须是 start-end");
            let start: usize = start.trim().parse().expect("区间起点");
            let end: usize = end.trim().parse().expect("区间终点");
            assert!(start <= end, "区间起点不得大于终点：{part}");
            (start, end)
        })
        .collect()
}

/// 把区间表渲染回 `"start-end,start-end"` 形式。
pub fn render_ranges(ranges: &[(usize, usize)]) -> String {
    ranges
        .iter()
        .map(|(start, end)| format!("{start}-{end}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// 把 `ranges` 覆盖到的字节**清零**（其余字节原样保留）。
///
/// 用于「canonical 形式」：握手报文里依赖墙钟的区段被清零后，
/// 剩下的字节才是**跨进程逐字节可复现**的那部分。
pub fn zero_ranges(bytes: &[u8], ranges: &[(usize, usize)]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    for (start, end) in ranges {
        assert!(*end <= out.len(), "区间越界：{start}-{end}");
        for byte in &mut out[*start..*end] {
            *byte = 0;
        }
    }
    out
}

// ---------------------------------------------------------------- 共享常量

/// 帧方向：发起方 → 响应方。
pub const DIR_I2R: &str = "initiator_to_responder";
/// 帧方向：响应方 → 发起方。
pub const DIR_R2I: &str = "responder_to_initiator";

/// 帧类型名（与 `FrameType::to_u8` 一一对应）。
pub fn frame_type_name(frame_type: FrameType) -> &'static str {
    match frame_type {
        FrameType::Data => "data",
        FrameType::Control => "control",
        FrameType::Keepalive => "keepalive",
    }
}

/// 由名字还原帧类型。
pub fn frame_type_from_name(name: &str) -> FrameType {
    match name {
        "data" => FrameType::Data,
        "control" => FrameType::Control,
        "keepalive" => FrameType::Keepalive,
        other => panic!("未知帧类型 {other}"),
    }
}

// ---------------------------------------------------------------- 会话构造助手

/// 构造（发起方, 响应方）一对**未握手**的会话。
///
/// 与 [`session_pair`] 的区别：**不**完成握手 ⇒ 会话停在「未握手」态，
/// 此时收发会被「状态不允许该操作」拒绝。
pub fn unhandshaked_pair(
    initiator_static_private: [u8; 32],
    responder_static_public: [u8; 32],
    responder_static_private: [u8; 32],
    initiator_static_public: [u8; 32],
) -> (Session, Session) {
    let initiator = Session::new(SessionConfig::new(
        SessionRole::Initiator,
        initiator_static_private,
        responder_static_public,
    ))
    .expect("发起方会话可构造");
    let responder = Session::new(SessionConfig::new(
        SessionRole::Responder,
        responder_static_private,
        initiator_static_public,
    ))
    .expect("响应方会话可构造");
    (initiator, responder)
}

/// 构造（发起方, 响应方）一对**已建立**的会话。
///
/// ⚠️ 必须是**已建立**的：会话未建立时 `open_frame` / `seal_frame`
/// 会在可用性检查处被拦下并返回 `session.invalid_state`，
/// 于是「认证失败」「超长明文」这两类场景**永远取不到自己的标签**。
pub fn session_pair(
    initiator_static_private: [u8; 32],
    responder_static_public: [u8; 32],
    responder_static_private: [u8; 32],
    initiator_static_public: [u8; 32],
) -> (Session, Session) {
    let mut initiator = Session::new(SessionConfig::new(
        SessionRole::Initiator,
        initiator_static_private,
        responder_static_public,
    ))
    .expect("发起方会话可构造");
    let mut responder = Session::new(SessionConfig::new(
        SessionRole::Responder,
        responder_static_private,
        initiator_static_public,
    ))
    .expect("响应方会话可构造");
    // 完成一轮握手 ⇒ 两侧传输密钥落地、会话进入「已建立」。
    let now = Instant::now();
    let initiation = initiator
        .create_initiation([0xA1; 32], 10, now)
        .expect("initiation 可生成");
    responder
        .consume_initiation(&initiation, now)
        .expect("initiation 可剥壳");
    let response = responder
        .create_response([0xB2; 32], 11, now)
        .expect("response 可生成");
    initiator
        .consume_response(&response, now)
        .expect("response 可消费");
    (initiator, responder)
}

/// 推进到「下一轮」可用的时刻。
///
/// ⚠️ 两个**独立**的时钟源都必须跨过：
/// - **墙钟**（TAI64N，刻度 ~16.78ms）：否则重连的 initiation 会被
///   重放检查拒绝（时间戳不晚于上一轮）；
/// - **单调钟**（会话层洪水窗口 20ms）：否则重连会被洪水检查拒绝。
pub fn advance_round(previous: Instant) -> Instant {
    const GAP: Duration = Duration::from_millis(50);
    let before = lengsuo_wireguard::handshake::tai64n_now();
    loop {
        std::thread::sleep(Duration::from_millis(2));
        let now = Instant::now();
        let tai_advanced = lengsuo_wireguard::handshake::tai64n_now() != before;
        let monotonic = now
            .checked_duration_since(previous)
            .is_some_and(|gap| gap >= GAP);
        if tai_advanced && monotonic {
            return now;
        }
    }
}
