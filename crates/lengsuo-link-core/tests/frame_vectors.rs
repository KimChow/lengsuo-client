//! 固定测试向量（供移动端 Swift/Kotlin 侧对拍）。
//!
//! **位置（路径稳定）**：`crates/lengsuo-link-core/tests/frame_vectors.rs`，
//! JSON 内嵌在 [`VECTORS_JSON`] 常量里（**纯 JSON 文本**，无注释无尾逗号）。
//! 完整字段说明与移动端读取步骤见仓内 `docs/link-frame-spec.md` §7。
//!
//! # 为什么向量里能放密文字节
//!
//! 传输层 nonce = `4 字节零前缀 || 计数器 LE64`，**由计数器派生、不含随机数**
//! （见 `crates/lengsuo-wireguard/src/transport.rs`）。给定固定的
//! **密钥 + 接收者标识 + 起始计数器**，密文**逐字节可复现**，所以本文件给出的是
//! **整帧期望字节**（`frame_hex`），移动端可以拿它做字节级对拍，
//! 而不只是「明文 → 能解出来」这种弱断言。
//!
//! ⚠️ 密钥是**测试专用**（全 0x5A），不得用于任何真实会话。
//!
//! # 三重校验
//!
//! 1. [`vectors_are_canonical_json`]：内嵌 JSON 与「解析后重新渲染」**逐字节相同**。
//! 2. [`each_vector_reproduces_expected_frame_bytes`]：按输入重算的整帧字节
//!    与 `frame_hex` **逐字节相同**。
//! 3. [`each_vector_decodes_back_to_its_plaintext`]：`frame_hex` 能解回
//!    类型 / 序号 / 明文。

use lengsuo_link_core::frame::{decode_exact, open_frame, seal_frame, FrameType, FRAME_HEADER_LEN};
use lengsuo_wireguard::transport::{Receiver, Sender, TransportKey};

// ---------------------------------------------------------------- 极小 JSON 取值器

/// 定位 `"<key>":` 之后的位置（键不存在即 panic）。
fn value_start(text: &str, key: &str) -> usize {
    let needle = format!("\"{key}\":");
    let at = text
        .find(&needle)
        .unwrap_or_else(|| panic!("缺少字段 {key}"));
    at + needle.len()
}

/// 取字符串字段的值。
fn str_field(text: &str, key: &str) -> String {
    let rest = text[value_start(text, key)..].trim_start();
    assert!(rest.starts_with('"'), "字段 {key} 不是字符串");
    let end = rest[1..].find('"').expect("字符串未闭合") + 1;
    rest[1..end].to_string()
}

/// 取无符号整数字段的值。
fn num_field(text: &str, key: &str) -> u64 {
    let rest = text[value_start(text, key)..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    assert!(end > 0, "字段 {key} 不是整数");
    rest[..end].parse().expect("整数")
}

/// 切出数组字段里每个对象的文本（花括号配平，跳过字符串内的花括号）。
fn array_items(text: &str, key: &str) -> Vec<String> {
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

// ---------------------------------------------------------------- 常量与工具

/// **规范化 JSON 文本**：向量源 = 仓根 `vectors/frame-vectors.json`。
///
/// 用 `include_str!` 指向那**一个文件** ⇒ 编译产物里的常量**就是**文件内容，
/// **结构上不可能**与文件漂移（移动端也直接读同一份文件）。
///
/// 格式与移动端读取方式见本文件头部说明。
const VECTORS_JSON: &str = include_str!("../../../vectors/frame-vectors.json");

/// 测试专用密钥字节（全 0x5A）。**仅用于测试**，不得用于任何真实会话。
const TEST_KEY: [u8; 32] = [0x5Au8; 32];

/// 期望的接收者标识（与 JSON 的 `receiver` 一致）。
const VECTOR_RECEIVER: u32 = 0x1122_3344;

/// 十六进制小写编码。
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("写字符串");
    }
    out
}

/// 十六进制解码（拒绝奇数长度与非法字符）。
fn from_hex(text: &str) -> Vec<u8> {
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

/// 一条测试向量。
#[derive(Debug, Clone)]
struct Vector {
    /// 向量名（用于断言信息）。
    name: String,
    /// 帧类型。
    frame_type: FrameType,
    /// 帧序号。
    seq: u64,
    /// 传输层计数器（决定 nonce）。
    counter: u64,
    /// 明文。
    plaintext: Vec<u8>,
    /// 期望的整帧字节。
    frame: Vec<u8>,
}

/// 帧类型名（与 `FrameType::to_u8` 一一对应）。
fn frame_type_name(frame_type: FrameType) -> &'static str {
    match frame_type {
        FrameType::Data => "data",
        FrameType::Control => "control",
        FrameType::Keepalive => "keepalive",
    }
}

/// 由名字还原帧类型。
fn frame_type_from_name(name: &str) -> FrameType {
    match name {
        "data" => FrameType::Data,
        "control" => FrameType::Control,
        "keepalive" => FrameType::Keepalive,
        other => panic!("未知帧类型 {other}"),
    }
}

/// 测试专用密钥。
fn vector_key() -> TransportKey {
    TransportKey::new(&TEST_KEY).expect("测试密钥长度固定为 32 字节")
}

/// 解析整个向量文件。
fn parse_vectors() -> Vec<Vector> {
    assert_eq!(
        str_field(VECTORS_JSON, "format"),
        "lengsuo-link-frame-vectors"
    );
    assert_eq!(num_field(VECTORS_JSON, "version"), 1);
    assert_eq!(str_field(VECTORS_JSON, "spec"), "docs/link-frame-spec.md");
    assert_eq!(
        num_field(VECTORS_JSON, "receiver"),
        u64::from(VECTOR_RECEIVER)
    );
    assert_eq!(
        from_hex(&str_field(VECTORS_JSON, "key_hex")),
        TEST_KEY.to_vec()
    );
    array_items(VECTORS_JSON, "vectors")
        .iter()
        .map(|item| Vector {
            name: str_field(item, "name"),
            frame_type: frame_type_from_name(&str_field(item, "frame_type")),
            seq: num_field(item, "seq"),
            counter: num_field(item, "counter"),
            plaintext: from_hex(&str_field(item, "plaintext_hex")),
            frame: from_hex(&str_field(item, "frame_hex")),
        })
        .collect()
}

/// 用向量输入重算整帧字节。
fn recompute(vector: &Vector) -> Vec<u8> {
    let mut sender = Sender::new(vector_key(), VECTOR_RECEIVER, vector.counter);
    seal_frame(
        &mut sender,
        vector.frame_type,
        vector.seq,
        &vector.plaintext,
    )
    .expect("按向量输入重算必须成功")
}

/// 把向量重新渲染成规范化 JSON 文本（与 `VECTORS_JSON` 的排版一致）。
fn render(vectors: &[Vector]) -> String {
    let mut out = String::from(
        "{\n  \"format\": \"lengsuo-link-frame-vectors\",\n  \"version\": 1,\n  \
         \"spec\": \"docs/link-frame-spec.md\",\n",
    );
    out.push_str(&format!("  \"key_hex\": \"{}\",\n", to_hex(&TEST_KEY)));
    out.push_str(&format!(
        "  \"receiver\": {VECTOR_RECEIVER},\n  \"vectors\": [\n"
    ));
    for (index, vector) in vectors.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"name\": \"{}\",\n", vector.name));
        out.push_str(&format!(
            "      \"frame_type\": \"{}\",\n",
            frame_type_name(vector.frame_type)
        ));
        out.push_str(&format!("      \"seq\": {},\n", vector.seq));
        out.push_str(&format!("      \"counter\": {},\n", vector.counter));
        out.push_str(&format!(
            "      \"plaintext_hex\": \"{}\",\n",
            to_hex(&vector.plaintext)
        ));
        out.push_str(&format!(
            "      \"frame_hex\": \"{}\"\n",
            to_hex(&vector.frame)
        ));
        out.push_str(if index + 1 == vectors.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }
    out.push_str("  ]\n}\n");
    out
}

// ---------------------------------------------------------------- 用例

#[test]
fn vectors_are_canonical_json() {
    let vectors = parse_vectors();
    assert!(!vectors.is_empty(), "向量文件不能为空");
    assert_eq!(render(&vectors), VECTORS_JSON, "内嵌 JSON 与规范渲染不一致");
}

#[test]
fn each_vector_reproduces_expected_frame_bytes() {
    for vector in parse_vectors() {
        let actual = recompute(&vector);
        assert_eq!(
            to_hex(&actual),
            to_hex(&vector.frame),
            "向量 {} 的整帧字节不匹配",
            vector.name
        );
        assert!(
            actual.len() >= FRAME_HEADER_LEN,
            "向量 {} 的帧长不足一个帧头",
            vector.name
        );
    }
}

#[test]
fn each_vector_decodes_back_to_its_plaintext() {
    for vector in parse_vectors() {
        let decoded = decode_exact(&vector.frame).expect("向量必须可解码");
        assert_eq!(
            decoded.frame_type, vector.frame_type,
            "向量 {}",
            vector.name
        );
        assert_eq!(decoded.seq, vector.seq, "向量 {}", vector.name);

        let mut receiver = Receiver::new(vector_key(), VECTOR_RECEIVER, u64::MAX);
        let opened = open_frame(&mut receiver, &vector.frame).expect("向量必须可解封");
        assert_eq!(opened.plaintext, vector.plaintext, "向量 {}", vector.name);
        assert_eq!(opened.seq, vector.seq, "向量 {}", vector.name);
        assert_eq!(opened.frame_type, vector.frame_type, "向量 {}", vector.name);
    }
}

#[test]
fn frame_header_layout_is_stable() {
    // 帧头 20 字节：magic(2) version(1) type(1) seq(8) len(2) flags(2) crc(4)。
    for vector in parse_vectors() {
        let head = &vector.frame[..FRAME_HEADER_LEN];
        assert_eq!(&head[0..2], &[0x4C, 0x53], "向量 {} 的魔数", vector.name);
        assert_eq!(head[2], 1, "向量 {} 的版本", vector.name);
        assert_eq!(head[3], vector.frame_type.to_u8(), "向量 {}", vector.name);
        assert_eq!(
            u64::from_be_bytes(head[4..12].try_into().unwrap()),
            vector.seq,
            "向量 {} 的序号",
            vector.name
        );
        assert_eq!(
            u16::from_be_bytes(head[12..14].try_into().unwrap()) as usize,
            vector.frame.len() - FRAME_HEADER_LEN,
            "向量 {} 的载荷长度",
            vector.name
        );
        assert_eq!(
            u16::from_be_bytes(head[14..16].try_into().unwrap()),
            0,
            "向量 {} 的保留位必须为 0",
            vector.name
        );
    }
}

/// 重新生成规范化 JSON 文本（供维护者核对）。
///
/// 默认跳过：它只做打印，不参与断言。用 `cargo test -p lengsuo-link-core
/// --test frame_vectors -- --ignored --nocapture` 实跑。
#[test]
#[ignore = "仅用于重新生成向量 JSON"]
fn regenerate_vectors_json() {
    let vectors = parse_vectors();
    print!("{}", render(&vectors));
    // 逐条重算，确保重算结果与文件里的一致（不一致时上面的断言会先失败）。
    for vector in &vectors {
        assert_eq!(recompute(vector), vector.frame, "向量 {}", vector.name);
    }
}
