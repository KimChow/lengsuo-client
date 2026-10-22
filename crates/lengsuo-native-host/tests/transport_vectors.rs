//! ⭐ 固定测试向量回放：本卡字节定义的防漂移锚点。
//!
//! `tests/vectors/native-host-transport-v1.json` 把**管道帧**的字节布局
//! （4 字节本机字节序长度前缀 + JSON 载荷）、分片语义、两个上限、
//! 以及来源解析的接受/拒绝形状，全部钉成**字面量**。
//!
//! 本套件**只做「实现 ⇒ 与 JSON 字面量逐字节比对」**：
//! JSON 里的每个 hex 都是**独立手算**的期望值
//! （按 Chromium 的帧定义手写 u32 小端头），⛔ 绝不是「先编码再解码回来相等」
//! 那种自家往返。
//!
//! # 字节序
//!
//! 管道帧的长度前缀是**本机字节序**（Chromium 收发两侧同机同序）。
//! 向量文件按**小端**记录（参考平台 = 作者机器 = 部署平台），
//! 并在 `pipe_frame.length_prefix_field.endian_in_this_file` 里写明。
//! 本套件在**大端**主机上会把期望字节的帧头 4 字节**换序**后再比对，
//! 这样同一份文件在两类主机上都可用，且文件里的字面量始终是参考平台的字节。
//!
//! # 组织方式
//!
//! 按**主题**拆成三个子模块：
//! - [`vectors::support`]：共享夹具（读向量文件、取条目、解 hex、换字节序）。
//! - [`vectors::frames`]：管道帧回放（合法 / 分片 / 非法 / 上限）。
//! - [`vectors::origins`]：来源回放（合法 / 非法）。
//!
//! 结构性常量与来源出处的用例留在本文件。

#[path = "vectors/frames.rs"]
mod frames;
#[path = "vectors/origins.rs"]
mod origins;
#[path = "vectors/support.rs"]
mod support;

use lengsuo_native_host::frame::{FRAME_HEADER_LEN, MAX_FRAME_PAYLOAD_LEN};
use lengsuo_native_host::origin::{EXTENSION_ID_LEN, EXTENSION_SCHEME_PREFIX};

use support::load;

// ---------------------------------------------------------------- 结构性常量

#[test]
fn vector_file_pins_the_pipe_frame_layout() {
    let frame = load().get("pipe_frame").expect("向量文件缺 pipe_frame 段");
    assert_eq!(frame["header_len"].as_u64(), Some(4));
    assert_eq!(frame["payload_offset"].as_u64(), Some(4));
    assert_eq!(frame["max_payload_len"].as_u64(), Some(1_048_576));
    // 字节序也钉进向量：⛔ 不能只钉布局不钉字节序。
    let field = &frame["length_prefix_field"];
    assert_eq!(field["offset"].as_u64(), Some(0));
    assert_eq!(field["width"].as_u64(), Some(4));
    assert_eq!(field["endian"].as_str(), Some("native"));
    assert_eq!(field["endian_in_this_file"].as_str(), Some("little"));
    assert_eq!(field["meaning"].as_str(), Some("payload byte count"));
    assert_eq!(field["excludes_frame_header"].as_bool(), Some(true));
    // 载荷是 JSON 文本，不是二进制业务帧。
    assert_eq!(frame["payload_is_json_text"].as_bool(), Some(true));

    // 本 crate 的常量必须与向量文件一致。
    assert_eq!(FRAME_HEADER_LEN, 4);
    assert_eq!(MAX_FRAME_PAYLOAD_LEN, 1_048_576);
}

#[test]
fn vector_file_pins_the_origin_shape() {
    let origin = load().get("origin").expect("向量文件缺 origin 段");
    assert_eq!(
        origin["scheme_prefix"].as_str(),
        Some(EXTENSION_SCHEME_PREFIX)
    );
    assert_eq!(origin["extension_id_len"].as_u64(), Some(32));
    assert_eq!(origin["extension_id_alphabet"].as_str(), Some("a-p"));
    assert_eq!(origin["case_sensitive"].as_bool(), Some(false));
    assert_eq!(
        origin["canonical_form"].as_str(),
        Some("chrome-extension://<extension_id>/")
    );
    assert_eq!(origin["trailing_slash_accepted"].as_bool(), Some(true));
    assert_eq!(origin["argv_position"].as_u64(), Some(1));

    assert_eq!(EXTENSION_ID_LEN, 32);
    assert_eq!(EXTENSION_SCHEME_PREFIX, "chrome-extension://");
}

#[test]
fn vector_file_carries_the_source_of_truth_note() {
    let note = load()["note"].as_str().expect("note 必须是字符串");
    assert!(
        note.contains("Chromium"),
        "note 必须写明字节真相是 Chromium"
    );
    assert!(
        note.contains("本机字节序"),
        "note 必须写明长度前缀是本机字节序（不是大端）"
    );
    let source = load()["source_of_truth"]
        .as_str()
        .expect("source_of_truth 必须是字符串");
    assert!(
        source.contains("native_message_process_host.cc"),
        "source_of_truth 必须点名 Chromium 的实现文件"
    );
}
