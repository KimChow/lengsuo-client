use super::*;
use crate::mux::frame::TargetNetwork;
use ss_core::target::TargetAddr;

/// 固化 New+数据帧的线上布局（对照参考 `FrameMetadata.WriteTo` +
/// `writeMetaWithFrame`：`metaLen | id | status | option | network | port | type |
/// addr | dataLen | data`）。
///
/// `metaLen` 在参考里取自「写完全部元数据段后的长度减去写完 2 字节长度前缀后的
/// 长度」（`len1 - len0`，`len0` 在 `Extend(2)` **之后**取），故不含自身。
#[test]
fn new_data_frame_wire_layout_matches_reference() {
    let mut wire = Vec::new();
    let mut writer = SessionWriter::request(
        1,
        (TargetAddr::V4([127, 0, 0, 1], 0x4651), TargetNetwork::Tcp),
        TargetNetwork::Tcp,
    );
    writer.write_data(&mut wire, b"hello").expect("可写");
    assert_eq!(
        wire,
        vec![
            0x00, 0x0c, // metaLen = 12（不含自身）
            0x00, 0x01, // session id
            0x01, // New
            0x01, // OptionData
            0x01, // TargetNetworkTCP
            0x46, 0x51, // port 18001
            0x01, // IPv4
            0x7f, 0x00, 0x00, 0x01, // 127.0.0.1
            0x00, 0x05, // 数据长度
            b'h', b'e', b'l', b'l', b'o',
        ]
    );
}
