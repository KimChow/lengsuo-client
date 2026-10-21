//! 帧编解码的单元测试（从父模块拆出以保持单文件 ≤400 行软约束）。
//!
//! 断言与拆分前逐字一致，未增删任何用例。

use super::*;
use ss_core::target::TargetAddr;

#[test]
fn status_and_network_maps_match_reference() {
    assert_eq!(SessionStatus::New.to_byte(), 0x01);
    assert_eq!(SessionStatus::Keep.to_byte(), 0x02);
    assert_eq!(SessionStatus::End.to_byte(), 0x03);
    assert_eq!(SessionStatus::KeepAlive.to_byte(), 0x04);
    assert_eq!(SessionStatus::from_byte(0x05), None);
    assert_eq!(SessionStatus::from_byte(0x00), None);
    assert_eq!(TargetNetwork::Tcp.to_byte(), 0x01);
    assert_eq!(TargetNetwork::Udp.to_byte(), 0x02);
    assert_eq!(TargetNetwork::from_byte(0x00), None);
    assert_eq!(TargetNetwork::from_byte(0x03), None);
}

#[test]
fn new_frame_roundtrip_port_then_address() {
    let meta = FrameMetadata {
        session_id: 0x1234,
        status: SessionStatus::New,
        option: OPTION_DATA,
        target: Some((
            TargetAddr::Domain("example.invalid".to_string(), 443),
            TargetNetwork::Tcp,
        )),
        source: None,
        local: None,
        udp_continuation: false,
    };
    let mut wire = Vec::new();
    meta.encode_into(&mut wire).expect("可编码");
    // metaLen = 2(id) + 1(status) + 1(option) + 1(network) + 2(port) + 1(len) + 15
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 24);
    assert_eq!(&wire[2..], &{
        let mut v = vec![0x12, 0x34, 0x01, 0x01, 0x01, 0x01, 0xBB, 0x02, 15];
        v.extend_from_slice(b"example.invalid");
        v
    });
    let decoded = FrameMetadata::decode_meta(&wire[2..], true).expect("可解码");
    assert_eq!(decoded, meta);
}

#[test]
fn new_frame_carries_ipv6_and_domain_targets() {
    let v6 = FrameMetadata {
        session_id: 1,
        status: SessionStatus::New,
        option: 0,
        target: Some((TargetAddr::V6([0x22; 16], 8080), TargetNetwork::Tcp)),
        source: None,
        local: None,
        udp_continuation: false,
    };
    let mut wire = Vec::new();
    v6.encode_into(&mut wire).expect("可编码");
    // metaLen = 4 + 1 + 2 + 1 + 16
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 24);
    assert_eq!(&wire[6..9], &[TARGET_NETWORK_TCP, 0x1F, 0x90]);
    assert_eq!(wire[9], 3, "IPv6 地址类型字节");
    assert_eq!(&wire[10..], &[0x22u8; 16]);
    assert_eq!(
        FrameMetadata::decode_meta(&wire[2..], false)
            .expect("可解码")
            .target,
        v6.target
    );
}

#[test]
fn end_frame_has_no_address() {
    let meta = FrameMetadata {
        session_id: 7,
        status: SessionStatus::End,
        option: 0,
        target: None,
        source: None,
        local: None,
        udp_continuation: false,
    };
    let mut wire = Vec::new();
    meta.encode_into(&mut wire).expect("可编码");
    assert_eq!(wire.len(), 6, "metaLen 回填为 4（id2+status1+option1）");
    let decoded = FrameMetadata::decode_meta(&wire[2..], true).expect("可解码");
    assert_eq!(decoded.status, SessionStatus::End);
    assert!(decoded.target.is_none());
}

#[test]
fn keep_without_address_is_four_byte_meta() {
    let body = [0x00, 0x05, SESSION_STATUS_KEEP, OPTION_DATA];
    let decoded = FrameMetadata::decode_meta(&body, true).expect("可解码");
    assert_eq!(decoded.session_id, 5);
    assert_eq!(decoded.status, SessionStatus::Keep);
    assert!(decoded.has_data());
}

#[test]
fn oversized_metalen_is_rejected() {
    let mut wire = vec![0x02, 0x01]; // 513
    wire.extend_from_slice(&[0u8; 513]);
    let err = FrameMetadata::decode_from(&mut &wire[..], false);
    assert!(matches!(err, Err(FrameError::MetaTooLong)));
}

#[test]
fn unknown_status_is_rejected() {
    let body = [0x00, 0x01, 0x09, 0x00];
    let err = FrameMetadata::decode_meta(&body, false);
    assert!(matches!(err, Err(FrameError::UnknownStatus { status: 9 })));
}

#[test]
fn short_new_meta_without_address_is_insufficient() {
    let body = [0x00, 0x01, SESSION_STATUS_NEW, OPTION_DATA];
    let err = FrameMetadata::decode_meta(&body, true);
    assert!(matches!(err, Err(FrameError::ShortMeta { got: 4 })));
}

#[test]
fn data_frame_roundtrip_and_size_guard() {
    let mut wire = Vec::new();
    encode_data_into(&mut wire, b"hello").expect("可编码");
    assert_eq!(&wire[..2], &[0x00, 0x05]);
    assert_eq!(read_data(&mut &wire[..], true).expect("可读"), b"hello");
    // 写端不设 8KiB 上限（参考的 8192 是 SplitSize 分片大小，不是拒绝阈值）；
    // 读端才按 `size > buf.Size` 拒绝。
    let big = vec![0u8; STREAM_CHUNK_SIZE + 1];
    encode_data_into(&mut Vec::new(), &big).expect("写端允许超过分片大小");
    let mut oversize = vec![0x20, 0x01]; // 8193
    oversize.extend_from_slice(&big);
    assert!(matches!(
        read_data(&mut &oversize[..], true),
        Err(FrameError::PacketTooLarge { size: 8193 })
    ));
}
