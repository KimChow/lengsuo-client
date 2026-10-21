//! Vision 客户端流量层的单元测试（从父模块拆出以保持单文件 ≤400 行软约束）。
//!
//! 断言与拆分前逐字一致，未增删任何用例。

use super::super::test_util::CounterRng;
use super::*;

const UUID: [u8; 16] = [0x11; 16];

fn client() -> VisionClient {
    VisionClient::new(UUID, None, Box::new(CounterRng(0)))
}

/// 从 padding 块解析出 `(command, content, padding)`（已剥离可选的 16 字节 UUID）。
fn parse_block(block: &[u8]) -> (u8, &[u8], &[u8]) {
    let tail = if block.len() >= 16 && block[..16] == UUID {
        &block[16..]
    } else {
        block
    };
    let command = tail[0];
    let content_len = (usize::from(tail[1]) << 8) | usize::from(tail[2]);
    let padding_len = (usize::from(tail[3]) << 8) | usize::from(tail[4]);
    assert_eq!(tail[5..].len(), content_len + padding_len);
    let (content, padding) = tail[5..].split_at(content_len);
    (command, content, padding)
}

#[test]
fn first_packet_empty_uses_long_padding_rule() {
    let mut c = client();
    let block = c.encode_first_uplink(None);
    // CounterRng 第一次 next_u64=0：padding = 900 + 0 - 0。
    let (command, content, padding) = parse_block(&block);
    assert_eq!(command, COMMAND_PADDING_CONTINUE);
    assert!(content.is_empty());
    assert_eq!(padding.len(), 900);
    // 独立复算的参考规则边界：[900, 1400)，且 ≤ 8171 - content。
    assert!((900..1400).contains(&(padding.len())));
}

#[test]
fn first_packet_large_uses_direct_small_padding_rule() {
    let mut c = client();
    let payload = vec![0xABu8; 900];
    let block = c.encode_first_uplink(Some(&payload));
    let (command, content, padding) = parse_block(&block);
    assert_eq!(command, COMMAND_PADDING_CONTINUE);
    assert_eq!(content, &payload[..]);
    // contentLen >= testseed[0] 且 longPadding=false → rand(0, 256)，CounterRng 首值 0。
    assert_eq!(padding.len(), 0);
    assert!(padding.len() < 256);
}

#[test]
fn seven_writes_end_padding_then_direct_passthrough() {
    let mut c = client();
    let mut commands = Vec::new();
    for i in 0..8u8 {
        let payload = [i; 3];
        let block = c.encode_uplink(&payload);
        if block.as_slice() == &payload[..] {
            commands.push(0xFF); // 直通标记（不再包块）
        } else {
            let (command, content, _) = parse_block(&block);
            assert_eq!(content, &payload[..], "第 {} 次写入内容", i);
            commands.push(command);
        }
    }
    // 前 6 次 Continue，第 7 次 End，第 8 次直通（无 padding 块）。
    assert_eq!(
        commands,
        vec![
            COMMAND_PADDING_CONTINUE,
            COMMAND_PADDING_CONTINUE,
            COMMAND_PADDING_CONTINUE,
            COMMAND_PADDING_CONTINUE,
            COMMAND_PADDING_CONTINUE,
            COMMAND_PADDING_CONTINUE,
            COMMAND_PADDING_END,
            0xFF,
        ]
    );
}

#[test]
fn uplink_finish_emits_end_once() {
    let mut c = client();
    let payload = b"lonely request".to_vec();
    let block = c.encode_uplink(&payload);
    let (command, content, _) = parse_block(&block);
    assert_eq!(command, COMMAND_PADDING_CONTINUE);
    assert_eq!(content, &payload[..]);
    assert!(c.state.outbound.is_padding);
    let tail = c.encode_uplink_finish();
    assert!(!tail.is_empty());
    let (command, content, _) = parse_block(&tail);
    assert_eq!(command, COMMAND_PADDING_END);
    assert!(content.is_empty());
    assert!(!c.state.outbound.is_padding);
    assert!(c.encode_uplink_finish().is_empty());
}

#[test]
fn uuid_appears_only_in_the_first_block() {
    let mut c = client();
    let first = c.encode_uplink(b"first");
    assert_eq!(&first[..16], &UUID[..]);
    let second = c.encode_uplink(b"second");
    assert!(second.len() < 16 || second[..16] != UUID[..]);
}

#[test]
fn writer_reader_roundtrip_padding_blocks() {
    let payloads: Vec<Vec<u8>> = vec![
        b"shard one".to_vec(),
        b"shard two".to_vec(),
        b"shard three".to_vec(),
    ];
    let mut writer = client();
    let mut wire = Vec::new();
    let mut expected = Vec::new();
    for (i, payload) in payloads.iter().enumerate() {
        let mut block = writer.encode_uplink(payload);
        if i == payloads.len() - 1 {
            block.extend_from_slice(&writer.encode_uplink_finish());
        }
        wire.extend_from_slice(&block);
        expected.extend_from_slice(payload);
    }
    let mut reader = client();
    let mut got = Vec::new();
    for chunk in wire.chunks(7) {
        reader.decode_downlink(chunk, &mut got);
    }
    assert_eq!(got, expected);
    assert!(!reader.state.outbound.within_padding_buffers);
}

#[test]
fn reader_skips_padding_and_stops_after_continue_then_end() {
    let mut writer = client();
    // 首块带 UUID + Continue + content + padding，末块 End + 0 内容 + padding。
    let mut wire = writer.xtls_padding(COMMAND_PADDING_CONTINUE, b"abc", false);
    wire.extend_from_slice(&writer.xtls_padding(COMMAND_PADDING_END, b"", false));
    let mut reader = client();
    let mut out = Vec::new();
    // 一条消息切开喂给状态机，仍须只产出 "abc"。
    for chunk in wire.chunks(5) {
        reader.decode_downlink(chunk, &mut out);
    }
    assert_eq!(out, b"abc");
    assert!(!reader.state.outbound.within_padding_buffers);
}

#[test]
fn is_complete_record_accepts_only_whole_tls_records() {
    // 完整单记录：头 17 03 03 + BE16=3 + 3 字节体。
    let ok = vec![0x17, 0x03, 0x03, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
    assert!(is_complete_record(&ok));
    // 体被截断。
    let truncated = vec![0x17, 0x03, 0x03, 0x00, 0x03, 0xAA];
    assert!(!is_complete_record(&truncated));
    // 魔数不符。
    let bad_magic = vec![0x18, 0x03, 0x03, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
    assert!(!is_complete_record(&bad_magic));
}

#[test]
fn filter_recognizes_tls_13_server_hello() {
    // 构造最小可识别的 ServerHello：头 16 03 03 + BE16 长度 + 0x02。
    let mut state = TrafficState::new(UUID);
    let mut hello = vec![0x16, 0x03, 0x03, 0x00, 0x4E, 0x02];
    hello.resize(80, 0);
    // 嵌入 TLS 1.3 supported_versions 扩展（魔数 00 2b 00 02 03 04）。
    hello[50] = 0x00;
    hello[51] = 0x2b;
    hello[52] = 0x00;
    hello[53] = 0x02;
    hello[54] = 0x03;
    hello[55] = 0x04;
    // session_id_len 置 0；cipher suite 置 TLS_AES_128_GCM_SHA256（0x1301）。
    let session_id_len = 0usize;
    let suite_start = 43 + session_id_len + 1;
    hello[suite_start] = 0x13;
    hello[suite_start + 1] = 0x01;
    xtls_filter_tls_single(&mut state, &hello);
    assert!(state.is_tls && state.is_tls12_or_above);
    assert!(state.enable_xtls, "AES-128-GCM-SHA256 应开启直拷贝判据");
    assert_eq!(state.number_of_packet_to_filter, 0);
    assert_eq!(state.cipher, 0x1301);
}

#[test]
fn padding_length_respects_reference_clamp() {
    // contentLen < 900 且 longPadding：p=900+[0,500)-contentLen。
    assert_eq!(
        padding_length(100, true, &DEFAULT_TEST_SEED, &mut CounterRng(0)),
        800
    ); // 900 + 0 - 100
       // 短 padding 分支超上限时夹紧到 8192-21-contentLen。
    assert_eq!(
        padding_length(8000, false, &DEFAULT_TEST_SEED, &mut CounterRng(255)),
        8192 - 21 - 8000
    );
    // 大 contentLen 未逼近上限：p=[0,256)，不夹紧。
    assert_eq!(
        padding_length(900, false, &DEFAULT_TEST_SEED, &mut CounterRng(5)),
        5
    );
}

#[test]
fn padding_length_never_goes_negative() {
    // contentLen ≥ testseed[0]=900 但 longPadding 为真时，公式
    // `900 + rand(0,500) - contentLen` 会下溢成负数（参考用
    // NumberOfPacketToFilter 保证不可达，本仓接口不保证）。必须夹到 0：
    // 负值一旦 `as usize` 会在调试构建 panic。
    assert_eq!(
        padding_length(1200, true, &DEFAULT_TEST_SEED, &mut CounterRng(0)),
        0
    );
    // 夹紧与 0 下界共存：contentLen 撑爆 8192-21 上界时 max 本身为负。
    assert_eq!(
        padding_length(9000, false, &DEFAULT_TEST_SEED, &mut CounterRng(255)),
        0
    );
}
