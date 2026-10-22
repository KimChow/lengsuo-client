//! Vision 服务端流量层的单元测试（从父模块拆出以保持单文件 ≤400 行软约束）。
//!
//! 断言与拆分前逐字一致，未增删任何用例。

use super::super::client::{
    InboundState, VisionClient, COMMAND_PADDING_CONTINUE, COMMAND_PADDING_DIRECT,
    COMMAND_PADDING_END,
};
use super::super::framing::is_complete_record;
use super::super::test_util::CounterRng;
use super::super::unpad::Unpad;
use super::*;

const UUID: [u8; 16] = [0x22; 16];

fn server() -> VisionServer {
    VisionServer::new(UUID, None, Box::new(CounterRng(0)))
}

/// 从 padding 块解析 `(command, content, padding)`（剥可选 16 字节 UUID）。
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
fn unpad_roundtrips_single_continue_block_with_uuid() {
    // 造：UUID + Continue + content "hello" + 0 padding。
    let mut block = UUID.to_vec();
    block.push(COMMAND_PADDING_CONTINUE);
    block.extend_from_slice(&5u16.to_be_bytes());
    block.extend_from_slice(&0u16.to_be_bytes());
    block.extend_from_slice(b"hello");
    let mut state = InboundState::default();
    let mut out = Vec::new();
    state.unpad(&block, &UUID, &mut out);
    assert_eq!(out, b"hello");
    // Continue 后进入下一块头读取（块未结束）。
    assert_eq!(state.remaining_command, 5);
    assert_eq!(state.current_command, 0);
}

#[test]
fn unpad_strips_padding_and_ends_on_end_command() {
    // Continue 块 + End 块：应只吐内容，End 后回初始态。
    let mut wire = UUID.to_vec();
    wire.push(COMMAND_PADDING_CONTINUE);
    wire.extend_from_slice(&3u16.to_be_bytes());
    wire.extend_from_slice(&4u16.to_be_bytes());
    wire.extend_from_slice(b"abc");
    wire.extend_from_slice(&[0u8; 4]);
    wire.push(COMMAND_PADDING_END);
    wire.extend_from_slice(&0u16.to_be_bytes());
    wire.extend_from_slice(&2u16.to_be_bytes());
    wire.extend_from_slice(&[0u8; 2]);
    let mut state = InboundState::default();
    let mut out = Vec::new();
    state.unpad(&wire, &UUID, &mut out);
    assert_eq!(out, b"abc");
    assert!(state.is_initial());
    assert_eq!(state.current_command, COMMAND_PADDING_END as i32);
}

#[test]
fn unpad_returns_raw_when_first_block_lacks_uuid() {
    // 初始态但首 16 字节不是 UUID → 原样返回，不解析块。
    let wire = b"not a vision block at all";
    let mut state = InboundState::default();
    let mut out = Vec::new();
    state.unpad(wire, &UUID, &mut out);
    assert_eq!(out, wire);
    assert!(state.is_initial());
}

#[test]
fn unpad_reassembles_content_crossing_block_boundary() {
    // Continue 块（无 padding，内容 11 字节）紧接 End 块：`unpad` 需跨块重组，
    // 两个块命令不同但内容应连续吐出。
    let mut wire = UUID.to_vec();
    wire.push(COMMAND_PADDING_CONTINUE);
    wire.extend_from_slice(&11u16.to_be_bytes());
    wire.extend_from_slice(&0u16.to_be_bytes());
    wire.extend_from_slice(b"hello world");
    wire.push(COMMAND_PADDING_END);
    wire.extend_from_slice(&0u16.to_be_bytes());
    wire.extend_from_slice(&0u16.to_be_bytes());
    let mut state = InboundState::default();
    let mut out = Vec::new();
    state.unpad(&wire, &UUID, &mut out);
    assert_eq!(out, b"hello world");
    assert!(state.is_initial());
    assert_eq!(state.current_command, COMMAND_PADDING_END as i32);
}

#[test]
fn server_decode_uplink_roundtrips_client_encode() {
    // 本仓客户端上行编码 → 本仓服务端上行解码，逐字节一致。
    let payloads: Vec<Vec<u8>> = vec![
        b"request one".to_vec(),
        b"request two".to_vec(),
        b"request three".to_vec(),
    ];
    let mut wire = Vec::new();
    let mut expected = Vec::new();
    {
        let mut client = VisionClient::new(UUID, None, Box::new(CounterRng(0)));
        for (i, payload) in payloads.iter().enumerate() {
            let mut block = client.encode_uplink(payload);
            if i == payloads.len() - 1 {
                block.extend_from_slice(&client.encode_uplink_finish());
            }
            wire.extend_from_slice(&block);
            expected.extend_from_slice(payload);
        }
    }
    let mut server = server();
    let mut got = Vec::new();
    for chunk in wire.chunks(7) {
        server.decode_uplink(chunk, &mut got);
    }
    assert_eq!(got, expected);
    assert!(!server.state.inbound.within_padding_buffers);
}

#[test]
fn server_downlink_roundtrips_client_decode_downlink() {
    // 本仓服务端下行编码 → 本仓客户端下行解码，逐字节一致。
    let payloads: Vec<Vec<u8>> = vec![
        b"response one".to_vec(),
        b"response two".to_vec(),
        b"".to_vec(),
    ];
    let mut client = VisionClient::new(UUID, None, Box::new(CounterRng(0)));
    let mut server = server();
    let mut wire = Vec::new();
    let mut expected = Vec::new();
    for (i, payload) in payloads.iter().enumerate() {
        let first_empty = payload.is_empty();
        let mut block = if first_empty {
            server.encode_downlink(payload, true)
        } else {
            server.encode_downlink(payload, false)
        };
        if i == payloads.len() - 1 {
            block.extend_from_slice(&server.encode_downlink_finish());
        }
        wire.extend_from_slice(&block);
        expected.extend_from_slice(payload);
    }
    let mut got = Vec::new();
    for chunk in wire.chunks(5) {
        client.decode_downlink(chunk, &mut got);
    }
    assert_eq!(got, expected);
}

#[test]
fn downlink_empty_first_write_uses_long_padding_rule() {
    let mut server = server();
    let block = server.encode_downlink(&[], true);
    let (command, content, padding) = parse_block(&block);
    assert_eq!(command, COMMAND_PADDING_CONTINUE);
    assert!(content.is_empty());
    // CounterRng 首值 0：padding = 900 + 0 - 0。
    assert_eq!(padding.len(), 900);
    assert!((900..1400).contains(&padding.len()));
}

#[test]
fn downlink_first_block_carries_uuid_once() {
    let mut server = server();
    let first = server.encode_downlink(b"first", false);
    assert_eq!(&first[..16], &UUID[..]);
    let second = server.encode_downlink(b"second", false);
    assert!(second.len() < 16 || second[..16] != UUID[..]);
}

#[test]
fn downlink_direct_command_switches_direct_copy() {
    // 构造 TLS ServerHello 使 IsTLS / EnableXtls 打开，随后一条完整 TLS 应用数据块
    // 应触发 Direct 命令并切直拷贝。
    let mut server = server();
    // 第 1 次：ServerHello（控制 IsTLS/EnableXtls）。
    let mut hello = vec![0x16, 0x03, 0x03, 0x00, 0x4E, 0x02];
    hello.resize(80, 0);
    hello[50] = 0x00;
    hello[51] = 0x2b;
    hello[52] = 0x00;
    hello[53] = 0x02;
    hello[54] = 0x03;
    hello[55] = 0x04;
    let suite_start = 43 + 1;
    hello[suite_start] = 0x13;
    hello[suite_start + 1] = 0x01;
    let _ = server.encode_downlink(&hello, false);
    assert!(server.state.is_tls && server.state.enable_xtls);
    // 第 2 次：完整 TLS 应用数据记录（头 17 03 03 + BE16 长 = 体长，体为 8 字节）。
    let body = b"hello123";
    let mut record = vec![0x17, 0x03, 0x03, 0x00, body.len() as u8];
    record.extend_from_slice(body);
    assert!(is_complete_record(&record));
    let block = server.encode_downlink(&record, false);
    let (command, content, _) = parse_block(&block);
    assert_eq!(command, COMMAND_PADDING_DIRECT);
    assert_eq!(content, &record[..]);
    assert!(server.downlink_direct_copy());
    assert!(!server.state.inbound.is_padding);
}

#[test]
fn uplink_direct_command_switches_direct_copy() {
    // 服务端上行：客户端发来 Direct 命令块后进入直拷贝，后续字节原样透传。
    let mut server = server();
    let mut wire = UUID.to_vec();
    wire.push(COMMAND_PADDING_DIRECT);
    wire.extend_from_slice(&3u16.to_be_bytes());
    wire.extend_from_slice(&0u16.to_be_bytes());
    wire.extend_from_slice(b"abc");
    let mut out = Vec::new();
    server.decode_uplink(&wire, &mut out);
    assert_eq!(out, b"abc");
    assert!(server.uplink_direct_copy());
    let mut more = Vec::new();
    server.decode_uplink(b"raw tail", &mut more);
    assert_eq!(more, b"raw tail");
}
