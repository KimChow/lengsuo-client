//! 本仓客户端 ↔ 本仓服务端 Vision 流量层 Rust↔Rust 回环（非 `#[ignore]`）。
//!
//! 不依赖参考二进制：直接对 [`VisionClient`]（上行编码 / 下行解码）与
//! [`VisionServer`]（上行解码 / 下行编码）做字节级回环，覆盖：
//! - 小 / 大 / 空首包三种首包决策；
//! - 逐块（短块）喂入跨块重组；
//! - 256 KiB 大载荷逐字节比对。
use lengsuo_vless::vision::{client::VisionClient, server::VisionServer};

const KEY: [u8; 16] = [0x33; 16];
/// 覆盖「跨多条块」且不触发 `ReshapeMultiBuffer` 拆段的写入分块。
const CHUNK: usize = 4096;

fn server() -> VisionServer {
    VisionServer::new_with_os_rng(KEY, None)
}

fn client() -> VisionClient {
    VisionClient::new_with_os_rng(KEY, None)
}

/// 客户端上行编码 → 服务端上行解码，按 `wire_step` 分块喂入。
fn uplink_roundtrip(payload: &[u8], first_empty: bool, wire_step: usize) -> Vec<u8> {
    let mut client = client();
    let mut wire = Vec::new();
    let first_take = if first_empty {
        0
    } else {
        CHUNK.min(payload.len())
    };
    wire.extend_from_slice(&client.encode_first_uplink(if first_empty {
        None
    } else {
        Some(&payload[..first_take])
    }));
    let mut offset = first_take;
    while offset < payload.len() {
        let take = CHUNK.min(payload.len() - offset);
        wire.extend_from_slice(&client.encode_uplink(&payload[offset..offset + take]));
        offset += take;
    }
    wire.extend_from_slice(&client.encode_uplink_finish());

    let mut server = server();
    let mut got = Vec::new();
    for chunk in wire.chunks(wire_step.max(1)) {
        server.decode_uplink(chunk, &mut got);
    }
    got
}

/// 服务端下行编码 → 客户端下行解码，按 `wire_step` 分块喂入。
fn downlink_roundtrip(payload: &[u8], first_empty: bool, wire_step: usize) -> Vec<u8> {
    let mut server = server();
    let mut wire = Vec::new();
    if first_empty {
        wire.extend_from_slice(&server.encode_downlink(&[], true));
    }
    let mut offset = 0;
    while offset < payload.len() {
        let take = CHUNK.min(payload.len() - offset);
        wire.extend_from_slice(&server.encode_downlink(&payload[offset..offset + take], false));
        offset += take;
    }
    wire.extend_from_slice(&server.encode_downlink_finish());

    let mut client = client();
    let mut got = Vec::new();
    for chunk in wire.chunks(wire_step.max(1)) {
        client.decode_downlink(chunk, &mut got);
    }
    got
}

#[test]
fn uplink_small_payload_matches_byte_for_byte() {
    let payload = b"vision rust to rust uplink".to_vec();
    assert_eq!(uplink_roundtrip(&payload, false, 7), payload);
}

#[test]
fn uplink_empty_first_packet_uses_long_padding_block() {
    // 空首包：客户端插入 0 内容长 padding 块，服务端须剥离且不产出多余字节。
    let payload = b"after empty first".to_vec();
    assert_eq!(uplink_roundtrip(&payload, true, 13), payload);
}

#[test]
fn uplink_large_payload_matches_byte_for_byte() {
    let payload = (0..256 * 1024u32)
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>();
    assert_eq!(uplink_roundtrip(&payload, false, 1024), payload);
}

#[test]
fn downlink_small_payload_matches_byte_for_byte() {
    let payload = b"vision rust to rust downlink".to_vec();
    assert_eq!(downlink_roundtrip(&payload, false, 5), payload);
}

#[test]
fn downlink_large_payload_matches_byte_for_byte() {
    let payload = (0..256 * 1024u32)
        .map(|i| (i % 253) as u8)
        .collect::<Vec<_>>();
    assert_eq!(downlink_roundtrip(&payload, false, 333), payload);
}

#[test]
fn downlink_empty_first_write_is_skipped_by_reader() {
    // 服务端首包为空 → 插入 0 内容 Continue 块；客户端解码须只吐出真实内容。
    let payload = b"real downlink payload".to_vec();
    assert_eq!(downlink_roundtrip(&payload, true, 11), payload);
}

#[test]
fn every_split_of_a_small_stream_roundtrips() {
    // 对一条小上行 wire 逐一取分块步长，验证跨块重组在每个切点都成立。
    let payload = b"boundary sensitive payload across blocks".to_vec();
    let mut client = client();
    let mut wire = Vec::new();
    wire.extend_from_slice(&client.encode_uplink(&payload));
    wire.extend_from_slice(&client.encode_uplink_finish());

    for step in 1..=wire.len().min(64) {
        let mut server = server();
        let mut got = Vec::new();
        for chunk in wire.chunks(step) {
            server.decode_uplink(chunk, &mut got);
        }
        assert_eq!(got, payload, "分块步长 {step}");
    }
}
