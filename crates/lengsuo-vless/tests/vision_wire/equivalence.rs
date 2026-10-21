//! `vision_wire` 与**既有实现**的等价性用例：这是「接线正确、没改语义」的
//! **硬证据**。
//!
//! 关键点：用**确定性 RNG**（计数器 RNG）让 vision padding 的随机长度可复现，
//! 于是「新 API 写出的线上字节」可以和「直接调用既有 `VisionClient` /
//! `RecordWriter` 得到的字节」逐字节对比——任何接线偏差都会在这里暴露。
//!
//! 双向各证一次：
//! - **正向**：新 API 的线上输出 == 既有原语的输出（逐字节相同）；
//! - **反向**：新 API 的线上输入能被既有原语读出同样的明文（没引入额外封装）。

use lengsuo_vless::vision::client::VisionClient;
use lengsuo_vless::vision::record::{RecordReader, RecordWriter};
use lengsuo_vless::vision::server::VisionServer;
use lengsuo_vless::vision_wire::{RecordStream, VisionStream};
use tokio::io::AsyncWriteExt;

use super::common::{drain, record_config, vision_config, CounterRng, CTX, KEY, PIPE, UUID};

/// **等价性硬证据**：新 API（`VisionStream`）写出的线上字节，与**直接**调用既有
/// `VisionClient::encode_uplink` 得到的字节**逐字节相同**。
///
/// 确定性 RNG ⇒ padding 长度可复现 ⇒ 任何接线偏差都会在这里暴露。
#[tokio::test]
async fn vision_stream_output_is_byte_identical_to_existing_primitive() {
    let payloads: Vec<Vec<u8>> = vec![
        b"alpha".to_vec(),
        b"beta payload".to_vec(),
        vec![0x5Au8; 1500],
        (0..9000u32).map(|i| (i % 199) as u8).collect(),
    ];

    // 既有原语：直接调 `VisionClient`。
    let mut existing = VisionClient::new(UUID, None, Box::new(CounterRng(0)));
    let mut expected = Vec::new();
    for payload in &payloads {
        expected.extend_from_slice(&existing.encode_uplink(payload));
    }
    expected.extend_from_slice(&existing.encode_uplink_finish());

    // 新 API：走 `VisionStream`（同样的确定性 RNG ⇒ 同样的 padding 长度）。
    let (client, mut server) = tokio::io::duplex(256 * 1024);
    let mut stream = VisionStream::with_rng(client, vision_config(), Box::new(CounterRng(0)));
    let writer = tokio::spawn(async move {
        for payload in &payloads {
            stream.write_all(payload).await.unwrap();
        }
        stream.finish_uplink().await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let got = drain(&mut server).await;
    writer.await.unwrap();

    assert_eq!(got.len(), expected.len(), "线上字节长度必须一致");
    assert_eq!(got, expected, "新 API 与既有原语的线上字节必须逐字节相同");
}

/// **等价性硬证据**：新 API（`RecordStream`）写出的线上字节，与**直接**调用既有
/// `RecordWriter::seal` 得到的字节**逐字节相同**。
#[tokio::test]
async fn record_stream_output_is_byte_identical_to_existing_primitive() {
    let payloads: Vec<Vec<u8>> = vec![b"first".to_vec(), vec![0x11u8; 8192], vec![0x22u8; 8193]];

    let mut existing =
        RecordWriter::new(CTX, &KEY, lengsuo_vless::vision::record::Cipher::Aes256Gcm);
    let mut expected = Vec::new();
    for payload in &payloads {
        expected.extend_from_slice(&existing.seal(payload).unwrap());
    }

    let (client, mut server) = tokio::io::duplex(256 * 1024);
    let mut stream = RecordStream::new(client, &record_config()).unwrap();
    let writer = tokio::spawn(async move {
        for payload in &payloads {
            stream.write_all(payload).await.unwrap();
        }
        stream.shutdown().await.unwrap();
    });

    let got = drain(&mut server).await;
    writer.await.unwrap();

    assert_eq!(got, expected, "新 API 与既有原语的线上字节必须逐字节相同");
}

/// 记录层等价性的**反向**证据：新 API 收到的线上字节能被既有
/// `RecordReader` 读出**同样的明文**（接线没有引入额外封装/改写）。
#[tokio::test]
async fn record_stream_input_is_readable_by_existing_primitive() {
    let payload = b"existing reader must accept new writer output".to_vec();
    let (client, mut server) = tokio::io::duplex(PIPE);
    let mut stream = RecordStream::new(client, &record_config()).unwrap();
    let sent = payload.clone();
    let writer = tokio::spawn(async move {
        stream.write_all(&sent).await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let wire = drain(&mut server).await;
    writer.await.unwrap();

    let mut reader = RecordReader::new(CTX, &KEY, lengsuo_vless::vision::record::Cipher::Aes256Gcm);
    reader.push(&wire).unwrap();
    let mut got = Vec::new();
    while let Some(plain) = reader.next_plaintext().unwrap() {
        got.extend_from_slice(&plain);
    }
    reader.finish().unwrap();
    assert_eq!(got, payload, "既有读侧必须能直接读出新写侧的输出");
}

/// 流量层等价性的**反向**证据：新 API 收到的线上字节能被既有
/// [`VisionServer::decode_uplink`] 读出**同样的明文**。
///
/// 方向说明：`VisionStream` 写的是**上行**块，对端是服务端 ⇒ 用服务端侧的上行读
/// 原语解（客户端侧 `decode_downlink` 解的是下行块，方向相反）。
#[tokio::test]
async fn vision_stream_input_is_readable_by_existing_primitive() {
    let payload: Vec<u8> = (0..5000u32).map(|i| (i % 233) as u8).collect();
    let (client, mut server) = tokio::io::duplex(PIPE);
    let mut stream = VisionStream::with_rng(client, vision_config(), Box::new(CounterRng(3)));
    let sent = payload.clone();
    let writer = tokio::spawn(async move {
        stream.write_all(&sent).await.unwrap();
        stream.finish_uplink().await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let wire = drain(&mut server).await;
    writer.await.unwrap();

    let mut reader = VisionServer::new(UUID, None, Box::new(CounterRng(3)));
    let mut got = Vec::new();
    for chunk in wire.chunks(37) {
        reader.decode_uplink(chunk, &mut got);
    }
    assert_eq!(got, payload, "既有读侧必须能直接读出新写侧的输出");
}

/// **回归**：客户端下行块头被切成多次读时，不得把剩余块头字节当明文吐给调用方。
///
/// 复现路径：服务端下行写出一条 `End` 块（块头 5 字节 + 内容 + padding），客户端
/// 按 1 字节 / 2 字节 / 5 字节等极小步长喂进 [`VisionClient::decode_downlink`]。
///
/// 缺陷现象（修复前）：块头跨读边界时，`within_padding_buffers` 被提前置 `false`，
/// 后续字节走「直通明文」分支 ⇒ 5 个块头字节（`01 00 00 00 01`）被当作明文追加到
/// 输出尾部，载荷被污染（`4096 → 4101` 字节）。
///
/// 修复：状态更新额外把「块头尚未读完」（`remaining_command > 0`）判为仍在 padding
/// 阶段（与 [`VisionServer::decode_uplink`] 的同一补强对称）。
#[tokio::test]
async fn client_downlink_decoder_survives_split_block_header() {
    let payload = b"downlink payload that must not be polluted".to_vec();

    // 服务端下行编码：首块（带 UUID）+ 收尾 `End` 块。
    let mut server = VisionServer::new(UUID, None, Box::new(CounterRng(0)));
    let mut wire = server.encode_downlink(&payload, false);
    wire.extend_from_slice(&server.encode_downlink_finish());

    // 客户端下行解码：多种极小步长（含 1 字节，即块头被切成 5 次读）。
    for step in [1usize, 2, 3, 4, 5, 6, 7, 11, 29] {
        let mut reader = VisionClient::new(UUID, None, Box::new(CounterRng(0)));
        let mut got = Vec::new();
        for chunk in wire.chunks(step) {
            reader.decode_downlink(chunk, &mut got);
        }
        assert_eq!(
            got, payload,
            "步长 {step} 字节时下行块头跨读边界，块头字节不得泄漏成明文"
        );
    }
}
