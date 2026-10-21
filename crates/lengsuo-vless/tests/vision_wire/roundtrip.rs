//! `vision_wire` 的**正常往返**用例：载荷必须逐字节一致。
//!
//! 覆盖：
//! 1. 流量层往返（明文 → `VisionStream` → 线上字节 → `VisionStream` → 明文）；
//! 2. 记录层往返（明文 → `RecordStream` → 线上字节 → `RecordStream` → 明文）；
//! 3. 两层组合（参考顺序：流量层在外、记录层在内）；
//! 4. 首包直发决策（前导与首个块**同一次**写出）；
//! 5. 承载流写不动时的**恢复**（tokio 的「`Pending` 后必须用同一个 buffer 回来」
//!    契约）——不丢字节、不重复编码。

use lengsuo_vless::vision::server::VisionServer;
use lengsuo_vless::vision_wire::{RecordStream, VisionStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::common::{drain, record_config, vision_config, CounterRng, PIPE, UUID};

/// 流量层往返：明文 → `VisionStream` → 线上字节 → `VisionStream` → 明文，
/// 载荷必须**逐字节一致**。
#[tokio::test]
async fn vision_stream_roundtrip_preserves_payload_bytes() {
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    let (client, server) = tokio::io::duplex(PIPE);

    let mut client = VisionStream::with_rng(client, vision_config(), Box::new(CounterRng(0)));
    let mut server = VisionStream::with_rng(server, vision_config(), Box::new(CounterRng(0)));

    let sent = payload.clone();
    let writer = tokio::spawn(async move {
        client.write_all(&sent).await.unwrap();
        client.finish_uplink().await.unwrap();
        client.shutdown().await.unwrap();
    });

    let got = drain(&mut server).await;
    writer.await.unwrap();
    assert_eq!(got, payload, "流量层往返必须逐字节一致");
}

/// 记录层往返：明文 → `RecordStream` → 线上字节 → `RecordStream` → 明文，
/// 载荷必须**逐字节一致**。
#[tokio::test]
async fn record_stream_roundtrip_preserves_payload_bytes() {
    let payload: Vec<u8> = (0..30_000u32).map(|i| (i % 253) as u8).collect();
    let (client, server) = tokio::io::duplex(PIPE);

    let mut client = RecordStream::new(client, &record_config()).unwrap();
    let mut server = RecordStream::new(server, &record_config()).unwrap();

    let sent = payload.clone();
    let writer = tokio::spawn(async move {
        client.write_all(&sent).await.unwrap();
        client.shutdown().await.unwrap();
    });

    let got = drain(&mut server).await;
    writer.await.unwrap();
    assert_eq!(got, payload, "记录层往返必须逐字节一致");
}

/// 两层组合（参考顺序：流量层在外、记录层在内）：`VisionStream<RecordStream<S>>`
/// 往返必须逐字节一致。
#[tokio::test]
async fn vision_over_record_roundtrip_preserves_payload_bytes() {
    let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 241) as u8).collect();
    let (raw_client, raw_server) = tokio::io::duplex(PIPE);

    let client = RecordStream::new(raw_client, &record_config()).unwrap();
    let server = RecordStream::new(raw_server, &record_config()).unwrap();
    let mut client = VisionStream::with_rng(client, vision_config(), Box::new(CounterRng(7)));
    let mut server = VisionStream::with_rng(server, vision_config(), Box::new(CounterRng(7)));

    let sent = payload.clone();
    let writer = tokio::spawn(async move {
        client.write_all(&sent).await.unwrap();
        client.finish_uplink().await.unwrap();
        client.shutdown().await.unwrap();
    });

    let got = drain(&mut server).await;
    writer.await.unwrap();
    assert_eq!(got, payload, "流量层 + 记录层往返必须逐字节一致");
}

/// 首包直发决策（参考 `postRequest`）：`write_first(Some(..))` 与
/// `write_first(None)` 两条路径都必须把首个块与前导（VLESS 头）**同一次**写出。
#[tokio::test]
async fn vision_stream_write_first_sends_preamble_with_first_block() {
    let preamble = b"\x00VLESS-HEADER-BYTES".to_vec();
    let payload = b"first payload".to_vec();

    for first in [Some(payload.as_slice()), None] {
        let (client, mut server) = tokio::io::duplex(PIPE);
        let mut stream = VisionStream::with_rng(client, vision_config(), Box::new(CounterRng(0)));
        stream.set_preamble(&preamble);
        stream.write_first(first).await.unwrap();

        let mut wire = vec![0u8; PIPE];
        let read = tokio::time::timeout(super::common::LIMIT, server.read(&mut wire))
            .await
            .expect("读超时")
            .unwrap();
        assert!(read > preamble.len());
        assert_eq!(
            &wire[..preamble.len()],
            &preamble[..],
            "前导必须与首个块同一次写出"
        );
        // 首个块之后紧跟 vision 块头：UUID（16 字节）。
        assert_eq!(&wire[preamble.len()..preamble.len() + 16], &UUID[..]);
    }
}

/// 承载流**写不动**时（管道容量小于一次 vision 写入）⇒ `poll_write` 必须返回
/// `Pending` 并在读端腾出空间后**继续写完**同一轮（tokio 的
/// 「`Pending` 后必须用同一个 buffer 回来」契约）。
///
/// 这是「不丢字节、不重复编码」的关键路径：容量不足时一轮写入跨多次 poll。
#[tokio::test]
async fn vision_stream_resumes_a_blocked_write_without_losing_bytes() {
    // 管道容量刻意小于一个 vision 块（vision 块 = 21 字节头 + 内容 + padding）。
    let (client, mut server) = tokio::io::duplex(128);
    let mut stream = VisionStream::with_rng(client, vision_config(), Box::new(CounterRng(0)));
    let payload = vec![0x7Au8; 4096];

    let sent = payload.clone();
    let writer = tokio::spawn(async move {
        // `write_all` 内部会在 `Pending` 后用同一个 buffer 重试。
        stream.write_all(&sent).await.unwrap();
        stream.finish_uplink().await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let got = drain(&mut server).await;
    writer.await.unwrap();

    // 用既有原语解出明文：必须是**一份**载荷，不能重复也不能丢。
    //
    // 方向：本仓 `VisionStream` 写的是**上行**块 ⇒ 用服务端侧的上行读原语
    // [`VisionServer::decode_uplink`] 解（客户端侧 `decode_downlink` 解的是**下行**
    // 块，方向相反，不能混用）。
    let mut reader = VisionServer::new(UUID, None, Box::new(CounterRng(0)));
    let mut plain = Vec::new();
    for chunk in got.chunks(29) {
        reader.decode_uplink(chunk, &mut plain);
    }
    assert_eq!(plain, payload, "阻塞后恢复必须既不丢字节也不重复编码");
}
