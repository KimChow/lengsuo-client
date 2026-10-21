//! `vision_wire` 的**错误输入 fail-closed** 用例：非法参数 / 截断输入 ⇒
//! **显式报错**，不是静默产出垃圾数据。
//!
//! 覆盖：
//! 1. 记录层配置非法（空上下文 / 空密钥材料）⇒ 构造即失败；
//! 2. 记录层**截断输入** ⇒ 读时显式报错（`UnexpectedEof`）；
//! 3. 记录层**认证失败**（篡改）⇒ 读时显式报错（`InvalidData`）；
//! 4. 握手 padding 参数非法 ⇒ 显式报错，不静默改用参考默认表；
//! 5. 流量层：上行收尾后再写 ⇒ `BrokenPipe`；
//! 6. 流量层：`write_first` 重复调用 ⇒ 显式报错。

use lengsuo_vless::vision::record::{Cipher, RecordWriter};
use lengsuo_vless::vision_wire::{handshake_padding, RecordStream, VisionStream, VisionWireError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::common::{record_config, vision_config, CounterRng, CTX, KEY, LIMIT, PIPE};

/// 记录层配置非法（空上下文 / 空密钥材料）⇒ **构造即失败**，不产出任何字节。
#[test]
fn record_stream_rejects_empty_config() {
    let (client, _server) = tokio::io::duplex(PIPE);
    let mut config = record_config();
    config.ctx = String::new();
    assert!(matches!(
        RecordStream::new(client, &config),
        Err(VisionWireError::InvalidConfig(_))
    ));

    let (client, _server) = tokio::io::duplex(PIPE);
    let mut config = record_config();
    config.key = Vec::new();
    assert!(matches!(
        RecordStream::new(client, &config),
        Err(VisionWireError::InvalidConfig(_))
    ));
}

/// 记录层**截断输入** ⇒ 经新 API 读时显式报错（不是静默产出垃圾数据）。
///
/// 线上只放半条记录，然后让承载流 EOF：`RecordStream` 必须在收尾时报错。
#[tokio::test]
async fn record_stream_reports_truncated_input() {
    // 造一条真实记录，再截掉尾部 3 字节。
    let mut writer = RecordWriter::new(CTX, &KEY, Cipher::Aes256Gcm);
    let mut wire = writer.seal(b"truncated record body").unwrap();
    wire.truncate(wire.len() - 3);

    let (client, server) = tokio::io::duplex(PIPE);
    let mut stream = RecordStream::new(client, &record_config()).unwrap();

    // 对端只写截断的字节然后关闭（EOF）。
    let feeder = tokio::spawn(async move {
        let mut server = server;
        server.write_all(&wire).await.unwrap();
        server.shutdown().await.unwrap();
    });

    let mut buf = [0u8; 64];
    let outcome = tokio::time::timeout(LIMIT, stream.read(&mut buf)).await;
    feeder.await.unwrap();
    let outcome = outcome.expect("读超时");
    assert!(outcome.is_err(), "截断输入必须显式报错，实得 {outcome:?}");
    assert_eq!(
        outcome.unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof,
        "截断必须是 UnexpectedEof（fail-closed）"
    );
}

/// 记录层**认证失败**（线上字节被篡改）⇒ 经新 API 读时显式报错。
#[tokio::test]
async fn record_stream_reports_tampered_input() {
    let mut writer = RecordWriter::new(CTX, &KEY, Cipher::Aes256Gcm);
    let mut wire = writer.seal(b"authenticated record body").unwrap();
    // 改记录体的一个字节 ⇒ AEAD 认证失败。
    let last = wire.len() - 1;
    wire[last] ^= 0x01;

    let (client, server) = tokio::io::duplex(PIPE);
    let mut stream = RecordStream::new(client, &record_config()).unwrap();

    let feeder = tokio::spawn(async move {
        let mut server = server;
        server.write_all(&wire).await.unwrap();
        server.shutdown().await.unwrap();
    });

    let mut buf = [0u8; 64];
    let outcome = tokio::time::timeout(LIMIT, stream.read(&mut buf)).await;
    feeder.await.unwrap();
    let outcome = outcome.expect("读超时");
    assert!(outcome.is_err(), "篡改必须显式报错，实得 {outcome:?}");
    assert_eq!(
        outcome.unwrap_err().kind(),
        std::io::ErrorKind::InvalidData,
        "认证失败必须是 InvalidData（fail-closed）"
    );
}

/// 握手 padding 参数非法 ⇒ **显式报错**，不静默改用参考默认表。
#[test]
fn handshake_padding_rejects_invalid_spec() {
    let mut rng = CounterRng(0);
    for spec in ["99-35-35", "100-34-35", "100-35-34", "100", "a-b-c"] {
        assert!(
            matches!(
                handshake_padding(spec, &mut rng),
                Err(VisionWireError::Padding(_))
            ),
            "{spec} 必须显式报错"
        );
    }
    // 合法参数 ⇒ 计划可解算（长度 = 各段之和）。
    let plan = handshake_padding("100-111-1111.75-0-111.50-0-3333", &mut rng).unwrap();
    assert_eq!(plan.length, plan.lens.iter().sum::<usize>());
    assert_eq!(plan.gaps.len(), 1);
}

/// 流量层：上行收尾后再写 ⇒ 显式报错（`BrokenPipe`），不是静默丢弃。
#[tokio::test]
async fn vision_stream_rejects_write_after_finish() {
    let (client, _server) = tokio::io::duplex(PIPE);
    let mut stream = VisionStream::with_rng(client, vision_config(), Box::new(CounterRng(0)));
    stream.finish_uplink().await.unwrap();
    let error = stream.write_all(b"after finish").await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
}

/// 流量层：`write_first` 重复调用 ⇒ 显式报错。
#[tokio::test]
async fn vision_stream_rejects_second_write_first() {
    let (client, _server) = tokio::io::duplex(PIPE);
    let mut stream = VisionStream::with_rng(client, vision_config(), Box::new(CounterRng(0)));
    stream.write_first(None).await.unwrap();
    assert!(matches!(
        stream.write_first(None).await,
        Err(VisionWireError::UplinkFinished)
    ));
}
