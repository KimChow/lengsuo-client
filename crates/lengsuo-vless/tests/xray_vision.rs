//! VLESS Vision（`flow=xtls-rprx-vision`）客户端 ↔ 固定版本 Xray 入站互通。
//! 三个用例默认 `#[ignore]`，必须显式 `--ignored` 运行；未设置 `LENGSUO_XRAY`
//! 时打印跳过原因后返回（跳过不是互通通过，只有真正连上参考二进制才算）。
mod support;

use lengsuo_tls::TlsClient;
use lengsuo_vless::{
    header::{Command, Flow, Request},
    vision::client::VisionClient,
};
use serde_json::json;
use ss_core::target::TargetAddr;
use support::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

/// 上行第二次开始的分块大小。参考 `ReshapeMultiBuffer` 会把 ≥`buf.Size-21`（8171）
/// 的缓冲拆开，避免 `paddingLen = 8192-21-contentLen` 掉到负数；这里取 4096，同时
/// 覆盖「256 KiB 跨多条块」且不触发负 padding 边界。
const UPLINK_CHUNK: usize = 4096;

/// 参考 `Settings`：flow 必须写进 client 条目的 `"flow"` 字段。
fn vision_config(port: u16, cert: &rcgen::CertifiedKey) -> serde_json::Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": ID, "flow": "xtls-rprx-vision"}],
                "decryption": "none"
            },
            "streamSettings": {
                "security": "tls",
                "tlsSettings": {"certificates": [{
                    "certificate": cert.cert.pem().lines().collect::<Vec<_>>(),
                    "key": cert.key_pair.serialize_pem().lines().collect::<Vec<_>>()
                }]}
            }
        }],
        "outbounds": [{"protocol": "freedom"}]
    })
}

/// 解析首个上行 padding 块的 padding 长度，并校验块内自洽。
/// 块布局（参考 `XtlsPadding`）：`[16 字节 UUID][command(1)][contentLen BE16][paddingLen BE16][content][padding]`。
fn first_block_lengths(block: &[u8]) -> (u8, usize, usize) {
    assert!(block.len() >= 21, "首块至少 21 字节，实际 {}", block.len());
    assert_eq!(&block[..16], &KEY[..], "首个 padding 块必须携带 UUID");
    let command = block[16];
    let content_len = usize::from(u16::from_be_bytes([block[17], block[18]]));
    let padding_len = usize::from(u16::from_be_bytes([block[19], block[20]]));
    assert_eq!(
        block.len(),
        21 + content_len + padding_len,
        "块自洽：21 + content + padding"
    );
    (command, content_len, padding_len)
}

/// 一次完整回程：建立 Xray 入站 + 目标回环，按 first 决策发上行，读 `[0,0]` 响应头
/// 后解包下行直到收齐 payload。返回 `(首个 padding 块, 解包后的明文字节)`。
async fn run_vision_echo(payload: &[u8], first: Option<&[u8]>, chunk: usize) -> (Vec<u8>, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = listener.local_addr().unwrap().port();
    let port = free_port();
    let reference = launch(vision_config(port, &cert), port).await;

    // 目标回环：读满 payload 精确回写（不依赖 EOF 来判定回程边界）。
    let echo_payload = payload.to_vec();
    let echo = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = vec![0u8; echo_payload.len()];
        socket.read_exact(&mut received).await.unwrap();
        assert_eq!(received, echo_payload, "目标收到的上行明文必须逐字节一致");
        socket.write_all(&received).await.unwrap();
        socket.shutdown().await.unwrap();
    });

    let client = TlsClient::new("localhost", [cert.cert.der().clone()], WAIT).unwrap();
    let mut stream = client.connect(([127, 0, 0, 1], port).into()).await.unwrap();
    let request = Request {
        command: Command::Tcp,
        target: TargetAddr::V4([127, 0, 0, 1], target_port),
    };
    let header =
        lengsuo_vless::header::encode_with_flow(&request, &KEY, Flow::XtlsRprxVision).unwrap();
    let mut vision = VisionClient::new_with_os_rng(KEY, None);

    // 头与首个 padding 块必须同一次写出，使参考入站首个 vision 读 ≥21 字节。
    let mut wire = header;
    let first_block = match first {
        Some(_) => {
            let take = chunk.min(payload.len());
            let block = vision.encode_first_uplink(Some(&payload[..take]));
            wire.extend_from_slice(&block);
            let mut offset = take;
            while offset < payload.len() {
                let take = chunk.min(payload.len() - offset);
                wire.extend_from_slice(&vision.encode_uplink(&payload[offset..offset + take]));
                offset += take;
            }
            block
        }
        None => {
            let block = vision.encode_first_uplink(None);
            wire.extend_from_slice(&block);
            let mut offset = 0;
            while offset < payload.len() {
                let take = chunk.min(payload.len() - offset);
                wire.extend_from_slice(&vision.encode_uplink(&payload[offset..offset + take]));
                offset += take;
            }
            block
        }
    };
    wire.extend_from_slice(&vision.encode_uplink_finish());
    stream.write_all(&wire).await.unwrap();
    stream.flush().await.unwrap();

    // 响应头固定为空 addons `[0,0]`；其后才是 vision 流量。
    let mut response_header = [0u8; 2];
    stream.read_exact(&mut response_header).await.unwrap();
    assert_eq!(response_header, [0, 0], "vision 响应 addons 必须为空");

    let mut got = Vec::with_capacity(payload.len());
    let mut raw = [0u8; 16384];
    loop {
        if got.len() >= payload.len() {
            break;
        }
        match stream.read(&mut raw).await {
            Ok(0) => break,
            Ok(read) => vision.decode_downlink(&raw[..read], &mut got),
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => panic!("读回程失败 {error}"),
        }
    }
    stream.shutdown().await.unwrap();
    echo.await.unwrap();
    drop(reference);
    (first_block, got)
}

fn skip_without_binary() -> bool {
    if std::env::var("LENGSUO_XRAY").is_err() {
        eprintln!("跳过：未设置 LENGSUO_XRAY（未连接参考二进制，不算互通通过）");
        return true;
    }
    false
}

/// 情况 A：首包走「无数据 → 0 内容长 padding 块」路径。
/// padding 参考规则（独立复算）：`contentLen < 900 && long` → `900 + rand(0,500)`，
/// 落在 `[900, 1400)`；再随小载荷收尾。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn vision_small_first_packet_uses_long_padding() {
    if skip_without_binary() {
        return;
    }
    let payload = b"vision small first packet".to_vec();
    let (first_block, got) = timeout(WAIT * 2, run_vision_echo(&payload, None, UPLINK_CHUNK))
        .await
        .expect("互通超时");
    let (command, content_len, padding_len) = first_block_lengths(&first_block);
    assert_eq!(command, 0, "空首块命令应是 PADDING_CONTINUE");
    assert_eq!(content_len, 0, "空首块无内容");
    assert!(
        (900..1400).contains(&padding_len),
        "独立复算：p = 900 + rand(0,500) - 0 ∈ [900,1400)，实得 {padding_len}"
    );
    assert_eq!(got, payload, "下行解包必须逐字节一致");
}

/// 情况 B：首包 ≥900 字节，走「短 padding」直发路径。
/// padding 参考规则（独立复算）：`contentLen >= testseed[0]` 且非 long → `rand(0,256)`。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn vision_large_first_packet_uses_short_padding() {
    if skip_without_binary() {
        return;
    }
    let payload = (0..900u32).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let (first_block, got) = timeout(WAIT * 2, run_vision_echo(&payload, Some(&payload), 900))
        .await
        .expect("互通超时");
    let (command, content_len, padding_len) = first_block_lengths(&first_block);
    assert_eq!(command, 0, "首包命令应是 PADDING_CONTINUE");
    assert_eq!(content_len, 900, "首块内容应原样携带");
    assert!(
        padding_len < 256,
        "独立复算：p = rand(0,256) ∈ [0,256)，实得 {padding_len}"
    );
    assert_eq!(got, payload, "下行解包必须逐字节一致");
}

/// 情况 C：256 KiB 跨多条 padding 块回程，比对解包后的明文。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn vision_256kib_roundtrip_byte_compared() {
    if skip_without_binary() {
        return;
    }
    let payload = (0..256 * 1024u32)
        .map(|i| (i % 253) as u8)
        .collect::<Vec<_>>();
    let (first_block, got) = timeout(
        WAIT * 2,
        run_vision_echo(&payload, Some(&payload), UPLINK_CHUNK),
    )
    .await
    .expect("互通超时");
    let (_command, content_len, padding_len) = first_block_lengths(&first_block);
    assert_eq!(content_len, UPLINK_CHUNK, "首块携带第一个分块");
    assert!(padding_len < 256, "首块短 padding：p = rand(0,256)");
    assert_eq!(got.len(), payload.len(), "下行明文长度应与回程一致");
    assert_eq!(got, payload, "256 KiB 回程必须逐字节一致");
}
