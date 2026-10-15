//! 传统 Shadowsocks AEAD 异步 TCP 字节 chunk 层（`TcpWriter` / `TcpReader`）的正常
//! 路径与结构测试。口令是测试专用假凭据；这些自建 roundtrip 只证明本实现内部
//! 一致，**不宣称与参考实现实跑互通**（互通验收状态见 `docs/shadowsocks-status.md`）。
//!
//! 覆盖：四套件双向往返、每方向独立随机 salt、按上限跨 chunk 分块、目标地址字节
//! 跨 chunk 由上层续读、空输入不写终止帧、写半关闭后另一方向仍可回包（内存与真实
//! TCP 回环）。全部异步读写由 `tokio::time::timeout` 约束；读到 EOF 之前先关写半。

use std::time::Duration;

use lengsuo_shadowsocks::{CipherSuite, TargetAddr, TcpReader, TcpWriter, MAX_SEGMENT_PAYLOAD};
use ss_core::chunk::SIZE_WIRE_LEN;
use ss_core::crypto::TAG_LEN;
use tokio::io::{duplex, split, AsyncRead};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// 测试假口令，与任何生产凭据无关。
const PASSWORD: &[u8] = b"tcp-roundtrip-passw0rd";

const WAIT: Duration = Duration::from_secs(2);

const ALL_SUITES: [CipherSuite; 4] = [
    CipherSuite::Aes128Gcm,
    CipherSuite::Aes256Gcm,
    CipherSuite::ChaCha20IetfPoly1305,
    CipherSuite::XChaCha20IetfPoly1305,
];

/// 一个 chunk 的线上字节数：size 段 + 载荷密文（含 tag）。
fn frame_len(plain_len: usize) -> usize {
    SIZE_WIRE_LEN + plain_len + TAG_LEN
}

/// 单方向封包：一个 writer 依次 send 各段后写半关闭，返回线上字节。
/// `Vec<u8>` 作为写端只累积字节，不引入任何额外成帧。
async fn seal(suite: CipherSuite, segments: &[&[u8]]) -> Vec<u8> {
    let mut wire: Vec<u8> = Vec::new();
    {
        let mut writer =
            TcpWriter::new(&mut wire, suite, PASSWORD, WAIT).expect("测试套件应可构造写端");
        assert!(!writer.salt_sent(), "new 本身不做 I/O，salt 不得提前上线");
        for segment in segments {
            timeout(WAIT, writer.send(segment))
                .await
                .expect("send 未被外层超时")
                .expect("写出应成功");
            assert!(writer.salt_sent(), "成功 send 之后 salt 必已上线");
        }
        timeout(WAIT, writer.shutdown())
            .await
            .expect("shutdown 未被外层超时")
            .expect("正常收尾应成功");
    }
    wire
}

/// 单方向取包：最多 32 次 `recv`，绝不无限读流。返回（重组字节, 每 chunk 长度）。
async fn open<R: AsyncRead + Unpin>(suite: CipherSuite, read: R) -> (Vec<u8>, Vec<usize>) {
    let mut reader = TcpReader::new(read, suite, PASSWORD, WAIT).expect("可构造读端");
    let mut bytes = Vec::new();
    let mut sizes = Vec::new();
    for _ in 0..32 {
        match timeout(WAIT, reader.recv())
            .await
            .expect("recv 未被外层超时")
            .expect("读取应成功")
        {
            Some(chunk) => {
                assert!(
                    !chunk.is_empty(),
                    "正常 send 不得交付空 chunk（不伪造 EOF 帧）"
                );
                sizes.push(chunk.len());
                bytes.extend_from_slice(&chunk);
            }
            None => return (bytes, sizes),
        }
    }
    panic!("chunk 数量超过测试上限");
}

#[tokio::test]
async fn four_suites_roundtrip_both_directions() {
    timeout(WAIT, async {
        for suite in ALL_SUITES {
            let first = {
                let mut seg = Vec::new();
                TargetAddr::Domain("example.invalid".into(), 53)
                    .encode_checked(&mut seg)
                    .expect("假域名可编码");
                seg.extend_from_slice(b"GET /index HTTP/1.1\r\n\r\n");
                seg
            };
            let (mut client, server) = duplex(64 * 1024);
            let (mut server_read, mut server_write) = split(server);
            // 客户端 → 服务端方向。
            let mut writer = TcpWriter::new(&mut client, suite, PASSWORD, WAIT).expect("可构造");
            timeout(WAIT, writer.send(&first))
                .await
                .expect("send 未被外层超时")
                .expect("首段可写出");
            timeout(WAIT, writer.send(b"second segment bytes"))
                .await
                .expect("send 未被外层超时")
                .expect("次段可写出");
            // 服务端 → 客户端方向：独立 writer（独立 salt 与独立 nonce 序列）。
            let mut reply_writer =
                TcpWriter::new(&mut server_write, suite, PASSWORD, WAIT).expect("可构造");
            timeout(WAIT, reply_writer.send(b"HTTP/1.1 200 OK\r\n\r\nbody"))
                .await
                .expect("send 未被外层超时")
                .expect("回包可写出");
            // 读到 EOF 之前先关写半。
            timeout(WAIT, writer.shutdown())
                .await
                .expect("shutdown 未被外层超时")
                .expect("可半关闭");
            timeout(WAIT, reply_writer.shutdown())
                .await
                .expect("shutdown 未被外层超时")
                .expect("可半关闭");

            let (got, sizes) = timeout(WAIT, open(suite, &mut server_read))
                .await
                .expect("任务未被外层超时");
            let mut want = first.clone();
            want.extend_from_slice(b"second segment bytes");
            assert_eq!(got, want, "{suite:?} 请求方向字节不符");
            assert_eq!(sizes, vec![first.len(), 20], "{suite:?} 应按 send 边界成帧");

            let (reply, _) = timeout(WAIT, open(suite, &mut client))
                .await
                .expect("任务未被外层超时");
            assert_eq!(reply, b"HTTP/1.1 200 OK\r\n\r\nbody", "{suite:?} 回包不符");
        }
    })
    .await
    .expect("四套件往返超时");
}

#[tokio::test]
async fn each_direction_gets_a_fresh_random_salt_of_suite_length() {
    timeout(WAIT, async {
        for suite in ALL_SUITES {
            let a = seal(suite, &[b"same plaintext"]).await;
            let b = seal(suite, &[b"same plaintext"]).await;
            // salt 长度只由套件定义（AES-128-GCM 16，其余 32）。
            assert_eq!(a[..suite.salt_len()].len(), suite.salt_len());
            assert_ne!(
                &a[..suite.salt_len()],
                &b[..suite.salt_len()],
                "{suite:?} 两次封包必须用不同的随机 salt"
            );
            // 相同明文 + 不同 salt ⇒ 线上字节必然完全不同（不存在固定前缀复用）。
            assert_ne!(a, b, "{suite:?} 相同明文不应产出相同密文");
            assert_eq!(
                a.len(),
                suite.salt_len() + frame_len(14),
                "{suite:?} 帧总长不符"
            );
            // 两个方向互不相关 ⇒ 各自的 reader 都能解出自己那条流。
            let (got, _) = timeout(WAIT, open(suite, a.as_slice()))
                .await
                .expect("任务未被外层超时");
            assert_eq!(got, b"same plaintext");
            let (other, _) = timeout(WAIT, open(suite, b.as_slice()))
                .await
                .expect("任务未被外层超时");
            assert_eq!(other, b"same plaintext");
        }
    })
    .await
    .expect("salt 独立性超时");
}

#[tokio::test]
async fn oversized_input_is_split_across_chunks_and_reassembled() {
    timeout(WAIT, async {
        let total = MAX_SEGMENT_PAYLOAD + 4096;
        let big: Vec<u8> = (0..total).map(|i| i as u8).collect();
        let wire = seal(CipherSuite::Aes256Gcm, &[&big]).await;
        // 单次 send 的输入按上限切成两块；线上不含任何 size 明文为 0 的终止帧，
        // 因此总长恰为 salt + 两个 chunk 帧（这个等式同时排除了多余帧）。
        assert_eq!(
            wire.len(),
            CipherSuite::Aes256Gcm.salt_len() + frame_len(MAX_SEGMENT_PAYLOAD) + frame_len(4096),
            "分块后的线上长度不符"
        );
        let (got, sizes) = timeout(WAIT, open(CipherSuite::Aes256Gcm, wire.as_slice()))
            .await
            .expect("任务未被外层超时");
        assert_eq!(got, big, "跨 chunk 重组必须逐字节一致");
        assert_eq!(
            sizes,
            vec![MAX_SEGMENT_PAYLOAD, 4096],
            "载荷不得超过单个 chunk 明文上限，且不得补空帧"
        );
        // 上限本身与 size 段的 BE16 表达范围一致。
        assert!(MAX_SEGMENT_PAYLOAD > 0 && MAX_SEGMENT_PAYLOAD <= u16::MAX as usize);
    })
    .await
    .expect("跨 chunk 分块超时");
}

#[tokio::test]
async fn target_address_bytes_split_across_chunks_reassemble() {
    timeout(WAIT, async {
        // 上层把目标地址编进首段明文，本层只搬字节：地址字节被切成两个 chunk
        // 时，reader 交付的字节流仍然是同一序列，上层可续读解码。
        let mut encoded = Vec::new();
        TargetAddr::V6(
            [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00,
            ],
            8080,
        )
        .encode_checked(&mut encoded)
        .expect("假 IPv6 目标可编码");
        encoded.extend_from_slice(b"payload after address");
        let mid = 9; // 落在 IPv6 地址结构中间 ⇒ 必然跨 chunk
        let wire = seal(
            CipherSuite::ChaCha20IetfPoly1305,
            &[&encoded[..mid], &encoded[mid..]],
        )
        .await;
        let (bytes, sizes) = timeout(
            WAIT,
            open(CipherSuite::ChaCha20IetfPoly1305, wire.as_slice()),
        )
        .await
        .expect("任务未被外层超时");
        assert_eq!(bytes, encoded, "跨 chunk 字节序列不得丢失或重排");
        assert_eq!(sizes, vec![mid, encoded.len() - mid]);
        let (target, consumed) = TargetAddr::decode(&bytes).expect("上层可续读解码地址");
        assert_eq!(consumed, encoded.len() - b"payload after address".len());
        assert_eq!(
            target,
            TargetAddr::V6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00,],
                8080
            )
        );
        assert_eq!(&bytes[consumed..], b"payload after address");
    })
    .await
    .expect("地址跨 chunk 超时");
}

#[tokio::test]
async fn empty_input_puts_only_salt_on_the_wire() {
    timeout(WAIT, async {
        for suite in ALL_SUITES {
            let wire = seal(suite, &[&[]]).await;
            assert_eq!(
                wire.len(),
                suite.salt_len(),
                "{suite:?} 空载荷 send 只写 salt，不得写任何 chunk 帧（包括终止帧）"
            );
            let (bytes, sizes) = timeout(WAIT, open(suite, wire.as_slice()))
                .await
                .expect("任务未被外层超时");
            assert!(
                bytes.is_empty() && sizes.is_empty(),
                "{suite:?} 空输入方向应读到零 chunk 后正常收尾"
            );
        }
        // 空 send 可反复调用（只保证 salt 上线），并且零 chunk 方向读满即 EOF。
        let (mut client, mut server) = duplex(64);
        let mut writer =
            TcpWriter::new(&mut client, CipherSuite::Aes128Gcm, PASSWORD, WAIT).expect("可构造");
        for _ in 0..3 {
            timeout(WAIT, writer.send(&[]))
                .await
                .expect("send 未被外层超时")
                .expect("空载荷可写出");
        }
        timeout(WAIT, writer.shutdown())
            .await
            .expect("shutdown 未被外层超时")
            .expect("可半关闭");
        let (bytes, _) = timeout(WAIT, open(CipherSuite::Aes128Gcm, &mut server))
            .await
            .expect("任务未被外层超时");
        assert!(bytes.is_empty());
    })
    .await
    .expect("空输入超时");
}

#[tokio::test]
async fn half_close_in_memory_leaves_the_other_direction_open() {
    timeout(WAIT, async {
        let (mut client, server) = duplex(4096);
        let (mut server_read, mut server_write) = split(server);
        let mut writer =
            TcpWriter::new(&mut client, CipherSuite::Aes128Gcm, PASSWORD, WAIT).expect("可构造");
        let mut reply = TcpWriter::new(&mut server_write, CipherSuite::Aes128Gcm, PASSWORD, WAIT)
            .expect("可构造");
        timeout(WAIT, writer.send(b"ping"))
            .await
            .expect("send 未被外层超时")
            .expect("可写入");
        timeout(WAIT, writer.shutdown())
            .await
            .expect("shutdown 未被外层超时")
            .expect("可半关闭写端");
        // 半关闭之后：重复 shutdown 幂等，send 一律拒绝。
        timeout(WAIT, writer.shutdown())
            .await
            .expect("shutdown 未被外层超时")
            .expect("重复 shutdown 应幂等");
        let err = timeout(WAIT, writer.send(b"late"))
            .await
            .expect("send 未被外层超时")
            .expect_err("半关闭之后不得再发送");
        assert!(
            matches!(err, lengsuo_shadowsocks::TcpError::Closed),
            "应报 Closed，实际 {err:?}"
        );

        let (got, _) = timeout(WAIT, open(CipherSuite::Aes128Gcm, &mut server_read))
            .await
            .expect("任务未被外层超时");
        assert_eq!(got, b"ping", "读端应恰好在 chunk 边界看到 EOF");
        timeout(WAIT, reply.send(b"pong"))
            .await
            .expect("send 未被外层超时")
            .expect("回包方向不受写半关闭影响");
        timeout(WAIT, reply.shutdown())
            .await
            .expect("shutdown 未被外层超时")
            .expect("可半关闭");
        let (reply_bytes, _) = timeout(WAIT, open(CipherSuite::Aes128Gcm, &mut client))
            .await
            .expect("任务未被外层超时");
        assert_eq!(reply_bytes, b"pong", "半关闭只断一个方向");
    })
    .await
    .expect("内存半关闭超时");
}

#[tokio::test]
async fn real_tcp_loopback_half_close_then_reply() {
    timeout(WAIT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("可监听");
        let addr = listener.local_addr().expect("可取地址");
        let server = tokio::spawn(async move {
            let (accepted, _peer) = listener.accept().await.expect("可接受");
            let (mut read, mut write) = split(accepted);
            let (got, _) = open(CipherSuite::Aes128Gcm, &mut read).await;
            assert_eq!(got, b"ping over real tcp", "服务端应收到完整请求方向");
            let mut reply = TcpWriter::new(&mut write, CipherSuite::Aes128Gcm, PASSWORD, WAIT)
                .expect("可构造回包写端");
            timeout(WAIT, reply.send(b"pong"))
                .await
                .expect("send 未被外层超时")
                .expect("可回写");
            timeout(WAIT, reply.shutdown())
                .await
                .expect("shutdown 未被外层超时")
                .expect("回包方向收尾");
        });

        let connected = TcpStream::connect(addr).await.expect("可连接");
        let (mut read, mut write) = split(connected);
        let mut writer =
            TcpWriter::new(&mut write, CipherSuite::Aes128Gcm, PASSWORD, WAIT).expect("可构造");
        timeout(WAIT, writer.send(b"ping over real tcp"))
            .await
            .expect("send 未被外层超时")
            .expect("可写入");
        // 读到回包 EOF 之前必须关写半（tokio 的 shutdown 对 TcpStream 只做 SHUT_WR）。
        timeout(WAIT, writer.shutdown())
            .await
            .expect("shutdown 未被外层超时")
            .expect("可半关闭写端");
        let (reply, _) = timeout(WAIT, open(CipherSuite::Aes128Gcm, &mut read))
            .await
            .expect("任务未被外层超时");
        assert_eq!(reply, b"pong", "真实 TCP 半关闭后仍可收到回包");
        server.await.expect("服务端任务");
    })
    .await
    .expect("真实 TCP 半关闭超时");
}
