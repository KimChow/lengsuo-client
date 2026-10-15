//! Trojan UDP 数据报帧测试（请求头握手见 `tests/stream.rs`）。
//!
//! 覆盖：固定线上字节、两帧背靠背边界、IPv4/域名/IPv6 与极值载荷长度往返、
//! 发送侧与接收侧超长拒绝、坏 CRLF、帧截断、静默对端超时、零时长拒绝、
//! 单个截止时间覆盖整操作、错误不泄漏凭据。
//! 密码为测试专用假凭据；这些自建 roundtrip 只证明本实现内部一致，
//! 不宣称与 Xray 实跑互通。

use std::time::Duration;

use lengsuo_trojan::stream::{receive_datagram, send_datagram, Error};
use lengsuo_trojan::Credential;
use lengsuo_trojan::TargetAddr;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// 测试假密码。
const PASSWORD: &str = "Trojan-Test-Passwd";

/// 正常操作等待；SILENT 用于确认静默对端确实超时。
const WAIT: Duration = Duration::from_secs(2);
const SILENT: Duration = Duration::from_millis(30);

fn udp_target() -> TargetAddr {
    TargetAddr::V4([192, 0, 2, 1], 53)
}

/// 不经被测实现手工拼 UDP 帧，用于固定字节比对与损坏用例。
/// 测试地址均为已构造的合法值，故可直接使用 encode_into。
fn raw_frame(target: &TargetAddr, payload: &[u8], crlf: [u8; 2]) -> Vec<u8> {
    let mut buf = Vec::new();
    target.encode_into(&mut buf);
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(&crlf);
    buf.extend_from_slice(payload);
    buf
}

#[tokio::test]
async fn udp_frame_fixed_bytes_on_wire() {
    timeout(WAIT, async {
        let (mut client, mut server) = duplex(1024);
        send_datagram(&mut client, &udp_target(), b"hi", WAIT)
            .await
            .unwrap();
        // 长度字段是载荷字节数 2，分隔符必须是 CRLF。
        let expected = raw_frame(&udp_target(), b"hi", *b"\r\n");
        assert_eq!(
            expected,
            vec![0x01, 192, 0, 2, 1, 0, 53, 0, 2, b'\r', b'\n', b'h', b'i']
        );
        let mut seen = vec![0u8; expected.len()];
        server.read_exact(&mut seen).await.expect("可读原始帧");
        assert_eq!(
            seen, expected,
            "线上字节必须与 SOCKS 地址 + 大端长度 + CRLF + 载荷 一致"
        );
    })
    .await
    .expect("固定字节超时");
}

#[tokio::test]
async fn udp_two_frames_keep_boundaries() {
    timeout(WAIT, async {
        let (mut client, mut server) = duplex(8192);
        let first = vec![0xa5u8; 40];
        let second = vec![0x5au8; 3];
        send_datagram(&mut client, &udp_target(), &first, WAIT)
            .await
            .unwrap();
        send_datagram(
            &mut client,
            &TargetAddr::Domain("udp.test".into(), 5353),
            &second,
            WAIT,
        )
        .await
        .unwrap();

        // 两帧背靠背也必须按边界分读，不合并也不拆分。
        let (seen, body) = receive_datagram(&mut server, u16::MAX, WAIT).await.unwrap();
        assert_eq!((seen, body), (udp_target(), first));
        let (seen, body) = receive_datagram(&mut server, u16::MAX, WAIT).await.unwrap();
        assert_eq!(
            (seen, body),
            (TargetAddr::Domain("udp.test".into(), 5353), second)
        );

        // 帧读完之后流上没有多余字节被吞掉：对端静默即超时。
        assert!(matches!(
            receive_datagram(&mut server, u16::MAX, SILENT).await,
            Err(Error::Timeout)
        ));
    })
    .await
    .expect("双帧边界超时");
}

#[tokio::test]
async fn udp_roundtrip_covers_all_address_kinds() {
    timeout(WAIT, async {
        let targets = [
            TargetAddr::V4([198, 51, 100, 9], 9747),
            TargetAddr::Domain("sub.domain.example".into(), 8443),
            TargetAddr::V6([0x20u8; 16], 65535),
            TargetAddr::Domain("l".repeat(255), 1),
        ];
        for target in targets {
            for len in [0usize, 1, 255, 1500, 65535] {
                let (mut client, mut server) = duplex(70000);
                let packet = vec![(len % 251) as u8; len];
                send_datagram(&mut client, &target, &packet, WAIT)
                    .await
                    .unwrap();
                let (seen, body) = receive_datagram(&mut server, u16::MAX, WAIT).await.unwrap();
                assert_eq!(seen, target, "地址类型 {target:?} 长度 {len}");
                assert_eq!(body, packet, "长度 {len}");
            }
        }
    })
    .await
    .expect("UDP 地址往返超时");
}

#[tokio::test]
async fn udp_oversize_rejected_before_allocation_and_write() {
    timeout(WAIT, async {
        // 发送侧：载荷超出 2 字节长度域（>65535）在写任何字节前拒绝。
        let (mut client, mut server) = duplex(70000);
        let too_long = vec![0u8; 65536];
        assert!(matches!(
            send_datagram(&mut client, &udp_target(), &too_long, WAIT).await,
            Err(Error::FrameTooLarge)
        ));
        assert!(
            matches!(
                receive_datagram(&mut server, u16::MAX, SILENT).await,
                Err(Error::Timeout)
            ),
            "被拒绝的帧不得写出任何字节"
        );
        // 同一侧仍可用于合法帧：拒绝不会污染写端。
        send_datagram(&mut client, &udp_target(), b"ok", WAIT)
            .await
            .unwrap();

        // 接收侧：limit 在分配前检查，超限立即拒绝（长度域可达 65535）。
        let (mut writer, mut reader) = duplex(4096);
        writer
            .write_all(&raw_frame(&udp_target(), &[7u8; 1000], *b"\r\n"))
            .await
            .expect("可写入");
        assert!(matches!(
            receive_datagram(&mut reader, 512, WAIT).await,
            Err(Error::FrameTooLarge)
        ));

        // 域名长度非法的地址同样在写入前被 encode_checked 拒绝。
        for host in [String::new(), "x".repeat(256)] {
            let (mut w, mut r) = duplex(128);
            assert!(matches!(
                send_datagram(&mut w, &TargetAddr::Domain(host, 53), b"x", WAIT).await,
                Err(Error::Core(_))
            ));
            assert!(matches!(
                receive_datagram(&mut r, u16::MAX, SILENT).await,
                Err(Error::Timeout)
            ));
        }
    })
    .await
    .expect("超长拒绝超时");
}

#[tokio::test]
async fn udp_bad_crlf_and_truncated_frames_fail() {
    timeout(WAIT, async {
        let payload = b"abcdefgh".to_vec();
        // 坏 CRLF：只有 LF、CR 缺失、只有 CR，以及空格分隔，都必须拒绝。
        for crlf in [*b"\n\r", *b"\r\0", *b"\n\n", *b"  "] {
            let (mut writer, mut reader) = duplex(4096);
            writer
                .write_all(&raw_frame(&udp_target(), &payload, crlf))
                .await
                .expect("可写入");
            assert!(
                matches!(
                    receive_datagram(&mut reader, u16::MAX, WAIT).await,
                    Err(Error::InvalidCrlf)
                ),
                "分隔符 {crlf:?}"
            );
        }

        // 帧截断：每个截断点关闭写端后只能得到 EOF 类错误，绝不误判成功。
        // 截断点覆盖地址段、长度域、CRLF 与载荷。
        let frame = raw_frame(&udp_target(), &payload, *b"\r\n");
        assert_eq!(frame.len(), 7 + 2 + 2 + payload.len());
        for end in [1usize, 4, 6, 7, 8, 9, 10, 11, frame.len() - 1] {
            let (mut writer, mut reader) = duplex(4096);
            writer.write_all(&frame[..end]).await.expect("可写入");
            writer.shutdown().await.expect("可关闭写端");
            assert!(
                matches!(
                    receive_datagram(&mut reader, u16::MAX, WAIT).await,
                    Err(Error::Io(_))
                ),
                "截断点 {end}"
            );
        }

        // 非法 ATYP 与空域名在地址解析时立即失败，不等到超时。
        for bytes in [
            vec![0x99, 0, 0, 0, 0, 0, 80, 0, 1, b'\r', b'\n', b'x'],
            vec![0x03, 0, 0, 80, 0, 1, b'\r', b'\n'],
        ] {
            let (mut writer, mut reader) = duplex(4096);
            writer.write_all(&bytes).await.expect("可写入");
            assert!(
                matches!(
                    receive_datagram(&mut reader, u16::MAX, SILENT).await,
                    Err(Error::Core(_))
                ),
                "非法地址字节 {bytes:?}"
            );
        }
    })
    .await
    .expect("坏 CRLF 与截断超时");
}

#[tokio::test]
async fn one_deadline_covers_whole_fragmented_frame() {
    timeout(WAIT, async {
        // 分片且中途停顿超过截止时间：整操作超时，不因后续字节到达而成功。
        let frame = raw_frame(&udp_target(), b"payload", *b"\r\n");
        let (mut writer, mut reader) = duplex(4096);
        let split = frame.len() - 3;
        writer.write_all(&frame[..split]).await.expect("可写入首片");
        let rest = frame[split..].to_vec();
        let laggard = tokio::spawn(async move {
            tokio::time::sleep(SILENT).await;
            writer.write_all(&rest).await.expect("可写入尾片");
        });
        assert!(matches!(
            receive_datagram(&mut reader, u16::MAX, Duration::from_millis(5)).await,
            Err(Error::Timeout)
        ));
        laggard.await.expect("延迟写端任务");

        // 同样的分片在足够长的截止时间内可完整读出。
        let (mut writer, mut reader) = duplex(1);
        let bytes = frame.clone();
        let sender = tokio::spawn(async move {
            for byte in bytes {
                writer.write_all(&[byte]).await.expect("可写入");
            }
        });
        let (seen, body) = receive_datagram(&mut reader, u16::MAX, WAIT).await.unwrap();
        assert_eq!(seen, udp_target());
        assert_eq!(body, b"payload");
        sender.await.expect("逐字节写端任务");
    })
    .await
    .expect("整体截止时间超时");
}

#[tokio::test]
async fn zero_deadline_and_errors_reject_and_leak_nothing() {
    timeout(WAIT, async {
        let (mut client, mut server) = duplex(128);
        let target = udp_target();
        assert!(matches!(
            send_datagram(&mut client, &target, b"hi", Duration::ZERO).await,
            Err(Error::InvalidDeadline)
        ));
        assert!(matches!(
            receive_datagram(&mut server, u16::MAX, Duration::ZERO).await,
            Err(Error::InvalidDeadline)
        ));

        let hash = Credential::new(PASSWORD).as_hex().to_owned();
        let failures = [
            {
                let (mut w, mut r) = duplex(4096);
                w.write_all(&raw_frame(&target, b"x", *b"\n\n"))
                    .await
                    .expect("可写入");
                receive_datagram(&mut r, u16::MAX, WAIT).await.map(|_| ())
            },
            {
                let (mut w, mut r) = duplex(4096);
                w.write_all(&raw_frame(&target, &[0u8; 600], *b"\r\n"))
                    .await
                    .expect("可写入");
                receive_datagram(&mut r, 512, WAIT).await.map(|_| ())
            },
            send_datagram(&mut client, &target, &vec![0u8; 65536], WAIT)
                .await
                .map(|_| ()),
        ];
        for err in failures {
            let err = err.expect_err("用例必须失败");
            let text = format!("{err}");
            let debug = format!("{err:?}");
            assert!(!text.contains(PASSWORD), "Display 泄漏密码：{text}");
            assert!(!debug.contains(PASSWORD), "Debug 泄漏密码：{debug}");
            assert!(
                !text.contains(&hash) && !debug.contains(&hash),
                "错误泄漏哈希"
            );
        }
    })
    .await
    .expect("零时长与错误信息超时");
}
