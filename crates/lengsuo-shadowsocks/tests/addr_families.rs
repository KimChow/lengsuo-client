//! W4 核验卡：地址族（ATYP 0x03 域名 / 0x04 IPv6）在 **TCP 行程式读取**上的
//! 回归锁与 fail-closed 断言。
//!
//! 被测对象 `src/address.rs` 的 `AddressReader`（游标续读语义见其模块文档）。
//! 与参考（Xray `v26.3.27` `d2758a02`）的对应：`proxy/shadowsocks/protocol.go`
//! 的 `ReadTCPSession` 走 `common/protocol/address.go` 的 `readAddress`，域名
//! 分支无条件 `isValidDomain`（`address.go:219-221`，字符集 `address.go:159-166`）。
//! 本文件不改任何解析语义，只把实测行为钉成锁：
//!
//! - 域名族：空域名 / NUL / 非法字符（`/`）拒绝；长度恰 255 合法；族字节、
//!   长度字节、域名体、端口各断点跨 chunk 续读不丢字节；
//! - IPv6 族：`::1`、`2001:db8::1` 原样往返；16 字节体 / 端口 / 族字节截断
//!   一律 `Truncated`，补齐后从断点续读成功；
//! - fail-closed：未知族字节（0x07 与掩码后 0x17）报 `InvalidFrame`——字节
//!   不被消费、重读同样拒绝（「不重试」的永久错误语义）；中继路径上未知族
//!   字节最终关连接且绝不回退直连。
//!
//! 偏离锁定：参考对「首字符为 `[` 或数字」的域名会尝试 `net.ParseAddress`
//! 改写地址族（`address.go:210-214` maybeIPPrefix）；本端一律按域名处理
//! （`docs/shadowsocks-status.md` 偏离清单），有专门用例钉住该选择。
//! 长度字节是 u8，线上不存在「256 长度的域名」；256 只能在**编码侧**拒绝
//! （`TargetAddr::encode_checked`，由 `ss-core/tests/address_validation.rs`
//! 与 `tests/udp.rs` 锁定），读端以 255 为合法上限。

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use lengsuo_shadowsocks::address::NoStream;
use lengsuo_shadowsocks::{
    AddressReader, CipherSuite, RelayConfig, RelayConfigParts, RelayService, TargetAddr, TcpError,
    TcpWriter,
};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// 测试假口令，与任何生产凭据无关。
const PASSWORD: &str = "ss-addr-family-test-password";
/// 单次 I/O 的外层超时。
const WAIT: Duration = Duration::from_secs(2);

/// 底层为内存切片的读端：缓冲耗尽即 EOF（呈现为 Truncated）。
fn stream_reader(bytes: &[u8]) -> AddressReader<&[u8]> {
    AddressReader::new(bytes)
}

/// 无底层流的读端（与中继路径同构：字节全部由 `push` 喂入）。
fn pending_reader() -> AddressReader<NoStream> {
    AddressReader::from_pending()
}

#[tokio::test]
async fn domain_length_255_is_accepted_and_consumed_exactly() {
    let mut raw = vec![0x03, 255];
    raw.extend_from_slice(&[b'a'; 255]);
    raw.extend_from_slice(&[0x01, 0xBB]);
    let mut r = stream_reader(&raw);
    assert_eq!(
        r.read_target().await.unwrap(),
        TargetAddr::Domain("a".repeat(255), 443)
    );
    assert_eq!(r.buffered(), 0, "255 长度域名必须被精确消费");
}

#[tokio::test]
async fn domain_empty_is_rejected() {
    let mut r = stream_reader(&[0x03, 0x00, 0x01, 0xBB]);
    assert!(
        matches!(
            r.read_target().await.unwrap_err(),
            TcpError::InvalidFrame(0)
        ),
        "空域名必须拒绝（参考在 domainLength=0 上会越界，本端显式拒绝）"
    );
}

#[tokio::test]
async fn domain_with_nul_is_rejected() {
    let mut r = stream_reader(&[0x03, 3, b'a', 0, b'b', 0x01, 0xBB]);
    assert!(matches!(
        r.read_target().await.unwrap_err(),
        TcpError::InvalidFrame(3)
    ));
}

#[tokio::test]
async fn domain_with_illegal_char_is_rejected() {
    // 参考.isValidDomain 只允许 [0-9A-Za-z.\-_]；`/` 必须拒绝（address.go:219）。
    let mut r = stream_reader(&[0x03, 3, b'a', b'/', b'b', 0x01, 0xBB]);
    assert!(matches!(
        r.read_target().await.unwrap_err(),
        TcpError::InvalidFrame(3)
    ));
}

#[tokio::test]
async fn domain_splits_across_family_len_body_and_port_resume_cleanly() {
    let mut r = pending_reader();
    r.push(&[0x03]);
    assert!(
        matches!(
            r.read_target().await.unwrap_err(),
            TcpError::Truncated {
                expect: "域名长度"
            }
        ),
        "只有族字节 ⇒ 长度字节截断"
    );
    r.push(&[7, b'e', b'x']);
    assert!(matches!(
        r.read_target().await.unwrap_err(),
        TcpError::Truncated { expect: "域名" }
    ));
    r.push(b"ample");
    assert!(matches!(
        r.read_target().await.unwrap_err(),
        TcpError::Truncated { expect: "端口" }
    ));
    r.push(&[0x01, 0xBB]);
    assert_eq!(
        r.read_target().await.unwrap(),
        TargetAddr::Domain("example".into(), 443),
        "四个断点各断半后必须续读成功且不丢字节"
    );
    assert_eq!(r.buffered(), 0);
}

#[tokio::test]
async fn domain_split_last_chunk_may_carry_port_and_payload() {
    let mut r = pending_reader();
    r.push(&[0x03, 7, b'e', b'x', b'a', b'm']);
    r.push(b"ple");
    r.push(&[0x01, 0xBB, b'h', b'i']);
    assert_eq!(
        r.read_target().await.unwrap(),
        TargetAddr::Domain("example".into(), 443)
    );
    assert_eq!(
        r.take_pending(),
        b"hi".to_vec(),
        "同 chunk 载荷开头必须保留"
    );
}

#[tokio::test]
async fn ipv6_compressed_forms_roundtrip_from_stream() {
    let localhost = std::net::Ipv6Addr::LOCALHOST.octets();
    let doc = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // 2001:db8::1
    ];
    for (ip, port) in [(localhost, 53u16), (doc, 8080)] {
        let mut raw = vec![0x04];
        raw.extend_from_slice(&ip);
        raw.extend_from_slice(&port.to_be_bytes());
        let mut r = stream_reader(&raw);
        assert_eq!(r.read_target().await.unwrap(), TargetAddr::V6(ip, port));
        assert_eq!(r.buffered(), 0);
    }
}

#[tokio::test]
async fn ipv6_body_truncated_then_completed_resumes_without_loss() {
    let ip = std::net::Ipv6Addr::LOCALHOST.octets();
    let mut r = pending_reader();
    r.push(&[0x04]);
    r.push(&ip[..10]);
    assert!(
        matches!(
            r.read_target().await.unwrap_err(),
            TcpError::Truncated { expect: "地址" }
        ),
        "16 字节体断半 ⇒ Truncated"
    );
    r.push(&ip[10..]);

    assert!(matches!(
        r.read_target().await.unwrap_err(),
        TcpError::Truncated { expect: "端口" }
    ));
    r.push(&[0x00, 0x35]);
    assert_eq!(r.read_target().await.unwrap(), TargetAddr::V6(ip, 53));
}

#[tokio::test]
async fn ipv6_atyp_only_then_eof_is_truncated() {
    let mut r = stream_reader(&[0x04]);
    assert!(matches!(
        r.read_target().await.unwrap_err(),
        TcpError::Truncated { expect: "地址" }
    ));
}

#[tokio::test]
async fn ipv6_port_truncated_is_error_not_eof() {
    let mut raw = vec![0x04];
    raw.extend_from_slice(&[0u8; 16]);
    raw.push(0x00); // 端口只有 1 字节
    let mut r = stream_reader(&raw);
    assert!(matches!(
        r.read_target().await.unwrap_err(),
        TcpError::Truncated { expect: "端口" }
    ));
}

#[tokio::test]
async fn unknown_atyp_is_permanent_and_never_consumed() {
    let mut r = pending_reader();
    r.push(&[0x07, 1, 2, 3, 4, 0x01, 0xBB, b'x']);
    assert!(matches!(
        r.read_target().await.unwrap_err(),
        TcpError::InvalidFrame(7)
    ));
    assert_eq!(r.buffered(), 8, "拒绝后字节必须原地保留");
    // 永久错误语义：重读同样拒绝（映射外值不猜、不重试；调用方必须关连接）。
    assert!(matches!(
        r.read_target().await.unwrap_err(),
        TcpError::InvalidFrame(7)
    ));
}

#[tokio::test]
async fn masked_unknown_atyp_rejected_after_mask() {
    // 0x17 & 0x0F = 0x07：高位是标志位，掩码后仍属映射外 ⇒ 拒绝。
    let mut r = stream_reader(&[0x17, 0, 0, 0, 0, 0, 0]);
    assert!(matches!(
        r.read_target().await.unwrap_err(),
        TcpError::InvalidFrame(7)
    ));
}

#[tokio::test]
async fn unmapped_atyp_values_are_rejected() {
    for atyp in [0x00u8, 0x02] {
        let bytes = [atyp, 0, 0, 0, 0, 0, 0];
        let mut r = stream_reader(&bytes);
        assert!(
            matches!(r.read_target().await.unwrap_err(), TcpError::InvalidFrame(a) if a == usize::from(atyp)),
            "映射外族字节 {atyp:#04x} 必须拒绝"
        );
    }
}

#[tokio::test]
async fn ip_like_domain_stays_domain_not_rewritten() {
    // 参考 maybeIPPrefix（address.go:210-214）会把 "127.0.0.1" 改写成 IPv4
    // 地址族；本端 TargetAddr 是纯类型化模型，一律按域名处理（有意偏离，
    // docs/shadowsocks-status.md 偏离清单）。此用例钉住本端选择。
    let mut raw = vec![0x03, 9];
    raw.extend_from_slice(b"127.0.0.1");
    raw.extend_from_slice(&[0x01, 0xBB]);
    let mut r = stream_reader(&raw);
    assert_eq!(
        r.read_target().await.unwrap(),
        TargetAddr::Domain("127.0.0.1".into(), 443)
    );
}

#[test]
fn relay_unknown_atyp_fails_closed_without_direct_fallback() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    tokio::task::LocalSet::new().block_on(&runtime, async {
        // 只监听不 accept：中继若错误地回退直连，这里会出现连接。
        let echo = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let service = RelayService::bind(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            RelayConfig::new(
                RelayConfigParts {
                    suite: CipherSuite::Aes128Gcm,
                    idle_timeout: Duration::from_millis(300),
                    replay: None,
                },
                PASSWORD.as_bytes(),
            ),
        )
        .await
        .expect("中继绑定");
        let relay = service.local_addr().expect("中继地址");
        let handle = service.start().await.expect("中继启动");

        let mut stream = TcpStream::connect(relay).await.expect("连接中继");
        let mut writer = TcpWriter::new(
            &mut stream,
            CipherSuite::Aes128Gcm,
            PASSWORD.as_bytes(),
            WAIT,
        )
        .expect("构造写端");
        // 口令正确 ⇒ 认证通过；地址族字节 0x07 映射外 ⇒ 解析必须拒绝。
        timeout(WAIT, writer.send(&[0x07, 1, 2, 3, 4, 0x01, 0xBB]))
            .await
            .expect("send 未被外层超时")
            .expect("send 应成功");
        timeout(WAIT, writer.shutdown())
            .await
            .expect("shutdown 未被外层超时")
            .expect("shutdown 应成功");
        drop(writer);

        // fail-closed：连接被关闭（读到 0 字节），且没有任何数据被中继出去。
        let mut buf = [0u8; 16];
        let n = timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("读回程未被外层超时")
            .unwrap_or(0);
        assert_eq!(n, 0, "未知地址族必须关连接，绝不回退直连");
        let probe = timeout(Duration::from_millis(200), echo.accept()).await;
        assert!(probe.is_err(), "中继不得为非法地址族拨号上游：{probe:?}");
        handle.shutdown().await.expect("中继应干净停止");
    });
}
