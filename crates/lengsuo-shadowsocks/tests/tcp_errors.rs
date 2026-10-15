//! 传统 Shadowsocks AEAD TCP chunk 层的错误路径测试：错误口令、截断（salt /
//! size 段 / 载荷段）、密文篡改、零截止时间、空口令、底层 I/O 失败与超时之后的
//! 永久 poison。口令是测试专用假凭据；错误消息不得包含任何口令或密钥材料。
//!
//! 这些测试只证明本实现 fail-closed 的内部一致，不宣称与参考实现实跑互通。

use std::time::Duration;

use lengsuo_shadowsocks::{CipherSuite, TcpError, TcpReader, TcpWriter};
use ss_core::chunk::SIZE_WIRE_LEN;
use tokio::io::duplex;
use tokio::time::timeout;

/// 测试假口令，与任何生产凭据无关。
const PASSWORD: &[u8] = b"tcp-error-path-passw0rd";
/// 另一个假口令，用于错误口令路径。
const OTHER_PASSWORD: &[u8] = b"tcp-error-path-wrong-pass";

const WAIT: Duration = Duration::from_secs(2);

/// size 段线上长度：BE16 明文 + tag。
const SIZE_SEGMENT_WIRE: usize = SIZE_WIRE_LEN + 16;

/// 单方向封包：依次 send 各段后写半关闭，返回线上字节。
async fn seal(suite: CipherSuite, segments: &[&[u8]]) -> Vec<u8> {
    let mut wire: Vec<u8> = Vec::new();
    {
        let mut writer =
            TcpWriter::new(&mut wire, suite, PASSWORD, WAIT).expect("测试套件应可构造写端");
        for segment in segments {
            timeout(WAIT, writer.send(segment))
                .await
                .expect("send 未被外层超时")
                .expect("写出应成功");
        }
        timeout(WAIT, writer.shutdown())
            .await
            .expect("shutdown 未被外层超时")
            .expect("正常收尾应成功");
    }
    wire
}

/// 断言错误是认证失败，且消息不泄露口令；随后确认方向已永久 poison。
async fn assert_auth_error_and_poison(mut reader: TcpReader<&[u8]>) {
    let err = timeout(WAIT, reader.recv())
        .await
        .expect("recv 未被外层超时")
        .expect_err("应认证失败");
    assert!(
        matches!(err, TcpError::Authentication),
        "应报认证失败，实际 {err:?}"
    );
    let leaked = format!("{err:?} {err}");
    assert!(!leaked.contains("passw0rd"), "错误消息不得包含口令");
    let again = timeout(WAIT, reader.recv())
        .await
        .expect("poison 后 recv 未被外层超时")
        .expect_err("poison 后必须继续失败");
    assert!(
        matches!(again, TcpError::Poisoned),
        "应报 Poisoned，实际 {again:?}"
    );
}

#[tokio::test]
async fn wrong_password_fails_closed_then_poisons() {
    timeout(WAIT, async {
        let wire = seal(CipherSuite::Aes128Gcm, &[b"secret payload"]).await;
        let reader = TcpReader::new(
            wire.as_slice(),
            CipherSuite::Aes128Gcm,
            OTHER_PASSWORD,
            WAIT,
        )
        .expect("可构造读端");
        assert_auth_error_and_poison(reader).await;
    })
    .await
    .expect("错误口令超时");
}

#[tokio::test]
async fn tampered_ciphertext_fails_authentication() {
    timeout(WAIT, async {
        for suite in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20IetfPoly1305] {
            let mut wire = seal(suite, &[b"authenticated bytes"]).await;
            let last = wire.len() - 1;
            wire[last] ^= 0x01; // 翻转载荷段 tag 末位
            let reader = TcpReader::new(wire.as_slice(), suite, PASSWORD, WAIT).expect("可构造");
            assert_auth_error_and_poison(reader).await;
        }
    })
    .await
    .expect("篡改超时");
}

#[tokio::test]
async fn truncated_salt_reports_truncated_then_poisons() {
    timeout(WAIT, async {
        let suite = CipherSuite::Aes128Gcm;
        let wire = seal(suite, &[b"payload"]).await;
        let short = &wire[..suite.salt_len() - 1];
        let mut reader = TcpReader::new(short, suite, PASSWORD, WAIT).expect("可构造");
        let err = timeout(WAIT, reader.recv())
            .await
            .expect("recv 未被外层超时")
            .expect_err("salt 不满必须报错");
        assert!(
            matches!(err, TcpError::Truncated { expect: "salt" }),
            "应报 salt 截断，实际 {err:?}"
        );
        let again = timeout(WAIT, reader.recv())
            .await
            .expect("poison 后 recv 未被外层超时")
            .expect_err("poison 后必须继续失败");
        assert!(
            matches!(again, TcpError::Poisoned),
            "应报 Poisoned，实际 {again:?}"
        );
    })
    .await
    .expect("salt 截断超时");
}

#[tokio::test]
async fn truncated_size_segment_and_body_are_distinct_truncations() {
    timeout(WAIT, async {
        let suite = CipherSuite::Aes128Gcm;
        let wire = seal(suite, &[b"payload bytes"]).await;
        let salt = suite.salt_len();
        // size 段读到一半结束：缓冲不足 2 字节明文长度头 ⇒ 归类为 size 段截断。
        let cut_in_size = salt + 1;
        let mut reader =
            TcpReader::new(&wire[..cut_in_size], suite, PASSWORD, WAIT).expect("可构造");
        let err = timeout(WAIT, reader.recv())
            .await
            .expect("recv 未被外层超时")
            .expect_err("size 段截断必须报错");
        assert!(
            matches!(err, TcpError::Truncated { expect: "size 段" }),
            "应报 size 段截断，实际 {err:?}"
        );
        // 载荷段读到一半结束（size 段完整，载荷+tag 中间截断）。
        let cut_in_body = salt + SIZE_SEGMENT_WIRE + 3;
        let mut reader =
            TcpReader::new(&wire[..cut_in_body], suite, PASSWORD, WAIT).expect("可构造");
        let err = timeout(WAIT, reader.recv())
            .await
            .expect("recv 未被外层超时")
            .expect_err("载荷段截断必须报错");
        assert!(
            matches!(
                err,
                TcpError::Truncated {
                    expect: "载荷段"
                }
            ),
            "应报载荷段截断，实际 {err:?}"
        );
    })
    .await
    .expect("帧截断超时");
}

#[tokio::test]
async fn io_failure_poisons_writer_direction() {
    timeout(WAIT, async {
        let (mut client, server) = duplex(64);
        drop(server); // 对端丢弃 ⇒ 缓冲填满后写入得到 BrokenPipe
        let mut writer =
            TcpWriter::new(&mut client, CipherSuite::Aes128Gcm, PASSWORD, WAIT).expect("可构造");
        // 负载必须大到超出 duplex 缓冲（64 字节）：salt + 单帧明文 300 字节 ≫ 64。
        let big = [0x5Au8; 300];
        let err = timeout(WAIT, writer.send(&big))
            .await
            .expect("send 未被外层超时")
            .expect_err("对端丢弃且缓冲耗尽后写入必须失败");
        assert!(
            matches!(err, TcpError::Io(_)),
            "应报底层 I/O 错误，实际 {err:?}"
        );
        let again = timeout(WAIT, writer.send(b"retry"))
            .await
            .expect("poison 后 send 未被外层超时")
            .expect_err("poison 后必须继续失败");
        assert!(
            matches!(again, TcpError::Poisoned),
            "应报 Poisoned，实际 {again:?}"
        );
    })
    .await
    .expect("写端 I/O 失败超时");
}

#[tokio::test]
async fn deadline_exceeded_poisons_reader_direction() {
    timeout(WAIT, async {
        let (client, _server) = duplex(64); // 对端存在但永不写 ⇒ 首次 recv 必然超时
        let mut reader = TcpReader::new(
            client,
            CipherSuite::Aes128Gcm,
            PASSWORD,
            Duration::from_millis(20),
        )
        .expect("可构造");
        let err = timeout(WAIT, reader.recv())
            .await
            .expect("recv 未被外层超时")
            .expect_err("无数据必须在截止时间报错");
        assert!(matches!(err, TcpError::Timeout), "应报超时，实际 {err:?}");
        let again = timeout(WAIT, reader.recv())
            .await
            .expect("poison 后 recv 未被外层超时")
            .expect_err("poison 后必须继续失败");
        assert!(
            matches!(again, TcpError::Poisoned),
            "应报 Poisoned，实际 {again:?}"
        );
    })
    .await
    .expect("读端超时 poison 超时");
}

/// `Result::expect_err` 的替身：成功类型（写端/读端）故意不实现 Debug，
/// 不能用 `expect_err`。失败时交出错误，成功时 panic。
fn expect_rejected<T>(outcome: Result<T, TcpError>, message: &str) -> TcpError {
    match outcome {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

#[tokio::test]
async fn invalid_construction_fails_before_any_io() {
    timeout(WAIT, async {
        let (mut client, _server) = duplex(64);
        // 零截止时间一律拒绝（tokio::time::timeout 对零时长立即过期，这里显式区分）。
        let err = expect_rejected(
            TcpWriter::new(
                &mut client,
                CipherSuite::Aes128Gcm,
                PASSWORD,
                Duration::ZERO,
            ),
            "零截止时间必须拒绝",
        );
        assert!(matches!(err, TcpError::InvalidDeadline), "实际 {err:?}");
        let err = expect_rejected(
            TcpReader::new(
                &mut client,
                CipherSuite::Aes128Gcm,
                PASSWORD,
                Duration::ZERO,
            ),
            "零截止时间必须拒绝",
        );
        assert!(matches!(err, TcpError::InvalidDeadline), "实际 {err:?}");
        // 空口令拒绝且不碰流。
        let err = expect_rejected(
            TcpWriter::new(&mut client, CipherSuite::Aes128Gcm, b"", WAIT),
            "空口令必须拒绝",
        );
        assert!(matches!(err, TcpError::Key(_)), "实际 {err:?}");
        let err = expect_rejected(
            TcpReader::new(&mut client, CipherSuite::Aes128Gcm, b"", WAIT),
            "空口令必须拒绝",
        );
        assert!(matches!(err, TcpError::Key(_)), "实际 {err:?}");
        // 构造失败不产生任何线上字节：对端在短窗口内读不到任何数据。
        use tokio::io::AsyncReadExt;
        let mut probe = Vec::new();
        match timeout(Duration::from_millis(100), client.read_buf(&mut probe)).await {
            // 无数据 ⇒ 读挂起直到超时，或直接确认缓冲为空。
            Err(_) => {}
            Ok(Ok(0)) => {}
            Ok(Ok(_)) => panic!("失败的构造不得写流，实际写入了字节"),
            Ok(Err(error)) => panic!("对端读取不应出错：{error}"),
        }
        assert!(probe.is_empty(), "失败的构造不得写流");
    })
    .await
    .expect("构造参数拒绝超时");
}
