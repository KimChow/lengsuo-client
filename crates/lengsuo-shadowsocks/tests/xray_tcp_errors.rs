//! 传统 Shadowsocks AEAD TCP 异常矩阵的真实 Xray 参考验收（仅回环、测试专用假口令）。
//!
//! 方向：本端 Rust 客户端 → Xray shadowsocks 入站 → freedom → 本端回环 echo。
//! 判定原则：**不把「读不到」当「被拒绝」**——错误路径必须观察到 Xray 主动关闭连接
//! （读到 EOF 或 reset），且回环目标零送达；静默超时判为失败。正向控制组先证明
//! 交付点会真实收到字节，否则否定断言只是空集。
//!
//! 参考面：Xray v26.3.27 / d2758a0，`proxy/shadowsocks/server.go` 的
//! `ReadTCPSession`（先读 50 字节、匹配用户失败即 drain 并关闭）与
//! `common/crypto/chunk.go`（`size <= buf.Size(8192)` 走小缓冲，否则按声明长度
//! allocate + 读取——Xray 对超长分块**不设 8192 明文上限**，这与本端 fail-closed 不同，
//! 是偏离清单里如实记录的一项）。

#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;

use std::net::Ipv4Addr;
use std::time::Duration;

use lengsuo_shadowsocks::{CipherSuite, TargetAddr, TcpError, TcpReader, TcpWriter};
use serde_json::json;
use ss_core::crypto::SessionAead;
use ss_core::kdf::{evp_bytes_to_key, hkdf_sha1_subkey};
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// 判定「不再抵达」的静默窗口：大于参考端正常送达耗时，避免把慢速误判成拒绝。
const SETTLE: Duration = Duration::from_millis(1500);
/// 整体预算：一次 Xray 启动 + 若干静默窗口。
const BUDGET: Duration = Duration::from_secs(120);
const NAME: &str = "aes-256-gcm";
/// 测试假口令，与任何生产凭据无关。
const PASSWORD: &str = "ss-tcp-error-matrix-passw0rd";
/// 另一个测试假口令，用于错误口令路径。
const WRONG: &str = "ss-tcp-error-matrix-wrong";
/// 超长分块的明文载荷长度（> 8192，参考实现仍会如实转发）。
const OVERSIZED: usize = 9000;

/// 读取结果三类：已经主动关闭（EOF/reset）、静默超时、意外读到了数据。
#[derive(Debug, PartialEq, Eq)]
enum Fate {
    Closed,
    TimedOut,
    Data(Vec<u8>),
}

/// 生成以 `\n` 结尾的可打印载荷，长度恰为 `size`（echo 用换行判断请求结束）。
fn line(size: usize) -> Vec<u8> {
    assert!(size >= 1);
    let mut payload = vec![0u8; size];
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = b'!' + (index % 90) as u8;
    }
    payload[size - 1] = b'\n';
    payload
}

/// echo：读满一行后回放到通道供断言，并原样回写、随后写半关闭。
async fn spawn_echo(listener: TcpListener) -> tokio::sync::mpsc::UnboundedReceiver<Vec<u8>> {
    let (send, recv) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (mut conn, _peer) = match timeout(WAIT, listener.accept()).await {
                Err(_) | Ok(Err(_)) => break,
                Ok(Ok(pair)) => pair,
            };
            let mut got: Vec<u8> = Vec::new();
            let mut buffer = [0u8; 8192];
            loop {
                let count = match timeout(WAIT, conn.read(&mut buffer)).await {
                    Err(_) | Ok(Err(_)) => break,
                    Ok(Ok(0)) => break,
                    Ok(Ok(count)) => count,
                };
                got.extend_from_slice(&buffer[..count]);
                if got.last() == Some(&b'\n') {
                    break;
                }
            }
            let _ = send.send(got.clone());
            let _ = timeout(WAIT, conn.write_all(&got)).await;
            let _ = timeout(WAIT, conn.shutdown()).await;
        }
    });
    recv
}

/// 收集 `within` 内抵达 echo 的全部请求行；窗口到点即停，绝不无限等待。
async fn gather(
    recv: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    within: Duration,
) -> Vec<Vec<u8>> {
    let mut got = Vec::new();
    loop {
        match timeout(within, recv.recv()).await {
            Err(_) | Ok(None) => break,
            Ok(Some(payload)) => got.push(payload),
        }
    }
    got
}

/// 单方向封包：TcpWriter 写若干段后写半关闭，返回线上字节。
async fn seal_stream(suite: CipherSuite, password: &[u8], segments: &[&[u8]]) -> Vec<u8> {
    let mut wire = Vec::new();
    let mut writer = TcpWriter::new(&mut wire, suite, password, WAIT).unwrap();
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
    wire
}

/// 用固定 salt 手工拼一个 chunk（size 段 + payload 段），与线上格式完全一致；
/// 只用于构造本端公开 API 无法指定的固定 salt / 超长分块。
fn manual_chunk(suite: CipherSuite, password: &[u8], salt: &[u8], payload: &[u8]) -> Vec<u8> {
    let master = evp_bytes_to_key(password, suite.key_len());
    let subkey = hkdf_sha1_subkey(&master, salt, suite.key_len());
    let mut aead = SessionAead::new(suite, subkey);
    let mut wire = Vec::new();
    wire.extend_from_slice(salt);
    wire.extend_from_slice(&aead.seal(&(payload.len() as u16).to_be_bytes()).unwrap());
    wire.extend_from_slice(&aead.seal(payload).unwrap());
    wire
}

/// 把一段线上字节发给 Xray 后写半关闭，再观察读取结果是被动关闭还是静默超时。
async fn send_and_probe(port: u16, wire: &[u8]) -> Fate {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("应可连接参考服务");
    timeout(WAIT, stream.write_all(wire))
        .await
        .expect("写出未被外层超时")
        .expect("写出失败");
    timeout(WAIT, stream.shutdown())
        .await
        .expect("shutdown 未被外层超时")
        .expect("写半关闭失败");
    let mut buffer = [0u8; 4096];
    match timeout(WAIT, stream.read(&mut buffer)).await {
        Err(_) => Fate::TimedOut,
        Ok(Err(_)) => Fate::Closed,
        Ok(Ok(0)) => Fate::Closed,
        Ok(Ok(count)) => Fate::Data(buffer[..count].to_vec()),
    }
}

fn server_config(port: u16, password: &str) -> serde_json::Value {
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"shadowsocks",
            "settings":{"method":NAME,"password":password,"network":"tcp"}}],
        "outbounds":[{"protocol":"freedom"}]})
}

/// 异常矩阵：错误口令、截断首包、篡改 tag、超长分块、半关闭，逐项给出判据与超时。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn tcp_error_matrix_against_xray() {
    timeout(BUDGET, async {
        let suite = CipherSuite::Aes256Gcm;
        let echo = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("echo 应可监听");
        let echo_port = echo.local_addr().expect("echo 应有地址").port();
        let mut arrivals = spawn_echo(echo).await;
        let target = TargetAddr::V4([127, 0, 0, 1], echo_port);
        let port = free_port();
        let reference = launch(server_config(port, PASSWORD), port).await;

        // 半关闭 + 正向控制组：正确口令经真实 TcpWriter 发送、写半关闭后仍读到回包，
        // 且交付点确实送达——先证明否定断言不是空集。
        let mut request = Vec::new();
        target.encode_checked(&mut request).expect("回环目标可编码");
        request.extend_from_slice(b"control-line\n");
        {
            let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .expect("应可连接参考服务");
            let (read_half, mut write_half) = stream.into_split();
            let mut writer = TcpWriter::new(&mut write_half, suite, PASSWORD.as_bytes(), WAIT)
                .expect("应可构造写端");
            timeout(WAIT, writer.send(&request))
                .await
                .expect("发送控制组未被外层超时")
                .expect("控制组应写出");
            timeout(WAIT, writer.shutdown())
                .await
                .expect("半关闭未被外层超时")
                .expect("写半关闭应成功");
            let mut reader =
                TcpReader::new(read_half, suite, PASSWORD.as_bytes(), WAIT).expect("应可构造读端");
            let mut reply = Vec::new();
            loop {
                let count = timeout(WAIT, reader.recv())
                    .await
                    .expect("读回包未被外层超时")
                    .expect("读回包失败");
                let Some(piece) = count else { break };
                reply.extend_from_slice(&piece);
            }
            assert_eq!(reply, b"control-line\n", "半关闭后仍应读到完整回包");
        }
        assert_eq!(
            gather(&mut arrivals, SETTLE).await,
            vec![b"control-line\n".to_vec()],
            "正向控制组必须送达回环目标一次"
        );

        // 错误口令：Xray 匹配不到用户，必须主动关闭连接，目标零送达。
        let mut wrong_request = Vec::new();
        target
            .encode_checked(&mut wrong_request)
            .expect("回环目标可编码");
        wrong_request.extend_from_slice(b"wrong-password\n");
        let wrong_wire = seal_stream(suite, WRONG.as_bytes(), &[&wrong_request]).await;
        let fate = send_and_probe(port, &wrong_wire).await;
        assert_eq!(fate, Fate::Closed, "错误口令必须让 Xray 主动关闭连接");
        assert!(
            gather(&mut arrivals, SETTLE).await.is_empty(),
            "错误口令的报文不得送达回环目标"
        );

        // 截断首包：只发 salt + 1 字节后写半关闭，Xray 读不满 50 字节即拒绝并关闭。
        let truncated = vec![0x11u8; suite.salt_len() + 1];
        let fate = send_and_probe(port, &truncated).await;
        assert_eq!(fate, Fate::Closed, "截断首包必须让 Xray 主动关闭连接");
        assert!(
            gather(&mut arrivals, SETTLE).await.is_empty(),
            "截断首包不得送达回环目标"
        );

        // 篡改 tag：salt + size 段认证通过，载荷段 tag 末位翻转后认证失败并关闭。
        let mut tampered_request = Vec::new();
        target
            .encode_checked(&mut tampered_request)
            .expect("回环目标可编码");
        tampered_request.extend_from_slice(b"tampered-tag\n");
        let mut tampered = seal_stream(suite, PASSWORD.as_bytes(), &[&tampered_request]).await;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let fate = send_and_probe(port, &tampered).await;
        assert_eq!(fate, Fate::Closed, "篡改 tag 必须让 Xray 主动关闭连接");
        assert!(
            gather(&mut arrivals, SETTLE).await.is_empty(),
            "篡改 tag 的报文不得送达回环目标"
        );

        // 超长分块：本端 fail-closed 拒绝；固定参考 Xray 对 chunk 明文无 8192 上限，
        // 会按声明长度读取并如实转发，这里把两侧实测行为都锁定下来。
        let mut oversized_plain = Vec::new();
        target
            .encode_checked(&mut oversized_plain)
            .expect("回环目标可编码");
        let data = line(OVERSIZED - oversized_plain.len());
        oversized_plain.extend_from_slice(&data);
        let oversized_wire =
            manual_chunk(suite, PASSWORD.as_bytes(), &[0x22u8; 32], &oversized_plain);
        {
            let mut reader =
                TcpReader::new(oversized_wire.as_slice(), suite, PASSWORD.as_bytes(), WAIT)
                    .expect("应可构造读端");
            let err = timeout(WAIT, reader.recv())
                .await
                .expect("recv 未被外层超时")
                .expect_err("超长分块必须被拒绝");
            assert!(
                matches!(err, TcpError::InvalidFrame(_)),
                "应报 InvalidFrame，实际 {err:?}"
            );
        }
        {
            let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .expect("应可连接参考服务");
            timeout(WAIT, stream.write_all(&oversized_wire))
                .await
                .expect("写出未被外层超时")
                .expect("写出失败");
            timeout(WAIT, stream.shutdown())
                .await
                .expect("shutdown 未被外层超时")
                .expect("写半关闭失败");
            drop(stream);
        }
        assert_eq!(
            gather(&mut arrivals, WAIT).await,
            vec![data],
            "固定参考 Xray 应如实转发超长分块的载荷（与本端 fail-closed 的偏离）"
        );

        drop(reference);
    })
    .await
    .expect("TCP 异常矩阵整体超时");
}
