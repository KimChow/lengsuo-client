//! **临时探针**（用完即删）：判定参考端 WS 外层对“客户端关写端”的真实语义。
//!
//! 三个场景：
//!
//! - A（对照）：**不**关写端，直接读 64 KiB 回程；
//! - B：关写端（本仓语义：`Close` 帧 + 底层 FIN）；
//! - C：关写端但**丢掉 `Close` 帧**（只发裸 FIN）。
//!
//! 用来区分“参考端把客户端的关写端当作**会话拆除**”还是“当作**半关闭**”。

use std::pin::Pin;
use std::process::{Command, Stdio};
use std::time::Duration;

use lengsuo_trojan::transport::ws;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::harness::{header_bytes, Identity, Target, PASSWORD, PATH, PAYLOAD, WAIT};
use super::support::free_port;

/// 写侧可选丢弃 WS `Close` 帧的包装。
///
/// `Close` 帧的线上形状固定为 6 字节：`0x88`（FIN|opcode 0x8）、`0x80`
/// （掩码位|长度 0）、4 字节掩码键。本仓 `ws` 写侧一次性把这 6 字节交给底层，
/// 因此在**帧首**判定即可精确命中。
struct BareFin<S> {
    inner: S,
    strip_close: bool,
}

impl<S: AsyncRead + Unpin> AsyncRead for BareFin<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for BareFin<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.strip_close && buf.len() >= 6 && buf[0] == 0x88 && buf[1] == 0x80 {
            // 丢弃整帧，对上层谎称已全部写入（上层据此推进写偏移）。
            return std::task::Poll::Ready(Ok(buf.len()));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

async fn read_all<S: AsyncRead + Unpin>(stream: &mut S) -> (usize, String) {
    let mut buf = vec![0u8; 1 << 16];
    let mut total = 0usize;
    loop {
        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
            Ok(Ok(0)) => return (total, "EOF".to_owned()),
            Ok(Ok(n)) => total += n,
            Ok(Err(error)) => return (total, format!("读错误 {error}")),
            Err(_) => return (total, "观察超时".to_owned()),
        }
    }
}

/// 跑一个场景。`mode`：0 = 不关写端；1 = `Close` 帧 + FIN；2 = 裸 FIN。
async fn scenario(mode: u8) {
    let identity = Identity::new();
    let port = free_port();
    let dir = std::path::PathBuf::from("/tmp/lengsuo-ws-probe");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = json!({"log":{"loglevel":"info"},
      "policy":{"levels":{"0":{"handshake":2}}},
      "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"trojan",
        "settings":{"clients":[{"password":PASSWORD}]},
        "streamSettings":{"security":"tls","tlsSettings":{"certificates":[{
           "certificate":identity.cert_pem().lines().collect::<Vec<_>>(),
           "key":identity.key_pem().lines().collect::<Vec<_>>()}]},
           "network":"ws","wsSettings":{"path":PATH,"host":"localhost"}}}],
      "outbounds":[{"protocol":"freedom"}]});
    let path = dir.join("config.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let log = std::fs::File::create(dir.join("xray.log")).unwrap();
    let mut child = Command::new(std::env::var("LENGSUO_XRAY").unwrap())
        .args(["run", "-config"])
        .arg(&path)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + WAIT;
    loop {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "参考端启动超时");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let total_reply = 64 * 1024;
    let target = Target::bind(vec![0xA5u8; total_reply]).await;
    let tls = identity
        .client()
        .connect(([127, 0, 0, 1], port).into())
        .await
        .unwrap();
    let mut stream = ws::Client::new(PATH, "localhost", "localhost")
        .upgrade(
            BareFin {
                inner: tls,
                strip_close: mode == 2,
            },
            WAIT,
        )
        .await
        .unwrap();
    let header = header_bytes(target.port(), PASSWORD);
    stream.write_all(&header).await.unwrap();
    stream.write_all(PAYLOAD).await.unwrap();
    stream.flush().await.unwrap();
    if mode != 0 {
        stream.shutdown().await.unwrap();
    }
    let (total, how) = read_all(&mut stream).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!(
        "### 场景 {mode}：回程收到 {total} / {total_reply} 字节，结束方式：{how}，accepted = {}",
        target.accepted()
    );
    println!(
        "### 参考端日志 ===\n{}",
        std::fs::read_to_string(dir.join("xray.log")).unwrap()
    );
    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::test]
#[ignore = "临时探针"]
async fn probe_ws_close_teardown() {
    scenario(0).await;
    scenario(1).await;
    scenario(2).await;
}
