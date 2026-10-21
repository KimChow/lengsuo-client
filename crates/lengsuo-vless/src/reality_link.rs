//! REALITY 客户端接入 VLESS 主连接链路。
//!
//! 主链路（[`crate::stream`]）的契约是「传入流必须由调用方完成安全传输认证」：
//! `stream::send_request` / `stream::receive_datagram` 只认 [`AsyncRead`] +
//! [`AsyncWrite`]。本模块提供的就是那条**已认证的字节流**：
//!
//! ```text
//! RealityConfig（见 [`crate::reality_config`]）──RealityStream::connect──▶ RealityStream
//! RealityStream ──stream::send_request / receive_response──▶ VLESS 头与载荷
//! ```
//!
//! 插入点在 **VLESS 头写入之前**：底层字节流由「裸 TCP」换成「REALITY + TLS 1.3
//! 记录层」后，VLESS 头与应用载荷都走 `Outbound::EncryptedApplication`。
//! 未配置 REALITY 时调用方根本不会构造本模块的类型，默认路径零变化。
//!
//! 客户端流程照搬 `tests/reality_xray_server.rs`（参考互通夹具）：
//! `build_reality_client_hello` → 写 `Outbound::PlainHandshake` →
//! `RealityClient::from_built` → `client_handshake` →
//! `RecordReader`/`RecordWriter`（应用数据阶段）。
//!
//! 参考与 VLESS 同基线：Xray v26.3.27 `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。
//! 客户端见 `transport/internet/reality/reality.go` 的 `UClient`。
//!
//! # 记录边界 ≠ 读边界
//!
//! `RecordReader` 按记录返回、会丢「一条记录内的字节分段」信息；而 VLESS 主链路的
//! `stream::receive_request` 是**逐字节**读头。因此握手完成后由后台任务按记录解封、
//! 把明文摊平成字节流交给管道（见 [`RealityStream`]）；读不满时继续取下一条记录
//! （与 `xtls/reality` `Conn.Read`「尾巴留给下一次 Read」一致）。
//!
//! 密钥材料不进日志或 `Debug`：错误类型只带静态文案。

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use aes_gcm::aead::rand_core::{CryptoRng, OsRng, RngCore};
use thiserror::Error;
use tokio::{
    io::{
        duplex, split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
    },
    net::TcpStream,
    task::{spawn, JoinHandle},
    time::{timeout, Instant},
};

use crate::reality::client::{build_reality_client_hello, ClientError, RealityClient};
use crate::reality::session::client_handshake;
use crate::reality::tls13::io::{Inbound, Outbound, RecordReader, RecordWriter};
use crate::reality::tls13::record::content_type;
use crate::reality::ClientVersion;
use crate::reality_config::RealityConfig;

/// 单条应用数据记录的上限（TLS 1.3 §5.1 的 `2^14`）。
const CHUNK: usize = 16384;

/// 每次底层 I/O 的截止时间（任务书：所有网络操作必须有界）。
const IO_DEADLINE: Duration = Duration::from_secs(10);

/// 写进认证载荷的客户端版本三元组（`SessionId[0..3]`，参考
/// `core.Version_x/y/z`）。取参考基线版本；默认服务端配置不校验版本。
pub const CLIENT_VERSION: ClientVersion = ClientVersion { x: 26, y: 3, z: 27 };

/// 建流失败。全部 fail-closed：失败即返回，不回退明文。
#[derive(Debug, Error)]
pub enum Error {
    /// 参考 `failed to get fingerprint`：构造 ClientHello 前就拒绝。
    #[error("REALITY: failed to get fingerprint")]
    Fingerprint,
    /// ClientHello 构造失败（低阶公钥等）。
    #[error("REALITY: failed to build client hello")]
    ClientHello,
    /// TLS 1.3 / REALITY 证书校验失败。
    #[error("REALITY: handshake failed")]
    Handshake,
    /// 连接或握手超时。
    #[error("REALITY: timed out")]
    Timeout,
    /// 底层 I/O 失败。
    #[error("REALITY: io error")]
    Io(#[from] io::Error),
}

/// REALITY 传输层：握好之后就是 VLESS 主链路要的那条「已认证字节流」。
///
/// 实现方式：握手完成后，用本 crate 既有的 [`RecordReader`] / [`RecordWriter`]
/// 各起一个后台任务，在「TCP 连接」与「内存管道（`tokio::io::duplex`）」之间
/// 搬运记录；调用方拿到的是管道的应用侧，因此 `AsyncRead` / `AsyncWrite`
/// 就是普通字节流（`poll_*` 里没有锁、没有 `await`），可直接传给
/// [`crate::stream::send_request`] 等主链路函数。
///
/// * 读任务：`RecordReader::next_record` → 丢弃非应用数据记录 → 明文写进管道
///   （对齐 `xtls/reality` `Conn.Read`：一条记录交付不完的尾巴由管道继续携带）；
/// * 写任务：管道里的字节按 `2^14` 切记录 → `RecordWriter` 写
///   `Outbound::EncryptedApplication`。
///
/// 后台任务只持有记录层与本端 TCP 半连接，不持有配置或公钥。
pub struct RealityStream {
    /// 应用侧（管道本端）：VLESS 头与载荷都从这里读写。
    app: DuplexStream,
    /// 读任务：TCP → 管道。对端关闭或出错后自行结束。
    reader_task: Option<JoinHandle<()>>,
    /// 写任务：管道 → TCP。应用侧 `shutdown` 后自行结束。
    ///
    /// `Option` 是**幂等闸**：`take()` 之后句柄即被「收走」，重复的
    /// `shutdown()` 不会再 await 同一个 `JoinHandle`（tokio 对**已完成**的
    /// 句柄二次 poll 会 panic：`JoinHandle polled after completion`）。
    writer_task: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for RealityStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityStream").finish_non_exhaustive()
    }
}

/// 管道容量（一条 TLS 记录的最大明文量的量级）。
const PIPE: usize = CHUNK;

impl RealityStream {
    /// 连接 `address`（`host:port`）并完成 REALITY + TLS 1.3 握手。
    ///
    /// `deadline` 同时约束 TCP 连接与整次握手；失败即返回，**不**回退明文。
    pub async fn connect(
        address: &str,
        config: &RealityConfig,
        deadline: Duration,
    ) -> Result<Self, Error> {
        let end = Instant::now() + deadline;
        let transport = timeout(deadline, TcpStream::connect(address))
            .await
            .map_err(|_| Error::Timeout)??;
        let mut rng = OsRng;
        Self::handshake_over(transport, config, address, &mut rng, end).await
    }

    /// 握手主体（熵源注入：测试用确定性熵复现，运行时用系统熵）。
    async fn handshake_over<R: RngCore + CryptoRng>(
        mut transport: TcpStream,
        config: &RealityConfig,
        dest: &str,
        rng: &mut R,
        end: Instant,
    ) -> Result<Self, Error> {
        let unix_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Io(io::Error::other("system clock before unix epoch")))?
            .as_secs() as u32;
        let mut built = build_reality_client_hello(
            &config.client.public_key,
            config.server_name(dest),
            &config.client.short_id,
            CLIENT_VERSION,
            unix_time,
            rng,
        )
        .map_err(|_| Error::ClientHello)?;
        let raw = built.raw.clone();
        let mut state = RealityClient::from_built(&mut built).map_err(|_| Error::ClientHello)?;
        // 参考 `uConn.HandshakeContext(ctx)`：失败即返回，绝不继续明文外发。
        let mut writer = RecordWriter::new();
        writer
            .write(&mut transport, &Outbound::PlainHandshake(raw))
            .await
            .map_err(|_| Error::Handshake)?;
        let outcome = client_handshake(&mut state, &mut transport, remaining(end))
            .await
            .map_err(|error| match error {
                ClientError::Handshake(crate::reality::tls13::handshake::HandshakeError::Io(
                    ref reason,
                )) if reason == "timeout" => Error::Timeout,
                _ => Error::Handshake,
            })?;
        let (read_half, write_half) = split(transport);
        let mut reader = RecordReader::new();
        reader.enable_cipher(outcome.reader);
        let mut writer = RecordWriter::new();
        writer.enable_cipher(outcome.writer);
        let (app, inner) = duplex(PIPE);
        let (inner_read, inner_write) = split(inner);
        let reader_task = spawn(async move {
            let _ = pump_reads(reader, read_half, inner_write).await;
        });
        let writer_task = spawn(async move {
            let _ = pump_writes(writer, inner_read, write_half).await;
        });
        Ok(Self {
            app,
            reader_task: Some(reader_task),
            writer_task: Some(writer_task),
        })
    }

    /// 关闭写方向（管道 → TCP 的写任务随之结束），返回前等任务收尾。
    ///
    /// **幂等**：重复调用不 panic，也不会二次 await 同一个 `JoinHandle`
    /// （tokio 对**已完成**的句柄二次 poll 会 panic：
    /// `JoinHandle polled after completion`）。写任务句柄用 `Option` 持有，
    /// `take()` 之后即被「收走」⇒ 后续调用直接跳过。
    ///
    /// 返回值语义：**第一次**调用照常返回 `app.shutdown()` 的结果（可能是
    /// `Err`）；**之后**的调用返回 `Ok(())`。第一次的错误不吞掉。
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.app.shutdown().await?;
        // 写任务句柄只 await 一次：`take()` 之后即「已收走」。
        if let Some(task) = self.writer_task.take() {
            let _ = task.await;
        }
        Ok(())
    }

    /// 收尾：关闭写方向并等读任务结束（对端已关闭时立即返回）。
    ///
    /// **幂等**：重复调用不 panic、不重复等待任何任务（读任务句柄同样
    /// `take()` 一次）。`shutdown()` 之后再 `close()` 也是安全的：`close()`
    /// 仍会把 `reader_task` 收完（读任务由 `shutdown()` 从未碰过）。
    pub async fn close(&mut self) {
        let _ = self.shutdown().await;
        if let Some(task) = self.reader_task.take() {
            let _ = task.await;
        }
    }

    /// 尚未收走的**后台任务数**（写任务 + 读任务）。
    ///
    /// 幂等判据（供调用方与测试断言，不是「不崩就行」）：
    /// - 新建流是 `2`（写任务 + 读任务都待收）；
    /// - 第一次 `shutdown()` 后是 `1`（写任务已收走，**读任务仍在**）；
    /// - 第一次 `close()` 后是 `0`（读任务也被收走）。
    ///
    /// 重复调用 `shutdown()` / `close()` **不再改变**该计数，也不再等待
    /// 任何已被收走的任务。
    pub fn pending_tasks(&self) -> usize {
        usize::from(self.writer_task.is_some()) + usize::from(self.reader_task.is_some())
    }
}

/// 截止时间剩余量（已耗尽时取 1ms，让底层立即超时而不是零时长）。
fn remaining(end: Instant) -> Duration {
    let left = end.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Duration::from_millis(1)
    } else {
        left
    }
}

/// 读任务：`RecordReader` 解封记录，把应用数据明文写进管道。
///
/// 非应用数据记录（握手期残余、`change_cipher_spec`）跳过；对端 alert 与解封
/// 失败直接结束任务，应用侧读到 EOF（fail-closed，不会补出任何明文）。
async fn pump_reads<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: RecordReader,
    mut transport: R,
    mut sink: W,
) -> io::Result<()> {
    loop {
        let record = timeout(IO_DEADLINE, reader.next_record(&mut transport))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "REALITY: 读记录超时"))?
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        match record {
            None => return Ok(()),
            Some(Inbound::PlainChangeCipherSpec) => continue,
            // 应用数据阶段不应再出现明文握手记录（含残余的 `Finished`）。
            Some(Inbound::PlainHandshake(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "REALITY: 应用数据阶段收到明文握手记录",
                ))
            }
            // `framed[0]` 是内容类型；alert 在 `RecordReader` 里已升级为错误。
            Some(Inbound::Encrypted(framed)) => {
                if framed.first() != Some(&content_type::APPLICATION_DATA) {
                    continue;
                }
                timeout(IO_DEADLINE, sink.write_all(&framed[1..]))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "REALITY: 应用侧读超时")
                    })??;
            }
        }
    }
}

/// 写任务：把管道里的应用字节按 `2^14` 切成记录，逐条加密写出。
async fn pump_writes<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut writer: RecordWriter,
    mut source: R,
    mut transport: W,
) -> io::Result<()> {
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let read = timeout(IO_DEADLINE, source.read(&mut buffer))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "REALITY: 应用侧写超时"))??;
        if read == 0 {
            return transport.shutdown().await;
        }
        timeout(
            IO_DEADLINE,
            writer.write(
                &mut transport,
                &Outbound::EncryptedApplication(buffer[..read].to_vec()),
            ),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "REALITY: 写记录超时"))?
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    }
}

impl AsyncRead for RealityStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.app).poll_read(cx, buf)
    }
}

impl AsyncWrite for RealityStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.app).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.app).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.app).poll_shutdown(cx)
    }
}
