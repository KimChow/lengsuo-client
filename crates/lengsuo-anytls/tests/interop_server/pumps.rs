//! 单流的两向中继任务与唯一的 TLS 写出通道。
//! 职责：字节进出（AsyncRead/AsyncWrite 抽象，不关心明文或 TLS）；帧语义在 session.rs。
use crate::report::{protocol, transport, Failure};
use lengsuo_anytls::frame::{Command, Frame};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::time::timeout;

/// 回程中继一次出站读取的块大小。
const CHUNK: usize = 2048;

/// 写出字节并回报错误；失败即视为会话终止（fail-closed）。
pub async fn pump_bytes<W>(writer: &mut W, bytes: &[u8], wait: Duration) -> Result<(), Failure>
where
    W: AsyncWrite + Unpin,
{
    timeout(wait, async {
        writer.write_all(bytes).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| transport("写出超时".to_owned()))
    .and_then(|outcome| outcome.map_err(|err| transport(format!("写出失败：{err}"))))
}

/// 唯一写出通道：把帧字节按序刷进 TLS，直到通道关闭或写失败。
pub async fn drain_writer<W>(mut writer: W, mut frames: UnboundedReceiver<Vec<u8>>, wait: Duration)
where
    W: AsyncWrite + Unpin,
{
    while let Some(bytes) = frames.recv().await {
        if pump_bytes(&mut writer, &bytes, wait).await.is_err() {
            break;
        }
    }
}

/// 会话内的写出与计数；克隆一份交给各回程任务。
#[derive(Clone)]
pub struct Session {
    pub frames: UnboundedSender<Vec<u8>>,
    pub wait: Duration,
}

impl Session {
    pub fn send(&self, frame: &Frame) -> Result<(), Failure> {
        let bytes = frame
            .encode()
            .map_err(|err| protocol(format!("帧编码失败：{err}")))?;
        self.frames
            .send(bytes)
            .map_err(|_| transport("写出通道已关闭".to_owned()))
    }
}

/// 单流的跨任务状态：客户端是否已 FIN、回程字节计数。
#[derive(Default)]
pub struct Flags {
    pub client_fin: AtomicBool,
    pub bytes_out: AtomicUsize,
}

/// 出站方向：把客户端数据写进目标，通道关闭（客户端 FIN 或会话收尾）后半关闭。
pub async fn feed_target(
    mut write: OwnedWriteHalf,
    mut inbound: UnboundedReceiver<Vec<u8>>,
    wait: Duration,
) {
    while let Some(bytes) = inbound.recv().await {
        if pump_bytes(&mut write, &bytes, wait).await.is_err() {
            break;
        }
    }
    let _ = write.shutdown().await;
}

/// 回程方向：读目标直到 EOF，按块发 PUSH；本端未先收到 FIN 时补发一条 FIN。
pub async fn collect_target(
    sid: u32,
    mut read: OwnedReadHalf,
    session: Session,
    flags: Arc<Flags>,
    wait: Duration,
) {
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let count = match timeout(wait, read.read(&mut buffer)).await {
            Err(_) => return,
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(count)) => count,
        };
        let frame = Frame {
            command: Command::Push,
            stream_id: sid,
            data: buffer[..count].to_vec(),
        };
        if session.send(&frame).is_err() {
            return;
        }
        flags.bytes_out.fetch_add(count, Ordering::Relaxed);
    }
    if !flags.client_fin.load(Ordering::Relaxed) {
        let _ = session.send(&crate::report::control(Command::Fin, sid));
    }
}
