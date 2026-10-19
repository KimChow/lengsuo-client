//! 会话写出侧：对齐参考 `session.writeControlFrame` / `writeDataFrame` / `writeConn`。
//!
//! 参考把发送缓冲区分片后按 padding 大小表切分：每片要么全是负载（直接写），
//! 要么「尾部负载 + 一个 Waste 帧」，要么「整片一个 Waste 帧」。`stop` 之前的写包
//! 计数达到后关闭填充。此处保留同样的切分算法，只把 buf 池换成 `Vec<u8>`。
//!
//! 与参考一致：控制帧的写超时是 5 秒；数据帧不设额外截止时间。
use crate::frame::{header_size, Command, Frame};
use crate::padding::{PaddingScheme, Spec};
use crate::Error;
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

/// 参考 `writeControlFrame` 的写超时。
const CONTROL_WRITE: Duration = Duration::from_secs(5);

/// 会话写出侧的全部状态：帧编码、padding 方案与写包计数。
pub struct FrameWriter<S> {
    stream: S,
    padding: PaddingScheme,
    /// `sendPadding`：一旦达到 `stop` 就永久关闭。
    send_padding: bool,
    /// `pktCounter`。
    packets: u32,
}

impl<S: AsyncWrite + Unpin> FrameWriter<S> {
    pub fn new(stream: S, padding: PaddingScheme) -> Self {
        Self {
            stream,
            padding,
            send_padding: true,
            packets: 0,
        }
    }

    pub fn padding(&self) -> &PaddingScheme {
        &self.padding
    }

    /// 替换 padding 方案（收到 UpdatePaddingScheme 后由客户端调用）。
    pub fn set_padding(&mut self, padding: PaddingScheme) {
        self.padding = padding;
    }

    /// 控制帧：带 5 秒写超时；失败返回错误，调用方须关闭会话。
    pub async fn control(&mut self, command: Command, stream_id: u32) -> Result<(), Error> {
        self.control_data(command, stream_id, &[]).await
    }

    /// 带载荷的控制帧（Settings / ServerSettings / UpdatePaddingScheme / 失败 SYNACK）。
    pub async fn control_data(
        &mut self,
        command: Command,
        stream_id: u32,
        data: &[u8],
    ) -> Result<(), Error> {
        let frame = Frame {
            command,
            stream_id,
            data: data.to_vec(),
        };
        let bytes = frame.encode()?;
        timeout(CONTROL_WRITE, self.conn_write(&bytes))
            .await
            .map_err(|_| Error::Timeout)?
    }

    /// 数据帧：无写超时；字节数与参考一致（未被填充吞掉的部分）。
    pub async fn data(&mut self, stream_id: u32, data: &[u8]) -> Result<usize, Error> {
        let mut bytes = Vec::with_capacity(header_size() + data.len());
        bytes.push(Command::Push as u8);
        bytes.extend_from_slice(&stream_id.to_be_bytes());
        bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
        bytes.extend_from_slice(data);
        let written = data.len();
        self.conn_write(&bytes).await?;
        Ok(written)
    }

    /// 参考 `writeConn`：先按大小表切分写出，剩余部分再整块写出。
    /// 暴露给 `server::sink` 复用同一条 padded 写出路径。
    pub async fn write_many(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.conn_write(bytes).await
    }

    async fn conn_write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if !self.send_padding {
            return self.write_all(bytes).await;
        }
        self.packets += 1;
        let mut rest = bytes;
        let sizes = self.padding.specs(self.packets).to_vec();
        for spec in sizes {
            let size = match spec {
                Spec::Check => {
                    // 参考：载荷已写完就停止处理本包，否则跳过该条目。
                    if rest.is_empty() {
                        break;
                    }
                    continue;
                }
                Spec::Range { min, max } => random_size(min, max),
            };
            let size = size as usize;
            let remain = rest.len();
            if remain > size {
                // 整片都是负载。
                self.write_all(&rest[..size]).await?;
                rest = &rest[size..];
            } else if remain > 0 {
                // 尾部负载 + 一个 Waste 帧（帧头不计入大小表）。
                let padding = size.saturating_sub(remain + header_size());
                if padding > 0 {
                    let mut buffer = Vec::with_capacity(remain + header_size() + padding);
                    buffer.extend_from_slice(rest);
                    buffer.extend_from_slice(&waste_frame(padding as u16)?);
                    self.write_all(&buffer).await?;
                } else {
                    self.write_all(rest).await?;
                }
                rest = &[];
            } else {
                // 整片都是填充。
                self.write_all(&waste_frame(size as u16)?).await?;
                rest = &[];
            }
        }
        if !rest.is_empty() {
            self.write_all(rest).await?;
        }
        if self.packets >= self.padding.stop() {
            self.send_padding = false;
        }
        Ok(())
    }

    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }
}

/// 以参考的 5 秒写超时写一段已编码的控制帧字节（供不持有 `FrameWriter` 的路径复用）。
pub async fn write_control<S: AsyncWrite + Unpin>(
    stream: &mut S,
    bytes: &[u8],
) -> Result<(), Error> {
    timeout(CONTROL_WRITE, async {
        stream.write_all(bytes).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| Error::Timeout)??;
    Ok(())
}

/// Waste 帧：cmd=0、stream id=0、BE16 长度 = padding。
fn waste_frame(padding: u16) -> Result<Vec<u8>, Error> {
    Frame {
        command: Command::Waste,
        stream_id: 0,
        data: vec![0u8; padding as usize],
    }
    .encode()
}

/// 参考 `rand.Int(rand.Reader, big.NewInt(max-min)) + min`：`min == max` 时固定返回 min。
fn random_size(min: i64, max: i64) -> i64 {
    if max <= min {
        return min;
    }
    let span = (max - min) as u64;
    let low = low_u64();
    min + (low % span) as i64
}

/// 一次性熵：从操作系统取 8 字节；失败时退化为进程内计数器，
/// 保证写出路径不因取随机数失败而中断会话。
fn low_u64() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static FALLBACK: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);
    let mut bytes = [0u8; 8];
    if getrandom::getrandom(&mut bytes).is_ok() {
        u64::from_le_bytes(bytes)
    } else {
        let previous = FALLBACK.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
        previous ^ previous.rotate_left(17)
    }
}
