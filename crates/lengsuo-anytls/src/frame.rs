//! 基线 anytls-go fd6167acd6d73b9fa3e607659951847fbc9e6c50，协议 v2。
//! 只处理帧结构；方向、Settings顺序、Stream ID单调性由会话层检查。
use crate::Error;
use std::time::Duration;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

/// 帧头长度：cmd(1) + stream id(4) + length(2)，与参考 `headerOverHeadSize` 一致。
pub const fn header_size() -> usize {
    7
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Waste = 0,
    Syn = 1,
    Push = 2,
    Fin = 3,
    Settings = 4,
    Alert = 5,
    UpdatePadding = 6,
    SynAck = 7,
    HeartRequest = 8,
    HeartResponse = 9,
    ServerSettings = 10,
}
impl TryFrom<u8> for Command {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Error> {
        Ok(match value {
            0 => Self::Waste,
            1 => Self::Syn,
            2 => Self::Push,
            3 => Self::Fin,
            4 => Self::Settings,
            5 => Self::Alert,
            6 => Self::UpdatePadding,
            7 => Self::SynAck,
            8 => Self::HeartRequest,
            9 => Self::HeartResponse,
            10 => Self::ServerSettings,
            _ => return Err(Error::Invalid),
        })
    }
}

/// 不派生 Debug，避免应用载荷出现在诊断日志。
#[derive(PartialEq, Eq)]
pub struct Frame {
    pub command: Command,
    pub stream_id: u32,
    pub data: Vec<u8>,
}
impl Frame {
    fn validate(&self) -> Result<(), Error> {
        if self.data.len() > u16::MAX as usize {
            return Err(Error::TooLarge);
        }
        if !self.data.is_empty()
            && matches!(
                self.command,
                Command::Syn | Command::Fin | Command::HeartRequest | Command::HeartResponse
            )
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(7 + self.data.len());
        bytes.push(self.command as u8);
        bytes.extend_from_slice(&self.stream_id.to_be_bytes());
        bytes.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.data);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), Error> {
        let head = bytes.get(..7).ok_or(Error::Incomplete)?;
        let command = Command::try_from(head[0])?;
        let stream_id = u32::from_be_bytes(head[1..5].try_into().expect("固定长度"));
        let length = u16::from_be_bytes([head[5], head[6]]) as usize;
        let data = bytes.get(7..7 + length).ok_or(Error::Incomplete)?.to_vec();
        let frame = Self {
            command,
            stream_id,
            data,
        };
        frame.validate()?;
        Ok((frame, 7 + length))
    }
    pub async fn write<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
        wait: Duration,
    ) -> Result<(), Error> {
        if wait.is_zero() {
            return Err(Error::Invalid);
        }
        let bytes = self.encode()?;
        timeout(wait, async {
            stream.write_all(&bytes).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| Error::Timeout)??;
        Ok(())
    }
    pub async fn read<R: AsyncRead + Unpin>(
        stream: &mut R,
        limit: u16,
        wait: Duration,
    ) -> Result<Self, Error> {
        if wait.is_zero() {
            return Err(Error::Invalid);
        }
        timeout(wait, async {
            let mut head = [0; 7];
            // 帧头在**帧边界**：一个字节都没读到 = 对端干净关闭；读到一半 = 截断。
            let filled = fill(stream, &mut head).await?;
            if filled < head.len() {
                return Err(eof_error(if filled == 0 {
                    Eof::Clean
                } else {
                    Eof::Truncated
                }));
            }
            let command = Command::try_from(head[0])?;
            let length = u16::from_be_bytes([head[5], head[6]]);
            if length > limit {
                return Err(Error::TooLarge);
            }
            let mut data = vec![0; length as usize];
            // 载荷在**帧内**：头已完整、长度字段声明了 N 字节却只收到 <N ⇒
            // 截断（哪怕一个字节都没收到也是截断——此时已不在帧边界上）。
            let filled = fill(stream, &mut data).await?;
            if filled < data.len() {
                return Err(eof_error(Eof::Truncated));
            }
            let frame = Self {
                command,
                stream_id: u32::from_be_bytes(head[1..5].try_into().expect("固定长度")),
                data,
            };
            frame.validate()?;
            Ok(frame)
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
}

/// 帧读侧的收尾分类：把「干净收尾」与「截断」分成两个**有名**的取值。
///
/// 这是本卡修的缺陷的核心（`docs/audit-all1.md` §6 P2-10 ①）：旧实现用
/// `read_exact` 读帧头与载荷，把「一个字节都没读到」与「读到一半」**都**报成
/// `ErrorKind::UnexpectedEof` ⇒ 调用方无法区分「对端正常关闭」与「帧被中途
/// 截断」⇒ 截断帧被当作正常收尾（fail-open）。
///
/// 语义对齐参考 anytls-go `proxy/session/session.go:190` 的 `io.ReadFull`：
/// 一个字节都没读到是 `io.EOF`（正常收尾），读到一半才是 `io.ErrUnexpectedEOF`
/// （截断，fail-closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eof {
    /// 帧边界处的干净 EOF：对端正常关闭。
    Clean,
    /// 帧中途 EOF：帧被截断（协议错误，必须 fail-closed）。
    Truncated,
}
impl std::fmt::Display for Eof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => f.write_str("对端已关闭连接"),
            Self::Truncated => f.write_str("帧被截断"),
        }
    }
}
impl std::error::Error for Eof {}

/// 读 `buf`，返回**实际读到的字节数**。
///
/// - 返回值 `< buf.len()` ⇒ 提前 EOF（字节不够，被截断）；
/// - 返回值 `== buf.len()` ⇒ 读满。
///
/// ⛔ 不能用 `read_exact`：它把「一个字节都没读到」与「读到一半」**都**报成
/// `ErrorKind::UnexpectedEof` ⇒ 调用方无法区分「对端正常关闭」与「帧被中途
/// 截断」⇒ 截断帧被当作正常收尾（fail-open）。
/// ⛔ 不得「读多少算多少」：读到一半必须**报错**，绝不能把截断帧当有效帧交付
/// （那才是真正的 fail-open）。
async fn fill<R: AsyncRead + Unpin>(stream: &mut R, buf: &mut [u8]) -> Result<usize, Error> {
    let mut filled = 0;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]).await {
            // `Ok(0)` = EOF。
            Ok(0) => return Ok(filled),
            Ok(count) => filled += count,
            Err(err) => return Err(Error::Io(err)),
        }
    }
    Ok(filled)
}

/// EOF 分类的错误值。
///
/// ⚠️ 外层 `ErrorKind` 仍是 `UnexpectedEof`：既有用例把「传输层 EOF」的 kind
/// 钉在 `UnexpectedEof` 上（`tests/lifecycle.rs:316` 取 `Error::Io(io).kind()`、
/// `tests/lifecycle/half_close.rs:203` 断言截断的 kind 是 `UnexpectedEof`、
/// `tests/interop_server/session.rs:320` 用 `kind() == UnexpectedEof` 判干净
/// 收尾）⇒ 改 kind 会打红**不可修改**的既有用例。
/// **分类信息由内层 [`Eof`] 承载**（可用 [`eof_kind`] 取回）⇒「干净 EOF」与
/// 「截断」仍是**两个不同的错误值**，既有断言却不必改动。
fn eof_error(kind: Eof) -> Error {
    Error::Io(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, kind))
}

/// 从错误里取回 EOF 分类（`None` = 不是 EOF 类错误，例如超时或连接重置）。
pub fn eof_kind(err: &Error) -> Option<Eof> {
    match err {
        Error::Io(io) => io
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<Eof>())
            .copied(),
        _ => None,
    }
}
