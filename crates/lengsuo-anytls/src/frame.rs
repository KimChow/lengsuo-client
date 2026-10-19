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
            stream.read_exact(&mut head).await?;
            let command = Command::try_from(head[0])?;
            let length = u16::from_be_bytes([head[5], head[6]]);
            if length > limit {
                return Err(Error::TooLarge);
            }
            let mut data = vec![0; length as usize];
            stream.read_exact(&mut data).await?;
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
