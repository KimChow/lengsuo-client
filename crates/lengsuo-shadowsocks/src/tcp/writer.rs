//! 单方向的发送端（[`Writer`]）：写出随机 salt 与后续 AEAD chunk。
//!
//! 与参考 `common/crypto/auth.go` 的 `AuthenticationWriter` 对应：一个方向一条
//! 独立的 salt + nonce 序列。**从不读取**，也**从不等待对端回复**。
//!
//! 持有 salt 派生出的 subkey 与 nonce 序列，因此**故意不实现 `Debug`**，
//! 避免密钥材料进入日志或调试输出。

use std::time::Duration;

use ss_core::chunk::write_chunk;
use ss_core::crypto::{CipherSuite, SessionAead};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use super::{check_timeout, core_error, Error, Result, MAX_SEGMENT_PAYLOAD};
use crate::key::MasterKey;

/// 一个方向的发送端：写出随机 salt 与后续 AEAD chunk，不读取、不等对端回复。
///
/// 持有 salt 派生出的 subkey 与 nonce 序列，因此**故意不实现 `Debug`**，
/// 避免密钥材料进入日志或调试输出。
pub struct Writer<W> {
    inner: W,
    suite: CipherSuite,
    aead: SessionAead,
    salt: Vec<u8>,
    salt_sent: bool,
    closed: bool,
    poisoned: bool,
    wait: Duration,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    /// 检查参数、取新随机 salt 并派生本方向会话。空口令、套件参数不符、零截止
    /// 时间都在返回 `Err` 时失败，不写出任何字节，也不留半构造状态。
    /// salt 在此刻生成，但直到首次 `send` 才上线；`new` 本身不做 I/O。
    pub fn new(write: W, suite: CipherSuite, password: &[u8], wait: Duration) -> Result<Self> {
        check_timeout(wait)?;
        let key = MasterKey::new(suite, password)?;
        let salt = key.new_salt().map_err(|_| Error::Entropy)?;
        let aead = key.session(&salt)?;
        Ok(Self {
            inner: write,
            suite,
            aead,
            salt,
            salt_sent: false,
            closed: false,
            poisoned: false,
            wait,
        })
    }

    #[must_use]
    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// 本套件 salt 长度。
    #[must_use]
    pub fn salt_len(&self) -> usize {
        self.suite.salt_len()
    }

    /// salt 是否已上线（首次成功的 `send` 之后为真）。
    #[must_use]
    pub fn salt_sent(&self) -> bool {
        self.salt_sent
    }

    /// 底层写端引用（例如查询 `TcpStream` 状态）。
    #[must_use]
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// 底层写端可变引用。绕过本类型直接写字节会破坏帧边界，仅供非协议用途
    /// （如查询能力、设置 socket 选项）。
    #[must_use]
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// 交出底层写端。若本方向已失效，流上字节位置不可恢复，调用方仍须关闭连接。
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// 把 `payload` 作为若干 chunk 写出：首次调用先把 salt 写出，随后按
    /// `MAX_SEGMENT_PAYLOAD` 分块，最后 flush。不等待也不读取对端任何字节。
    ///
    /// 空载荷不发送任何 chunk 帧（尤其不发送 size 明文为 0 的终止帧）；首次
    /// 空载荷仍会把 salt 上线，使该方向成为一个已建立、零 chunk 的空流。
    /// 一次调用是一个整体：单个 `wait` 覆盖 salt 与全部分块。
    /// 任何错误之后本方向永久失效，调用方必须关闭连接。
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        self.usable()?;
        let outcome = self.send_inner(payload).await;
        if outcome.is_err() {
            self.poisoned = true;
        }
        outcome
    }

    /// 正常收尾：flush 后对底层做写半关闭（TCP 上是 `SHUT_WR`），让对端恰好在
    /// chunk 边界看到 EOF。不发送终止帧，因此不消耗 nonce。可重复调用；
    /// 之后 `send` 报 `Closed`。超时或 I/O 失败同样永久失效本方向。
    pub async fn shutdown(&mut self) -> Result<()> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.closed {
            return Ok(());
        }
        let wait = self.wait;
        let inner = &mut self.inner;
        let outcome = timeout(wait, async move {
            inner.flush().await?;
            inner.shutdown().await
        })
        .await;
        match outcome {
            Ok(Ok(())) => {
                self.closed = true;
                Ok(())
            }
            Ok(Err(io)) => {
                self.poisoned = true;
                Err(Error::Io(io))
            }
            Err(_) => {
                self.poisoned = true;
                Err(Error::Timeout)
            }
        }
    }

    async fn send_inner(&mut self, payload: &[u8]) -> Result<()> {
        let wait = self.wait;
        let need_salt = !self.salt_sent;
        // 逐字段借用：salt 只读，inner/aead 可变，三者互不重叠。
        let salt = &self.salt;
        let inner = &mut self.inner;
        let aead = &mut self.aead;
        timeout(wait, async move {
            if need_salt {
                inner.write_all(salt).await.map_err(Error::Io)?;
            }
            for piece in payload.chunks(MAX_SEGMENT_PAYLOAD) {
                write_chunk(inner, aead, piece).await.map_err(core_error)?;
            }
            inner.flush().await.map_err(Error::Io)
        })
        .await
        .map_err(|_| Error::Timeout)??;
        self.salt_sent = true;
        Ok(())
    }

    fn usable(&self) -> Result<()> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.closed {
            return Err(Error::Closed);
        }
        Ok(())
    }
}
