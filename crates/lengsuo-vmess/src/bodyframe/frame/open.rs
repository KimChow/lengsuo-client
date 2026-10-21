//! 数据段帧的**读侧**解封装：解一帧（长度段 + 载荷密文 + 明文 padding）。
//!
//! 语义来源（只读参考，固定 commit `d2758a02`）：`common/crypto/auth.go`
//! `AuthenticationReader.readSize` / `readInternal` —— 先取 padding 长度、
//! 再解码长度段、最后按声明长度读载荷；EOF 判据是「声明长度 == AEAD
//! overhead + padding」。

use crate::{Error, Result};

use super::BodyFrame;

impl BodyFrame {
    /// 解一帧（输入是「长度段 + 载荷密文(+padding)」的完整字节）。
    ///
    /// `Ok(None)` = EOF 帧。
    pub fn open(&mut self, wire: &[u8]) -> Result<Option<Vec<u8>>> {
        let len_wire = self.mode.wire_len();
        if wire.len() < len_wire {
            return Err(Error::Truncated {
                need: len_wire,
                got: wire.len(),
            });
        }
        let (declared, padding) = self.read_declared(&wire[..len_wire])?;
        self.finish(declared, padding, &wire[len_wire..])
    }

    /// 从字节流同步解一帧：读长度段 → 按声明长度读载荷 → 解密。
    ///
    /// `Ok(None)` = EOF 帧；字节不足 = [`Error::Truncated`]（与异步版的
    /// [`Error::Io`] 不同——同步版不区分 I/O 错误种类）。
    pub fn open_from(&mut self, stream: &mut &[u8]) -> Result<Option<Vec<u8>>> {
        let len_wire = self.mode.wire_len();
        if stream.len() < len_wire {
            return Err(Error::Truncated {
                need: len_wire,
                got: stream.len(),
            });
        }
        let (declared, padding) = self.read_declared(&stream[..len_wire])?;
        let total = len_wire + declared as usize;
        if stream.len() < total {
            return Err(Error::Truncated {
                need: total,
                got: stream.len(),
            });
        }
        let body = &stream[len_wire..total];
        *stream = &stream[total..];
        self.finish(declared, padding, body)
    }

    /// 异步读一帧。`Ok(None)` = EOF 帧；读端关闭/截断 = [`Error::Io`]。
    pub async fn read_from<R: tokio::io::AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<Vec<u8>>> {
        let len_wire = self.mode.wire_len();
        let mut len = [0u8; 2 + crate::bodyframe::TAG_LEN];
        tokio::io::AsyncReadExt::read_exact(reader, &mut len[..len_wire])
            .await
            .map_err(|error| crate::io_err(&error))?;
        // 先解长度段（同时消耗 padding 掩码），再按声明长度读载荷。
        let (declared, padding) = self.read_declared(&len[..len_wire])?;
        let mut body = vec![0u8; declared as usize];
        tokio::io::AsyncReadExt::read_exact(reader, &mut body)
            .await
            .map_err(|error| crate::io_err(&error))?;
        self.finish(declared, padding, &body)
    }

    /// **同步**读一帧（阻塞式 `Read`）。
    ///
    /// 与 [`Self::read_from`] 语义相同：先读长度段、解出声明长度，再按声明长度
    /// 读载荷。区别只在 I/O 是同步的——服务端夹具跑在阻塞线程里，用得上。
    pub fn read_sync<R: std::io::Read>(&mut self, reader: &mut R) -> Result<Option<Vec<u8>>> {
        let len_wire = self.mode.wire_len();
        let mut len = [0u8; 2 + crate::bodyframe::TAG_LEN];
        read_exact_sync(reader, &mut len[..len_wire])?;
        let (declared, padding) = self.read_declared(&len[..len_wire])?;
        let mut body = vec![0u8; declared as usize];
        read_exact_sync(reader, &mut body)?;
        self.finish(declared, padding, &body)
    }
}

/// 同步读满 `buf`；不足即 [`Error::Io`]（`UnexpectedEof`）。
fn read_exact_sync<R: std::io::Read>(reader: &mut R, buf: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader
            .read(&mut buf[filled..])
            .map_err(|error| crate::io_err(&error))?;
        if n == 0 {
            return Err(Error::Io("UnexpectedEof".to_string()));
        }
        filled += n;
    }
    Ok(())
}
