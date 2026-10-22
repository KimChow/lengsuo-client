//! 记录流的发送 / 接收方向：对齐 `CommonConn.Write` / `CommonConn.Read`。
//!
//! 从 [`super`] 拆出以保持单文件 ≤400 行（软约束）。

use super::cipher::Aead;
use super::codec::{decode_header, encode_header, HEADER_LEN, MAX_BODY_LEN, MIN_BODY_LEN};
use super::{Cipher, Error, RECORD_CHUNK, TAG_LEN};

/// AEAD 记录发送方向（对齐 `CommonConn.Write`：按 8192 分块，5 字节头作 AAD）。
#[derive(Debug)]
pub struct RecordWriter {
    aead: Aead,
}

impl RecordWriter {
    pub fn new(ctx: &str, key: &[u8], cipher: Cipher) -> Self {
        Self {
            aead: Aead::new(ctx, key, cipher),
        }
    }

    pub fn is_poisoned(&self) -> bool {
        false // 发送方向只有 nonce 用尽才失败，失败即返回错误并弃用实例
    }

    /// 已使用记录数（= 已消耗 nonce 次数；仅诊断）。
    pub fn sequence(&self) -> u64 {
        let mut count = 0u64;
        for byte in self.aead.nonce() {
            count = (count << 8) | u64::from(*byte);
        }
        count
    }

    /// 把整段明文按参考分块封成连续记录字节（头 + 密文||tag）。
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        for chunk in plaintext.chunks(RECORD_CHUNK) {
            let body_len = chunk.len() + TAG_LEN;
            if body_len > MAX_BODY_LEN {
                return Err(Error::InvalidRecordLength {
                    got: body_len,
                    min: MIN_BODY_LEN,
                    max: MAX_BODY_LEN,
                });
            }
            let mut header = [0u8; HEADER_LEN];
            encode_header(&mut header, body_len);
            let body = self.aead.seal(None, chunk, &header)?;
            out.extend_from_slice(&header);
            out.extend_from_slice(&body);
        }
        Ok(out)
    }
}

/// AEAD 记录接收方向（对齐 `CommonConn.Read`：重组成完整记录并按序解封）。
pub struct RecordReader {
    pending: Vec<u8>,
    aead: Aead,
    poisoned: bool,
}

impl RecordReader {
    pub fn new(ctx: &str, key: &[u8], cipher: Cipher) -> Self {
        Self {
            pending: Vec::with_capacity(HEADER_LEN + MIN_BODY_LEN),
            aead: Aead::new(ctx, key, cipher),
            poisoned: false,
        }
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn buffered(&self) -> usize {
        self.pending.len()
    }

    /// 追加线上字节；凑不齐一条记录属于正常等待。
    pub fn push(&mut self, wire: &[u8]) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.pending.len().saturating_add(wire.len()) > HEADER_LEN + MAX_BODY_LEN {
            let got = self.pending.len() + wire.len();
            self.poisoned = true;
            self.pending.clear();
            return Err(Error::InvalidRecordLength {
                got,
                min: MIN_BODY_LEN,
                max: MAX_BODY_LEN,
            });
        }
        self.pending.extend_from_slice(wire);
        Ok(())
    }

    /// 取出下一条记录的明文；不足一条返回 `Ok(None)`。
    pub fn next_plaintext(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.pending.len() < HEADER_LEN {
            return Ok(None);
        }
        let header: [u8; HEADER_LEN] = self.pending[..HEADER_LEN].try_into().expect("5 字节");
        let body_len = decode_header(&header).map_err(|_| self.fail())?;
        let total = HEADER_LEN + body_len;
        if self.pending.len() < total {
            return Ok(None);
        }
        let body = self.pending[HEADER_LEN..total].to_vec();
        let plaintext = match self.aead.open(None, &body, &header) {
            Ok(plaintext) => plaintext,
            Err(error) => {
                self.poisoned = true;
                self.pending.clear();
                return Err(error);
            }
        };
        self.pending.drain(..total);
        Ok(Some(plaintext))
    }

    /// 流结束检查：残字节即截断。
    pub fn finish(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.pending.is_empty() {
            return Ok(());
        }
        let got = self.pending.len();
        let need = if self.pending.len() >= HEADER_LEN {
            let header: [u8; HEADER_LEN] = self.pending[..HEADER_LEN].try_into().expect("5 字节");
            match decode_header(&header) {
                Ok(body_len) => HEADER_LEN + body_len - got,
                Err(_) => HEADER_LEN - got,
            }
        } else {
            HEADER_LEN - got
        };
        self.poisoned = true;
        self.pending.clear();
        Err(Error::Truncated { need, got })
    }

    fn fail(&mut self) -> Error {
        self.poisoned = true;
        self.pending.clear();
        Error::InvalidHeader
    }
}
