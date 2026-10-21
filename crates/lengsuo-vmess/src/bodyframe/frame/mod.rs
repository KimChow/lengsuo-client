//! 数据段一帧的组装与拆解（长度段 + 载荷密文 + 明文 padding）。
//!
//! 语义来源（只读参考，固定 commit `d2758a02`）：
//! - `common/crypto/auth.go` `AuthenticationWriter.seal`：写一帧的顺序是
//!   **先算 padding 长度、再封载荷、再编码长度段**；padding 是**明文**随机字节，
//!   追加在密文之后，不参与认证；声明长度 = 载荷密文长（含 tag）+ paddingLen。
//! - `common/crypto/auth.go` `AuthenticationReader.readSize`：读端同样**先**
//!   取 padding 长度（掩码流下一段），**再**解码长度段；掩码流跨帧连续。
//! - `common/crypto/auth.go` `AuthenticationReader.readInternal`：EOF 判据是
//!   「声明长度 == AEAD overhead + padding」（即空载荷帧）。
//! - `common/crypto/chunk.go` `AEADChunkSizeParser`：认证长度段线上 18 字节。
//!
//! 长度段的三种形态（参考 `EncodeRequestBody` 的选项组合）：
//! - [`SizeMode::Plain`]：裸 BE16（`PlainChunkSizeParser`）；
//! - [`SizeMode::Masked`]：SHA3-Shake128 掩码（`ShakeSizeParser`）；
//! - [`SizeMode::Authenticated`]：AEAD 认证（`AEADSizeParser`，替换掉 Shake 解析器，
//!   此时掩码流只用于 padding 长度）。
//!
//! 拆分：帧上下文与长度段/载荷的核心编解码在本文件，写侧封装在 [`seal`]，
//! 读侧解封装在 [`open`]。

mod open;
mod seal;

use crate::bodyframe::{size_mode_for_options, BodyCipher, BodySuite, SizeMode};
use crate::chunkframe::DataSizeParser;
use crate::{Error, Result};

/// 一个数据段帧的封装上下文：套件 + 长度段形态 + 掩码流 + padding 开关。
///
/// 不实现 `Debug`（内含密钥材料）。
///
/// 掩码流（`DataSizeParser`）只在 `ChunkMasking` 开启时存在：
/// - `SizeMode::Masked`：掩码流用于长度段（每帧 2 字节）；
/// - `SizeMode::Authenticated`：掩码流只用于 padding 长度（每帧 2 字节），
///   长度段本身是 AEAD 认证的（对齐参考 `AEADSizeParser` 替换掉 Shake 解析器
///   后，padding 生成器仍是同一个 Shake 解析器实例）。
pub struct BodyFrame {
    cipher: BodyCipher,
    mode: SizeMode,
    mask: Option<DataSizeParser>,
    padding: bool,
}

impl BodyFrame {
    /// 构造帧上下文。`mask` 传 `Some` 表示开启了 chunk 掩码（内部保存 Shake 状态）。
    pub fn new(
        cipher: BodyCipher,
        mode: SizeMode,
        mask: Option<DataSizeParser>,
        padding: bool,
    ) -> Self {
        BodyFrame {
            cipher,
            mode,
            mask,
            padding,
        }
    }

    /// 按请求 option 字节与安全档构造（含掩码流与 padding 开关）。
    ///
    /// `request_body_key/iv` 是**请求方向**的 body key/iv：载荷用 `body_key`，
    /// 认证长度段用 `request_body_key/iv`（响应方向两者不同）。
    pub fn for_request(
        suite: BodySuite,
        body_key: &[u8; 16],
        body_iv: &[u8; 16],
        request_body_key: &[u8; 16],
        request_body_iv: &[u8; 16],
        option: u8,
    ) -> Result<Self> {
        const OPT_CHUNK_MASKING: u8 = 0x04;
        const OPT_GLOBAL_PADDING: u8 = 0x08;
        let mode = size_mode_for_options(option, suite)?;
        let mut cipher = BodyCipher::from_suite(suite, body_key, body_iv);
        if mode == SizeMode::Authenticated {
            cipher.enable_authenticated_length(request_body_key, request_body_iv)?;
        }
        let mask = (option & OPT_CHUNK_MASKING != 0).then(|| DataSizeParser::new(body_iv));
        Ok(Self::new(
            cipher,
            mode,
            mask,
            option & OPT_GLOBAL_PADDING != 0,
        ))
    }

    /// 本帧上下文（诊断/测试用）。
    #[must_use]
    pub const fn cipher(&self) -> &BodyCipher {
        &self.cipher
    }

    /// 可变借用（诊断/测试用）。
    #[must_use]
    pub fn cipher_mut(&mut self) -> &mut BodyCipher {
        &mut self.cipher
    }

    /// 当前帧的 padding 长度（未开启 padding 时为 0）。
    ///
    /// 参考 `AuthenticationWriter.seal` 的顺序是**先算 padding、再编码长度段**，
    /// 掩码流的消耗顺序必须与之一致。
    fn next_padding_len(&mut self) -> Result<u16> {
        if !self.padding {
            return Ok(0);
        }
        let mask = self.mask.as_mut().ok_or(Error::Unsupported {
            feature: "global padding without chunk masking",
        })?;
        Ok(mask.next_padding_len())
    }

    /// 单帧的净载荷上限（明文字节数）。
    ///
    /// 对齐参考 `common/crypto/auth.go` 的 `AuthenticationWriter.writeStream`：
    /// ```text
    /// payloadSize = buf.Size - auth.Overhead() - sizeParser.SizeBytes() - maxPadding
    /// ```
    /// 其中 `buf.Size` = 8192、`maxPadding` = 64、`sizeParser.SizeBytes()` 是
    /// 长度段的线上字节数（裸/掩码 2，AEAD 认证 18）。
    #[must_use]
    pub fn max_payload(&self) -> usize {
        let overhead = self.cipher.suite().overhead();
        let size_bytes = self.mode.wire_len();
        let max_padding = if self.padding {
            crate::bodyframe::MAX_PADDING_LEN
        } else {
            0
        };
        crate::bodyframe::REF_BUF_SIZE
            .saturating_sub(overhead)
            .saturating_sub(size_bytes)
            .saturating_sub(max_padding)
    }

    /// 长度段在线上的字节数（本帧上下文）。
    #[must_use]
    pub const fn len_wire_len(&self) -> usize {
        self.mode.wire_len()
    }

    /// 解长度段：返回本帧长度段之后应跟随的字节数，以及本帧的 padding 长度。
    fn read_declared(&mut self, len_wire: &[u8]) -> Result<(u16, u16)> {
        let padding = self.next_padding_len()?;
        let declared = match self.mode {
            SizeMode::Plain => {
                if len_wire.len() < 2 {
                    return Err(Error::Truncated {
                        need: 2,
                        got: len_wire.len(),
                    });
                }
                u16::from_be_bytes([len_wire[0], len_wire[1]])
            }
            SizeMode::Masked => {
                if len_wire.len() < 2 {
                    return Err(Error::Truncated {
                        need: 2,
                        got: len_wire.len(),
                    });
                }
                let mask = self.mask.as_mut().ok_or(Error::Unsupported {
                    feature: "masked size without chunk masking",
                })?;
                mask.decode_size([len_wire[0], len_wire[1]])
            }
            SizeMode::Authenticated => self.cipher.open_len_segment(len_wire)?,
        };
        Ok((declared, padding))
    }

    /// 解载荷段（`body` = 长度段声明的全部字节，含 padding）。
    fn finish(&mut self, declared: u16, padding: u16, body: &[u8]) -> Result<Option<Vec<u8>>> {
        if body.len() < declared as usize {
            return Err(Error::Truncated {
                need: declared as usize,
                got: body.len(),
            });
        }
        if body.len() != declared as usize {
            return Err(Error::BadLength {
                declared: declared as usize,
                got: body.len(),
            });
        }
        let overhead = self.cipher.suite().overhead();
        // EOF 判据（参考 `AuthenticationReader.readInternal`）：
        // 声明长度 == AEAD overhead + padding 即空载荷帧。
        if declared as usize == overhead + padding as usize {
            return Ok(None);
        }
        if (declared as usize) < overhead + padding as usize {
            return Err(Error::BadLength {
                declared: declared as usize,
                got: overhead + padding as usize,
            });
        }
        let ct_len = declared as usize - padding as usize;
        let plain = self.cipher.open_payload(&body[..ct_len])?;
        Ok(Some(plain))
    }
}

#[cfg(test)]
mod tests;
