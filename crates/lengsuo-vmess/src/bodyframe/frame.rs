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

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::bodyframe::{size_mode_for_options, BodyCipher, BodySuite, SizeMode, TAG_LEN};
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

    /// 封一帧：长度段 + 载荷密文 + 明文 padding，追加到 `out`。
    ///
    /// `payload` 超过本帧的净载荷上限时**按参考的切分方式分成多帧**
    /// （见 [`Self::max_payload`]）：参考的 `AuthenticationWriter.writeStream`
    /// 把载荷切成 `buf.Size - overhead - sizeBytes - maxPadding` 的片，每片
    /// 各自封一帧；`writePacket`（UDP）则一包一帧，不切分。
    pub fn seal(&mut self, out: &mut Vec<u8>, payload: &[u8]) -> Result<()> {
        if payload.is_empty() {
            // 空载荷帧 = 终止帧（参考 `AuthenticationWriter.WriteMultiBuffer` 的
            // 空 MultiBuffer 分支：恰好一帧，不是零帧）。
            return self.seal_one(out, payload);
        }
        let limit = self.max_payload();
        for piece in payload.chunks(limit) {
            self.seal_one(out, piece)?;
        }
        Ok(())
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

    /// 封**一**帧（不切分）。
    fn seal_one(&mut self, out: &mut Vec<u8>, payload: &[u8]) -> Result<()> {
        let padding = self.next_padding_len()?;
        let ct = self.cipher.seal_payload(payload)?;
        let total = u16::try_from(ct.len() + padding as usize).map_err(|_| Error::BadLength {
            declared: ct.len() + padding as usize,
            got: u16::MAX as usize,
        })?;
        match self.mode {
            SizeMode::Plain => out.extend_from_slice(&total.to_be_bytes()),
            SizeMode::Masked => {
                let mask = self.mask.as_mut().ok_or(Error::Unsupported {
                    feature: "masked size without chunk masking",
                })?;
                out.extend_from_slice(&mask.encode_size(total));
            }
            SizeMode::Authenticated => {
                let segment = self.cipher.seal_len_segment(total)?;
                out.extend_from_slice(&segment);
            }
        }
        out.extend_from_slice(&ct);
        if padding > 0 {
            let mut pad = vec![0u8; padding as usize];
            crate::fill_random(&mut pad)?;
            out.extend_from_slice(&pad);
        }
        Ok(())
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

    /// 异步写一帧。
    pub async fn write_to<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        payload: &[u8],
    ) -> Result<()> {
        let mut frame = Vec::with_capacity(self.mode.wire_len() + payload.len() + TAG_LEN + 64);
        self.seal(&mut frame, payload)?;
        writer
            .write_all(&frame)
            .await
            .map_err(|error| crate::io_err(&error))
    }

    /// 异步读一帧。`Ok(None)` = EOF 帧；读端关闭/截断 = [`Error::Io`]。
    pub async fn read_from<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<Vec<u8>>> {
        let len_wire = self.mode.wire_len();
        let mut len = [0u8; 2 + TAG_LEN];
        reader
            .read_exact(&mut len[..len_wire])
            .await
            .map_err(|error| crate::io_err(&error))?;
        // 先解长度段（同时消耗 padding 掩码），再按声明长度读载荷。
        let (declared, padding) = self.read_declared(&len[..len_wire])?;
        let mut body = vec![0u8; declared as usize];
        reader
            .read_exact(&mut body)
            .await
            .map_err(|error| crate::io_err(&error))?;
        self.finish(declared, padding, &body)
    }

    /// 长度段在线上的字节数（本帧上下文）。
    #[must_use]
    pub const fn len_wire_len(&self) -> usize {
        self.mode.wire_len()
    }

    /// **同步**读一帧（阻塞式 `Read`）。
    ///
    /// 与 [`Self::read_from`] 语义相同：先读长度段、解出声明长度，再按声明长度
    /// 读载荷。区别只在 I/O 是同步的——服务端夹具跑在阻塞线程里，用得上。
    pub fn read_sync<R: std::io::Read>(&mut self, reader: &mut R) -> Result<Option<Vec<u8>>> {
        let len_wire = self.mode.wire_len();
        let mut len = [0u8; 2 + TAG_LEN];
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

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = *b"request-body-key";
    const IV: [u8; 16] = *b"request-body-iv!";

    /// `Result::expect_err` 需要 `T: Debug`，而 `BodyCipher`/`BodyFrame` 刻意
    /// 不实现 `Debug`（内含密钥）。这里显式取错误变体。
    fn expect_err<T>(result: Result<T>) -> Error {
        match result {
            Ok(_) => panic!("预期失败但成功了"),
            Err(error) => error,
        }
    }

    fn roundtrip(suite: BodySuite, option: u8) {
        let mut seal = BodyFrame::for_request(suite, &KEY, &IV, &KEY, &IV, option).expect("可建");
        let mut open = BodyFrame::for_request(suite, &KEY, &IV, &KEY, &IV, option).expect("可建");
        let mut wire = Vec::new();
        seal.seal(&mut wire, b"hello").expect("可写");
        seal.seal(&mut wire, &[0x5Au8; 300]).expect("可写");
        seal.seal(&mut wire, b"").expect("EOF 可写");

        let mut cursor = &wire[..];
        let first = open.open_from(&mut cursor).expect("可解");
        assert_eq!(
            first.as_deref(),
            Some(&b"hello"[..]),
            "suite={suite:?} option={option:#x}"
        );
        let second = open.open_from(&mut cursor).expect("可解");
        assert_eq!(second.as_deref(), Some(&[0x5Au8; 300][..]));
        let eof = open.open_from(&mut cursor).expect("可解");
        assert!(eof.is_none(), "终止帧应得到 None 而非空载荷");
        assert!(cursor.is_empty(), "不得吞尾部字节");
    }

    #[test]
    fn roundtrip_all_suites_all_size_modes() {
        for suite in [
            BodySuite::None,
            BodySuite::Aes128Gcm,
            BodySuite::ChaCha20Poly1305,
        ] {
            for option in [0x00u8, 0x04, 0x0C] {
                roundtrip(suite, option);
            }
            if suite != BodySuite::None {
                roundtrip(suite, 0x10); // 认证长度段
                roundtrip(suite, 0x1C); // 认证长度段 + 掩码 + padding
            }
        }
    }

    #[test]
    fn cross_suite_ciphertext_does_not_open() {
        let mut aes_seal =
            BodyFrame::for_request(BodySuite::Aes128Gcm, &KEY, &IV, &KEY, &IV, 0).expect("可建");
        let mut wire = Vec::new();
        aes_seal.seal(&mut wire, b"cross-suite").expect("可写");
        let mut chacha_open =
            BodyFrame::for_request(BodySuite::ChaCha20Poly1305, &KEY, &IV, &KEY, &IV, 0)
                .expect("可建");
        let err = expect_err(chacha_open.open(&wire));
        assert!(matches!(err, Error::AuthFailed), "实际 {err:?}");
    }

    #[test]
    fn authenticated_length_tamper_is_rejected() {
        let mut seal =
            BodyFrame::for_request(BodySuite::ChaCha20Poly1305, &KEY, &IV, &KEY, &IV, 0x10)
                .expect("可建");
        let mut wire = Vec::new();
        seal.seal(&mut wire, b"payload").expect("可写");
        wire[3] ^= 0x01; // 破坏认证长度段密文
        let mut open =
            BodyFrame::for_request(BodySuite::ChaCha20Poly1305, &KEY, &IV, &KEY, &IV, 0x10)
                .expect("可建");
        let err = expect_err(open.open(&wire));
        assert!(matches!(err, Error::AuthFailed), "实际 {err:?}");
    }

    #[test]
    fn global_padding_without_masking_is_rejected() {
        let err = expect_err(BodyFrame::for_request(
            BodySuite::Aes128Gcm,
            &KEY,
            &IV,
            &KEY,
            &IV,
            0x08,
        ));
        assert!(matches!(err, Error::Unsupported { .. }));
    }
}
