//! 数据段帧的**写侧**封装：封一帧（长度段 + 载荷密文 + 明文 padding）。
//!
//! 语义来源（只读参考，固定 commit `d2758a02`）：`common/crypto/auth.go`
//! `AuthenticationWriter.seal` —— 先算 padding 长度、再封载荷、再编码长度段。

use tokio::io::AsyncWriteExt;

use crate::bodyframe::SizeMode;
use crate::{Error, Result};

use super::BodyFrame;

impl BodyFrame {
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

    /// 异步写一帧。
    pub async fn write_to<W: tokio::io::AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        payload: &[u8],
    ) -> Result<()> {
        let mut frame = Vec::with_capacity(
            self.mode.wire_len() + payload.len() + crate::bodyframe::TAG_LEN + 64,
        );
        self.seal(&mut frame, payload)?;
        writer
            .write_all(&frame)
            .await
            .map_err(|error| crate::io_err(&error))
    }
}
