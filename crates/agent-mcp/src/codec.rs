//! JSON-RPC 2.0 分帧编解码：`Content-Length` 头（LSP 式）与行分隔 JSON。
//!
//! 两种分帧由 [`Framing`] 在运行期选择（参数选择，非 cargo feature），默认
//! [`Framing::NewlineDelimited`]——MCP stdio 现行规范写法，也便于 `bash + cat`
//! 之类的最小 server。解码是纯状态机 [`FrameDecoder`]：只负责“从字节流切出
//! 一条完整帧体”，不做 JSON 之外的语义校验，语义校验由 [`crate::protocol`] 完成。
//!
//! fail-closed 语义：解码器一旦返回错误（含超长、截断、非法头），字节流已
//! 无法重新对齐，调用方必须丢弃这条连接（客户端把它标记为 poisoned），不得
//! 尝试跳过字节继续读。

use serde::Serialize;

use crate::error::Error;

/// 默认帧体上限：8 MiB。防御对端写出超长帧耗尽内存。
pub const DEFAULT_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// `Content-Length` 模式下头块上限：64 KiB。
const MAX_HEADER_BLOCK_BYTES: usize = 64 * 1024;

/// 分帧方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Framing {
    /// 一行一个 JSON 消息，`\n` 结尾；忽略空行，容忍尾部 `\r`。
    #[default]
    NewlineDelimited,
    /// `Content-Length: <n>\r\n\r\n<n 字节帧体>`；其余头按规范忽略。
    ContentLength,
}

impl Framing {
    /// 把一条可序列化消息编码成可直接写入 transport 的字节。
    ///
    /// # Errors
    /// [`Error::MalformedMessage`]：JSON 序列化失败（例如 `NaN`）。失败时
    /// 不产生任何字节，调用方可安全继续使用同一连接。
    pub fn encode<T: Serialize>(self, value: &T) -> Result<Vec<u8>, Error> {
        let body = serde_json::to_vec(value).map_err(|e| Error::MalformedMessage {
            reason: format!("序列化 JSON-RPC 消息失败：{e}"),
        })?;
        Ok(match self {
            Self::NewlineDelimited => {
                let mut out = Vec::with_capacity(body.len() + 1);
                out.extend_from_slice(&body);
                out.push(b'\n');
                out
            }
            Self::ContentLength => {
                let head = format!("Content-Length: {}\r\n\r\n", body.len());
                let mut out = Vec::with_capacity(head.len() + body.len());
                out.extend_from_slice(head.as_bytes());
                out.extend_from_slice(&body);
                out
            }
        })
    }

    /// 创建对应的增量解码器（默认帧上限）。
    #[must_use]
    pub fn decoder(self) -> FrameDecoder {
        FrameDecoder::new(self, DEFAULT_MAX_FRAME_BYTES)
    }

    /// 创建带自定义帧上限的增量解码器。
    #[must_use]
    pub fn decoder_with_limit(self, max_frame_bytes: usize) -> FrameDecoder {
        FrameDecoder::new(self, max_frame_bytes)
    }
}

/// 增量帧解码器。
#[derive(Debug, Clone)]
pub struct FrameDecoder {
    framing: Framing,
    max_frame_bytes: usize,
    buf: Vec<u8>,
    /// `Content-Length` 模式下已解析出头块、正在等待的帧体长度。
    pending_body_len: Option<usize>,
    /// 缓冲超出上限：状态不可信，后续每次调用都返回同一错误。
    broken: Option<String>,
}

impl FrameDecoder {
    /// 新建解码器。`max_frame_bytes` 为 0 时按默认上限处理。
    #[must_use]
    pub fn new(framing: Framing, max_frame_bytes: usize) -> Self {
        Self {
            framing,
            max_frame_bytes: if max_frame_bytes == 0 {
                DEFAULT_MAX_FRAME_BYTES
            } else {
                max_frame_bytes
            },
            buf: Vec::new(),
            pending_body_len: None,
            broken: None,
        }
    }

    /// 追加读取到的字节；`max_frame_bytes` 由调用方在帧体长度已知时把关，
    /// 这里只对无界增长做保护并记录损坏原因（fail-closed）。
    pub fn push(&mut self, data: &[u8]) {
        if self.broken.is_some() {
            return;
        }
        self.buf.extend_from_slice(data);
        let limit =
            self.max_frame_bytes
                .saturating_add(if self.framing == Framing::ContentLength {
                    MAX_HEADER_BLOCK_BYTES
                } else {
                    0
                });
        if self.buf.len() > limit {
            self.fail(format!(
                "未成帧数据 {} 字节超过上限 {limit}，拒绝继续缓冲",
                self.buf.len()
            ));
        }
    }

    /// 已缓冲但尚未构成完整帧的字节数（诊断用）。
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    /// 当前正在等待的帧体长度（`Content-Length` 模式）。
    #[must_use]
    pub fn pending_body_len(&self) -> Option<usize> {
        self.pending_body_len
    }

    /// 对端已关闭写入：若仍有残留字节，说明存在被截断的帧。
    ///
    /// # Errors
    /// [`Error::MalformedFrame`]：EOF 时缓冲区仍有非空白字节。
    pub fn finish(&self) -> Result<(), Error> {
        if let Some(reason) = &self.broken {
            return Err(Error::MalformedFrame {
                reason: reason.clone(),
            });
        }
        if self.buf.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        Err(Error::MalformedFrame {
            reason: format!("对端在帧中途结束输出，残留 {} 字节", self.buf.len()),
        })
    }

    /// 取下一条完整帧体。`Ok(None)` 表示需要更多字节。
    ///
    /// # Errors
    /// [`Error::FrameTooLarge`] 或 [`Error::MalformedFrame`]；错误之后解码器
    /// 永久处于损坏状态。
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if let Some(reason) = &self.broken {
            return Err(Error::MalformedFrame {
                reason: reason.clone(),
            });
        }
        let result = match self.framing {
            Framing::NewlineDelimited => self.next_line(),
            Framing::ContentLength => self.next_length_prefixed(),
        };
        if let Err(e) = &result {
            self.fail(e.to_string());
        }
        result
    }

    fn fail(&mut self, reason: String) {
        self.buf.clear();
        self.pending_body_len = None;
        self.broken = Some(reason);
    }

    fn next_line(&mut self) -> Result<Option<Vec<u8>>, Error> {
        loop {
            let Some(idx) = self.buf.iter().position(|b| *b == b'\n') else {
                return Ok(None);
            };
            let mut line = self.buf.drain(..=idx).collect::<Vec<u8>>();
            line.pop(); // 去掉 '\n'
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue; // 空行只是分隔噪音，跳过
            }
            if line.len() > self.max_frame_bytes {
                return Err(Error::FrameTooLarge {
                    length: line.len(),
                    max: self.max_frame_bytes,
                });
            }
            // serde_json 产生的 JSON 不含裸换行；出现即为流对齐错误。
            std::str::from_utf8(&line).map_err(|_| Error::MalformedFrame {
                reason: "行分隔帧体不是合法 UTF-8".to_string(),
            })?;
            return Ok(Some(line));
        }
    }

    fn next_length_prefixed(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if let Some(len) = self.pending_body_len {
            // 头已消费，只等帧体。
            if self.buf.len() < len {
                return Ok(None);
            }
            let body = self.buf.drain(..len).collect::<Vec<u8>>();
            self.pending_body_len = None;
            return finish_body(body, self.max_frame_bytes);
        }
        let Some(sep) = find_header_end(&self.buf) else {
            return Ok(None);
        };
        if sep > MAX_HEADER_BLOCK_BYTES {
            return Err(Error::MalformedFrame {
                reason: format!("头块超过 {MAX_HEADER_BLOCK_BYTES} 字节仍未结束"),
            });
        }
        let header_block = self.buf.drain(..sep + 4).collect::<Vec<u8>>();
        let header_text = String::from_utf8_lossy(&header_block[..header_block.len() - 4]);
        let length = parse_content_length(&header_text)?;
        if length > self.max_frame_bytes {
            return Err(Error::FrameTooLarge {
                length,
                max: self.max_frame_bytes,
            });
        }
        if self.buf.len() < length {
            self.pending_body_len = Some(length);
            return Ok(None);
        }
        let body = self.buf.drain(..length).collect::<Vec<u8>>();
        finish_body(body, self.max_frame_bytes)
    }
}

/// 帧体收齐后的校验：空帧视为损坏（JSON-RPC 不允许零长度消息）。
fn finish_body(body: Vec<u8>, max_frame_bytes: usize) -> Result<Option<Vec<u8>>, Error> {
    if body.is_empty() {
        return Err(Error::MalformedFrame {
            reason: "帧体长度为 0".to_string(),
        });
    }
    if body.len() > max_frame_bytes {
        return Err(Error::FrameTooLarge {
            length: body.len(),
            max: max_frame_bytes,
        });
    }
    std::str::from_utf8(&body).map_err(|_| Error::MalformedFrame {
        reason: "帧体不是合法 UTF-8".to_string(),
    })?;
    Ok(Some(body))
}

/// 查找头块结束 `\r\n\r\n`，返回首个 `\r` 的下标。
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// 从头块文本解析 `Content-Length`（大小写不敏感，其余头忽略）。
fn parse_content_length(header_block: &str) -> Result<usize, Error> {
    let mut found: Option<usize> = None;
    for line in header_block.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            return Err(Error::MalformedFrame {
                reason: format!("非法头行（缺少冒号）：{line:?}"),
            });
        };
        if !key.trim().eq_ignore_ascii_case("content-length") {
            continue;
        }
        let digits = value.trim();
        match digits.parse::<usize>() {
            Ok(n) if n > 0 => {
                if found.is_some() {
                    return Err(Error::MalformedFrame {
                        reason: "重复的 Content-Length 头".to_string(),
                    });
                }
                found = Some(n);
            }
            Ok(_) => {
                return Err(Error::MalformedFrame {
                    reason: "Content-Length 为 0".to_string(),
                });
            }
            Err(_) => {
                return Err(Error::MalformedFrame {
                    reason: format!("Content-Length 不是正整数：{digits:?}"),
                });
            }
        }
    }
    found.ok_or_else(|| Error::MalformedFrame {
        reason: "头块缺少 Content-Length".to_string(),
    })
}
