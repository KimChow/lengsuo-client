//! 帧编解码：newline-delimited JSON（18 册实证 "JSON over stdio"）。
//!
//! 参考端文档只给出 `JSON over stdio`，未提 `Content-Length` 头帧，故 P1 采用
//! **行分隔 JSON**：一行一条 wire 消息，`\n` 结尾（容忍尾部 `\r`，忽略空行）。
//! 全部纯函数 + 增量状态机 [`LineDecoder`]，不碰 socket/进程——传输接线是 P2。
//!
//! fail-closed：解码器一旦超长（单行超过上限），字节流无法重新对齐，
//! 之后每次调用都返回 [`Error::Broken`]，调用方必须丢弃这条连接。

use serde::{de::DeserializeOwned, Serialize};

use crate::control::TopLevel;
use crate::error::Error;
use crate::message::Message;

/// 默认单行上限：8 MiB（防御对端超长行耗尽内存）。
pub const DEFAULT_MAX_LINE_BYTES: usize = 8 * 1024 * 1024;

/// 把一条可序列化消息编码为一帧（JSON 单行 + `\n`）。
///
/// # Errors
/// [`Error::MalformedMessage`]：JSON 序列化失败（如浮点 `NaN`）。
/// 失败时不产生任何字节。
pub fn encode_frame<T: Serialize>(value: &T) -> crate::Result<Vec<u8>> {
    let body = serde_json::to_vec(value).map_err(|e| Error::MalformedMessage {
        reason: format!("序列化帧体失败：{e}"),
    })?;
    if body.contains(&b'\n') {
        // serde_json 紧凑输出不会含裸换行；防御性断言（字符串内换行是 \n 转义）。
        return Err(Error::MalformedMessage {
            reason: "序列化产物含裸换行，违反行帧约束".into(),
        });
    }
    let mut out = Vec::with_capacity(body.len() + 1);
    out.extend_from_slice(&body);
    out.push(b'\n');
    Ok(out)
}

/// 一次性解码一条完整帧体（不含行尾；行尾会被容忍）。
///
/// # Errors
/// [`Error::MalformedMessage`]：JSON 非法或顶层形态不可归类。
pub fn decode_frame(bytes: &[u8]) -> crate::Result<TopLevel> {
    let trimmed = trim_line(bytes);
    let value: serde_json::Value =
        serde_json::from_slice(trimmed).map_err(|e| Error::MalformedMessage {
            reason: format!("帧体 JSON 解析失败：{e}"),
        })?;
    TopLevel::classify(value)
}

/// 一次性解码一条完整帧体为 JSON-RPC 三分类。
///
/// # Errors
/// [`Error::MalformedMessage`]：JSON 非法或非标准 RPC 形态（control 信封走
/// [`decode_frame`]）。
pub fn decode_message(bytes: &[u8]) -> crate::Result<Message> {
    match decode_frame(bytes)? {
        TopLevel::Rpc(m) => Ok(m),
        TopLevel::ControlRequest(_)
        | TopLevel::ControlNotification(_)
        | TopLevel::ControlResponse(_) => Err(Error::MalformedMessage {
            reason: "帧体是 control 信封，不是 JSON-RPC 消息".into(),
        }),
    }
}

/// 强类型便捷解码：帧体 → 目标类型。
///
/// # Errors
/// [`Error::MalformedMessage`]：JSON 非法或类型不匹配。
pub fn decode_json<T: DeserializeOwned>(bytes: &[u8]) -> crate::Result<T> {
    let trimmed = trim_line(bytes);
    serde_json::from_slice(trimmed).map_err(Error::from)
}

fn trim_line(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len();
    while end > 0 && (bytes[end - 1] == b'\n' || bytes[end - 1] == b'\r') {
        end -= 1;
    }
    &bytes[..end]
}

/// 增量行解码器：喂入任意切分的字节块，吐出完整行（帧体，不含 `\n`）。
///
/// 状态机与 agent-mcp 的帧解码同款语义：空行忽略；`\r\n` 与 `\n` 等价；
/// 超长行 fail-closed。
#[derive(Debug, Clone)]
pub struct LineDecoder {
    max_line_bytes: usize,
    buf: Vec<u8>,
    broken: Option<String>,
}

impl Default for LineDecoder {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_LINE_BYTES)
    }
}

impl LineDecoder {
    /// 新建解码器；`max_line_bytes` 为 0 时取默认上限。
    #[must_use]
    pub fn new(max_line_bytes: usize) -> Self {
        Self {
            max_line_bytes: if max_line_bytes == 0 {
                DEFAULT_MAX_LINE_BYTES
            } else {
                max_line_bytes
            },
            buf: Vec::new(),
            broken: None,
        }
    }

    /// 是否已进入不可恢复状态。
    #[must_use]
    pub fn is_broken(&self) -> bool {
        self.broken.is_some()
    }

    /// 喂入一块字节，返回本次可吐出的完整帧体（每条不含行尾）。
    ///
    /// # Errors
    /// [`Error::FrameTooLarge`]：首次超长（本次调用不吐出任何帧）。
    /// [`Error::Broken`]：此前已损坏，错误内容与首次一致。
    pub fn feed(&mut self, bytes: &[u8]) -> crate::Result<Vec<Vec<u8>>> {
        if let Some(reason) = &self.broken {
            return Err(Error::Broken {
                reason: reason.clone(),
            });
        }
        self.buf.extend_from_slice(bytes);
        if self.buf.len() > self.max_line_bytes {
            // 找不到换行且已超长：字节流无法重新对齐，fail-closed。
            if memchr_nl(&self.buf).is_none() {
                self.broken = Some(format!("未完结行超过 {} 字节上限", self.max_line_bytes));
                self.buf.clear();
                return Err(Error::FrameTooLarge {
                    limit: self.max_line_bytes,
                });
            }
        }
        let mut frames = Vec::new();
        while let Some(idx) = memchr_nl(&self.buf) {
            let line = self.buf.drain(..=idx).collect::<Vec<u8>>();
            let body = trim_line(&line);
            if body.is_empty() {
                continue; // 忽略空行
            }
            if body.len() > self.max_line_bytes {
                let reason = format!("单行 {} 字节超过上限 {}", body.len(), self.max_line_bytes);
                self.broken = Some(reason.clone());
                return Err(Error::Broken { reason });
            }
            frames.push(body.to_vec());
        }
        Ok(frames)
    }

    /// 流结束钩子：残留未完结内容视为截断（fail-closed）。
    ///
    /// # Errors
    /// [`Error::MalformedMessage`]：缓冲仍有非空残留（对端截断/崩溃）。
    pub fn finish(&mut self) -> crate::Result<()> {
        let residual = trim_line(&self.buf);
        if !residual.is_empty() {
            self.buf.clear();
            return Err(Error::MalformedMessage {
                reason: "流结束时仍有未完结的帧（截断）".into(),
            });
        }
        self.buf.clear();
        Ok(())
    }
}

fn memchr_nl(buf: &[u8]) -> Option<usize> {
    buf.iter().position(|&b| b == b'\n')
}
