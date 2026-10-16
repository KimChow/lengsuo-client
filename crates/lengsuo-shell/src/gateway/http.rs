//! 极简单连接 HTTP/1.1 客户端（只覆盖本地网关回环所需的子集）。
//!
//! 有意不引入 hyper：v0 只需要「一条请求 + 一条响应」，请求体与响应体都按
//! `Content-Length` 读取（同时兼容 chunked 与无长度时读到 EOF 的形态）。任何
//! 不符合本子集的响应都返回 [`HttpError`]，不猜测、不回退（fail-closed）。
//!
//! 本模块不理解网关语义，只做字节层编解码；状态码与信封解析在 `rpc` 模块。

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 响应体上限：本地网关的 RPC 响应必须是小信封（大结果走引用），超限直接拒绝，
/// 防止被异常响应打爆内存（AGENT-KICKOFF.md §3「大结果不进 content」）。
pub const MAX_RESPONSE_BYTES: usize = 8 << 20;

/// 响应头区域上限。
const MAX_HEADER_BYTES: usize = 64 << 10;

/// 本地回环上的单条 HTTP 响应。
pub struct HttpResponse {
    /// 状态码。
    pub status: u16,
    /// 响应头（头名已转小写）。
    pub headers: Vec<(String, String)>,
    /// 完整响应体。
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// 查头（大小写不敏感）。
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k == &name)
            .map(|(_, v)| v.as_str())
    }
}

/// 字节层错误。全部由调用方归因，本身不含网关语义。
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// 底层 IO 错误。
    #[error("网关连接 IO 错误")]
    Io(#[from] io::Error),
    /// 响应状态行非法（非 HTTP/1.x 或无状态码）。
    #[error("网关响应状态行非法")]
    BadStatusLine,
    /// 响应头无法解析。
    #[error("网关响应头非法")]
    BadHeaders,
    /// 响应体长度与声明不符，或分块编码非法，或未达上限前连接断开。
    #[error("网关响应体不完整或分块编码非法")]
    TruncatedBody,
    /// 响应超出 [`MAX_RESPONSE_BYTES`]。
    #[error("网关响应超出上限 {0} 字节")]
    TooLarge(usize),
}

/// 向已建立的连接写一条请求，然后读取一条完整响应。
///
/// 每请求一条连接并带 `Connection: close`，避免连接复用带来的状态泄漏；
/// v0 网关是本地回环，握手成本可忽略（取舍记入 PROTOCOL-NOTES.md）。
#[allow(clippy::too_many_arguments)]
pub async fn request(
    stream: &mut TcpStream,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    timeout: Duration,
) -> Result<HttpResponse, HttpError> {
    let mut out = String::new();
    let _ = write!(
        &mut out,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
    );
    for (name, value) in headers {
        let _ = write!(&mut out, "{name}: {value}\r\n");
    }
    let _ = write!(&mut out, "Content-Length: {}\r\n\r\n", body.len());
    let mut wire = out.into_bytes();
    wire.extend_from_slice(body);

    tokio::time::timeout(timeout, async {
        stream.write_all(&wire).await?;
        stream.flush().await?;
        read_response(stream).await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "gateway rpc timeout"))?
}

/// 读取状态行 + 头 + 体。
async fn read_response(stream: &mut TcpStream) -> Result<HttpResponse, HttpError> {
    let mut carry: VecDeque<u8> = VecDeque::new();
    let mut tmp = [0_u8; 8 * 1024];
    let head_text = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(HttpError::TruncatedBody);
        }
        carry.extend(tmp[..n].iter().copied());
        if let Some(pos) = find_header_end(&mut carry) {
            let bytes: Vec<u8> = carry.drain(..pos + 4).collect();
            break String::from_utf8_lossy(&bytes[..bytes.len() - 4]).into_owned();
        }
        if carry.len() > MAX_HEADER_BYTES {
            return Err(HttpError::BadHeaders);
        }
    };
    let (status, headers) = parse_head(&head_text)?;

    let mut body = Vec::new();
    let rest: Vec<u8> = carry.iter().copied().collect();
    consume_body(stream, &mut body, rest, &headers, status).await?;
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

/// 在缓冲中定位头结束标记 `\r\n\r\n`，返回其起始下标。
fn find_header_end(buf: &mut VecDeque<u8>) -> Option<usize> {
    buf.make_contiguous()
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
}

/// 解析状态行与响应头。
fn parse_head(head: &str) -> Result<(u16, Vec<(String, String)>), HttpError> {
    let mut lines = head.split("\r\n");
    let mut parts = lines.next().ok_or(HttpError::BadStatusLine)?.splitn(3, ' ');
    let version = parts.next().ok_or(HttpError::BadStatusLine)?;
    if !version.starts_with("HTTP/1.") {
        return Err(HttpError::BadStatusLine);
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or(HttpError::BadStatusLine)?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or(HttpError::BadHeaders)?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    Ok((status, headers))
}

/// 读取响应体：chunked 优先，其次 `Content-Length`，无长度声明时读到 EOF。
async fn consume_body(
    stream: &mut TcpStream,
    acc: &mut Vec<u8>,
    rest: Vec<u8>,
    headers: &[(String, String)],
    status: u16,
) -> Result<(), HttpError> {
    let get = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    if status == 204 || status == 304 || (100..200).contains(&status) {
        return Ok(());
    }
    if get("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        return read_chunked(stream, acc, rest).await;
    }
    if let Some(len) = get("content-length") {
        let need: usize = len.trim().parse().map_err(|_| HttpError::TruncatedBody)?;
        if need > MAX_RESPONSE_BYTES {
            return Err(HttpError::TooLarge(MAX_RESPONSE_BYTES));
        }
        acc.extend_from_slice(&rest);
        guard(acc)?;
        let mut tmp = [0_u8; 8 * 1024];
        while acc.len() < need {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(HttpError::TruncatedBody);
            }
            let keep = need - acc.len();
            acc.extend_from_slice(&tmp[..n.min(keep)]);
        }
        return Ok(());
    }
    // 无长度声明：请求带 Connection: close，服务端响应后必然关闭。
    acc.extend_from_slice(&rest);
    let mut tmp = [0_u8; 8 * 1024];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        acc.extend_from_slice(&tmp[..n]);
        guard(acc)?;
    }
}

fn guard(acc: &[u8]) -> Result<(), HttpError> {
    if acc.len() > MAX_RESPONSE_BYTES {
        return Err(HttpError::TooLarge(MAX_RESPONSE_BYTES));
    }
    Ok(())
}

/// 读取 chunked 体。非法分块、缺 CRLF、提前 EOF 一律判定截断，不做容错补齐。
async fn read_chunked(
    stream: &mut TcpStream,
    acc: &mut Vec<u8>,
    rest: Vec<u8>,
) -> Result<(), HttpError> {
    let mut pending: VecDeque<u8> = rest.into();
    loop {
        let line = take_line(stream, &mut pending).await?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| HttpError::TruncatedBody)?;
        if size == 0 {
            // 终结块之后是可选 trailer 行，以空行结束。
            loop {
                let trailer = take_line(stream, &mut pending).await?;
                if trailer.is_empty() {
                    return Ok(());
                }
            }
        }
        while pending.len() < size {
            let mut tmp = [0_u8; 8 * 1024];
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(HttpError::TruncatedBody);
            }
            pending.extend(tmp[..n].iter().copied());
        }
        let take = size.min(pending.len());
        acc.extend(pending.drain(..take));
        guard(acc)?;
        // 跳过本块尾部的 CRLF。
        let _ = take_line(stream, &mut pending).await?;
    }
}

/// 从 pending 或 socket 取一行（不含 CRLF）。行超长视为非法。
async fn take_line(
    stream: &mut TcpStream,
    pending: &mut VecDeque<u8>,
) -> Result<String, HttpError> {
    let mut tmp = [0_u8; 1024];
    loop {
        if let Some(pos) = pending.iter().position(|b| *b == b'\n') {
            let raw: Vec<u8> = pending.drain(..=pos).collect();
            let line = raw
                .strip_suffix(b"\n")
                .unwrap_or(&raw)
                .strip_suffix(b"\r")
                .unwrap_or(raw.strip_suffix(b"\n").unwrap_or(&raw));
            return Ok(String::from_utf8_lossy(line).into_owned());
        }
        if pending.len() > 1024 {
            return Err(HttpError::TruncatedBody);
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(HttpError::TruncatedBody);
        }
        pending.extend(tmp[..n].iter().copied());
    }
}
