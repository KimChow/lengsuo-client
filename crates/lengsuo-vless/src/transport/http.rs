//! 同源说明：本文件与 `crates/lengsuo-trojan/src/transport/http.rs` 同源（逐字
//! 复制），后续应收敛到共享 crate。
//!
//! HTTP/1.1 Upgrade 握手的共享原语（WS 与 HTTPUpgrade 共用）。
//!
//! 对齐参考两个 dialer 的**线上字节**（`websocket/dialer.go` 与
//! `httpupgrade/dialer.go`），而不是它们的 Go API：
//!
//! - 请求行：`GET <path> HTTP/1.1`；
//! - `Host`：参考优先级是配置 `Host` → TLS `serverName` → 目标地址字面量；
//! - 升级三元组：`Connection: Upgrade`、`Upgrade: websocket`；
//! - WS 额外带 `Sec-WebSocket-Version: 13` 与 `Sec-WebSocket-Key`（16 字节随机数
//!   base64；gorilla 生成请求时即写入），HTTPUpgrade **不带**这两个头（参考 dialer
//!   只设 Connection/Upgrade 与 `net/http` 自动头）。
//!
//! 响应解析只做“读到空行为止”的增量读取：逐行读到 `\r\n\r\n`，长度上限
//! `MAX_RESPONSE_HEADER`，避免无界缓冲。参考用 `net/http` 与 `http.ReadResponse`
//! 解析，本模块手写等价的最小解析（不引入 HTTP 依赖，见 `transport` 模块注释）。

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::transport::Error;

/// 响应头长度上限（对齐参考 `ws.go` 服务端 `MaxHeaderBytes = 8192` 量级）。
pub(crate) const MAX_RESPONSE_HEADER: usize = 8192;

/// 解析后的 HTTP 响应行与头部（大小写不敏感的头名查找）。
pub(crate) struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

impl Response {
    /// 头部值查找，头名大小写不敏感（HTTP 头名不区分大小写）。
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// 参考两个 dialer 的共同判据：`101 Switching Protocols` +
    /// `Upgrade: websocket` + `Connection: upgrade`（值大小写不敏感）。
    pub fn is_switching_protocols(&self) -> Result<(), Error> {
        if self.status != 101 {
            return Err(Error::UpgradeRejected(format!("状态码 {}", self.status)));
        }
        let upgrade = self.header("upgrade").unwrap_or("");
        let connection = self.header("connection").unwrap_or("");
        if !upgrade.eq_ignore_ascii_case("websocket") {
            return Err(Error::UpgradeRejected(format!("Upgrade: {upgrade}")));
        }
        if !connection.eq_ignore_ascii_case("upgrade") {
            return Err(Error::UpgradeRejected(format!("Connection: {connection}")));
        }
        Ok(())
    }
}

/// 逐行读到空行（`\r\n\r\n`），解析成状态行 + 头部列表；超长或格式错即拒绝。
///
/// 只消费响应头本身，`\r\n\r\n` 之后的字节**留在流上**——这正是 HTTPUpgrade
/// 的升级点语义（其后是裸 VLESS 字节），也方便 WS 侧继续读帧。
pub(crate) async fn read_response<R: AsyncRead + Unpin>(
    reader: &mut R,
    wait: Duration,
) -> Result<Response, Error> {
    crate::transport::check_deadline(wait)?;
    let header = timeout(wait, read_header_block(reader))
        .await
        .map_err(|_| Error::Timeout)??;
    parse_response(&header)
}

/// 边读边找 `\r\n\r\n`，返回（含分隔符的）头部字节块；超上限即拒绝。
async fn read_header_block<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::with_capacity(256);
    loop {
        if buf.len() >= MAX_RESPONSE_HEADER {
            return Err(Error::BadResponse);
        }
        let byte = reader.read_u8().await.map_err(Error::Io)?;
        buf.push(byte);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
    }
}

/// 解析头部块：状态行 `HTTP/1.1 101 <reason>` + 若干 `Name: value` 行。
fn parse_response(block: &[u8]) -> Result<Response, Error> {
    let text = std::str::from_utf8(block).map_err(|_| Error::BadResponse)?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or(Error::BadResponse)?;
    let status = parse_status(status_line)?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or(Error::BadResponse)?;
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    Ok(Response { status, headers })
}

/// 从 `HTTP/1.1 101 Switching Protocols` 取状态码。
fn parse_status(line: &str) -> Result<u16, Error> {
    let mut parts = line.split(' ');
    let version = parts.next().ok_or(Error::BadResponse)?;
    if !version.starts_with("HTTP/") {
        return Err(Error::BadResponse);
    }
    let code = parts.next().ok_or(Error::BadResponse)?;
    code.parse::<u16>().map_err(|_| Error::BadResponse)
}

/// 写出 `GET <path> HTTP/1.1` 升级请求（请求行 + 头 + 空行 + flush）。
///
/// `headers` 已包含全部要发送的头（含 Host 与升级三元组），由调用方按各自
/// 传输的参考头集合构造，避免两处传输各写一份请求行/收尾逻辑。
pub(crate) async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    path: &str,
    headers: &[(String, String)],
    wait: Duration,
) -> Result<(), Error> {
    crate::transport::check_deadline(wait)?;
    let mut request = Vec::with_capacity(256);
    request.extend_from_slice(format!("GET {path} HTTP/1.1\r\n").as_bytes());
    for (name, value) in headers {
        request.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    request.extend_from_slice(b"\r\n");
    timeout(wait, async {
        writer.write_all(&request).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| Error::Timeout)??;
    Ok(())
}

/// 参考路径归一化（对齐 `Config.GetNormalizedPath`）：空 → `/`，不以 `/` 开头
/// 则补上，其余原样。
#[must_use]
pub(crate) fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_owned();
    }
    if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

/// `Host` 头取值优先级（对齐参考 dialer）：显式 `host` → TLS `server_name` →
/// `authority`（`dest` 的 `host:port` 字面量，`*:80`/`*:443` 特例仍由调用方决定）。
#[must_use]
pub(crate) fn host_header(host: &str, server_name: &str, authority: &str) -> String {
    if !host.is_empty() {
        return host.to_owned();
    }
    if !server_name.is_empty() {
        return server_name.to_owned();
    }
    authority.to_owned()
}
