//! 同源说明：本文件与 `crates/lengsuo-trojan/src/transport/server.rs` 同源（逐字
//! 复制，仅文档改为 VLESS），后续应收敛到共享 crate。
//!
//! 外层传输的**服务端侧**升级（WS / HTTPUpgrade），对齐参考
//! `transport/internet/websocket/hub.go` 与 `transport/internet/httpupgrade/hub.go`。
//!
//! 与客户端侧 (`ws.rs` / `httpupgrade.rs`) 共用同一个 HTTP 升级语义，区别在方向：
//!
//! - 服务端先**读**升级请求：校验 `Host`（若配置）、`path`，再要求
//!   `Connection: upgrade` 与 `Upgrade: websocket`（值大小写不敏感，参考
//!   `requestHandler.ServeHTTP` / `server.upgrade`）；
//! - WS 还要读 `Sec-WebSocket-Key` 并回 `Sec-WebSocket-Accept`；参考在
//!   `Sec-WebSocket-Protocol` 上做 `Ed`（early data）透传，本仓不实现 Ed
//!   （无延迟拨号层），故不读不回应，如实记入文档「仍未覆盖项」；
//! - HTTPUpgrade 直接回 `101 Switching Protocols`，无 Accept 头（参考 `hub.go`）。
//!
//! 服务端方向的方向性差异（RFC 6455 §5.1）：
//!
//! - 读到的客户端帧**必须掩码**，否则协议错误；
//! - 服务端写出的帧**不得掩码**。
//!
//! 本模块只服务“Xray 作客户端 → 本仓服务端”的反向互通，不重复 VLESS 认证逻辑
//! （认证由 `crate::server` 在升级后的流上完成）。

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

use crate::transport::http;
use crate::transport::httpupgrade;
use crate::transport::sha1::accept_key;
use crate::transport::{check_deadline, Error};

/// 服务端升级配置。
#[derive(Debug, Clone)]
pub struct Config {
    /// 期望路径（已按 `GetNormalizedPath` 归一化）。
    pub path: String,
    /// 期望 `Host`；空表示不校验。
    pub host: String,
}

impl Config {
    #[must_use]
    pub fn new(path: impl Into<String>, host: impl Into<String>) -> Self {
        let path = http::normalize_path(&path.into());
        Self {
            path,
            host: host.into(),
        }
    }
}

/// 读入的升级请求（仅本模块关心的字段）。
struct Request {
    method: String,
    path: String,
    host: String,
    connection: String,
    upgrade: String,
    ws_key: Option<String>,
}

/// 读一个 HTTP 请求头（到 `\r\n\r\n`）并解析关心字段。
async fn read_upgrade_request<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Request, Error> {
    let mut buf = Vec::with_capacity(256);
    loop {
        if buf.len() >= http::MAX_RESPONSE_HEADER {
            return Err(Error::BadResponse);
        }
        let mut byte = [0u8; 1];
        use tokio::io::AsyncReadExt as _;
        reader.read_exact(&mut byte).await.map_err(Error::Io)?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&buf).map_err(|_| Error::BadResponse)?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(Error::BadResponse)?;
    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or(Error::BadResponse)?.to_owned();
    let path = parts.next().ok_or(Error::BadResponse)?.to_owned();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    let find = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    };
    Ok(Request {
        method,
        path,
        host: find("host").unwrap_or_default(),
        connection: find("connection").unwrap_or_default(),
        upgrade: find("upgrade").unwrap_or_default(),
        ws_key: find("sec-websocket-key"),
    })
}

impl Request {
    /// 参考服务端判据：`GET` + 路径匹配 + `Connection: upgrade` + `Upgrade: websocket`。
    fn validate(&self, config: &Config) -> Result<(), Error> {
        if self.method != "GET" {
            return Err(Error::UpgradeRejected(format!("方法 {}", self.method)));
        }
        if self.path != config.path {
            return Err(Error::UpgradeRejected(format!("路径 {}", self.path)));
        }
        if !config.host.is_empty() && !self.host.eq_ignore_ascii_case(&config.host) {
            return Err(Error::UpgradeRejected(format!("Host {}", self.host)));
        }
        if !self.connection.eq_ignore_ascii_case("upgrade") {
            return Err(Error::UpgradeRejected(format!(
                "Connection {}",
                self.connection
            )));
        }
        if !self.upgrade.eq_ignore_ascii_case("websocket") {
            return Err(Error::UpgradeRejected(format!("Upgrade {}", self.upgrade)));
        }
        Ok(())
    }
}

/// 读升级请求 + 回 101（WebSocket：带 Accept；HTTPUpgrade：不带）。
/// 返回底层流，供上层在其上跑 VLESS。
async fn accept_inner<S>(
    stream: S,
    config: &Config,
    websocket: bool,
    wait: Duration,
) -> Result<S, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt as _;
    check_deadline(wait)?;
    let mut stream = stream;
    let request = timeout(wait, read_upgrade_request(&mut stream))
        .await
        .map_err(|_| Error::Timeout)??;
    request.validate(config)?;
    let mut response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\n"
        .to_owned();
    if websocket {
        let key = request
            .ws_key
            .ok_or_else(|| Error::UpgradeRejected("缺 Sec-WebSocket-Key".to_owned()))?;
        response.push_str(&format!("Sec-WebSocket-Accept: {}\r\n", accept_key(&key)));
    }
    response.push_str("\r\n");
    timeout(wait, async {
        stream.write_all(response.as_bytes()).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| Error::Timeout)??;
    Ok(stream)
}

/// 服务端 WS 升级：返回一个“服务端方向”的 WS 连接（收掩码帧、发不掩码帧）。
pub async fn accept_ws<S>(stream: S, config: &Config, wait: Duration) -> Result<WsServer<S>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let inner = accept_inner(stream, config, true, wait).await?;
    Ok(WsServer::new(inner))
}

/// 服务端 HTTPUpgrade 升级：返回裸字节流。
pub async fn accept_httpupgrade<S>(
    stream: S,
    config: &Config,
    wait: Duration,
) -> Result<httpupgrade::Upgraded<S>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let inner = accept_inner(stream, config, false, wait).await?;
    Ok(httpupgrade::Upgraded::new(inner))
}

/// 服务端方向的 WebSocket 连接：直接复用 `ws::ServerConnection`（收掩码帧、
/// 发不掩码帧），此处只做类型别名，不重复帧逻辑。
pub type WsServer<S> = crate::transport::ws::ServerConnection<S>;
