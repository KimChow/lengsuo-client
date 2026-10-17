//! 测试用 mock 本地网关：只用 tokio TCP + tokio-tungstenite，不引入 gpui/axum。
//!
//! 覆盖 AGENT-KICKOFF.md §6 对 `lengsuo-shell` 的要求「网关客户端对 mock 的 roundtrip」：
//! - `POST /rpc`：解析真实请求行/头/体，记录 `X-Gateway-Token` 与请求体，按规则回信封、
//!   回原始 HTTP 状态，或挂起不回（驱动客户端超时路径）。
//! - `GET /events`：WS 服务端握手（带 token 校验回调），按顺序推送文本帧。
//! - 握手文件：临时目录里的 `gateway.json`，`Drop` 时清理。
//!
//! mock 一律绑 `127.0.0.1:0`（随机端口），与协议 §2 的监听形态一致。

#![allow(dead_code)]

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::Message;

/// mock 收到的一条请求，用于断言客户端确实带上了 token 与规定形态的请求体。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenRequest {
    pub method: String,
    pub path: String,
    pub token: Option<String>,
    pub body: String,
}

/// RPC 侧行为规则。
#[derive(Debug, Clone)]
pub enum RpcBehaviour {
    /// 回 HTTP 200 + `{code,msg,data}` 信封。
    Envelope {
        code: i64,
        msg: &'static str,
        /// `data` 的 JSON 文本；`"null"` 表示无数据。
        data: &'static str,
    },
    /// 回原始 HTTP 状态与文本体（不含信封，用于区分 HTTP 层错误）。
    Raw { status: u16, body: &'static str },
    /// 读完请求但不回任何字节，直到被 `shutdown` 中止（触发客户端超时）。
    Hang,
}

/// 事件流侧行为。
#[derive(Debug, Clone)]
pub struct EventsBehaviour {
    /// 握手成功后按顺序推送的帧文本（一帧一个 JSON，或刻意非法的内容）。
    pub frames: Vec<String>,
    /// 要求请求头携带的 token；`None` 表示不校验。
    pub expected_token: Option<String>,
    /// 推完 `frames` 后是否由服务端发出 Close（用于断言 `EventError::Closed`）。
    pub close_after_frames: bool,
}

/// 已启动的 mock 网关。`Drop`/`shutdown` 时中止所有在途任务。
pub struct MockGateway {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<SeenRequest>>>,
    accept: JoinHandle<()>,
    conns: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl MockGateway {
    /// 起一个 RPC mock。第 N 条连接用 `rules[N]`，越界后重复用最后一条。
    pub async fn rpc(rules: Vec<RpcBehaviour>, expected_token: Option<String>) -> Self {
        let listener = bind().await;
        let conn_index = Arc::new(AtomicUsize::new(0));
        let this = Self::spawn(listener, move |stream, seen| {
            let rules = rules.clone();
            let expected_token = expected_token.clone();
            let conn_index = Arc::clone(&conn_index);
            async move {
                let nth = conn_index.fetch_add(1, Ordering::SeqCst);
                rpc_conn(stream, seen, rules, expected_token, nth).await;
            }
        });
        // 等待监听器进入可接受状态，避免客户端首连偶发拒绝。
        tokio::time::sleep(Duration::from_millis(20)).await;
        this
    }

    /// 起一个事件流 mock。
    pub async fn events(behaviour: EventsBehaviour) -> Self {
        let listener = bind().await;
        let this = Self::spawn(listener, move |stream, _seen| {
            let behaviour = behaviour.clone();
            async move { events_conn(stream, behaviour).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        this
    }

    fn spawn<F, Fut>(listener: TcpListener, handler: F) -> Self
    where
        F: Fn(TcpStream, Arc<Mutex<Vec<SeenRequest>>>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let addr = listener.local_addr().expect("mock 绑定随机端口成功");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let conns = Arc::new(Mutex::new(Vec::new()));
        let accept = {
            let seen_for_loop = Arc::clone(&seen);
            let conns = Arc::clone(&conns);
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _peer)) = listener.accept().await else {
                        return;
                    };
                    let task = tokio::spawn(handler(stream, Arc::clone(&seen_for_loop)));
                    conns.lock().expect("mock 状态锁").push(task);
                }
            })
        };
        Self {
            addr,
            seen,
            accept,
            conns,
        }
    }

    /// mock 监听地址。
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// mock 已记录的请求（按到达顺序）。
    pub fn seen(&self) -> Vec<SeenRequest> {
        self.seen.lock().expect("mock 状态锁").clone()
    }

    /// 停掉 mock：中止 accept 与所有在途连接任务。
    pub async fn shutdown(self) {
        self.accept.abort();
        let tasks: Vec<JoinHandle<()>> = {
            let mut guard = self.conns.lock().expect("mock 状态锁");
            std::mem::take(&mut *guard)
        };
        for task in tasks {
            task.abort();
        }
        // 留一点收尾时间，避免端口/任务状态泄漏到下一个测试。
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// 绑定 127.0.0.1 随机端口。
async fn bind() -> TcpListener {
    TcpListener::bind("127.0.0.1:0".parse::<SocketAddr>().expect("loopback 地址"))
        .await
        .expect("mock 网关绑定失败")
}

/// 处理一条 `/rpc` HTTP 连接。
async fn rpc_conn(
    mut stream: TcpStream,
    seen: Arc<Mutex<Vec<SeenRequest>>>,
    rules: Vec<RpcBehaviour>,
    expected_token: Option<String>,
    nth: usize,
) {
    let Ok(request) = read_request(&mut stream).await else {
        return;
    };
    seen.lock().expect("mock 状态锁").push(request.clone());
    let rule = rules
        .get(nth)
        .cloned()
        .or_else(|| rules.last().cloned())
        .unwrap_or(RpcBehaviour::Hang);
    // token 不符：网关侧鉴权拒绝，先于任何业务语义（协议 §2）。
    if let Some(want) = &expected_token {
        if request.token.as_deref() != Some(want.as_str()) {
            let _ = write_response(&mut stream, 403, b"forbidden").await;
            return;
        }
    }
    match rule {
        RpcBehaviour::Hang => {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        RpcBehaviour::Raw { status, body } => {
            let _ = write_response(&mut stream, status, body.as_bytes()).await;
        }
        RpcBehaviour::Envelope { code, msg, data } => {
            let body = format!(r#"{{"code":{code},"msg":"{msg}","data":{data}}}"#);
            let _ = write_response(&mut stream, 200, body.as_bytes()).await;
        }
    }
    let _ = stream.shutdown().await;
}

/// 处理一条 `/events` WebSocket 连接。
// 闭包返回类型由 tungstenite 的 `Callback` 签名固定，`ErrorResponse` 的体积不归本 mock 控。
#[allow(clippy::result_large_err)]
async fn events_conn(stream: TcpStream, behaviour: EventsBehaviour) {
    let expected = behaviour.expected_token.clone();
    let callback = move |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
        let got = req
            .headers()
            .get("X-Gateway-Token")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let ok = match &expected {
            Some(want) => got.as_deref() == Some(want.as_str()),
            None => true,
        };
        if ok {
            Ok(resp)
        } else {
            // 只带状态码，不回任何载荷内容（token 不外泄）。
            Err(Response::builder()
                .status(403)
                .body(Some(String::new()))
                .expect("构造 403 拒绝响应"))
        }
    };
    let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(stream, callback).await else {
        return;
    };
    for frame in &behaviour.frames {
        if ws.send(Message::text(frame.clone())).await.is_err() {
            return;
        }
    }
    let _ = ws.flush().await;
    if behaviour.close_after_frames {
        // 服务端主动收口：客户端应看到 Closed，而不是提前 EOF 造成的假失败。
        let _ = ws.close(None).await;
        let _ = ws.flush().await;
        return;
    }
    // 保持连接直到对端关闭，避免提前 EOF 让测试看到假失败。
    while ws.next().await.is_some() {}
}

/// 一条帧文本：`{seq, session_id, kind, payload, ts_ms}`。
pub fn event_json(seq: u64, session: &str, kind: &str, payload: &str, ts_ms: u64) -> String {
    format!(
        r#"{{"seq":{seq},"session_id":"{session}","kind":"{kind}","payload":{payload},"ts_ms":{ts_ms}}}"#
    )
}

/// 读取一条 HTTP 请求（请求行 + 头 + `Content-Length` 体）。
pub async fn read_request(stream: &mut TcpStream) -> io::Result<SeenRequest> {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0_u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 64 * 1024 {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut words = lines.next().unwrap_or("").splitn(3, ' ');
    let method = words.next().unwrap_or("").to_owned();
    let path = words.next().unwrap_or("").to_owned();
    let mut token = None;
    let mut need = 0_usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let lower = name.trim().to_ascii_lowercase();
        let value = value.trim().to_owned();
        if lower == "x-gateway-token" {
            token = Some(value);
        } else if lower == "content-length" {
            need = value.parse().unwrap_or(0);
        }
    }
    let mut body = buf[head_end..].to_vec();
    while body.len() < need {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(need);
    Ok(SeenRequest {
        method,
        path,
        token,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// 写一条 HTTP 响应（带 `Connection: close`）。
pub async fn write_response(stream: &mut TcpStream, status: u16, body: &[u8]) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
        reason = reason(status),
        len = body.len(),
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        _ => "Status",
    }
}

/// 临时握手文件：写 `gateway.json`，`Drop` 时删除文件与目录。
pub struct TempHandshakeFile {
    dir: PathBuf,
    path: PathBuf,
}

impl TempHandshakeFile {
    /// 在独立临时目录写出指定内容（内容非法也照写，用于 fail-closed 断言）。
    pub fn with_content(content: &str) -> io::Result<Self> {
        let dir = temp_dir("handshake");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("gateway.json");
        std::fs::write(&path, content)?;
        Ok(Self { dir, path })
    }

    /// 只建目录、不写文件：得到一个确定不存在的路径。
    pub fn missing() -> io::Result<Self> {
        let dir = temp_dir("missing");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("gateway.json");
        Ok(Self { dir, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempHandshakeFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let id = SEQ.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("lengsuo-shell-{tag}-{}-{id}", std::process::id()))
}

/// 指向某个已监听端口的手写握手文件内容。
pub fn handshake_json(addr: SocketAddr, token: &str) -> String {
    format!(
        r#"{{"port":{},"pid":{},"token":"{token}"}}"#,
        addr.port(),
        std::process::id()
    )
}
