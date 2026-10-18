//! 一次性微型 HTTP 服务器：按请求路径回预置响应，可带一个中间重定向。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// 一条预置响应：请求路径 -> （状态行、`Content-Type`、正文）。
pub struct Route {
    pub path: String,
    pub status: &'static str,
    pub content_type: &'static str,
    pub body: String,
}

impl Route {
    pub fn new(path: &str, status: &'static str, content_type: &'static str, body: &str) -> Route {
        Route {
            path: path.to_string(),
            status,
            content_type,
            body: body.to_string(),
        }
    }
}

/// 一次性微型 HTTP 服务器：按请求路径回预置响应，可带一个中间重定向。
pub struct TestServer {
    addr: SocketAddr,
    joiner: Option<thread::JoinHandle<()>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl TestServer {
    /// 起服务器（回环、端口 0 由内核分配）；`redirect_from` 命中的路径先回 301 到 `/final`。
    pub fn start(routes: Vec<Route>, redirect_from: Option<&str>) -> TestServer {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) => panic!("监听失败：{error}"),
        };
        let addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(error) => panic!("取地址失败：{error}"),
        };
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
        let joiner = thread::spawn(move || {
            serve(
                listener,
                routes,
                redirect_from.map(ToString::to_string),
                shutdown_rx,
            )
        });
        // 服务器起线程后需就绪才有 listen；一次极短的让步足够本地回环。
        thread::sleep(Duration::from_millis(50));
        TestServer {
            addr,
            joiner: Some(joiner),
            shutdown_tx: Some(shutdown_tx),
        }
    }

    /// 本机地址上的完整 URL，如 `http://127.0.0.1:PORT/doc`。
    pub fn url(&self, path: &str) -> String {
        format!(
            "http://{}:{}/{}",
            self.addr.ip(),
            self.addr.port(),
            path.trim_matches('/')
        )
    }

    /// 发关闭信号并 join 服务线程。
    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(joiner) = self.joiner.take() {
            let _ = joiner.join();
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// 接受连接逐条处理，直到收到关闭信号或监听错误。
fn serve(
    listener: TcpListener,
    routes: Vec<Route>,
    redirect_from: Option<String>,
    shutdown_rx: mpsc::Receiver<()>,
) {
    let _ = listener.set_nonblocking(true);
    while shutdown_rx.try_recv().is_err() {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let _ = handle_conn(stream, &routes, redirect_from.as_deref());
            }
            // 无连接可读时让出，避免空转。
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10))
            }
            Err(_) => return,
        }
    }
}

/// 读请求行与请求头，按路径回响应。
fn handle_conn(
    mut stream: TcpStream,
    routes: &[Route],
    redirect_from: Option<&str>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    // 丢弃请求头余部。
    let mut header = String::new();
    loop {
        header.clear();
        if reader.read_line(&mut header)? == 0 || header.trim().is_empty() {
            break;
        }
    }

    if let Some(from) = redirect_from {
        if path == from {
            let target = format!("http://{}/final", stream.local_addr()?);
            return write_response(
                &mut stream,
                "301 Moved Permanently",
                &format!("Location: {target}\r\n"),
                "",
            );
        }
    }

    match routes.iter().find(|route| route.path == path) {
        Some(route) => write_response(
            &mut stream,
            route.status,
            &format!("Content-Type: {}\r\n", route.content_type),
            &route.body,
        ),
        None => write_response(&mut stream, "404 Not Found", "", "missing"),
    }
}

/// 写 `Content-Length` 定界响应：`extra_headers` 为不含 `Content-Length` 的附加头。
fn write_response(
    stream: &mut TcpStream,
    status: &str,
    extra_headers: &str,
    body: &str,
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}
