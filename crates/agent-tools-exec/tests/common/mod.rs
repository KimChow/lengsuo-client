//! 测试辅助：真实子进程、后台线程收流、一次性微型 HTTP 服务器。
//!
//! 库本体只依赖 tokio 的 process/time/io-util 等特性；测试另需 `rt`/`macros`，由
//! dev-dependencies 提供，用 `#[tokio::test]` 直接跑 async。
//!
//! 同步子进程的输出一律在本线程之外的工作线程上收取并 reap：主线程直接 `wait` 会让
//! rustix 的 SIGCHLD 回收线程抢先 reap，`Child::try_wait` 随即报 "already dead"、
//! ExitCodeStatus 缺失，退出码读不出来。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use agent_tools_exec::{ExecError, ExecResult, FetchResult, WebFetcher};

/// 结果与期望逐字段比对。
pub fn check_exec(
    outcome: Result<ExecResult, ExecError>,
    exit: i32,
    stdout: &str,
    stderr: &str,
    truncated: bool,
    timed_out: bool,
) {
    let result = match outcome {
        Ok(result) => result,
        Err(error) => panic!("执行失败：{error}"),
    };
    assert_eq!(result.exit_code, exit, "退出码；stderr={:?}", result.stderr);
    assert_eq!(result.stdout, stdout, "stdout");
    assert_eq!(result.stderr, stderr, "stderr");
    assert_eq!(result.truncated, truncated, "truncated");
    assert_eq!(result.timed_out, timed_out, "timed_out");
}

/// 断言失败路径的错误展示文本。
pub fn check_exec_error(outcome: Result<ExecResult, ExecError>, message: &str) {
    match outcome {
        Ok(result) => panic!("期望失败，实际成功：{result:?}"),
        Err(error) => assert_eq!(error.to_string(), message),
    }
}

/// 抓取成功路径的逐字段比对。
pub fn check_fetch(
    outcome: Result<FetchResult, ExecError>,
    final_url: &str,
    title: &str,
    markdown: &str,
) {
    let result = match outcome {
        Ok(result) => result,
        Err(error) => panic!("抓取失败：{error}"),
    };
    assert_eq!(result.final_url, final_url, "final_url");
    assert_eq!(result.title, title, "title");
    assert_eq!(result.text_markdown, markdown, "text_markdown");
}

/// 断言抓取失败的错误展示文本。
pub fn check_fetch_error(outcome: Result<FetchResult, ExecError>, message: &str) {
    match outcome {
        Ok(result) => panic!("期望失败，实际成功：{result:?}"),
        Err(error) => assert_eq!(error.to_string(), message),
    }
}

pub fn default_fetcher() -> WebFetcher {
    WebFetcher::new(Duration::from_millis(500), 1_048_576)
}

/// 抓取器，把响应字节上限与文本上限一并设成 `limit`。
pub fn fetcher_at_limit(limit: usize) -> WebFetcher {
    WebFetcher::with_max_text_bytes(Duration::from_millis(500), limit, limit)
}

pub fn fetcher_with_timeout(timeout: Duration) -> WebFetcher {
    WebFetcher::new(timeout, 4096)
}

/// 收流结束标志：主线程 reap 后置位，工作线程看到即退出。
#[derive(Default)]
struct DoneFlag(AtomicBool);

impl DoneFlag {
    fn done(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    fn set(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

type SharedDone = Arc<DoneFlag>;

/// 后台线程按行读一路输出直到 EOF，或读到 `done` 置位；每行之间查一次标志。
fn spawn_line_reader(
    source: impl Read + Send + 'static,
    done: SharedDone,
) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    let _ = thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            let mut buffer = String::new();
            let mut lines = BufReader::new(source).lines();
            while let Ok(Some(line)) = lines.next() {
                buffer.push_str(&line);
                buffer.push('\n');
                if done.done() {
                    break;
                }
            }
            let _ = tx.send(buffer);
        });
    rx
}

/// 一个已启动的同步子进程：stdin 已交后台线程写入，两路输出由工作线程收取。
pub struct TestProcess {
    child: Child,
    stdin_writer: Option<thread::JoinHandle<()>>,
    stdout_rx: mpsc::Receiver<String>,
    stderr_rx: mpsc::Receiver<String>,
    done: SharedDone,
}

/// 起进程：`cwd` 为工作目录，`input` 写 stdin。
pub fn spawn_process(program: &Path, args: &[&str], cwd: &Path, input: &str) -> TestProcess {
    let mut child = match Command::new(program)
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => panic!(
            "启动 {} 失败：{} {error}",
            program.display(),
            args.join(" ")
        ),
    };

    let payload = input.to_string();
    let mut stdin = match child.stdin.take() {
        Some(stdin) => stdin,
        None => panic!("stdin 未接管道"),
    };
    let stdin_writer = thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            let mut cursor = payload.as_bytes();
            let mut chunk = [0_u8; 8192];
            loop {
                match cursor.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        if stdin.write_all(&chunk[..read]).is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = stdin.flush();
            drop(stdin);
        })
        .expect("起 stdin 线程");

    let done = Arc::new(DoneFlag::default());
    let Some(stdout_pipe) = child.stdout.take() else {
        panic!("stdout 未接管道")
    };
    let Some(stderr_pipe) = child.stderr.take() else {
        panic!("stderr 未接管道")
    };
    let stdout_rx = spawn_line_reader(stdout_pipe, Arc::clone(&done));
    let stderr_rx = spawn_line_reader(stderr_pipe, Arc::clone(&done));

    TestProcess {
        child,
        stdin_writer: Some(stdin_writer),
        stdout_rx,
        stderr_rx,
        done,
    }
}

impl TestProcess {
    /// 等待退出至多 `timeout`，回 `(退出码, stdout, stderr)`；超时则杀进程回 `None`。
    ///
    /// 顺序要紧：先 join stdin 线程（否则 stdin 悬挂，进程不退出），再轮询 reap，
    /// 最后置收流标志取回缓冲。
    pub fn finish(&mut self, timeout: Duration) -> Option<(i32, String, String)> {
        if let Some(handle) = self.stdin_writer.take() {
            let _ = handle.join();
        }
        let started = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.done.set();
                    let code = status
                        .code()
                        .unwrap_or_else(|| status.signal().unwrap_or(0));
                    return Some((
                        code,
                        self.drain(&mut self.stdout_rx),
                        self.drain(&mut self.stderr_rx),
                    ));
                }
                Ok(None) => {
                    if started.elapsed() > timeout {
                        let _ = self.child.kill();
                        let _ = self.child.wait();
                        self.done.set();
                        return None;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("轮询退出状态失败：{error}"),
            }
        }
    }

    /// 收流线程在 `done` 置位后很快发回缓冲；2s 等待是有余量的上界。
    fn drain(&self, rx: &mut mpsc::Receiver<String>) -> String {
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(text) | Err(mpsc::RecvTimeoutError::Disconnected) => text,
            Err(mpsc::RecvTimeoutError::Timeout) => String::new(),
        }
    }
}

/// 在 `cwd` 跑一条命令，回其 stdout（断言成功）。
pub fn run_in(program: &Path, args: &[&str], cwd: &Path) -> String {
    let mut process = spawn_process(program, args, cwd, "");
    match process.finish(Duration::from_secs(10)) {
        Some((0, stdout, _stderr)) => stdout,
        Some((code, _stdout, stderr)) => panic!("{} 退出 {code}：{stderr}", program.display()),
        None => panic!("{} 超时", program.display()),
    }
}

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
