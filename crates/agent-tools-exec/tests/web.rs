//! WebFetch 验收：scheme 拒绝、HTTP 状态错误，以及对本地最小 HTTP 服务器的
//! happy 路径（标题提取、重定向跟随、字节上限）。
//!
//! 服务器用 `std::net::TcpListener` 起线程，不引入测试框架依赖。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use agent_tools_exec::{ExecError, WebFetcher};

/// 极简固定响应服务器：每次 accept 处理一条请求。
struct TestServer {
    addr: String,
    joiner: Option<thread::JoinHandle<()>>,
}

impl TestServer {
    /// `handler` 收到请求首行与路径，返回完整 HTTP 响应文本。
    fn spawn(handler: impl Fn(&str) -> String + Send + 'static) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("绑定测试端口");
        let addr = listener.local_addr().expect("本地地址").to_string();
        let joiner = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let handler = &handler;
                if let Err(e) = respond(stream, handler) {
                    eprintln!("测试服务器忽略一个连接: {e}");
                }
            }
        });
        TestServer {
            addr,
            joiner: Some(joiner),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}/{}", self.addr, path.trim_start_matches('/'))
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // listener 随线程退出释放；不阻塞等待，join 只做尽力收尾。
        if let Some(j) = self.joiner.take() {
            let _ = std::thread::spawn(move || {
                let _ = j.join();
            });
        }
    }
}

fn respond(
    mut stream: TcpStream,
    handler: &(impl Fn(&str) -> String + Send + 'static),
) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];
    let mut request = String::new();
    // 读到请求头结束（或缓冲区上限）即可，本测试不使用请求体。
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        request.push_str(&String::from_utf8_lossy(&buf[..n]));
        if request.contains("\r\n\r\n") || request.len() > 900 {
            break;
        }
    }
    stream.write_all(handler(&request).as_bytes())?;
    stream.flush()?;
    Ok(())
}

/// 异步断言一律带超时（AGENTS.md：异步读写测试必须有超时）。
async fn guard<T: Send + 'static>(f: impl std::future::Future<Output = T> + Send) -> T {
    tokio::time::timeout(Duration::from_secs(15), f)
        .await
        .expect("测试等待超时")
}

fn fetcher(max_bytes: usize) -> WebFetcher {
    WebFetcher::new(Duration::from_secs(5), max_bytes)
}

const PAGE: &str = "<html><head><title>本地测试页</title></head>\
                    <body><h1>标题一</h1><p>正文内容</p></body></html>";

#[tokio::test]
async fn fetches_a_local_page_and_extracts_title_and_text() {
    let server = TestServer::spawn(|_| {
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            PAGE.len(),
            PAGE
        )
    });
    let r = guard(fetcher(10_000).fetch_to_markdown(&server.url("/")))
        .await
        .expect("happy 路径应抓取成功");
    assert_eq!(r.title.as_deref(), Some("本地测试页"), "标题提取");
    assert!(
        r.text_markdown.contains("# 标题一"),
        "块级/标题结构应保留: {:?}",
        r.text_markdown
    );
    assert!(r.text_markdown.contains("正文内容"));
    assert!(!r.text_markdown.contains('<'), "标签必须剥净");
    assert_eq!(r.final_url, server.url("/"));
}

#[tokio::test]
async fn rejects_non_http_schemes_including_file() {
    let err = guard(fetcher(1000).fetch_to_markdown("file:///etc/passwd"))
        .await
        .expect_err("file:// 必须拒绝");
    assert!(matches!(err, ExecError::InvalidUrl(_)), "实得 {err:?}");
    for bad in ["gopher://x/y", "ftp://127.0.0.1/", "data:text/html,hi"] {
        let e = fetcher(1000).fetch_to_markdown(bad).await;
        assert!(
            matches!(e, Err(ExecError::InvalidUrl(_))),
            "{bad} 应报 InvalidUrl，实得 {e:?}"
        );
    }
    let e = fetcher(1000).fetch_to_markdown("not a url").await;
    assert!(matches!(e, Err(ExecError::InvalidUrl(_))), "实得 {e:?}");
}

#[tokio::test]
async fn non_2xx_becomes_http_status_error() {
    for (code, body) in [
        ("404 Not Found", "no such page"),
        ("500 Internal Server Error", "boom"),
        ("403 Forbidden", "denied"),
    ] {
        let server = TestServer::spawn(move |_| {
            format!(
                "HTTP/1.1 {code}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
        });
        let url = server.url("/x");
        let err = guard(fetcher(1000).fetch_to_markdown(&url))
            .await
            .expect_err(&format!("{code} 必须失败"));
        let expected = match code.split(' ').next().unwrap() {
            "404" => 404,
            "500" => 500,
            _ => 403,
        };
        assert_eq!(
            err,
            ExecError::HttpStatus {
                code: expected,
                url: url.clone()
            },
            "状态码与最终 URL 都要带上"
        );
    }
}

#[tokio::test]
async fn follows_one_redirect_and_reports_the_final_url() {
    let server = TestServer::spawn(|request| {
        if request.starts_with("GET /from") {
            "HTTP/1.1 302 Found\r\nlocation: /to\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                .to_string()
        } else {
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                PAGE.len(),
                PAGE
            )
        }
    });
    let from = server.url("/from");
    let r = guard(fetcher(10_000).fetch_to_markdown(&from))
        .await
        .expect("fetch");
    assert_eq!(
        r.final_url,
        server.url("/to"),
        "final_url 应是重定向后的地址"
    );
    assert_eq!(r.title.as_deref(), Some("本地测试页"));
}

#[tokio::test]
async fn redirect_loops_are_capped_at_five_hops() {
    let server = TestServer::spawn(|_| {
        "HTTP/1.1 302 Found\r\nlocation: /loop\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            .to_string()
    });
    let url = server.url("/loop");
    let err = guard(fetcher(1000).fetch_to_markdown(&url))
        .await
        .expect_err("重定向环必须失败");
    // 实现以 Io("重定向超过上限") 报告环（reqwest 的 redirect 策略被禁用后自计数）。
    assert!(
        matches!(&err, ExecError::Io(m) if m.contains("重定向")),
        "实得 {err:?}"
    );
}

#[tokio::test]
async fn body_is_capped_at_max_bytes() {
    // 不声明 content-length、连接不关：字节流一直往下灌，
    // 只有客户端侧的下载上限能挡住它。
    const TOTAL: usize = 300_000;
    // 流式灌数据需要裸 TcpStream，TestServer 的 String handler 装不下 ⇒ 原生监听。
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\n");
        let chunk = vec![b'#'; 8 * 1024];
        let mut sent = 0usize;
        while sent < TOTAL {
            match stream.write_all(&chunk) {
                Ok(()) => sent += chunk.len(),
                Err(_) => break,
            }
        }
        // 不主动关连接：由客户端下载上限先生效（本测试的前提）。
        std::thread::sleep(std::time::Duration::from_secs(5));
    });
    let r = guard(fetcher(64).fetch_to_markdown(&format!("http://{addr}/")))
        .await
        .expect("fetch");
    assert!(
        r.text_markdown.len() <= 64 + 8,
        "正文必须有界，实得 {}",
        r.text_markdown.len()
    );
    assert!(r.text_markdown.chars().all(|c| c == '#'));
}

#[tokio::test]
async fn plain_text_body_is_passed_through_without_title() {
    let body = "just plain text\nsecond line";
    let server = TestServer::spawn(move |_| {
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    });
    let r = guard(fetcher(1000).fetch_to_markdown(&server.url("/")))
        .await
        .expect("fetch");
    assert_eq!(r.title, None, "非 HTML 没有标题");
    assert_eq!(r.text_markdown, "just plain text\nsecond line");
}

#[tokio::test]
async fn connection_failure_is_an_io_error_not_a_panic() {
    // 绑定后立刻 drop：端口没人听，连接必失败。
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = dead.local_addr().unwrap().to_string();
    drop(dead);
    let err = guard(fetcher(1000).fetch_to_markdown(&format!("http://{addr}/"))).await;
    assert!(err.is_err(), "无人监听的端口必须失败");
}

#[test]
fn servers_are_usable_from_plain_sync_threads_too() {
    // 冒烟：确保测试服务器本身能被 std TcpStream 打通（防框架级误判）。
    let server =
        TestServer::spawn(|_| "HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n".to_string());
    let mut stream = TcpStream::connect(&server.addr).expect("连接测试服务器");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .expect("写请求");
    let mut buf = String::new();
    stream.read_to_string(&mut buf).expect("读响应");
    assert!(buf.starts_with("HTTP/1.1 204"), "实得 {buf:?}");
}
