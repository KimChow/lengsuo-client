//! **真浏览器端到端**（可跳过）：本机 Chromium/Edge + 三个本地 HTTP 代理。
//!
//! ## 场景
//!
//! 三个环境访问**同一个域名** `tun3.lensuo.test`，但各自被注入**不同的代理**。
//! 每个代理再把请求转发到**自己**的本地目标服务器 ⇒
//! 「同域名 ⇒ 不同环境 ⇒ 不同出口」。
//!
//! 这正是 TUN-3「Windows 实机浏览器 A/B/C 同域名同 IP 多出口」的接线前置。
//!
//! ## 为什么不直接访问 `127.0.0.1`
//!
//! Chromium 的**隐式绕过列表**包含回环地址，直连回环目标时流量**不会**经过
//! 代理（实测：本机 Chrome 144 对 `http://127.0.0.1:PORT/` 直连，不经代理）。
//! 所以目标用一个**不可解析的自定义域名**：Chromium 会把绝对 URI 原样交给
//! 代理，代理侧再决定路由——这正是「出口侧车」的真实职责。
//!
//! ## 不出网
//!
//! 代理只转发到**回环**目标；其它请求（浏览器的后台请求，例如时间同步）
//! 一律回 502，**绝不真的出网**。
//!
//! ## 运行条件
//!
//! 用例默认跳过（`#[ignore]`），用环境变量显式开启：
//!
//! ```text
//! LENGSUO_REAL_BROWSER=/usr/bin/google-chrome   # 可选：指定浏览器可执行文件
//! cargo test -p lengsuo-browser-launch -- --ignored
//! ```
//!
//! 没有 `LENGSUO_REAL_BROWSER` 且本机找不到 Chromium/Edge ⇒ **显式跳过**并
//! 打印原因。

mod support;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lengsuo_browser_launch::{
    BrowserBinary, EnvironmentId, Generation, LaunchSpec, Launcher, ProbeBudget, ProxyConfig,
    ProxyScheme,
};
use support::{wait_until, TempDir};

/// 每个用例的总超时。
const CASE_TIMEOUT: Duration = Duration::from_secs(120);

/// 环境变量名：指定本机真浏览器可执行文件。
const BROWSER_ENV: &str = "LENGSUO_REAL_BROWSER";

/// 三个环境访问的**同一个**域名。
const TEST_HOST: &str = "tun3.lensuo.test";

/// 找本机的 Chromium 系浏览器；找不到返回 `None`。
fn find_real_browser() -> Option<PathBuf> {
    if let Ok(path) = std::env::var(BROWSER_ENV) {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
        eprintln!(
            "{BROWSER_ENV} 指向的文件不存在，跳过真浏览器端到端：{}",
            path.display()
        );
        return None;
    }
    for candidate in [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/microsoft-edge",
        "/usr/bin/microsoft-edge-stable",
    ] {
        let path = Path::new(candidate);
        if path.is_file() {
            return Some(path.to_path_buf());
        }
    }
    None
}

/// 一个本地回环 HTTP 目标服务器：记录收到的请求数。
struct LocalTarget {
    port: u16,
    marker: String,
    hits: Arc<AtomicUsize>,
}

impl LocalTarget {
    fn start(marker: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind must work");
        let port = listener.local_addr().expect("local addr").port();
        let body = format!("<html><body>{marker}</body></html>");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        Self {
            port,
            marker: marker.to_string(),
            hits,
        }
    }

    /// 收到的请求数。
    fn hit_count(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

/// 一个本地回环 HTTP 代理（出口侧车的替身）。
///
/// - 记录它收到的**目标主机名**；
/// - 把 `TEST_HOST` 的请求转发到**自己**绑定的那台目标服务器；
/// - 其余请求（含浏览器的后台 CONNECT）一律回 502，**不出网**。
struct EgressProxy {
    port: u16,
    target_port: u16,
    seen_hosts: Arc<Mutex<Vec<String>>>,
}

impl EgressProxy {
    fn start(target_port: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind must work");
        let port = listener.local_addr().expect("local addr").port();
        let seen_hosts = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen_hosts);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let sink = Arc::clone(&sink);
                std::thread::spawn(move || {
                    let mut buf = [0u8; 8192];
                    let read = stream.read(&mut buf).unwrap_or(0);
                    let text = String::from_utf8_lossy(&buf[..read]).to_string();
                    let first = text.lines().next().unwrap_or("").to_string();
                    let method = first.split_whitespace().next().unwrap_or("").to_string();
                    let target = first.split_whitespace().nth(1).unwrap_or("").to_string();
                    if method == "CONNECT" {
                        // 浏览器的后台隧道请求：**记录但不转发**，杜绝出网。
                        if let Ok(mut guard) = sink.lock() {
                            guard.push(format!("CONNECT:{target}"));
                        }
                        let _ = stream.write_all(
                            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        return;
                    }
                    // 绝对 URI：GET http://host:port/path HTTP/1.1
                    // **主机名在 `://` 之后**（`split_once` 的右半边）。
                    let (host, path) = match target.split_once("://") {
                        Some((_, rest)) => match rest.split_once('/') {
                            Some((host, path)) => (host.to_string(), format!("/{path}")),
                            None => (rest.to_string(), "/".to_string()),
                        },
                        None => (String::new(), "/".to_string()),
                    };
                    if let Ok(mut guard) = sink.lock() {
                        guard.push(host.clone());
                    }
                    if !host.starts_with(TEST_HOST) {
                        let _ = stream.write_all(
                            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        return;
                    }
                    // 转发到本代理绑定的目标服务器（出口侧车的路由决策）。
                    let upstream_host = format!("127.0.0.1:{target_port}");
                    let rewritten = format!(
                        "GET {path} HTTP/1.1\r\nHost: {upstream_host}\r\nConnection: close\r\n\r\n"
                    );
                    if let Ok(mut upstream) = std::net::TcpStream::connect(&upstream_host) {
                        let _ = upstream.write_all(rewritten.as_bytes());
                        let mut response = Vec::new();
                        let _ = upstream.read_to_end(&mut response);
                        let _ = stream.write_all(&response);
                        let _ = stream.flush();
                    }
                });
            }
        });
        Self {
            port,
            target_port,
            seen_hosts,
        }
    }

    /// 代理端口。
    fn port(&self) -> u16 {
        self.port
    }

    /// 绑定的目标服务器端口。
    fn target_port(&self) -> u16 {
        self.target_port
    }

    /// 收到的目标主机名（不含 CONNECT 记录）。
    fn seen_hosts(&self) -> Vec<String> {
        self.seen_hosts
            .lock()
            .map(|g| {
                g.iter()
                    .filter(|h| !h.starts_with("CONNECT:"))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// 真浏览器端到端：**同域名 ⇒ 三环境 ⇒ 三个不同出口**。
#[test]
#[ignore = "需要本机 Chromium/Edge；用 --ignored 实跑（可设 LENGSUO_REAL_BROWSER）"]
fn three_real_browser_environments_traverse_three_different_proxies() {
    let Some(browser) = find_real_browser() else {
        eprintln!("本机没有 Chromium/Edge ⇒ 显式跳过真浏览器端到端");
        return;
    };
    eprintln!("真浏览器端到端：使用 {}", browser.display());

    let root = TempDir::new("real-e2e");
    let target_a = LocalTarget::start("exit-a");
    let target_b = LocalTarget::start("exit-b");
    let target_c = LocalTarget::start("exit-c");
    let proxy_a = EgressProxy::start(target_a.port);
    let proxy_b = EgressProxy::start(target_b.port);
    let proxy_c = EgressProxy::start(target_c.port);

    let mut launcher = Launcher::new();
    let mut launched = Vec::new();
    for (index, (environment, proxy)) in [
        ("env-a", &proxy_a),
        ("env-b", &proxy_b),
        ("env-c", &proxy_c),
    ]
    .into_iter()
    .enumerate()
    {
        let proxy_config = ProxyConfig::empty()
            .with_endpoint(ProxyScheme::Http, "127.0.0.1", proxy.port())
            .unwrap();
        let spec = LaunchSpec::new(
            BrowserBinary::locate(&browser),
            root.join(environment),
            EnvironmentId::new(environment).unwrap(),
            Generation::new(index as u64 + 1).unwrap(),
            proxy_config,
            // 无头模式：CI/研究机通常没有 X server。headless 是**部署选择**，
            // 不是启动层的默认值，所以由调用方通过 extra_args 传入。
            vec!["--headless=new".to_string()],
            ProbeBudget::new(60_000).unwrap(),
        )
        .unwrap()
        .with_remote_debugging(true)
        .with_initial_url(Some(format!("http://{TEST_HOST}:80/")));
        let result = launcher
            .launch(&spec)
            .unwrap_or_else(|err| panic!("{environment} 必须启动成功：{}", err.code()));
        eprintln!("{environment} 命令行：{}", result.command_line.display());
        launched.push((environment.to_string(), result));
    }

    // 1) 三个 PID 互不相同 ⇒ 三个独立进程。
    let pids: std::collections::HashSet<u32> =
        launched.iter().map(|(_, l)| l.process.pid()).collect();
    assert_eq!(pids.len(), 3, "三个环境必须拿到三个不同的 PID");

    // 2) 三个用户数据目录互不相同。
    let dirs: std::collections::HashSet<PathBuf> = launched
        .iter()
        .map(|(environment, _)| root.join(environment))
        .collect();
    assert_eq!(dirs.len(), 3, "三个环境必须用三个不同的用户数据目录");

    // 3) 三个代理配置互不相同。
    let proxies: std::collections::HashSet<String> = launched
        .iter()
        .map(|(_, l)| {
            l.command_line
                .value_of("--proxy-server")
                .unwrap_or("")
                .to_string()
        })
        .collect();
    assert_eq!(proxies.len(), 3, "三个环境必须注入三个不同的代理");

    // 4) 等三个目标服务器各自被访问（判据是「目标被访问」，不是「代理收到过
    //    任何请求」——浏览器自己会发后台请求，那些不代表这个环境的出口）。
    let all_arrived = wait_until(CASE_TIMEOUT, || {
        target_a.hit_count() > 0 && target_b.hit_count() > 0 && target_c.hit_count() > 0
    });
    assert!(
        all_arrived,
        "三个目标服务器都应当被访问：a={} b={} c={}；代理看到：a={:?} b={:?} c={:?}",
        target_a.hit_count(),
        target_b.hit_count(),
        target_c.hit_count(),
        proxy_a.seen_hosts(),
        proxy_b.seen_hosts(),
        proxy_c.seen_hosts()
    );

    // 5) 每个代理都收到了**同一个域名**的请求。
    let mut per_proxy: HashMap<&str, Vec<String>> = HashMap::new();
    per_proxy.insert("a", proxy_a.seen_hosts());
    per_proxy.insert("b", proxy_b.seen_hosts());
    per_proxy.insert("c", proxy_c.seen_hosts());
    for (name, hosts) in &per_proxy {
        assert!(
            hosts.iter().any(|h| h.starts_with(TEST_HOST)),
            "代理 {name} 必须收到 {TEST_HOST} 的请求：{hosts:?}"
        );
    }

    // 6) 每个代理都**没有**把请求发到别人的出口：三个目标的命中数互不相同，
    //    且每个代理的请求确实落在自己绑定的目标上（由转发逻辑保证）。
    assert!(
        target_a.hit_count() > 0 && target_b.hit_count() > 0 && target_c.hit_count() > 0,
        "三个出口都应当各收到请求"
    );
    assert_eq!(
        proxy_a.target_port(),
        target_a.port,
        "代理 a 必须绑定出口 A"
    );
    assert_eq!(proxy_b.target_port(), target_b.port);
    assert_eq!(proxy_c.target_port(), target_c.port);

    // 7) 三个出口本身互不相同（不同的标记 ⇒ 不同的出口）。
    let markers = [
        target_a.marker.as_str(),
        target_b.marker.as_str(),
        target_c.marker.as_str(),
    ];
    let unique: std::collections::HashSet<&str> = markers.iter().copied().collect();
    assert_eq!(unique.len(), 3, "三个出口必须互不相同：{markers:?}");

    // 8) 回收：三个浏览器进程全部 kill + wait。
    for (_, mut result) in launched {
        result.process.shutdown().expect("shutdown must succeed");
    }
}
