//! 跨平台的测试脚手架。
//!
//! **假浏览器**是本 crate 自带的 bin 目标 `lengsuo-fake-browser`
//! （见 `src/bin/lengsuo-fake-browser.rs`）：它读参数、记录参数与环境变量、
//! 监听一个本地回环端口并把端口号写进 `DevToolsActivePort`。
//!
//! 这样测试在 Linux 与 Windows 上跑的是**同一个可执行文件**，不需要 shell
//! 脚本、不需要 `.bat`、不需要 `python3`：**不下载真浏览器、不连公网**。

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// 假浏览器可执行文件路径。
///
/// `CARGO_BIN_EXE_<name>` 由 cargo 为集成测试注入，指向**本次构建**产出的
/// bin 目标，因此在任何平台上都是真实可执行的原生程序。
#[must_use]
pub fn fake_browser_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_lengsuo-fake-browser"))
}

/// 一个临时目录，用完自动删除。
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// 在系统临时目录下建一个带唯一后缀的目录。
    pub fn new(tag: &str) -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "lengsuo-launch-{tag}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("temp dir must be creatable");
        Self { path }
    }

    /// 目录路径。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 目录下的某个子路径。
    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// 读回假浏览器记录下来的参数。
pub fn read_args(user_data_dir: &Path) -> Vec<String> {
    let path = user_data_dir.join("args.txt");
    let text = std::fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .map(|line| line.trim_end_matches('\r').to_string())
        .filter(|line| !line.is_empty())
        .collect()
}

/// 读回假浏览器记录下来的环境变量。
pub fn read_env(user_data_dir: &Path) -> BTreeMap<String, String> {
    let path = user_data_dir.join("env.txt");
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if let Some((key, value)) = line.split_once('=') {
            map.insert(key.to_string(), value.to_string());
        }
    }
    map
}

/// 一个本地回环 HTTP 代理（只记录收到的请求，不出网）。
///
/// 用于「三个环境 ⇒ 三个代理 ⇒ 三个出口」的断言：每个代理记录自己收到的
/// 目标主机名，三者互不相同即证明流量走了不同出口。
pub struct RecordingProxy {
    port: u16,
    seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl RecordingProxy {
    /// 绑定一个回环端口并开始记录。
    #[must_use]
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind must work");
        let port = listener.local_addr().expect("local addr").port();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                // 读请求头，取 Host 行作为「出口目标」。
                let mut buf = [0u8; 2048];
                let read = stream.read(&mut buf).unwrap_or(0);
                let text = String::from_utf8_lossy(&buf[..read]).to_string();
                let host = text
                    .lines()
                    .find_map(|line| {
                        let lower = line.to_ascii_lowercase();
                        if lower.starts_with("host:") {
                            Some(line[5..].trim().to_string())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| "unknown".to_string());
                if let Ok(mut guard) = sink.lock() {
                    guard.push(host);
                }
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
                let _ = stream.flush();
            }
        });
        Self { port, seen }
    }

    /// 代理端口。
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// 已经收到的目标主机名列表。
    #[must_use]
    pub fn seen_hosts(&self) -> Vec<String> {
        self.seen.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

/// 等待某个条件成立，最多等 `timeout`；成立返回 `true`。
pub fn wait_until<F: FnMut() -> bool>(timeout: Duration, mut check: F) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if check() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
