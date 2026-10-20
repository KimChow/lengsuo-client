//! 就绪探测：**可判定**的条件 + **总超时**，绝不靠 sleep 猜。
//!
//! 两条内置策略：
//! 1. [`ReadinessStrategy::DevToolsPort`]：Chromium 以 `--remote-debugging-port=0`
//!    启动时会自选一个空闲端口，并把端口号写进用户数据目录下的
//!    `DevToolsActivePort` 文件。探测读该文件、解析端口，再对该端口做一次
//!    **TCP 连接**——连得上才算「浏览器已能接受连接」。
//! 2. [`ReadinessStrategy::TcpConnect`]：直接对已知地址做连接探测（用于
//!    「侧车代理已就绪」这类外部判据）。
//!
//! 两条策略都有**总预算**；超预算 ⇒ [`LaunchError::ProbeTimeout`]，调用方负责
//! 立即回收进程。浏览器在就绪前退出 ⇒ [`LaunchError::ExitedBeforeReady`]。

use std::io::{ErrorKind, Read};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::process::Child;
use std::time::{Duration, Instant};

use crate::error::LaunchError;
use crate::identity::ProbeBudget;

/// Chromium 写入用户数据目录的调试端口文件名。
pub const DEVTOOLS_PORT_FILE: &str = "DevToolsActivePort";

/// 轮询间隔。**不是**「睡一会儿就当就绪」，而是「隔一会儿检查一次可判定条件」。
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// 单次连接尝试的上限。
const CONNECT_TIMEOUT: Duration = Duration::from_millis(250);

/// 就绪判据。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ReadinessStrategy {
    /// 读 `<user-data-dir>/DevToolsActivePort` 并连接该端口。
    #[default]
    DevToolsPort,
    /// 连接一个已知的地址。
    TcpConnect {
        /// 主机名或 IP。
        host: String,
        /// 端口。
        port: u16,
    },
}

/// 探测结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeOutcome {
    /// 探测到的端口（DevTools 策略下为浏览器自选端口）。
    pub port: Option<u16>,
}

/// 进程存活观察：探测期间用来发现「浏览器提前退出」。
///
/// 抽成 trait 是为了让**超时路径**可以在测试里用一个「永远活着」的桩来驱动，
/// 而不必真的拉起一个常驻进程。
pub trait ProcessWatch {
    /// 进程是否已经退出（`true` = 已退出）。
    fn has_exited(&mut self) -> Result<bool, std::io::Error>;
}

impl ProcessWatch for Child {
    fn has_exited(&mut self) -> Result<bool, std::io::Error> {
        Ok(self.try_wait()?.is_some())
    }
}

/// 就绪探测：等到判据成立，或预算耗尽。
///
/// `watch` 用于发现「浏览器提前退出」——那样要立刻失败，而不是空等预算。
pub fn wait_for_ready(
    strategy: &ReadinessStrategy,
    user_data_dir: &Path,
    watch: &mut dyn ProcessWatch,
    budget: ProbeBudget,
) -> Result<ProbeOutcome, LaunchError> {
    let started = Instant::now();
    let total = Duration::from_millis(budget.total_ms());
    loop {
        // 1) 浏览器提前退出 ⇒ 立即失败（fail-closed，不空等）。
        match watch.has_exited() {
            Ok(true) => return Err(LaunchError::ExitedBeforeReady),
            Ok(false) => {}
            Err(error) => {
                return Err(LaunchError::SpawnFailed { kind: error.kind() });
            }
        }

        // 2) 判据是否成立。
        if let Some(outcome) = check(strategy, user_data_dir, started, total) {
            return Ok(outcome);
        }

        // 3) 预算耗尽 ⇒ 明确超时。
        if started.elapsed() >= total {
            return Err(LaunchError::ProbeTimeout {
                budget_ms: budget.total_ms(),
            });
        }

        std::thread::sleep(POLL_INTERVAL);
    }
}

/// 检查一次判据；`None` 表示「还没成立，再等」。
fn check(
    strategy: &ReadinessStrategy,
    user_data_dir: &Path,
    started: Instant,
    total: Duration,
) -> Option<ProbeOutcome> {
    match strategy {
        ReadinessStrategy::DevToolsPort => {
            let port = read_devtools_port(user_data_dir)?;
            if connects("127.0.0.1", port, remaining(started, total)) {
                Some(ProbeOutcome { port: Some(port) })
            } else {
                None
            }
        }
        ReadinessStrategy::TcpConnect { host, port } => {
            if connects(host, *port, remaining(started, total)) {
                Some(ProbeOutcome { port: Some(*port) })
            } else {
                None
            }
        }
    }
}

/// 剩余预算，单次连接最多用 `CONNECT_TIMEOUT`。
fn remaining(started: Instant, total: Duration) -> Duration {
    total
        .checked_sub(started.elapsed())
        .unwrap_or(Duration::ZERO)
        .min(CONNECT_TIMEOUT)
}

/// 读 `DevToolsActivePort`：首行是端口号。
fn read_devtools_port(user_data_dir: &Path) -> Option<u16> {
    let path = user_data_dir.join(DEVTOOLS_PORT_FILE);
    let mut file = std::fs::File::open(path).ok()?;
    let mut text = String::new();
    // 端口文件很小；读到 64 字节足够拿到首行。
    let mut buf = [0u8; 64];
    let read = file.read(&mut buf).ok()?;
    text.push_str(&String::from_utf8_lossy(&buf[..read]));
    let first = text.lines().next()?.trim();
    first.parse::<u16>().ok().filter(|p| *p != 0)
}

/// 尝试连接一次；成功即代表「已能接受连接」。
fn connects(host: &str, port: u16, timeout: Duration) -> bool {
    if timeout.is_zero() {
        return false;
    }
    let target = format!("{host}:{port}");
    let mut addrs = match target.to_socket_addrs() {
        Ok(addrs) => addrs,
        Err(_) => return false,
    };
    let addr: SocketAddr = match addrs.next() {
        Some(addr) => addr,
        None => return false,
    };
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(stream) => {
            // 立刻关闭，避免给浏览器留下半开连接。
            drop(stream);
            true
        }
        // 连不上就是「还没就绪」，等下一轮。
        Err(_) => false,
    }
}

/// 启动前清掉可能残留的端口文件，避免读到上一轮的旧端口。
pub fn clear_stale_port_file(user_data_dir: &Path) {
    let path = user_data_dir.join(DEVTOOLS_PORT_FILE);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{
        clear_stale_port_file, read_devtools_port, wait_for_ready, ProcessWatch, ReadinessStrategy,
    };
    use crate::error::LaunchError;
    use crate::identity::ProbeBudget;
    use std::io::Write;
    use std::net::TcpListener;
    use std::path::PathBuf;

    /// 一个「永远活着」的桩：让超时路径不必真的拉起常驻进程。
    struct AlwaysAlive;

    impl ProcessWatch for AlwaysAlive {
        fn has_exited(&mut self) -> Result<bool, std::io::Error> {
            Ok(false)
        }
    }

    /// 一个「已经退出」的桩。
    struct AlreadyExited;

    impl ProcessWatch for AlreadyExited {
        fn has_exited(&mut self) -> Result<bool, std::io::Error> {
            Ok(true)
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lengsuo-probe-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_missing_port_file_yields_no_port() {
        let dir = temp_dir("missing");
        assert_eq!(read_devtools_port(&dir), None);
    }

    #[test]
    fn the_first_line_of_the_port_file_is_the_port() {
        let dir = temp_dir("first-line");
        let mut file = std::fs::File::create(dir.join("DevToolsActivePort")).unwrap();
        writeln!(file, "45123").unwrap();
        writeln!(file, "/devtools/browser/abc").unwrap();
        assert_eq!(read_devtools_port(&dir), Some(45123));
    }

    #[test]
    fn a_stale_port_file_is_removed() {
        let dir = temp_dir("stale");
        let path = dir.join("DevToolsActivePort");
        std::fs::write(&path, "1\n").unwrap();
        clear_stale_port_file(&dir);
        assert!(!path.exists());
    }

    #[test]
    fn a_tcp_connect_to_a_closed_port_times_out_within_the_budget() {
        // 绑定一个端口再放掉，得到一个几乎肯定没人监听的端口。
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let dir = temp_dir("closed");
        let mut watch = AlwaysAlive;
        let outcome = wait_for_ready(
            &ReadinessStrategy::TcpConnect {
                host: "127.0.0.1".into(),
                port,
            },
            &dir,
            &mut watch,
            ProbeBudget::new(300).unwrap(),
        );
        assert!(matches!(outcome, Err(LaunchError::ProbeTimeout { .. })));
    }

    #[test]
    fn the_timeout_reports_the_budget_it_gave_up_on() {
        let dir = temp_dir("budget");
        let mut watch = AlwaysAlive;
        let outcome = wait_for_ready(
            &ReadinessStrategy::TcpConnect {
                host: "127.0.0.1".into(),
                port: 1,
            },
            &dir,
            &mut watch,
            ProbeBudget::new(120).unwrap(),
        );
        assert_eq!(
            outcome.unwrap_err(),
            LaunchError::ProbeTimeout { budget_ms: 120 }
        );
    }

    #[test]
    fn a_tcp_connect_to_a_listening_port_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let dir = temp_dir("open");
        let mut watch = AlwaysAlive;
        let outcome = wait_for_ready(
            &ReadinessStrategy::TcpConnect {
                host: "127.0.0.1".into(),
                port,
            },
            &dir,
            &mut watch,
            ProbeBudget::new(3_000).unwrap(),
        )
        .unwrap();
        assert_eq!(outcome.port, Some(port));
    }

    #[test]
    fn the_devtools_strategy_needs_both_the_file_and_a_live_port() {
        // 只写端口文件但没人监听 ⇒ 还不算就绪。
        let dir = temp_dir("file-only");
        std::fs::write(dir.join("DevToolsActivePort"), "1\n").unwrap();
        let mut watch = AlwaysAlive;
        let outcome = wait_for_ready(
            &ReadinessStrategy::DevToolsPort,
            &dir,
            &mut watch,
            ProbeBudget::new(200).unwrap(),
        );
        assert!(matches!(outcome, Err(LaunchError::ProbeTimeout { .. })));
    }

    #[test]
    fn the_devtools_strategy_succeeds_when_the_port_is_live() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let dir = temp_dir("file-live");
        std::fs::write(dir.join("DevToolsActivePort"), format!("{port}\n")).unwrap();
        let mut watch = AlwaysAlive;
        let outcome = wait_for_ready(
            &ReadinessStrategy::DevToolsPort,
            &dir,
            &mut watch,
            ProbeBudget::new(3_000).unwrap(),
        )
        .unwrap();
        assert_eq!(outcome.port, Some(port));
    }

    #[test]
    fn a_process_that_exits_before_ready_fails_immediately() {
        let dir = temp_dir("exited");
        let mut watch = AlreadyExited;
        let outcome = wait_for_ready(
            &ReadinessStrategy::TcpConnect {
                host: "127.0.0.1".into(),
                port: 1,
            },
            &dir,
            &mut watch,
            ProbeBudget::new(3_000).unwrap(),
        );
        assert_eq!(outcome.unwrap_err(), LaunchError::ExitedBeforeReady);
    }
}
