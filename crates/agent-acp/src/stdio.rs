//! 真实 stdio 传输：spawn 子进程，stdout → reader 线程（[`LineDecoder`] +
//! [`crate::codec::decode_frame`] 归类），stdin ← writer 线程。同步线程模型。
//!
//! 安全基线：spawn 前对子进程环境做 **scrub**——`env_clear` 后只装回过滤过的
//! 变量：保留最小系统变量白名单，剔除凭据族（名字含 `KEY`/`TOKEN`/`SECRET`/
//! `PASSWORD` 等，或云厂商前缀），支持显式 denylist 追加与「白名单整体替换」
//! 两档收口。非 UTF-8 变量名/值一律剥离（不确定即敏感，fail-closed）。
//!
//! stderr 策略：**透传不解析**（`Stdio::inherit()`），agent 诊断直落父进程
//! stderr，不与 stdout 帧流混淆。
//!
//! 拆除（[`Teardown`] 钩子，Client 关闭或 Transport 未被接管即丢弃时执行一次）：
//! 释放 stdin 通道（writer flush + 关 stdin，agent 读到 EOF 自然退出）→
//! 有界等待 writer/reader 线程 → 子进程仍活则 `kill` + reap。任何一步都有界，
//! 最坏路径是 kill 倒逼管道 EOF，卡不住调用方。

use std::io::{Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::codec::{decode_frame, LineDecoder, DEFAULT_MAX_LINE_BYTES};
use crate::error::Error;
use crate::transport::{event_channel, FrameSink, SourceEvent, Teardown, Transport};

/// 默认拆除有界等待：2 秒。
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// 读块大小：8 KiB（行帧在 [`LineDecoder`] 里重组，块大小不影响语义）。
const READ_CHUNK_BYTES: usize = 8 * 1024;

/// 凭据族变量名模式（大写包含匹配）。
const CREDENTIAL_PATTERNS: &[&str] = &[
    "KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "COOKIE",
    "AUTH",
];

/// 凭据族前缀（云厂商/凭证链）。
const CREDENTIAL_PREFIXES: &[&str] = &["AWS_", "AZURE_", "GCP_", "GOOGLE_", "ALIBABA_CLOUD_"];

/// 最小系统变量白名单（allowlist 模式下唯一保留集）。
pub const SYSTEM_ENV_KEEP: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    "TMP",
    "TEMP",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "NODE_EXTRA_CA_CERTS",
];

/// 变量名是否属于凭据族（不确定即视为敏感）。
#[must_use]
pub fn is_credential_env(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    CREDENTIAL_PREFIXES.iter().any(|p| upper.starts_with(p))
        || CREDENTIAL_PATTERNS.iter().any(|p| upper.contains(p))
}

/// scrub 规则：该变量是否可传给子进程。
#[must_use]
pub fn env_pair_allowed(key: &str, allowlist_only: bool, extra_denied: &[String]) -> bool {
    if extra_denied.iter().any(|d| d == key) || is_credential_env(key) {
        return false;
    }
    !allowlist_only || SYSTEM_ENV_KEEP.contains(&key)
}

/// spawn 配置。
#[derive(Debug, Clone)]
pub struct SpawnConfig {
    /// 可执行文件路径。
    pub program: String,
    /// 参数表。
    pub args: Vec<String>,
    /// 追加剥离的环境变量名（精确匹配）。
    pub denied_env: Vec<String>,
    /// true：子进程环境整体替换为白名单（最严格）；false：按凭据族模式剥离。
    pub allowlist_only_env: bool,
    /// 单行帧上限。
    pub max_line_bytes: usize,
    /// 拆除时有界等待上限。
    pub shutdown_timeout: Duration,
}

impl SpawnConfig {
    /// 以程序名新建配置（其余取安全默认）。
    #[must_use]
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            denied_env: Vec::new(),
            allowlist_only_env: false,
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
        }
    }

    /// 追加一个参数。
    #[must_use]
    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }
}

/// 写侧：帧字节经通道交给 writer 线程落子进程 stdin。
///
/// 写入集中在一根线程：管道写满只挂起 writer，不阻塞路由线程与调用方。
struct StdinSink {
    tx: Option<Sender<Vec<u8>>>,
}

impl FrameSink for StdinSink {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), Error> {
        let Some(tx) = &self.tx else {
            return Err(Error::Transport {
                reason: "子进程 stdin 已关闭".into(),
            });
        };
        tx.send(frame.to_vec()).map_err(|_| Error::Transport {
            reason: "子进程 stdin writer 线程已退出".into(),
        })
    }

    /// 释放发送端 → writer 收到断连 → flush + 关 stdin。幂等。
    fn close(&mut self) {
        self.tx = None;
    }
}

/// 回收子进程：kill + wait，绝不留孤儿/僵尸。
fn reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// 起 writer 线程；线程资源耗尽时返回 Err（由 [`spawn_stdio`] 负责收尸）。
fn spawn_writer(stdin: ChildStdin, rx: Receiver<Vec<u8>>) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("acp-stdio-writer".into())
        .spawn(move || {
            let mut stdin = stdin;
            while let Ok(frame) = rx.recv() {
                if stdin
                    .write_all(&frame)
                    .and_then(|()| stdin.flush())
                    .is_err()
                {
                    break; // 对端退出：后续 send_frame 会看到线程结束而报错。
                }
            }
            let _ = stdin.flush();
            drop(stdin); // 关 stdin：agent 读到 EOF，自然收尾。
        })
}

/// 起 reader 线程；线程资源耗尽时返回 Err（由 [`spawn_stdio`] 负责收尸）。
fn spawn_reader(
    mut stdout: std::io::BufReader<std::process::ChildStdout>,
    tx: Sender<SourceEvent>,
    max_line_bytes: usize,
) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("acp-stdio-reader".into())
        .spawn(move || {
            let mut dec = LineDecoder::new(max_line_bytes);
            let mut chunk = vec![0_u8; READ_CHUNK_BYTES];
            loop {
                match stdout.read(&mut chunk) {
                    Ok(0) => {
                        // EOF：残留未完结字节是截断帧，fail-closed 下毒。
                        let reason = dec.finish().err().map(|e| e.to_string());
                        let _ = tx.send(SourceEvent::Closed { reason });
                        return;
                    }
                    Ok(n) => match dec.feed(&chunk[..n]) {
                        Ok(frames) => {
                            for body in frames {
                                let ev = match decode_frame(&body) {
                                    Ok(top) => SourceEvent::Frame(top),
                                    Err(e) => SourceEvent::BadFrame {
                                        reason: e.to_string(),
                                    },
                                };
                                if tx.send(ev).is_err() {
                                    return; // 路由已停。
                                }
                            }
                        }
                        Err(e) => {
                            // 超长行/已损坏：字节流无法重新对齐，终止连接。
                            let _ = tx.send(SourceEvent::Closed {
                                reason: Some(e.to_string()),
                            });
                            return;
                        }
                    },
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        let _ = tx.send(SourceEvent::Closed {
                            reason: Some(format!("读取子进程 stdout 失败：{e}")),
                        });
                        return;
                    }
                }
            }
        })
}

/// 有界等待线程退出；超时返回 false（放弃等待句柄，kill 已倒逼其解阻塞）。
fn join_bounded(handle: JoinHandle<()>, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let _ = handle.join();
    true
}

/// 拆除子进程：关 stdin → 有界等线程 → kill + reap。钩子内按 move 语义执行一次。
fn teardown(
    stdin_tx_clone: Sender<Vec<u8>>,
    mut child: Child,
    writer: JoinHandle<()>,
    reader: JoinHandle<()>,
    timeout: Duration,
) {
    drop(stdin_tx_clone); // sink 的 tx 此前已释放：writer 收到断连 → flush+关 stdin。
    if !join_bounded(reader, timeout) || !join_bounded(writer, timeout) {
        // 线程卡住：kill 倒逼 stdout EOF / stdin 写失败，不等线程。
        reap(&mut child);
        return;
    }
    // 线程已退：agent 不理 stdin EOF 也 kill，绝不留孤儿/僵尸。
    if !matches!(child.try_wait(), Ok(Some(_))) {
        reap(&mut child);
    }
}

/// scrub 当前进程环境并 spawn 子进程，返回接好管道的 [`Transport`]
/// （带一次性拆除钩子；[`crate::client::Client`] 接管，或自身丢弃时触发）。
///
/// # Errors
/// [`Error::Io`]：spawn 失败、子进程未提供 stdin/stdout 管道，或 reader/writer
/// 线程起不来（失败前一律先 kill+reap 子进程，不留孤儿）。
pub fn spawn_stdio(cfg: &SpawnConfig) -> crate::Result<Transport> {
    let mut command = Command::new(&cfg.program);
    command
        .args(&cfg.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()); // 透传不解析。
    command.env_clear();
    for (k, v) in std::env::vars_os() {
        let (Some(k), Some(v)) = (k.into_string().ok(), v.into_string().ok()) else {
            continue; // 非 UTF-8：不确定即剥离。
        };
        if env_pair_allowed(&k, cfg.allowlist_only_env, &cfg.denied_env) {
            command.env(&k, &v);
        }
    }
    let shutdown_timeout = cfg.shutdown_timeout;
    let max_line_bytes = cfg.max_line_bytes;
    let mut child = command.spawn().map_err(|e| Error::Io {
        reason: format!(
            "启动 ACP agent 子进程失败（program={:?}）：{e}",
            cfg.program
        ),
    })?;
    let stdin = match (child.stdin.take(), child.stdout.take()) {
        (Some(si), Some(so)) => (si, so),
        _ => {
            // 管道缺失：先收尸再报错，不留孤儿。
            reap(&mut child);
            return Err(Error::Io {
                reason: "子进程未提供 stdin/stdout 管道".into(),
            });
        }
    };

    // 线程起不来也先收尸：模块契约是「任何路径都不留孤儿进程」。
    let (frame_tx, frame_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let writer = match spawn_writer(stdin.0, frame_rx) {
        Ok(h) => h,
        Err(e) => {
            reap(&mut child);
            return Err(Error::Io {
                reason: format!("启动 stdio writer 线程失败：{e}"),
            });
        }
    };
    let (source, ev_tx) = event_channel();
    let reader = match spawn_reader(std::io::BufReader::new(stdin.1), ev_tx, max_line_bytes) {
        Ok(h) => h,
        Err(e) => {
            // 先收尸倒逼 writer 从管道写/通道收里解阻塞，再回收该线程。
            reap(&mut child);
            drop(frame_tx);
            let _ = writer.join();
            return Err(Error::Io {
                reason: format!("启动 stdio reader 线程失败：{e}"),
            });
        }
    };

    let sink = Box::new(StdinSink {
        tx: Some(frame_tx.clone()),
    });
    let teardown = Teardown::new(move || {
        teardown(frame_tx, child, writer, reader, shutdown_timeout);
    });
    Ok(Transport::with_teardown(sink, source, teardown))
}
