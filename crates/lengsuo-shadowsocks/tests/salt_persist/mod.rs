//! 入站 salt 记忆池持久化的**共享测试辅助**（仅回环、假口令、临时目录）。
//!
//! 被 `tests/salt_persist_runtime.rs` 通过 `#[path]` 引入；同一编译单元里的
//! `salt_persist_worker` 用例扮演跨进程语义的独立实例（进程 A / 进程 B）。
//!
//! 状态文件一律落在系统临时目录并在使用后删除；口令一律是假凭据。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use lengsuo_shadowsocks::{
    CipherSuite, RelayConfig, RelayConfigParts, SaltStateConfig, TargetAddr,
};
use ss_core::chunk::write_chunk;
use ss_core::crypto::SessionAead;
use ss_core::kdf::{evp_bytes_to_key, hkdf_sha1_subkey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub mod worker;

/// 测试假口令，与任何生产凭据无关。
pub const PASSWORD: &str = "ss-salt-persist-fake-passw0rd";
/// 上一代假口令（密钥轮换用例用），同样与任何生产凭据无关。
pub const PREVIOUS_PASSWORD: &str = "ss-salt-persist-fake-previous";
/// 本用例集统一使用的套件（salt 长度 32 字节）。
pub const SUITE: CipherSuite = CipherSuite::Aes256Gcm;
/// 单次 I/O 等待上限。
pub const WAIT: Duration = Duration::from_secs(5);
/// 子进程总超时（超时就杀掉子进程，保证测试不挂死）。
pub const WORKER_TIMEOUT: Duration = Duration::from_secs(60);
/// worker 用的固定 salt（32 字节，匹配 `SUITE`）。
pub const FIXED_SALT: [u8; 32] = [0x5Au8; 32];

/// 临时目录守卫：状态文件只落系统临时目录，用例结束删除。
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "lengsuo-ss-salt-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("创建临时目录失败");
        TempDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn hex_decode(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "hex 必须是偶数长度");
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("非法 hex"))
        .collect()
}

/// 用**固定 salt** 构造一段合法的 TCP 线上字节（salt + 一个 chunk）。
///
/// 本端公开的 `TcpWriter` 强随机生成 salt，无法指定，因此这里用 ss-core 原语拼帧，
/// 只改变 salt 选择，不改任何线上格式。首段明文 = 目标地址 + 载荷（中继的握手要求）。
pub async fn fixed_salt_stream(salt: &[u8], target: &TargetAddr, payload: &[u8]) -> Vec<u8> {
    assert_eq!(salt.len(), SUITE.salt_len(), "salt 长度必须与套件一致");
    let master = evp_bytes_to_key(PASSWORD.as_bytes(), SUITE.key_len());
    let subkey = hkdf_sha1_subkey(&master, salt, SUITE.key_len());
    let mut aead = SessionAead::new(SUITE, subkey);
    let mut plain = Vec::new();
    target.encode_checked(&mut plain).expect("回环目标可编码");
    plain.extend_from_slice(payload);
    let mut wire = Vec::new();
    wire.extend_from_slice(salt);
    write_chunk(&mut wire, &mut aead, &plain).await.unwrap();
    wire
}

/// 回环 echo：接受一条连接并把收到的字节原样回写。
pub async fn spawn_echo() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo 地址");
    tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.expect("echo accept");
        let mut buffer = vec![0u8; 8192];
        loop {
            let got = match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(got) => got,
            };
            if stream.write_all(&buffer[..got]).await.is_err() {
                break;
            }
        }
        let _ = stream.shutdown().await;
    });
    addr
}

/// 单线程 runtime + LocalSet：中继用 `spawn_local`，必须在 LocalSet 里驱动。
pub fn local_set() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

/// worker 用例的**完整测试名**（子模块里的用例名带模块前缀）。
/// `--exact` 必须用全名，否则子进程会「零用例通过」（退出码 0 但什么都没做）。
const WORKER_TEST_NAME: &str = "salt_persist::worker::salt_persist_worker";

/// 跑一个 worker 子进程并收集输出。**超时即杀掉子进程**（绝不挂死）。
///
/// 断言子进程**确实跑了 1 个用例**：`--exact` 名字写错时 libtest 会「零用例通过」
/// 并返回退出码 0 —— 那种 exit 0 绝不算成功。
pub fn run_worker(mode: &str, envs: &[(&str, String)]) -> std::process::Output {
    let exe = std::env::current_exe().expect("取当前测试二进制失败");
    let mut command = Command::new(exe);
    command
        .args(["--exact", WORKER_TEST_NAME, "--nocapture"])
        .env("LENGSUO_SALT_WORKER", mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }
    let mut child = command.spawn().expect("spawn worker 子进程失败");
    let stdout = child.stdout.take().expect("取 stdout");
    let stderr = child.stderr.take().expect("取 stderr");
    // 输出单独由线程收，避免管道写满把子进程卡死。
    let stdout_reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let mut reader = std::io::BufReader::new(stdout);
        let _ = std::io::Read::read_to_end(&mut reader, &mut buffer);
        buffer
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let mut reader = std::io::BufReader::new(stderr);
        let _ = std::io::Read::read_to_end(&mut reader, &mut buffer);
        buffer
    });
    let deadline = Instant::now() + WORKER_TIMEOUT;
    let status = loop {
        match child.try_wait().expect("等待 worker 子进程失败") {
            Some(status) => break status,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("worker 子进程超时（{WORKER_TIMEOUT:?}）");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };
    let out = stdout_reader.join().expect("收 stdout 线程");
    let err = stderr_reader.join().expect("收 stderr 线程");
    let summary = String::from_utf8_lossy(&out);
    // worker 用 `std::process::exit(0)` 收尾 ⇒ libtest 不会打印汇总行；
    // 但「running 1 test」足以证明过滤器**恰好命中一个**用例。名字写错时 libtest
    // 会打印「running 0 tests」并以退出码 0 结束 —— 那种 exit 0 绝不算成功。
    assert!(
        summary.contains("running 1 test") && !summary.contains("running 0 tests"),
        "worker 子进程必须真的跑 1 个用例（--exact 名字写错会零用例通过）：\n{summary}"
    );
    std::process::Output {
        status,
        stdout: out,
        stderr: err,
    }
}

/// 子进程共用的环境变量（路径、salt、口令、窗口）。
pub fn worker_env(
    path: &Path,
    window_ms: u64,
    previous: Option<&str>,
) -> Vec<(&'static str, String)> {
    let mut envs = vec![
        ("LENGSUO_SALT_PATH", path.to_string_lossy().into_owned()),
        ("LENGSUO_SALT_SALT", hex_encode(&FIXED_SALT)),
        ("LENGSUO_SALT_PASSWORD", PASSWORD.to_string()),
        ("LENGSUO_SALT_WINDOW_MS", window_ms.to_string()),
    ];
    if let Some(previous) = previous {
        envs.push(("LENGSUO_SALT_PREVIOUS_PASSWORD", previous.to_string()));
    }
    envs
}

/// 中继配置：挂上 salt 状态文件（路径 + 窗口）。
pub fn relay_config(path: &Path, window_ms: u64) -> RelayConfig {
    RelayConfig::new(
        RelayConfigParts {
            suite: SUITE,
            idle_timeout: Duration::from_secs(5),
            replay: Some((64, Duration::from_millis(window_ms))),
        },
        PASSWORD.as_bytes(),
    )
    .with_salt_state(SaltStateConfig::new(path.to_path_buf()))
}

/// 与中继做一次「写固定 salt 帧 → 半关闭写端 → 读回程到 EOF」的往返。
///
/// `Ok(bytes)` 表示交付点拿到了回程字节；`Err(reason)` 表示连接被关（拒绝）。
pub async fn exchange(relay: std::net::SocketAddr, wire: &[u8]) -> Result<Vec<u8>, String> {
    let mut stream = tokio::time::timeout(WAIT, TcpStream::connect(relay))
        .await
        .map_err(|_| "连接中继超时".to_string())?
        .map_err(|err| format!("连接中继失败：{err}"))?;
    tokio::time::timeout(WAIT, stream.write_all(wire))
        .await
        .map_err(|_| "写中继超时".to_string())?
        .map_err(|err| format!("写中继失败：{err}"))?;
    // 写半关闭（SHUT_WR）：请求方向干净结束 ⇒ 中继对上游半关闭 ⇒ 回程以 EOF 收尾。
    tokio::time::timeout(WAIT, stream.shutdown())
        .await
        .map_err(|_| "写半关闭超时".to_string())?
        .map_err(|err| format!("写半关闭失败：{err}"))?;
    let mut got = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        match tokio::time::timeout(WAIT, stream.read(&mut buffer)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(count)) => got.extend_from_slice(&buffer[..count]),
            Ok(Err(err)) => return Err(format!("读中继失败：{err}")),
            Err(_) => return Err("读中继超时".to_string()),
        }
    }
    if got.is_empty() {
        Err("连接被关闭且零字节交付".to_string())
    } else {
        Ok(got)
    }
}

/// worker 子进程的输入（从环境变量读）。
pub struct WorkerCtx {
    pub path: PathBuf,
    pub salt: Vec<u8>,
    pub password: String,
    pub previous: Option<String>,
    pub window_ms: u64,
}

/// 从环境变量解析 worker 输入。
pub fn ctx_from_env() -> WorkerCtx {
    WorkerCtx {
        path: PathBuf::from(std::env::var("LENGSUO_SALT_PATH").expect("缺少状态文件路径")),
        salt: hex_decode(&std::env::var("LENGSUO_SALT_SALT").expect("缺少 salt")),
        password: std::env::var("LENGSUO_SALT_PASSWORD").expect("缺少口令"),
        previous: std::env::var("LENGSUO_SALT_PREVIOUS_PASSWORD").ok(),
        window_ms: std::env::var("LENGSUO_SALT_WINDOW_MS")
            .expect("缺少窗口")
            .parse()
            .expect("窗口不是整数"),
    }
}
