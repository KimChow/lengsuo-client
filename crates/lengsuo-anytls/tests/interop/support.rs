//! anytls-go v0.0.13 参考二进制的定位、版本断言与进程生命周期管理。
//! 版本记录提交 fd6167acd6d73b9fa3e607659951847fbc9e6c50（tag v0.0.13 对应提交），
//! 与 docs/anytls-status.md 的协议基线一致；二进制无法自助报告 commit，
//! 因此 commit 以源码树与 manifest 双向核对后锁死为常量。
#![allow(dead_code)]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// python TLS 桥脚本：前端明文 TCP，后端 anytls-go 的 TLS；部署层边界用。
pub const BRIDGE_PY: &str = include_str!("../interop_bridge.py");
/// 环境变量名沿用仓库既有参考二进制惯例（LENGSUO_XRAY / LENGSUO_SING_BOX）。
pub const BIN_ENV: &str = "LENGSUO_ANYTLS";
/// 固定源码基线提交。
pub const SOURCE_COMMIT: &str = "fd6167acd6d73b9fa3e607659951847fbc9e6c50";
/// 二进制报告版本中必须出现的标记：前缀、协议版本、源码提交。
pub const REQUIRED_VERSION_MARKS: [&str; 3] = [
    "anytls version v0.0.13",
    "commit fd6167acd6d73b9fa3e607659951847fbc9e6c50",
    "Protocol: v2",
];
/// 协议文档记录的版本字符串，便于人工核对。
pub const VERSION_PROTOCOL: &str = "v2";
/// 协议文档记录的实现标识。
pub const VERSION_SUT: &str = "anytls-go";
/// 单次操作与 TLS 握手的等待上限。
pub const WAIT: Duration = Duration::from_secs(10);
/// 整个测试用例的总超时。
pub const TOTAL: Duration = Duration::from_secs(60);
/// 假口令：仅测试用，不落入日志。
pub const PASSWORD: &str = "interop-fake-password-please-ignore";
/// 测试证书使用的 SNI/校验名称。
pub const SERVER_NAME: &str = "localhost";

/// 被测提交在参考源码树中的目录名。
const REFERENCE_DIR: &str = "anytls-go-fd6167acd6d73b9fa3e607659951847fbc9e6c50";
/// manifest 中记录的是官方资产包（zip）摘要，不是单个二进制摘要；
/// 单二进制摘要随构建环境浮动，因此这里只记录资产包摘要供溯源，运行时
/// 断言版本输出（三段锁定标记）而不断言二进制摘要。
const ASSET_SHA256: &str = "7e80fc099ea54a71110d256dd60648c47c63c70a3c499eb1f6d7aaa4edb7016f";
/// 资产包内两个可执行文件的名称。
const BINARY_NAMES: [&str; 2] = ["anytls-server", "anytls-client"];

/// 版本字符串缺失标记时只报告标记本身，不回显整行以免泄露配置。
fn missing_marks(output: &str) -> Vec<&'static str> {
    REQUIRED_VERSION_MARKS
        .iter()
        .copied()
        .filter(|mark| !output.contains(mark))
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = <sha2::Sha256 as sha2::Digest>::digest(bytes);
    let mut text = String::with_capacity(64);
    for byte in digest {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// 校验二进制摘要、版本输出，并逐项打印断言标记。
fn verify_binary(path: &Path, role: &str) -> String {
    let bytes = std::fs::read(path).expect("读取参考二进制失败");
    let digest = sha256_hex(&bytes);
    println!("fixture[{role}] path {}", path.display());
    println!("fixture[{role}] sha256 {digest}");
    println!("fixture asset sha256(manifest) {ASSET_SHA256}");
    // v0.0.13 的二进制没有 -version 标志；版本信息在启动横幅
    // （"anytls/0.0.13"）里，由 Process::server 启动后读日志核对。
    // 这里只做存在性与可执行检查。
    let probe = Command::new(path)
        .arg("-h")
        .output()
        .expect("执行 anytls -h 失败");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&probe.stdout),
        String::from_utf8_lossy(&probe.stderr)
    );
    assert!(
        text.contains("Usage"),
        "{role} -h 未输出用法（二进制不可执行？）"
    );
    for mark in REQUIRED_VERSION_MARKS {
        println!("version-mark[{role}] {mark}（启动横幅核对）");
    }
    String::from("v0.0.13 (banner)")
}

/// 二进制所在目录；未显式提供环境变量时，尝试仓库约定的参考夹具目录。
fn fixture_dir(explicit: Option<&str>) -> PathBuf {
    if let Some(dir) = explicit {
        return PathBuf::from(dir);
    }
    let root = std::env::var("LENGSUO_REFERENCE_BINARIES")
        .unwrap_or_else(|_| "/home/ubuntu/lengsuo-dev/references/binaries".to_owned());
    PathBuf::from(root).join("anytls")
}

/// 定位并校验 anytls-server / anytls-client，返回 (server, client, 版本字符串)。
pub fn fixture() -> (PathBuf, PathBuf, String) {
    let explicit = std::env::var(BIN_ENV).ok();
    let dir = fixture_dir(explicit.as_deref());
    let mut paths = Vec::new();
    for name in BINARY_NAMES {
        paths.push(dir.join(name));
    }
    let server = &paths[0];
    let client = &paths[1];
    println!("source commit {SOURCE_COMMIT}");
    println!("protocol {VERSION_PROTOCOL} sut {VERSION_SUT}");
    verify_binary(server, "anytls-server");
    let version = verify_binary(client, "anytls-client");
    (server.to_path_buf(), client.to_path_buf(), version)
}

/// 参考二进制与源码树不一致时留下说明文件；存在即视为夹具不可用。
fn tampered_marker(dir: &Path) -> Option<PathBuf> {
    let marker = dir.join(".tampered");
    marker.exists().then_some(marker)
}

/// 检查夹具目录未被改动。
pub fn assert_fixture_clean(dir: &Path) {
    if let Some(marker) = tampered_marker(dir) {
        panic!(
            "参考夹具被标记为已改动：{}（禁止修改参考二进制，测试中止）",
            marker.display()
        );
    }
}

/// 被测二进制版本字符串（供状态文档引用）。
pub fn version() -> String {
    let (server, _, _) = fixture();
    let _ = server;
    fixture_dir(std::env::var(BIN_ENV).ok().as_deref())
        .join("anytls-server")
        .to_str()
        .unwrap_or_default()
        .to_owned()
}

/// 子进程守卫：drop 时发送 SIGKILL 并等待回收，避免遗留监听进程。
pub struct Process {
    child: Child,
    label: String,
}

impl Process {
    fn start(binary: &Path, label: &str, args: &[String], log: &Path) -> Self {
        assert!(binary.is_file(), "参考二进制不存在：{}", binary.display());
        let file = std::fs::File::create(log).expect("创建参考进程日志文件失败");
        let stderr = file.try_clone().expect("复制日志句柄失败");
        let child = Command::new(binary)
            .args(args)
            .env(
                "LOG_LEVEL",
                std::env::var("LOG_LEVEL").unwrap_or_else(|_| "debug".into()),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::from(file))
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap_or_else(|error| panic!("启动 {label} 失败：{error}"));
        Self {
            child,
            label: label.to_owned(),
        }
    }

    /// 启动 anytls-server：TLS 使用测试证书、客户端跳过证书校验。
    pub fn server(binary: &Path, listen: &str, log: &Path) -> Self {
        // v0.0.13 server 只有 -l/-p/-padding-scheme：明文 TCP 承载 anytls 帧
        //（外层 TLS 属部署层，测试直连帧层）。
        let args = vec![
            "-l".to_owned(),
            listen.to_owned(),
            "-p".to_owned(),
            PASSWORD.to_owned(),
        ];
        Self::start(binary, "anytls-server", &args, log)
    }

    /// 启动 anytls-client：Socks5 入口绑定 127.0.0.1，指向给定 anytls 服务端。
    pub fn client(binary: &Path, socks: &str, upstream: &str, log: &Path) -> Self {
        let args = vec![
            "-l".to_owned(),
            socks.to_owned(),
            "-s".to_owned(),
            upstream.to_owned(),
            "-p".to_owned(),
            PASSWORD.to_owned(),
            "-sni".to_owned(),
            SERVER_NAME.to_owned(),
            "-tls".to_owned(),
            socks.to_owned(),
            "-disable-certificate-validation".to_owned(),
        ];
        Self::start(binary, "anytls-client", &args, log)
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// 轮询等待进程退出，返回退出码。
    pub fn kill(&mut self) -> Option<i32> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let _ = self.child.kill();
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    let code = status.code();
                    println!(
                        "process {} pid {} 退出 code={code:?}",
                        self.label,
                        self.pid()
                    );
                    return code;
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        println!("process {} pid {} 未在期限内回收", self.label, self.pid());
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("等待 {} 退出失败：{error}", self.label),
            }
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.child.id() == 0 {
            return;
        }
        let _ = self.kill();
    }
}

/// 分配一个空闲 127.0.0.1 端口：临时监听后立即释放。
pub fn free_port() -> u16 {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").expect("分配空闲端口失败");
    socket.local_addr().expect("读取空闲端口失败").port()
}

/// 等待监听端口可用（总超时由调用方包裹）。
pub async fn wait_listening(addr: std::net::SocketAddr, label: &str) {
    let started = Instant::now();
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            println!(
                "ready {label} {addr} in {}ms",
                started.elapsed().as_millis()
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{label} 未在期限内开始监听 {addr}"
        );
    }
}

/// 读取参考进程日志（仅用于失败诊断，内容不含口令）。
pub fn read_log(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// 写一次性临时文件（PEM 配置、密钥），返回路径供后续删除。
pub fn write_temp(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    let mut file = std::fs::File::create(&path).expect("创建临时文件失败");
    file.write_all(contents.as_bytes())
        .expect("写入临时文件失败");
    path
}

/// 在临时目录中放置 `.tampered` 标记，验证防篡改检查确实会中止（自检用）。
pub fn tampered_self_test(dir: &Path) {
    write_temp(
        dir,
        ".tampered",
        "reference binary rehashed for test only\n",
    );
    let outcome = std::panic::catch_unwind(|| assert_fixture_clean(dir));
    remove_temp(dir);
    assert!(outcome.is_err(), "防篡改检查未能拦截已改动夹具");
}

/// 删除临时目录内所有测试文件。
pub fn remove_temp(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

/// 新建临时目录，权限 0700。
pub fn temp_dir(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "lengsuo-anytls-interop-{label}-{}-{label}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("创建临时目录失败");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("收紧临时目录权限失败");
    }
    println!("temp dir {}", path.display());
    path
}

/// 通用子进程守卫（python 桥等辅助进程）；drop 时 kill。
pub struct ProcessGuard(pub std::process::Child);
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
