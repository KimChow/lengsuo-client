//! 最小 Xray 夹具：为 `tests/xray_tcp.rs` 拉起一个监听 127.0.0.1 的 VMess 入站，
//! 目标 UUID 由调用方给出，日志与配置写入临时目录，Drop 时 kill + wait。
//!
//! 不新增依赖：临时目录用 `std::env::temp_dir()` + 进程号 + 计数，配置用 `format!`
//! 手工生成，端口用 `bind 0` 后释放的方式探测空闲端口。选择这样做的原因见报告
//! 「偏离清单」：本 crate 的依赖集被 `Cargo.lock` 锁定，新增 `tempfile`/`serde_json`
//! 会触发 lock 变更，违反本卡「不改 Cargo.lock」的约束。

pub mod codec;

use std::fs;
use std::io::Read as _;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT_SUFFIX: AtomicU64 = AtomicU64::new(0);

/// 探测一个空闲端口：bind 0 拿到端口后立即释放。
fn reserve_free_port() -> Option<u16> {
    for _ in 0..16 {
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", 0)) {
            if let Ok(addr) = listener.local_addr() {
                return Some(addr.port());
            }
        }
    }
    None
}

/// 把字符串转成 JSON 双引号包裹值（本夹具只出现 UUID/绝对路径，无控制字符）。
fn json_str(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// 生成 VMess 入站配置文件内容（inbound vmess，clients=[{id,alterId:0}]，network tcp）。
#[allow(dead_code)] // 夹具被 xray_tcp / xray_udp 两个编译单元共享，默认路径只在旧单元用。
fn config_json(port: u16, uuid: &str, dir: &Path) -> String {
    config_json_with_idle(port, uuid, dir, None)
}

/// 同上，可选 `policy.levels.0.connIdle`（秒）。VMess 夹具用 `None` 保持
/// xray_tcp.rs 既有行为不变；UDP 截断用例用它把活动链收回窗口压到判据内。
fn config_json_with_idle(port: u16, uuid: &str, dir: &Path, idle_secs: Option<u64>) -> String {
    let access = json_str(&dir.join("access.log").to_string_lossy());
    let error = json_str(&dir.join("error.log").to_string_lossy());
    let uuid = json_str(uuid);
    let policy = match idle_secs {
        Some(secs) => format!(",\"policy\":{{\"levels\":{{\"0\":{{\"connIdle\":{secs}}}}}}}"),
        None => String::new(),
    };
    format!(
        concat!(
            "{{\"log\":{{\"loglevel\":\"warning\",\"access\":{access},\"error\":{error}}},",
            "\"inbounds\":[{{\"tag\":\"vmess-in\",\"listen\":\"127.0.0.1\",\"port\":{port},",
            "\"protocol\":\"vmess\",\"settings\":{{\"clients\":[{{\"id\":{uuid},\"alterId\":0}}]}},",
            "\"streamSettings\":{{\"network\":\"tcp\"}}}}],",
            "\"outbounds\":[{{\"tag\":\"direct\",\"protocol\":\"freedom\",\"settings\":{{}}}}],",
            "\"routing\":{{\"rules\":[{{\"type\":\"field\",\"inboundTag\":[\"vmess-in\"],\"outboundTag\":\"direct\"}}]}}",
            "{policy}}}"
        ),
        access = access,
        error = error,
        port = port,
        uuid = uuid,
        policy = policy,
    )
}

/// 读取文件最后 `lines` 行（不足则全量），失败返回空串。
fn read_log_tail(path: &Path, lines: usize) -> String {
    let Ok(mut file) = fs::File::open(path) else {
        return String::new();
    };
    let mut content = String::new();
    if file.read_to_string(&mut content).is_err() {
        return String::new();
    }
    let all: Vec<&str> = content.lines().collect();
    let start = all.len().saturating_sub(lines);
    all[start..].join("\n")
}

/// `abdb2251-…-22e1` 式打码（打印诊断时避免泄漏完整 UUID）。
pub fn mask_uuid(uuid: &str) -> String {
    if uuid.len() <= 12 {
        return "***".to_string();
    }
    format!("{}…{}", &uuid[..8], &uuid[uuid.len() - 4..])
}

/// 已启动的 Xray VMess 入站夹具。
pub struct XrayFixture {
    port: u16,
    dir: PathBuf,
    cfg_path: PathBuf,
    uuid: String,
    /// 仅用于复现配置诊断（`None` = 参考默认 300s）。
    idle_secs: Option<u64>,
    child: Option<Child>,
}

impl XrayFixture {
    /// 启动 xray：写配置、spawn `xray run -c <cfg>`，轮询端口就绪（有超时）。
    /// 任何一步失败都会 kill 子进程并返回含诊断的 `Err`。
    pub fn start(bin: &Path, uuid: &str) -> Result<Self, String> {
        Self::start_inner(bin, uuid, None)
    }

    /// 同 [`Self::start`]，但显式设置 `policy.levels.0.connIdle`（秒）。
    /// 仅供 UDP 截断用例把 inactivity 回收压进判据窗口；缺省仍为参考默认 300s。
    #[allow(dead_code)] // 仅 xray_udp 用；xray_tcp 编译单元不引用。
    pub fn start_with_idle_timeout(bin: &Path, uuid: &str, idle_secs: u64) -> Result<Self, String> {
        Self::start_inner(bin, uuid, Some(idle_secs))
    }

    fn start_inner(bin: &Path, uuid: &str, idle_secs: Option<u64>) -> Result<Self, String> {
        let port = reserve_free_port().ok_or("无法在 127.0.0.1 探测到空闲端口")?;

        let suffix = NEXT_SUFFIX.fetch_add(1, Ordering::Relaxed);
        let epoch_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "lengsuo-vmess-xray-{}-{}-{suffix}",
            std::process::id(),
            epoch_millis
        ));
        fs::create_dir_all(&dir).map_err(|e| format!("创建临时目录失败: {e}"))?;

        let cfg_path = dir.join("config.json");
        let process_log = dir.join("process.log");
        let generated = config_json_with_idle(port, uuid, &dir, idle_secs);
        fs::write(&cfg_path, &generated).map_err(|e| format!("写配置失败: {e}"))?;

        let log_file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&process_log)
            .map_err(|e| format!("打开进程日志失败: {e}"))?;

        let child = Command::new(bin)
            .arg("run")
            .arg("-c")
            .arg(&cfg_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(
                log_file
                    .try_clone()
                    .map_err(|e| format!("复制句柄失败: {e}"))?,
            ))
            .stderr(Stdio::from(log_file))
            .spawn()
            .map_err(|e| format!("spawn xray 失败（{bin:?}）: {e}"))?;

        let mut fixture = XrayFixture {
            port,
            dir,
            cfg_path,
            uuid: uuid.to_string(),
            idle_secs,
            child: Some(child),
        };

        // 轮询端口就绪；子进程提前退出则带日志失败。
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = fixture.child_exit_status() {
                let report = fixture.report();
                return Err(format!("xray 启动中退出（status={status}）\n{report}"));
            }

            if TcpStream::connect_timeout(
                &SocketAddr::from(([127, 0, 0, 1], port)),
                Duration::from_millis(200),
            )
            .is_ok()
            {
                return Ok(fixture);
            }

            if Instant::now() >= deadline {
                let report = fixture.report();
                return Err(format!("xray 端口 {port} 在超时内未就绪\n{report}"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// 非阻塞探测子进程是否已退出（`try_wait` 需要可变借用，故封装成 &mut 方法）。
    fn child_exit_status(&mut self) -> Option<std::process::ExitStatus> {
        let child = self.child.as_mut()?;
        child.try_wait().unwrap_or_default()
    }

    /// 入站监听地址。
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    /// 失败诊断：打码后的配置 + 各日志尾部。
    pub fn report(&self) -> String {
        let masked_cfg =
            config_json_with_idle(self.port, &mask_uuid(&self.uuid), &self.dir, self.idle_secs);
        let error_tail = read_log_tail(&self.dir.join("error.log"), 40);
        let process_tail = read_log_tail(&self.dir.join("process.log"), 40);
        let access_tail = read_log_tail(&self.dir.join("access.log"), 20);
        let mut out = String::new();
        out.push_str("=== 配置 / 日志目录 ===\n");
        out.push_str(&self.cfg_path.to_string_lossy());
        out.push_str("\n=== 配置（UUID 打码）===\n");
        out.push_str(&masked_cfg);
        out.push_str("\n=== xray process.log 尾部 ===\n");
        out.push_str(&process_tail);
        out.push_str("\n=== xray access.log 尾部 ===\n");
        out.push_str(&access_tail);
        out.push_str("\n=== xray error.log 尾部 ===\n");
        out.push_str(&error_tail);
        out
    }
}

impl Drop for XrayFixture {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // 临时目录保留在 /tmp 下供事后排查（不设自动删除，避免丢日志）。
    }
}
