//! 参考互通用例的**公共夹具**：拉起参考入站、取当前时间、假载荷。
//!
//! 语义基线：Xray commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。
//!
//! 本模块只做「怎么把参考拉起来」，**不含任何断言**——断言在
//! [`super::reference_interop`] 的各条用例里。
//!
//! 凭据说明：UUID 是**随机生成的测试假凭据**，全程**不打印**（避免日志泄漏）。

use std::path::PathBuf;
use std::time::Duration;

use lengsuo_vmess::aead;
use lengsuo_vmess::request::{Command, HeaderPlanner, KeySource, RequestHeader, SecurityOption};
use ss_core::target::TargetAddr;

/// 连接超时。
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// 回程超时。
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// 假载荷（不含任何真实凭据）。
pub const PAYLOAD: &[u8] = b"vmess-security-matrix-extra-probe";

/// ⛔ **打给参考的请求不得用固定的历史时间戳**。
///
/// 参考 `proxy/vmess/aead/authid.go:110`：
/// `math.Abs(math.Abs(float64(t))-float64(time.Now().Unix())) > 120` ⇒
/// 超过 120 秒的时间戳被判 `ErrInvalidTime`，**在用户校验阶段就拒**，
/// **根本到不了安全档判定** ⇒ 那样写出来的用例是**假绿**（测到的是
/// 「用户校验失败」而不是「档位被拒」）。
///
/// 所以打给参考的 AuthID 一律用**当前时间**。
///
/// 本仓自己的单元测试用固定 `NOW`（`common.rs`）是安全的，因为那走本仓的
/// `decode_request_header` 并**显式传入**时间。
#[must_use]
pub fn current_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("系统时间在 UNIX 纪元之后")
        .as_secs() as i64
}

/// 惰性获取参考二进制；未设置时打印原因并返回 `None`（调用方 `return` 跳过）。
///
/// ⛔ 「未设置就跳过」**不算**通过——任务书要求 `#[ignore]` 用例必须带
/// `--ignored` 实跑并贴退出码；这里只保证「没装参考二进制时不误报失败」。
pub fn xray_bin() -> Option<PathBuf> {
    match std::env::var_os("LENGSUO_XRAY") {
        Some(path) => Some(PathBuf::from(path)),
        None => {
            eprintln!(
                "SKIP: 环境变量 LENGSUO_XRAY 未设置，跳过参考互通用例。\
                 原因：没有参考二进制可拉起，无法证明与参考的档位语义一致。"
            );
            None
        }
    }
}

/// 拉起一个参考 VMess 入站（127.0.0.1，临时端口，UUID 为随机假凭据）。
///
/// 用参考二进制自己的 `run -c` 起进程；配置里只放一个 inbound（vmess）
/// 与一个 outbound（freedom）。UID 由调用方生成，**不打印**。
pub fn start_xray_inbound(bin: &PathBuf, uuid: &str) -> Result<(u16, std::process::Child), String> {
    // 端口探测：bind 0 后立即释放（与本仓既有夹具同一手法，不新增依赖）。
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| format!("探测空闲端口失败: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("取端口失败: {e}"))?
        .port();
    drop(listener);

    let dir = std::env::temp_dir().join(format!(
        "lengsuo-vmess-extra-{}-{}",
        std::process::id(),
        port
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建临时目录失败: {e}"))?;
    let cfg_path = dir.join("config.json");
    let config = format!(
        concat!(
            "{{\"log\":{{\"loglevel\":\"warning\"}},",
            "\"inbounds\":[{{\"tag\":\"vmess-in\",\"listen\":\"127.0.0.1\",\"port\":{port},",
            "\"protocol\":\"vmess\",\"settings\":{{\"clients\":[{{\"id\":\"{uuid}\",\"alterId\":0}}]}},",
            "\"streamSettings\":{{\"network\":\"tcp\"}}}}],",
            "\"outbounds\":[{{\"tag\":\"direct\",\"protocol\":\"freedom\",\"settings\":{{}}}}]}}"
        ),
        port = port,
        uuid = uuid,
    );
    std::fs::write(&cfg_path, &config).map_err(|e| format!("写配置失败: {e}"))?;
    let child = std::process::Command::new(bin)
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn 参考进程失败: {e}"))?;

    // 等端口就绪（有上限）。
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            return Ok((port, child));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut child = child;
    let _ = child.kill();
    let _ = child.wait();
    Err(format!("参考入站端口 {port} 在超时内未就绪"))
}

/// 构造一条请求头明文（目标 = 本地回显后端）。
///
/// `security` 是**头里声明**的档位；`option` 是线上 option 字节。
#[must_use]
pub fn plan_request_header(
    keys: &KeySource,
    target: TargetAddr,
    security: SecurityOption,
    option: u8,
) -> Vec<u8> {
    HeaderPlanner::new(KeySource {
        body_key: keys.body_key,
        body_iv: keys.body_iv,
        response_header: keys.response_header,
    })
    .plan_with(
        &RequestHeader {
            target: Some(target),
            command: Command::Tcp,
            security,
            option,
            padding_len: 0,
        },
        &[],
    )
    .expect("请求头明文可编码")
}

/// 把请求头明文的 security 低 4 位改成 `nibble`，并**重算 FNV 尾部**。
///
/// FNV 覆盖整个明文（**含** security 字节）⇒ 改完不重算的话，参考会先在
/// 校验和上拒绝，**测不到** security 判定。
///
/// 明文布局：第 35 字节 = `paddingLen << 4 | Security`（参考
/// `proxy/vmess/encoding/server.go:202-203`；本仓
/// `src/request.rs:236,253` 构造、`src/server/decode.rs:217` 读）。
#[must_use]
pub fn rewrite_security_nibble(plain: &[u8], nibble: u8) -> Vec<u8> {
    let mut plain = plain.to_vec();
    plain[35] = (plain[35] & 0xF0) | (nibble & 0x0F);
    let body_len = plain.len() - 4;
    let tail = lengsuo_vmess::request::fnv1a32(&plain[..body_len]).to_be_bytes();
    plain[body_len..].copy_from_slice(&tail);
    plain
}

/// 用当前时间的 AuthID 封装请求头（手工封头路径）。
///
/// ⛔ 不用固定时间戳——见 [`current_unix_seconds`] 的说明（超过 120 秒会被
/// 参考判 `ErrInvalidTime`，用例就成了假绿）。
#[must_use]
///
/// 返回 `(auth_id, sealed_header)`：调用方需要 `auth_id` 做**本仓自校验**
/// （用同一个 auth 解开自己封的头，确认字节没被改坏）——只返回 header
/// 的话调用方拿不到 auth，自校验就做不了。
pub fn seal_header_now(cmd_key: &[u8], plain: &[u8]) -> (lengsuo_vmess::AuthId, Vec<u8>) {
    let auth = lengsuo_vmess::create_auth_id_with(
        cmd_key,
        current_unix_seconds(),
        &[0x01, 0x02, 0x03, 0x04],
    );
    let header = aead::seal_header_with(cmd_key, auth.as_bytes(), &[0x11; 8], plain);
    (auth, header)
}
