//! `lengsuo-hysteria` 参考互通测试的**共享支撑代码**。
//!
//! 放在 `tests/support/` 子目录里：cargo 只把 `tests/*.rs` 顶层文件与
//! `tests/*/main.rs` 当作测试目标，子目录里的 `mod.rs` **不会**被当成
//! 独立测试目标（与 `lengsuo-anytls` 的 `tests/interop/support.rs` 同范式）。

/// 把任意字符串安全地嵌进 **JSON 字符串字面量**。
///
/// 起因（本机 Windows 实测复现）：参考 Xray 的配置以 JSON 文本喂给它，
/// 而证书/私钥路径是**平台相关的**。Windows 上路径形如
/// `C:\Users\Kim\AppData\Local\Temp\...\cert.pem`，反斜杠若不转义，
/// JSON 解析会直接报 `invalid character 'U' in string escape code`
/// ⇒ **Xray 根本起不来**；Linux 路径不含反斜杠，所以问题只在 Windows 暴露。
///
/// 规则（RFC 8259）：`\` → `\\`，`"` → `\"`，其余 U+0000..U+001F
/// 控制字符 → `\u00XX`。路径里不会出现非 ASCII 之外的其它需要转义的字符，
/// 但控制字符仍按规范处理，避免以后有人把换行等塞进路径。
#[allow(dead_code)] // 由部分测试目标引用；support 按目标分别编译
pub fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// 就绪探测的**单次尝试**预算。
///
/// 单次尝试必须**自带上限**，否则「服务端没起」这类故障会退化成永久挂起：
/// Windows 上向未监听端口发 UDP 是**静默丢弃**（不是 `ECONNREFUSED`），
/// 于是 `connect()` 会一直等一个永远不会到的回应，把外层
/// `for _ in 0..80 { sleep(250ms) }` 的 20s 总预算完全架空。
#[allow(dead_code)] // 由部分测试目标引用；support 按目标分别编译
pub const PROBE_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// 给单次就绪探测加**墙钟上限**：超时按失败计入，重试由调用方决定。
///
/// 返回 `Ok(Ok(v))` = 成功；`Ok(Err(e))` = 快速失败并带错误；`Err(_)` = 超时。
#[allow(dead_code)] // 同上
pub async fn with_attempt_timeout<F: std::future::Future>(
    fut: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    tokio::time::timeout(PROBE_ATTEMPT_TIMEOUT, fut).await
}

/// 汇总参考服务端的 **stdout + stderr** 文本。
///
/// 参考 Xray 把「配置加载失败」这类**启动期**错误打到 **stdout**
/// （实测：Windows 上非法 JSON 路径的报错在 `xray-stdout.log` 里，
/// `xray-stderr.log` 是空的）。只读 stderr 会让排查完全失明 ⇒ 两个都读。
#[allow(dead_code)] // 由部分测试目标引用；support 按目标分别编译
pub fn server_logs(dir: &std::path::Path) -> String {
    let mut out = String::new();
    for name in ["xray-stdout.log", "xray-stderr.log"] {
        let text = std::fs::read_to_string(dir.join(name)).unwrap_or_default();
        if text.trim().is_empty() {
            continue;
        }
        out.push_str("--- ");
        out.push_str(name);
        out.push_str(" ---\n");
        out.push_str(text.trim_end());
        out.push('\n');
    }
    if out.is_empty() {
        out.push_str("(参考服务端 stdout/stderr 均为空)");
    }
    out
}

/// 回灌端：接受一条 TCP 连接，读满 `warmup` 字节后按 `obey` 决定是否以
/// `rate`（字节/秒）节拍回灌 `total` 字节（`!obey` = 全速，作对照组）。
///
/// 独立线程实现（阻塞 IO，不占用测试运行时）；`linger` 让写端在灌完后
/// 保持打开，避免对端先见到 FIN 而提前结束计数。
///
/// 通过 `ready` 回报「已读满 `warmup`、此刻开始回灌」：回灌的节拍从**此刻**
/// 起算，两端秒表对齐，免得开局窗口爬升算进上游上传的耗时。
#[allow(dead_code)] // 仅 brutal_wire 测试目标引用
pub fn paced_sink(
    listener: std::net::TcpListener,
    warmup: usize,
    total: usize,
    rate: f64,
    obey: bool,
    linger: std::time::Duration,
    ready: std::sync::mpsc::SyncSender<std::time::Instant>,
) {
    use std::io::{Read, Write};
    let Ok((mut sock, _)) = listener.accept() else {
        return;
    };
    let _ = sock.set_nodelay(true);
    // 读与写**并行**：客户端是「先写满请求、再读回程」的顺序流（见 brutal_wire
    // 的说明——`TcpProxyStream` 不提供 split，无法在同一 conn 上并发读写），
    // 若回灌端也「先读满 warmup 再回灌」，双方互等 ⇒ 客户端收到的回程只有
    // 首个窗口那点字节（实测 18854/65536）。故读侧单开一个线程把请求读掉，
    // 主线程立即按节拍回灌。
    let mut reader = match sock.try_clone() {
        Ok(clone) => clone,
        Err(_) => return,
    };
    std::thread::spawn(move || {
        let mut left = warmup;
        let mut buf = vec![0u8; 256 * 1024];
        while left > 0 {
            let cap = left.min(buf.len());
            match reader.read(&mut buf[..cap]) {
                Ok(0) | Err(_) => return,
                Ok(n) => left -= n,
            }
        }
        // 继续排空，避免客户端写端被回压卡住。
        let mut drain = vec![0u8; 64 * 1024];
        while let Ok(n) = reader.read(&mut drain) {
            if n == 0 {
                break;
            }
        }
    });
    let block = ((rate / 100.0).max(1.0)) as usize;
    let payload = vec![0xa5u8; block];
    let started = std::time::Instant::now();
    let _ = ready.send(started);
    let mut sent = 0;
    while sent < total {
        let n = block.min(total - sent);
        if sock.write_all(&payload[..n]).is_err() {
            return;
        }
        sent += n;
        if obey {
            let deadline = started + std::time::Duration::from_secs_f64(sent as f64 / rate);
            while let Some(wait) = deadline.checked_duration_since(std::time::Instant::now()) {
                std::thread::sleep(wait.min(std::time::Duration::from_millis(5)));
            }
        }
    }
    let _ = sock.flush();
    std::thread::sleep(linger);
    let _ = sock.shutdown(std::net::Shutdown::Both);
}

/// 在后台线程上启动 [`paced_sink`]；先绑定 `127.0.0.1:0` 并返回实际端口。
#[allow(dead_code)] // 同上
pub fn spawn_paced_sink(
    warmup: usize,
    total: usize,
    rate: f64,
    obey: bool,
    linger: std::time::Duration,
) -> (u16, std::sync::mpsc::Receiver<std::time::Instant>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("回灌端绑定 127.0.0.1:0");
    let port = listener.local_addr().expect("回灌端地址").port();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || paced_sink(listener, warmup, total, rate, obey, linger, tx));
    (port, rx)
}
