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
