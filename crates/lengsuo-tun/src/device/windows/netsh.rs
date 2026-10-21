//! `netsh` 子命令封装：按协议族设置与查询适配器 MTU。

use super::{Error, Result};

/// 运行 `netsh` 并返回 stdout；非 0 退出码转为类型化错误。
///
/// 与 wintun 绑定的 `run_command` 同为「只看退出码」的语义，但本层保留
/// stderr 文案便于实机排障。**不写入系统目录、不改路由、不碰非本适配器接口。**
fn run_netsh(args: &[&str]) -> Result<String> {
    let output = std::process::Command::new("netsh")
        .args(args)
        .output()
        .map_err(|io| Error::Device {
            reason: format!("调用 netsh 失败：{io}"),
        })?;
    if !output.status.success() {
        let text = String::from_utf8_lossy(if output.stderr.is_empty() {
            &output.stdout
        } else {
            &output.stderr
        });
        return Err(Error::Device {
            reason: format!("netsh {} 失败：{}", args.join(" "), text.trim()),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// 按协议族设置适配器 MTU（`family` 为 `"ipv4"` 或 `"ipv6"`）。
///
/// 存在的理由：wintun 绑定的 `set_mtu` **只设 IPv4**（见 [`Device::set_mtu`] 取证），
/// 双栈环境必须补设 IPv6，否则 [`Device::mtu`] 的回读不可信。
pub(super) fn set_adapter_mtu_for(name: &str, family: &str, mtu: usize) -> Result<()> {
    let quoted = format!("\"{name}\"");
    run_netsh(&[
        "interface",
        family,
        "set",
        "subinterface",
        &quoted,
        &format!("mtu={mtu}"),
        "store=persistent",
    ])
    .map(|_| ())
}

/// 按协议族读取适配器 MTU；该协议族没有对应行时返回 `None`。
///
/// 解析 `netsh interface <family> show subinterfaces` 的表格行，
/// 匹配适配器名后取首列 MTU。**读不到或格式变化时返回 `None` 而非猜测值**，
/// 由调用方决定回退策略。
pub(super) fn query_adapter_mtu(name: &str, family: &str) -> Result<Option<u16>> {
    let text = run_netsh(&["interface", family, "show", "subinterfaces"])?;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("---") {
            continue;
        }
        // 只认含本适配器名的行；表头行不含适配器名，自然跳过。
        if !trimmed.contains(name) {
            continue;
        }
        // 首列是 MTU；按空白切分，第一段必须是十进制整数。
        if let Some(first) = trimmed.split_whitespace().next() {
            if let Ok(value) = first.parse::<u16>() {
                return Ok(Some(value));
            }
        }
    }
    Ok(None)
}
