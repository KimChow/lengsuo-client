//! 渲染 Chromium 系的命令行。
//!
//! 依据是 Chromium 的**公开命令行约定**（本机 `~/ref/` 无参考实现时以此为准）：
//! - `--user-data-dir=<dir>`：指定用户数据目录；
//! - `--proxy-server=<scheme=host:port;...>`：按 scheme 指定代理；
//! - `--proxy-bypass-list=<a;b>`：绕过列表；
//! - `--no-first-run` / `--no-default-browser-check`：抑制首次运行向导；
//! - `--remote-debugging-port=0`：让浏览器自选一个空闲端口并把端口号写进
//!   用户数据目录下的 `DevToolsActivePort` 文件（就绪探测用）。
//!
//! **凭据绝不出现在这里**：渲染结果里只有代理端点。渲染完成后还要跑一次
//! [`crate::credential::assert_no_credential_leak`] 自检。

use crate::error::LaunchError;
use crate::proxy::ProxyConfig;
use crate::spec::LaunchSpec;

/// 渲染出的命令行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLine {
    program: String,
    args: Vec<String>,
}

impl CommandLine {
    /// 可执行文件路径。
    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    /// 参数列表（**不含**可执行文件本身）。
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// 拼成一行，仅用于日志与断言；**不是**传给 OS 的真实命令。
    #[must_use]
    pub fn display(&self) -> String {
        let mut out = self.program.clone();
        for arg in &self.args {
            out.push(' ');
            out.push_str(arg);
        }
        out
    }

    /// 某个 `--key=value` 参数的值。
    #[must_use]
    pub fn value_of(&self, key: &str) -> Option<&str> {
        let prefix = format!("{key}=");
        self.args
            .iter()
            .find_map(|arg| arg.strip_prefix(prefix.as_str()))
    }
}

/// 渲染一次启动的命令行。
pub fn render(spec: &LaunchSpec) -> Result<CommandLine, LaunchError> {
    let binary = spec.binary().path().ok_or(LaunchError::BinaryMissing)?;
    let mut args: Vec<String> = Vec::new();

    args.push(format!(
        "--user-data-dir={}",
        spec.user_data_dir().display()
    ));
    args.push("--no-first-run".to_string());
    args.push("--no-default-browser-check".to_string());

    let proxy: &ProxyConfig = spec.proxy();
    args.push(format!("--proxy-server={}", proxy.chromium_server_value()?));
    if let Some(bypass) = proxy.chromium_bypass_value() {
        args.push(format!("--proxy-bypass-list={bypass}"));
    }

    if spec.remote_debugging() {
        // 0 = 由浏览器自己挑一个空闲端口，端口号随后写进
        // <user-data-dir>/DevToolsActivePort。
        args.push("--remote-debugging-port=0".to_string());
    }

    for extra in spec.extra_args() {
        args.push(extra.clone());
    }

    if let Some(url) = spec.initial_url() {
        args.push(url.to_string());
    }

    Ok(CommandLine {
        program: binary.display().to_string(),
        args,
    })
}

#[cfg(test)]
mod tests {
    use super::render;
    use crate::error::LaunchError;
    use crate::identity::{EnvironmentId, Generation, ProbeBudget};
    use crate::proxy::{ProxyConfig, ProxyScheme};
    use crate::spec::{BrowserBinary, LaunchSpec};
    use std::path::PathBuf;

    fn spec(proxy: ProxyConfig, extra: Vec<String>) -> LaunchSpec {
        LaunchSpec::new(
            BrowserBinary::Found(PathBuf::from("/opt/browser/chrome")),
            PathBuf::from("/tmp/env-a/profile"),
            EnvironmentId::new("env-a").unwrap(),
            Generation::new(1).unwrap(),
            proxy,
            extra,
            ProbeBudget::new(5_000).unwrap(),
        )
        .unwrap()
    }

    fn proxy() -> ProxyConfig {
        ProxyConfig::empty()
            .with_endpoint(ProxyScheme::Http, "127.0.0.1", 8080)
            .unwrap()
    }

    #[test]
    fn the_user_data_dir_and_proxy_are_injected() {
        let line = render(&spec(proxy(), vec![])).unwrap();
        assert_eq!(line.value_of("--user-data-dir"), Some("/tmp/env-a/profile"));
        assert_eq!(line.value_of("--proxy-server"), Some("http=127.0.0.1:8080"));
        assert!(line.args().iter().any(|a| a == "--no-first-run"));
    }

    #[test]
    fn the_debugging_port_is_only_rendered_when_requested() {
        let line = render(&spec(proxy(), vec![])).unwrap();
        assert_eq!(line.value_of("--remote-debugging-port"), None);
        let line = render(&spec(proxy(), vec![]).with_remote_debugging(true)).unwrap();
        assert_eq!(line.value_of("--remote-debugging-port"), Some("0"));
    }

    #[test]
    fn extra_args_are_appended_after_the_injected_ones() {
        let line = render(&spec(proxy(), vec!["--lang=zh-CN".to_string()])).unwrap();
        assert_eq!(line.args().last().unwrap(), "--lang=zh-CN");
    }

    #[test]
    fn a_missing_binary_refuses_to_render() {
        let spec = LaunchSpec::new(
            BrowserBinary::Missing,
            PathBuf::from("/tmp/env-a/profile"),
            EnvironmentId::new("env-a").unwrap(),
            Generation::new(1).unwrap(),
            proxy(),
            vec![],
            ProbeBudget::new(5_000).unwrap(),
        )
        .unwrap();
        assert_eq!(render(&spec).unwrap_err(), LaunchError::BinaryMissing);
    }

    #[test]
    fn the_bypass_list_is_rendered_when_present() {
        let proxy = proxy()
            .with_bypass(vec!["<local>", "*.example.test"])
            .unwrap();
        let line = render(&spec(proxy, vec![])).unwrap();
        assert_eq!(
            line.value_of("--proxy-bypass-list"),
            Some("<local>;*.example.test")
        );
    }
}
