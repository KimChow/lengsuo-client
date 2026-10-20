//! 一次浏览器启动的**完整描述**：谁、哪一代、哪个目录、哪个代理、多久。

use std::path::{Path, PathBuf};

use crate::error::LaunchError;
use crate::identity::{EnvironmentId, Generation, ProbeBudget};
use crate::proxy::ProxyConfig;

/// 浏览器可执行文件的定位结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserBinary {
    /// 已定位到的可执行文件路径。
    Found(PathBuf),
    /// 未找到可执行文件（**fail-closed**，不得降级为裸连）。
    Missing,
}

impl BrowserBinary {
    /// 定位一个可执行文件：必须是存在的**普通文件**。
    ///
    /// 目录、管道、不可执行文件一律当作 `Missing`，避免把「路径存在」
    /// 误当成「能启动」。
    #[must_use]
    pub fn locate(path: &Path) -> Self {
        match std::fs::metadata(path) {
            Ok(meta) if meta.is_file() => Self::Found(path.to_path_buf()),
            _ => Self::Missing,
        }
    }

    /// 路径（若有）。
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Found(path) => Some(path.as_path()),
            Self::Missing => None,
        }
    }

    /// 是否定位成功。
    #[must_use]
    pub fn is_found(&self) -> bool {
        matches!(self, Self::Found(_))
    }
}

/// 一次启动的完整描述。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSpec {
    binary: BrowserBinary,
    user_data_dir: PathBuf,
    environment: EnvironmentId,
    generation: Generation,
    proxy: ProxyConfig,
    extra_args: Vec<String>,
    probe_budget: ProbeBudget,
    remote_debugging: bool,
    initial_url: Option<String>,
}

impl LaunchSpec {
    /// 组装一次启动描述。
    ///
    /// 约束（全部 fail-closed，见 [`LaunchSpec::validate`]）：
    /// - 代理**必须**至少有一个端点；
    /// - 用户数据目录必须落在**某个根目录**下，且**每个环境一个**；
    /// - 附加参数不得含凭据材料。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binary: BrowserBinary,
        user_data_dir: PathBuf,
        environment: EnvironmentId,
        generation: Generation,
        proxy: ProxyConfig,
        extra_args: Vec<String>,
        probe_budget: ProbeBudget,
    ) -> Result<Self, LaunchError> {
        let spec = Self {
            binary,
            user_data_dir,
            environment,
            generation,
            proxy,
            extra_args,
            probe_budget,
            remote_debugging: false,
            initial_url: None,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// 打开 DevTools 端口（就绪探测用）。默认关闭。
    #[must_use]
    pub fn with_remote_debugging(mut self, enabled: bool) -> Self {
        self.remote_debugging = enabled;
        self
    }

    /// 设置启动后打开的初始 URL。
    ///
    /// URL 里**不得**带凭据（`https://user:pass@host/`）：URL 会原样出现在
    /// 进程命令行上。
    #[must_use]
    pub fn with_initial_url(mut self, url: Option<String>) -> Self {
        self.initial_url = url;
        self
    }

    /// 覆盖就绪探测的总预算。
    #[must_use]
    pub fn with_probe_budget(mut self, budget: ProbeBudget) -> Self {
        self.probe_budget = budget;
        self
    }

    /// 自检：代理必须有端点；参数与初始 URL 都不得像凭据。
    ///
    /// 在**构造时**与**启动时**各跑一次：构造后的 `with_*` 也能塞进凭据，
    /// 启动时那一次才是最后一道闸。
    pub(crate) fn validate(&self) -> Result<(), LaunchError> {
        if !self.proxy.has_endpoint() {
            return Err(LaunchError::Proxy(crate::error::ProxyError::NoEndpoint));
        }
        for arg in &self.extra_args {
            if arg.contains("://") && arg.contains('@') {
                return Err(LaunchError::CredentialLeak);
            }
        }
        if let Some(url) = &self.initial_url {
            if url_has_userinfo(url) {
                return Err(LaunchError::CredentialLeak);
            }
        }
        Ok(())
    }

    /// 浏览器可执行文件。
    #[must_use]
    pub fn binary(&self) -> &BrowserBinary {
        &self.binary
    }

    /// 用户数据目录（**每环境一个**）。
    #[must_use]
    pub fn user_data_dir(&self) -> &Path {
        &self.user_data_dir
    }

    /// 环境身份。
    #[must_use]
    pub fn environment(&self) -> &EnvironmentId {
        &self.environment
    }

    /// 代次。
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }

    /// 代理配置。
    #[must_use]
    pub fn proxy(&self) -> &ProxyConfig {
        &self.proxy
    }

    /// 附加启动参数。
    #[must_use]
    pub fn extra_args(&self) -> &[String] {
        &self.extra_args
    }

    /// 探测预算。
    #[must_use]
    pub fn probe_budget(&self) -> ProbeBudget {
        self.probe_budget
    }

    /// 是否打开 DevTools 端口。
    #[must_use]
    pub fn remote_debugging(&self) -> bool {
        self.remote_debugging
    }

    /// 初始 URL。
    #[must_use]
    pub fn initial_url(&self) -> Option<&str> {
        self.initial_url.as_deref()
    }
}

/// URL 是否带 userinfo（`user:pass@host`）。
///
/// 带 userinfo 的 URL 会**原样出现在进程命令行**上，所以必须拒绝。
fn url_has_userinfo(url: &str) -> bool {
    let Some((_, rest)) = url.split_once("://") else {
        return false;
    };
    // authority 是 `rest` 里第一个 `/` 之前（或 `?`/`#` 之前）的部分。
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    authority.contains('@')
}

#[cfg(test)]
mod tests {
    use super::{BrowserBinary, LaunchSpec};
    use crate::error::{LaunchError, ProxyError};
    use crate::identity::{EnvironmentId, Generation, ProbeBudget};
    use crate::proxy::{ProxyConfig, ProxyScheme};
    use std::path::PathBuf;

    fn proxy() -> ProxyConfig {
        ProxyConfig::empty()
            .with_endpoint(ProxyScheme::Http, "127.0.0.1", 8080)
            .unwrap()
    }

    fn spec() -> LaunchSpec {
        LaunchSpec::new(
            BrowserBinary::Missing,
            PathBuf::from("/tmp/env-a"),
            EnvironmentId::new("env-a").unwrap(),
            Generation::new(1).unwrap(),
            proxy(),
            vec![],
            ProbeBudget::new(5_000).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn a_well_formed_spec_is_accepted() {
        assert_eq!(spec().environment().as_str(), "env-a");
    }

    #[test]
    fn a_proxy_without_endpoint_is_refused() {
        let err = LaunchSpec::new(
            BrowserBinary::Missing,
            PathBuf::from("/tmp/env-a"),
            EnvironmentId::new("env-a").unwrap(),
            Generation::new(1).unwrap(),
            ProxyConfig::empty(),
            vec![],
            ProbeBudget::new(5_000).unwrap(),
        )
        .unwrap_err();
        assert_eq!(err, LaunchError::Proxy(ProxyError::NoEndpoint));
    }

    #[test]
    fn an_extra_argument_that_looks_like_a_credential_is_refused() {
        let err = LaunchSpec::new(
            BrowserBinary::Missing,
            PathBuf::from("/tmp/env-a"),
            EnvironmentId::new("env-a").unwrap(),
            Generation::new(1).unwrap(),
            proxy(),
            vec!["--proxy-server=http://u:p@host:1".to_string()],
            ProbeBudget::new(5_000).unwrap(),
        )
        .unwrap_err();
        assert_eq!(err, LaunchError::CredentialLeak);
    }

    #[test]
    fn an_initial_url_with_userinfo_is_refused() {
        // 初始 URL 会原样出现在进程命令行上 ⇒ 带 userinfo 必须拒绝。
        let leaky = spec().with_initial_url(Some("https://user:secret@host/path".to_string()));
        assert_eq!(leaky.validate().unwrap_err(), LaunchError::CredentialLeak);

        // 正常 URL 放行。
        let ok = spec().with_initial_url(Some("http://tun3.lensuo.test:80/".to_string()));
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn a_missing_binary_path_is_reported_as_missing() {
        let binary = BrowserBinary::locate(std::path::Path::new("/nonexistent/browser"));
        assert!(!binary.is_found());
        assert!(binary.path().is_none());
    }

    #[test]
    fn a_directory_is_not_a_binary() {
        let binary = BrowserBinary::locate(std::path::Path::new("/tmp"));
        assert!(!binary.is_found());
    }
}
