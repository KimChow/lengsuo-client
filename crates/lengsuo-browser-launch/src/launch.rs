//! `Launcher`：按环境启动浏览器进程，并把该环境的代理出口配置注入进去。
//!
//! ## 与 `lengsuo-browser-lifecycle` 的契约边界
//!
//! `lengsuo-browser-lifecycle` **明确声明**「never spawns or kills a process」，
//! 它是纯状态机：只决定阶段顺序、代次、期限与资源记账。本 crate 是**唯一**
//! 真正 `spawn` 的地方，因此：
//!
//! - 本 crate **不修改** lifecycle 的任何契约，也不往 lifecycle 里塞进程代码；
//! - 本 crate 借用 lifecycle 的 `RunGeneration` / `ProcessIdentity` 语义作为
//!   **代次/身份载体**，让启动层产出的东西能直接喂给状态机；
//! - 状态机**不**被本 crate 驱动：调用方负责按阶段回调状态机，本 crate 只
//!   负责「按规格把进程真正拉起来，并保证能回收」。
//!
//! ## fail-closed
//!
//! - 浏览器包/可执行文件缺失 ⇒ [`LaunchError::BinaryMissing`]，**不降级**；
//! - 代理配置没有端点 ⇒ [`LaunchError::Proxy`]，**不裸连**；
//! - 代理带凭据却没有投递方式 ⇒ [`LaunchError::Argument`]，**不默默丢掉**；
//! - 就绪探测超时 ⇒ [`LaunchError::ProbeTimeout`]，并**立即回收进程**；
//! - 命令行里出现凭据 ⇒ [`LaunchError::CredentialLeak`]，**拒绝启动**。

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::command::{render, CommandLine};
use crate::credential::{assert_no_credential_leak, CredentialInjection, CredentialPlan};
use crate::error::LaunchError;
use crate::probe::{clear_stale_port_file, wait_for_ready, ProbeOutcome, ReadinessStrategy};
use crate::process::BrowserProcess;
use crate::spec::LaunchSpec;

/// 一次成功启动的完整结果。
#[derive(Debug)]
pub struct Launched {
    /// 进程句柄（可取消、可 kill、可释放）。
    pub process: BrowserProcess,
    /// 渲染出的命令行（**不含凭据**）。
    pub command_line: CommandLine,
    /// 凭据投递计划（环境变量或文件，**不在命令行**）；无凭据时为 `None`。
    pub credential_plan: Option<CredentialPlan>,
    /// 就绪探测结果。
    pub readiness: ProbeOutcome,
}

/// 浏览器启动器。
///
/// 一个 `Launcher` 可以启动**多个**环境，但**同一个用户数据目录只能被占用
/// 一次**：重复占用会被拒绝（环境隔离被破坏 ⇒ fail-closed）。
#[derive(Debug, Default)]
pub struct Launcher {
    claimed_dirs: HashSet<PathBuf>,
    credential_injection: Option<CredentialInjection>,
}

impl Launcher {
    /// 新建启动器。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置默认的凭据投递方式（环境变量或文件）。
    ///
    /// 不设置时，若代理配置带凭据 ⇒ 启动被拒绝（**凭据必须有明确去处**，
    /// 不能默默丢掉，也不能落到命令行）。
    #[must_use]
    pub fn with_credential_injection(mut self, injection: CredentialInjection) -> Self {
        self.credential_injection = Some(injection);
        self
    }

    /// 启动一个环境。
    ///
    /// 失败路径**一定**回收已拉起的进程：函数返回 `Err` 时，不存在本 crate
    /// 启动的、仍存活的浏览器进程。失败时**用户数据目录的占用也会被释放**，
    /// 不会留下「幽灵占用」挡住后续启动。
    ///
    /// 成功时目录占用**保留**到本 `Launcher` 被丢弃：这样同一个目录不会在
    /// 旧进程还活着时被复用（fail-closed）。
    pub fn launch(&mut self, spec: &LaunchSpec) -> Result<Launched, LaunchError> {
        // 0) 最后一次自检：构造后加进来的参数/URL 也可能带凭据。
        spec.validate()?;

        // 1) 浏览器包必须存在 —— 不静默降级。
        let binary = spec.binary().path().ok_or(LaunchError::BinaryMissing)?;
        if !binary.is_file() {
            return Err(LaunchError::BinaryMissing);
        }

        // 2) 用户数据目录必须独占。
        let dir = spec.user_data_dir();
        self.claim_dir(dir)?;

        // 3) 真正的启动。失败 ⇒ 回收进程 + 释放目录占用。
        let outcome = self.launch_claimed(spec, dir, binary);
        if outcome.is_err() {
            self.release_dir(dir);
        }
        outcome
    }

    /// 已经占用目录之后的启动流程。
    fn launch_claimed(
        &self,
        spec: &LaunchSpec,
        dir: &Path,
        binary: &Path,
    ) -> Result<Launched, LaunchError> {
        // 4) 准备目录（不存在则创建）。
        std::fs::create_dir_all(dir).map_err(|error| LaunchError::Io { kind: error.kind() })?;

        // 5) 凭据投递计划。带凭据却没有投递方式 ⇒ 拒绝启动。
        let credential_plan = self.prepare_credential(spec, dir)?;

        // 6) 渲染命令行并做凭据泄漏自检。
        let command_line = render(spec)?;
        if let Some(credential) = spec.proxy().credential() {
            assert_no_credential_leak(&command_line.display(), credential)?;
        }

        // 7) 清掉上一轮残留的调试端口文件。
        //
        // **必须在 spawn 之前**：否则可能把浏览器刚写好的新端口文件删掉，
        // 探测就永远等不到就绪。
        let strategy = if spec.remote_debugging() {
            clear_stale_port_file(dir);
            ReadinessStrategy::DevToolsPort
        } else {
            ReadinessStrategy::default()
        };

        // 8) 拉起进程。
        let mut command = Command::new(binary);
        command
            .args(command_line.args())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let (Some(credential), Some(plan)) = (spec.proxy().credential(), &credential_plan) {
            // 凭据经**环境变量**交给侧车，不进 argv。
            command.env(
                plan.variable(),
                format!("{}:{}", credential.username(), credential.password()),
            );
        }
        let child = command
            .spawn()
            .map_err(|error| LaunchError::SpawnFailed { kind: error.kind() })?;
        let mut process = BrowserProcess::new(child, spec.environment().clone(), spec.generation());

        // 9) 就绪探测（有总超时）。失败 ⇒ 立即回收进程。
        let readiness = wait_for_ready(&strategy, dir, process.watch(), spec.probe_budget())
            .inspect_err(|_error| {
                // 关键：回收进程，绝不留孤儿。
                let _ = process.shutdown();
            })?;

        Ok(Launched {
            process,
            command_line,
            credential_plan,
            readiness,
        })
    }

    /// 准备凭据投递计划：无凭据 ⇒ `None`；有凭据 ⇒ 必须有投递方式。
    fn prepare_credential(
        &self,
        spec: &LaunchSpec,
        dir: &Path,
    ) -> Result<Option<CredentialPlan>, LaunchError> {
        let Some(credential) = spec.proxy().credential() else {
            return Ok(None);
        };
        let injection = self
            .credential_injection
            .clone()
            .ok_or(LaunchError::Argument("代理凭据缺少投递方式"))?;
        let plan = CredentialPlan::plan(credential, injection, dir)?;
        self.write_credential_file(&plan)?;
        Ok(Some(plan))
    }

    /// 写凭据文件（文件路径模式）。失败即拒绝启动。
    fn write_credential_file(&self, plan: &CredentialPlan) -> Result<(), LaunchError> {
        use std::io::Write;
        let path = plan.file_path();
        let mut file =
            std::fs::File::create(path).map_err(|error| LaunchError::Io { kind: error.kind() })?;
        file.write_all(plan.file_content().as_bytes())
            .map_err(|error| LaunchError::Io { kind: error.kind() })?;
        // Unix 上收紧权限：只有属主可读写。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// 占用一个用户数据目录。
    fn claim_dir(&mut self, dir: &Path) -> Result<(), LaunchError> {
        let key = normalize_dir(dir);
        if self.claimed_dirs.contains(&key) {
            return Err(LaunchError::UserDataDirInUse);
        }
        self.claimed_dirs.insert(key);
        Ok(())
    }

    /// 释放一个用户数据目录。
    fn release_dir(&mut self, dir: &Path) {
        self.claimed_dirs.remove(&normalize_dir(dir));
    }

    /// 当前被占用的用户数据目录数量。
    #[must_use]
    pub fn claimed_dir_count(&self) -> usize {
        self.claimed_dirs.len()
    }
}

/// 目录键：规范化大小写差异（Windows 上不区分大小写）。
fn normalize_dir(dir: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in dir.components() {
        out.push(part);
    }
    #[cfg(windows)]
    {
        out = PathBuf::from(out.to_string_lossy().to_lowercase());
    }
    out
}
