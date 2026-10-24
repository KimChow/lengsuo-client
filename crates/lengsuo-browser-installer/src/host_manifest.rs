//! 安装层：把 host manifest 渲染与注册计划落地，并做「宿主二进制存在性」
//! fail-closed 校验。
//!
//! 渲染 JSON 与注册计划全部复用 [`lengsuo_native_host::manifest`] / [`lengsuo_native_host::register`]，
//! **不复制字节**；本模块不做归档解压（与本 crate 现有归档校验库口径一致）。
//!
//! # 平台分工
//!
//! - `plan_host_install`：纯函数，零 IO；在 Linux 上可对两个平台的分支全部单测；
//!   Windows 分支只产出 `reg add` 命令行，不真执行 `reg.exe`。
//! - `install_host_manifest`：带 IO 的入口，先纯计划，再 fail-closed 校验宿主二进制
//!   是否存在且为普通文件，缺失则 **不写任何东西**；最后调用 `register`（POSIX 真写文件；
//!   Windows 经注入执行器跑 `reg add`）。
//!
//! # 四条自设工程决定（已上报至任务书，⛔ 不改任何契约字节）
//!
//! - G1：POSIX 的 `user_data_dir` 由启动方传入，故入口用结构体
//!   [`HostInstallRequest`] 而非契约 §5.4 的三参数签名（三参数在 POSIX 上不可实现）。
//!   报告里原样列为 `W5b-INSTALLER-UDD`。
//! - G2：Windows 清单文件落 `<install_root>\lengsuo.credential.json`（§5.4 未定文件位置）。
//! - G3：写任何东西前 fail-closed 校验 `<install_root>/lengsuo-native-host[.exe]`
//!   存在且为普通文件，缺失则 [`HostInstallError::HostBinaryMissing`] 且零副作用。
//! - G4：`description` = [`HOST_DESCRIPTION`] = "Lengsuo credential native messaging host"。

use std::path::{Path, PathBuf};

use lengsuo_native_host::{
    is_absolute_path, plan_posix, plan_windows, register as register_plan, render_host_manifest,
    CommandRunner, ManifestError, Platform, RegisterError, RegistrationPlan, HOST_NAME,
};

/// 宿主 manifest 安装请求：可直接构造，不做 builder。
#[derive(Debug, Clone)]
pub struct HostInstallRequest {
    /// 安装根目录（宿主二进制与本清单同级的目录）。
    pub install_root: PathBuf,
    /// 目标平台：决定路径绝对性判据与注册位置。
    pub platform: Platform,
    /// POSIX 必填：内核启动时的 `--user-data-dir`；Windows 不用。
    pub user_data_dir: Option<PathBuf>,
}

/// 安装计划（纯数据，供调用方日志/检查；不含执行结果）。
#[derive(Debug, Clone)]
pub struct HostInstallPlan {
    /// 宿主可执行文件路径，写入 manifest 的 `path` 字段。
    pub host_binary: String,
    /// 清单文件的实际落点（Windows 注册表里存的值；POSIX 落盘的文件）。
    pub manifest_file: String,
    /// 渲染后的 JSON 文本（无空白、无尾换行）。
    pub manifest_json: String,
    /// 平台注册计划。
    pub registration: RegistrationPlan,
}

/// 安装结果：记录实际写入的 manifest 文件路径，⛔ 不含凭据/私钥。
#[derive(Debug, Clone)]
pub struct HostInstallOutcome {
    /// 实际写入的 manifest 文件路径。
    pub manifest_file: String,
}

/// 宿主 manifest `description` 字段取值（G4，自设工程决定；契约 §5.4 未给常量）。
pub const HOST_DESCRIPTION: &str = "Lengsuo credential native messaging host";

/// 安装失败（⛔ 不 panic，⛔ 不做半途动作）。
#[derive(Debug)]
pub enum HostInstallError {
    /// `install_root` 不是该平台意义上的绝对路径。
    InstallRootNotAbsolute,

    /// POSIX 分支缺少 `user_data_dir`。
    MissingUserDataDir,

    /// 宿主二进制不存在或不是普通文件（fail-closed，不写任何东西）。
    HostBinaryMissing { path: String },

    /// manifest 渲染失败。
    Manifest(ManifestError),

    /// 注册计划失败。
    Register(RegisterError),

    /// 文件系统操作失败。
    Io {
        op: String,
        path: String,
        source: std::io::Error,
    },
}

impl std::fmt::Display for HostInstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostInstallError::InstallRootNotAbsolute => {
                write!(f, "install_root 不是平台意义上的绝对路径：拒绝安装")
            }
            HostInstallError::MissingUserDataDir => {
                write!(f, "POSIX 安装必须提供 user_data_dir：拒绝安装")
            }
            HostInstallError::HostBinaryMissing { path } => {
                write!(
                    f,
                    "宿主二进制缺失：{path}（不存在或不是普通文件），不写任何东西"
                )
            }
            HostInstallError::Manifest(e) => write!(f, "manifest 渲染失败：{e}"),
            HostInstallError::Register(e) => write!(f, "注册计划失败：{e}"),
            HostInstallError::Io { op, path, source } => {
                write!(f, "文件操作失败 {op} {path}: {source}")
            }
        }
    }
}

impl std::error::Error for HostInstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HostInstallError::Manifest(e) => Some(e),
            HostInstallError::Register(e) => Some(e),
            HostInstallError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// 构造安装计划（纯函数，零 IO）。
pub fn plan_host_install(req: &HostInstallRequest) -> Result<HostInstallPlan, HostInstallError> {
    let root = req.install_root.to_string_lossy();
    let root = root.trim_end_matches(['\\', '/']);
    if !is_absolute_path(root, req.platform) {
        return Err(HostInstallError::InstallRootNotAbsolute);
    }

    // 宿主二进制：<install_root>/lengsuo-native-host[.exe]（平台分隔符）。
    let host_binary = host_binary_path(root, req.platform);

    // 渲染 manifest JSON（字节真相由 native-host 渲染器负责，本卡不写字段字面量）。
    let manifest_json = render_host_manifest(&host_binary, HOST_DESCRIPTION, req.platform)
        .map_err(HostInstallError::Manifest)?;

    let (manifest_file, registration) = match req.platform {
        Platform::Windows => {
            // G2：清单文件落 <install_root>\<HOST_NAME>.json
            let manifest_file = format!("{root}\\{HOST_NAME}.json");
            let windows_plan = plan_windows(&manifest_file).map_err(HostInstallError::Register)?;
            (
                windows_plan.value_data.clone(),
                RegistrationPlan::Windows(windows_plan),
            )
        }
        Platform::Posix => {
            let user_data_dir = req
                .user_data_dir
                .as_ref()
                .ok_or(HostInstallError::MissingUserDataDir)?;
            let posix_plan =
                plan_posix(user_data_dir, &manifest_json).map_err(HostInstallError::Register)?;
            let manifest_file = posix_plan.manifest_file.to_string_lossy().to_string();
            (manifest_file, RegistrationPlan::Posix(posix_plan))
        }
    };

    Ok(HostInstallPlan {
        host_binary,
        manifest_file,
        manifest_json,
        registration,
    })
}

/// 宿主二进制路径：<install_root>/lengsuo-native-host[.exe]（平台分隔符）。
///
/// `root` 已是清理过尾部分隔符的字符串，由调用方统一处理，避免 `C:\x\` 再拼
/// 出双分隔符。
fn host_binary_path(root: &str, platform: Platform) -> String {
    match platform {
        Platform::Windows => format!("{root}\\lengsuo-native-host.exe"),
        Platform::Posix => format!("{root}/lengsuo-native-host"),
    }
}

/// 安装入口（契约 §5.4 所指）：先纯计划，再 fail-closed 校验宿主二进制，
/// 最后注册。
pub fn install_host_manifest<R: CommandRunner>(
    req: &HostInstallRequest,
    runner: &R,
) -> Result<HostInstallOutcome, HostInstallError> {
    let plan = plan_host_install(req)?;

    // fail-closed：宿主二进制必须存在且为普通文件，否则不写任何东西。
    let binary_path = Path::new(&plan.host_binary);
    match std::fs::metadata(binary_path) {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => {
            return Err(HostInstallError::HostBinaryMissing {
                path: plan.host_binary.clone(),
            })
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(HostInstallError::HostBinaryMissing {
                path: plan.host_binary.clone(),
            })
        }
        Err(source) => {
            return Err(HostInstallError::Io {
                op: "stat".to_owned(),
                path: plan.host_binary.clone(),
                source,
            })
        }
    }

    register_plan(&plan.registration, runner).map_err(HostInstallError::Register)?;

    Ok(HostInstallOutcome {
        manifest_file: plan.manifest_file.clone(),
    })
}
