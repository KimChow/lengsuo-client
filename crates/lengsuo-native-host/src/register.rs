//! 注册层：把 host manifest 装到 Chromium **会去读的**位置。
//!
//! [`crate::manifest`] 只渲染 JSON 文本（纯函数、不写文件）；本模块负责「装到哪、写什么」。
//!
//! # 两平台的落点（Chromium 自己的查找逻辑）
//!
//! | 平台 | Chromium 去哪读 | 本模块 |
//! |---|---|---|
//! | Windows | 注册表 `HKCU\SOFTWARE\Chromium\NativeMessagingHosts\<host 名>` 的**默认值** | [`plan_windows`] → 注入执行器 |
//! | POSIX | `<user_data_dir>/NativeMessagingHosts/<host 名>.json` | [`plan_posix`] → [`std::fs`] 落盘 |
//!
//! ## Windows 细节（源码钉住，不猜）
//!
//! - 值名是**默认值**：`launch_context_win.cc` 用 `key.ReadValue(nullptr, …)` 读无名值
//!   ⇒ 我们写 `/ve`，⛔ 不写具名值；
//! - 用户级优先：`:192` 先 `HKEY_CURRENT_USER`，`:195` 才 `HKEY_LOCAL_MACHINE`
//!   ⇒ 本模块**只写 HKCU**（用户无需管理员权限，且 HKCU 命中就不看 HKLM）；
//! - 品牌键：`:65-75` 先试 `SOFTWARE\Chromium\NativeMessagingHosts`，:78 才回退真浏览器
//!   的品牌键。⛔ 本模块**不写真浏览器品牌键**（会污染别人的浏览器）；
//! - 路径必须绝对：`:200-205` 非绝对直接拒绝（`"must be absolute"`）；
//! - 视图：`:87-90` 先 32 位再 64 位 ⇒ 不改 `/reg:32|/reg:64`，落哪个视图由执行器所用
//!   `reg.exe` 的位数决定，两边都能命中。
//!
//! ⚠️ **待取证（⛔ 不自行拍板）**：`:65-75` 那段 Chromium 品牌键受
//! `BUILDFLAG(CHROMIUM_BRANDING)` 门控；**我方自建内核是否定义了该宏未取证**。
//! 若没有定义，Chromium 品牌键分支不存在 ⇒ 只写它就等于没注册。
//!
//! ## POSIX 细节
//!
//! - 用户级：`chrome_paths.cc:481-483` = `<DIR_USER_DATA>/NativeMessagingHosts`。
//!   `user_data_dir` **必须由调用方给**（内核是用 `--user-data-dir=…` 启动的）
//!   ⇒ ⛔ 本模块不猜默认 profile 路径；
//! - 系统级 `/etc/chromium/native-messaging-hosts`（`:477-479`）需要 root ⇒ 本模块不写。
//!
//! # 平台分派与纯函数
//!
//! 平台判定与**命令行构造**都是纯函数（在 Linux 上全测）；只有「真的去写」那一步
//! 走注入执行器。Windows 分支**只产出命令行**，⛔ 不能在 Linux 上真跑 `reg.exe`。
//!
//! # IO 纪律
//!
//! - POSIX：真写文件（`std::fs`），先建父目录；⛔ 只建、不删别人的目录；
//! - Windows：⛔ 本模块**自己不 exec**，命令行交给 [`CommandRunner`]；
//! - `ponytail:` 直接 `fs::write`，不做临时文件 + rename 原子替换 —— 安装是一次性动作，
//!   且 manifest 的内容真相在我方渲染器（可重放）；真出现并发改写再升级。

use std::path::{Path, PathBuf};

use crate::manifest::{is_absolute_path, Platform, HOST_NAME};

/// Windows 注册表根：用户级（`:192` 先 HKCU）。⛔ 不用 HKLM。
pub const REGISTRY_ROOT: &str = "HKCU";

/// Windows 注册表子键（品牌 = Chromium；真浏览器品牌键不是我们的落点）。
pub const REGISTRY_SUBKEY: &str = r"SOFTWARE\Chromium\NativeMessagingHosts";

/// POSIX 用户级子目录名（`chrome_paths.cc:481-483`）。
pub const POSIX_USER_SUBDIR: &str = "NativeMessagingHosts";

/// 命令行执行的程序名（`.exe` 显式写，避开 PATHEXT 解析差异）。
pub const REG_PROGRAM: &str = "reg.exe";

/// Windows 注册计划（纯数据，**不含执行动作**）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsPlan {
    /// 完整子键路径（含根）：`<HKCU>\<子键>\<host 名>`。
    pub key_path: String,
    /// 值名：`None` = **默认值**（`ReadValue(nullptr, …)` 读的那一项）。
    pub value_name: Option<&'static str>,
    /// 值数据 = manifest 的**绝对路径**。
    pub value_data: String,
    /// 逐字符的 `reg add` 命令行（`/ve` 写默认值 + `/f` 免交互）。
    pub add_command: String,
    /// 逐字符的 `reg delete` 命令行（`/ve` 只删默认值，⛔ 不动别人的键）。
    pub delete_command: String,
}

/// POSIX 注册计划（纯数据）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixPlan {
    /// 要写的 manifest 文件绝对路径：`<user_data_dir>/NativeMessagingHosts/<host 名>.json`。
    pub manifest_file: PathBuf,
    /// 文件内容 = [`crate::manifest::render_host_manifest`] 的产物（无尾换行）。
    pub contents: String,
}

/// 注册计划（平台分派的载体）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationPlan {
    /// Windows：写注册表（经注入执行器）。
    Windows(WindowsPlan),
    /// POSIX：写用户级目录里的文件。
    Posix(PosixPlan),
}

/// 注入的**执行器**：把命令行交给平台去跑。
///
/// ⛔ 本 crate 自己不 `exec`（Linux 上更没有 `reg.exe` 可跑）。
///
/// ⚠️ 实现**必须直接 exec、不经 shell**（`CreateProcess` 一类）：命令行里的
/// `&`、`^`、`%` 若过 `cmd.exe` 会被解释成元字符 ⇒ 路径就可能指向别处。
pub trait CommandRunner {
    /// 执行一条命令行；失败时给出**人可读**原因（错误文本不含凭据）。
    ///
    /// # Errors
    /// 执行失败（进程起不来 / 退出码非 0）⇒ `Err(原因)`。
    fn run(&self, command_line: &str) -> Result<(), String>;
}

/// 注册失败（⛔ 不 panic；⛔ 不做半途动作）。
#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    /// `user_data_dir` 不是 POSIX 意义上的绝对路径：写它会落到当前目录。
    #[error("user_data_dir {dir:?} 不是 POSIX 绝对路径：拒绝注册")]
    UserDataDirNotAbsolute {
        /// 调用方给的目录原文。
        dir: String,
    },

    /// 要写入的 manifest 内容为空串：宁可注册失败，也不给浏览器留个空文件。
    #[error("manifest 内容为空：拒绝注册")]
    EmptyManifest,

    /// 撤销注册时给出的 manifest 文件路径不是 POSIX 绝对路径：
    /// 相对路径会落到当前目录，删除操作 ⛔ fail-closed。
    #[error("manifest 文件路径 {path:?} 不是 POSIX 绝对路径：拒绝删除")]
    ManifestFileNotAbsolute {
        /// 计划里的路径原文。
        path: String,
    },

    /// `path` 不是 Windows 意义上的绝对路径（`:200-205` 同样拒绝）。
    #[error("manifest 路径 {path:?} 不是 Windows 绝对路径：拒绝注册")]
    ManifestPathNotAbsolute {
        /// 调用方给的路径原文。
        path: String,
    },

    /// `path` 含命令行无法安全承载的字符（`"`）。
    #[error("manifest 路径 {path:?} 含 {ch:?}：命令行无法安全承载，拒绝注册")]
    ManifestPathNotCommandSafe {
        /// 调用方给的路径原文。
        path: String,
        /// 第一个越界字符。
        ch: char,
    },

    /// 文件系统操作失败（带出错的路径）。
    #[error("文件操作失败：{path}: {source}")]
    Io {
        /// 出错的路径。
        path: String,
        /// 底层 IO 错误。
        #[source]
        source: std::io::Error,
    },

    /// 注入的执行器失败。
    #[error("执行器失败：{0}")]
    RunnerFailed(String),
}

/// 构造 Windows 注册计划。
///
/// `manifest_absolute_path` = 宿主 manifest 文件的绝对路径（注册表里存的就是它）。
///
/// # Errors
/// - 非 Windows 绝对路径 ⇒ [`RegisterError::ManifestPathNotAbsolute`]；
/// - 含 `"`（命令行无法承载）⇒ [`RegisterError::ManifestPathNotCommandSafe`]。
pub fn plan_windows(manifest_absolute_path: &str) -> Result<WindowsPlan, RegisterError> {
    if !is_absolute_path(manifest_absolute_path, Platform::Windows) {
        return Err(RegisterError::ManifestPathNotAbsolute {
            path: manifest_absolute_path.to_owned(),
        });
    }
    if let Some(ch) = manifest_absolute_path.chars().find(|c| *c == '"') {
        return Err(RegisterError::ManifestPathNotCommandSafe {
            path: manifest_absolute_path.to_owned(),
            ch,
        });
    }

    let key_path = format!("{REGISTRY_ROOT}\\{REGISTRY_SUBKEY}\\{HOST_NAME}");
    Ok(WindowsPlan {
        value_data: manifest_absolute_path.to_owned(),
        add_command: format!(
            "{REG_PROGRAM} add {key} /ve /t REG_SZ /d {data} /f",
            key = quoted(&key_path),
            data = quoted(manifest_absolute_path)
        ),
        delete_command: format!("{REG_PROGRAM} delete {} /ve /f", quoted(&key_path)),
        key_path,
        value_name: None,
    })
}

/// 构造 POSIX 注册计划。
///
/// `user_data_dir` = 内核启动时的 `--user-data-dir`（调用方给）；
/// `manifest_json` = [`crate::manifest::render_host_manifest`] 的产物。
///
/// # Errors
/// - `user_data_dir` 非 POSIX 绝对路径 ⇒ [`RegisterError::UserDataDirNotAbsolute`]；
/// - `manifest_json` 空 ⇒ [`RegisterError::EmptyManifest`]。
pub fn plan_posix(user_data_dir: &Path, manifest_json: &str) -> Result<PosixPlan, RegisterError> {
    if !is_absolute_path(&user_data_dir.to_string_lossy(), Platform::Posix) {
        return Err(RegisterError::UserDataDirNotAbsolute {
            dir: user_data_dir.display().to_string(),
        });
    }
    if manifest_json.is_empty() {
        return Err(RegisterError::EmptyManifest);
    }
    Ok(PosixPlan {
        manifest_file: user_data_dir
            .join(POSIX_USER_SUBDIR)
            .join(format!("{HOST_NAME}.json")),
        contents: manifest_json.to_owned(),
    })
}

/// 登记注册计划（平台分派）。
///
/// POSIX 分支真写文件（⛔ 不调 `runner`）；Windows 分支把命令行交给 `runner`。
///
/// # Errors
/// 见 [`RegisterError`]。
pub fn register<R: CommandRunner>(
    plan: &RegistrationPlan,
    runner: &R,
) -> Result<(), RegisterError> {
    match plan {
        RegistrationPlan::Posix(plan) => write_manifest_file(plan),
        RegistrationPlan::Windows(plan) => run_command(&plan.add_command, runner),
    }
}

/// 撤销注册计划（幂等：本来就不在 ⇒ 成功）。
///
/// ⛔ POSIX 只删我们自己那个 manifest 文件（不删目录）；Windows 只删该键的**默认值**
/// （`/ve`，不删整个键、不碰别人的键）。
///
/// # Errors
/// 见 [`RegisterError`]。
pub fn deregister<R: CommandRunner>(
    plan: &RegistrationPlan,
    runner: &R,
) -> Result<(), RegisterError> {
    match plan {
        RegistrationPlan::Posix(plan) => remove_manifest_file(plan),
        RegistrationPlan::Windows(plan) => run_command(&plan.delete_command, runner),
    }
}

/// 写 POSIX manifest 文件（先建父目录）。
fn write_manifest_file(plan: &PosixPlan) -> Result<(), RegisterError> {
    if let Some(parent) = plan.manifest_file.parent() {
        std::fs::create_dir_all(parent).map_err(|source| RegisterError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }
    std::fs::write(&plan.manifest_file, plan.contents.as_bytes()).map_err(|source| {
        RegisterError::Io {
            path: plan.manifest_file.display().to_string(),
            source,
        }
    })
}

/// 删 POSIX manifest 文件（NotFound 视为成功）。
///
/// ⛔ 只删**绝对路径**：相对路径会落到当前目录，删除操作必须 fail-closed。
fn remove_manifest_file(plan: &PosixPlan) -> Result<(), RegisterError> {
    if !is_absolute_path(&plan.manifest_file.to_string_lossy(), Platform::Posix) {
        return Err(RegisterError::ManifestFileNotAbsolute {
            path: plan.manifest_file.display().to_string(),
        });
    }
    match std::fs::remove_file(&plan.manifest_file) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(RegisterError::Io {
            path: plan.manifest_file.display().to_string(),
            source,
        }),
    }
}

/// 把命令行交给注入的执行器。
fn run_command<R: CommandRunner>(command_line: &str, runner: &R) -> Result<(), RegisterError> {
    runner
        .run(command_line)
        .map_err(RegisterError::RunnerFailed)
}

/// 命令行参数加引号（键与值都加：路径可能含空格，恒加更省心且确定性）。
///
/// ⛔ 只对**已确认不含 `"`** 的入参调用（见 [`plan_windows`] 的校验）。
fn quoted(arg: &str) -> String {
    format!("\"{arg}\"")
}
