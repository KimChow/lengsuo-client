//! 代理凭据的投递方式：**环境变量**或**凭据文件**，绝不进命令行。
//!
//! Windows 上任何进程的命令行都可以被同机的其他用户用 `wmic`／任务管理器
//! 读出来，所以口令一旦写进 `--proxy-server=...` 就等于公开。
//!
//! 本 crate 的做法是：
//! - 浏览器**只拿到代理端点**，浏览器侧的代理是本机侧车（sidecar），它对
//!   上游的认证由侧车自己用 [`crate::proxy::ProxyCredential`] 完成；
//! - 若上游代理要求认证，浏览器启动时通过
//!   [`CredentialInjection::EnvironmentVariable`]（默认）或
//!   [`CredentialInjection::File`] 把凭据交给**侧车进程**，而不是浏览器。
//!
//! 两条投递路径都**不进入** `std::process::Command` 的参数列表：
//! - 环境变量路径：凭据写在 `Command::env` 里，不在 `argv`；
//! - 文件路径：凭据写在 `user_data_dir` 下的权限受限文件里，不在 `argv`。
//!
//! 两种路径都在渲染命令行之后做一次**泄漏自检**：命令行里若出现凭据明文，
//! 启动直接失败（[`crate::error::LaunchError::CredentialLeak`]）。

use std::path::{Path, PathBuf};

use crate::error::LaunchError;
use crate::proxy::ProxyCredential;

/// 凭据文件名（放在用户数据目录内）。
pub const CREDENTIAL_FILE_NAME: &str = "lengsuo-proxy-credential.json";

/// 凭据注入方式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialInjection {
    /// 通过环境变量交给侧车进程。变量名由调用方指定，必须落在本 crate 的
    /// 命名空间前缀内（见 [`SIDE_CAR_ENV_PREFIX`]），避免覆盖无关变量。
    EnvironmentVariable {
        /// 环境变量名（不含前缀时自动补上）。
        variable: String,
    },
    /// 写进用户数据目录下的权限受限文件，由侧车读取。
    File {
        /// 覆盖默认文件名（默认 [`CREDENTIAL_FILE_NAME`]）。
        file_name: Option<String>,
    },
}

/// 本 crate 专用环境变量的前缀。
pub const SIDE_CAR_ENV_PREFIX: &str = "LENGSUO_PROXY_";

/// 一份已经落地的凭据投递计划。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialPlan {
    injection: CredentialInjection,
    variable: String,
    file_path: PathBuf,
    content: String,
}

impl CredentialPlan {
    /// 为一组凭据生成投递计划。
    ///
    /// `user_data_dir` 是该环境独占的用户数据目录；文件路径落在它里面，
    /// 保证**每个环境的凭据文件互不相同**。
    pub fn plan(
        credential: &ProxyCredential,
        injection: CredentialInjection,
        user_data_dir: &Path,
    ) -> Result<Self, LaunchError> {
        let variable = match &injection {
            CredentialInjection::EnvironmentVariable { variable } => {
                let name = if variable.starts_with(SIDE_CAR_ENV_PREFIX) {
                    variable.clone()
                } else {
                    format!("{SIDE_CAR_ENV_PREFIX}{variable}")
                };
                if !is_safe_env_name(&name) {
                    return Err(LaunchError::Argument("凭据环境变量名非法"));
                }
                name
            }
            CredentialInjection::File { file_name } => {
                let name = file_name
                    .clone()
                    .unwrap_or_else(|| CREDENTIAL_FILE_NAME.to_string());
                if !is_safe_file_name(&name) {
                    return Err(LaunchError::Argument("凭据文件名非法"));
                }
                name
            }
        };
        let file_path = user_data_dir.join(match &injection {
            CredentialInjection::File { file_name } => file_name
                .clone()
                .unwrap_or_else(|| CREDENTIAL_FILE_NAME.to_string()),
            CredentialInjection::EnvironmentVariable { .. } => CREDENTIAL_FILE_NAME.to_string(),
        });
        let content = render_credential_file(credential);
        Ok(Self {
            injection,
            variable,
            file_path,
            content,
        })
    }

    /// 注入方式。
    #[must_use]
    pub fn injection(&self) -> &CredentialInjection {
        &self.injection
    }

    /// 环境变量名（仅环境变量路径有效）。
    #[must_use]
    pub fn variable(&self) -> &str {
        &self.variable
    }

    /// 凭据文件路径（文件路径有效；环境变量路径也留一份副本作为侧车的
    /// 兜底读取点，文件内容与变量内容相同）。
    #[must_use]
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// 凭据文件内容（JSON，含明文）。
    #[must_use]
    pub fn file_content(&self) -> &str {
        &self.content
    }
}

/// 把凭据渲染成侧车可读的 JSON。
///
/// 明文只出现在这个函数的返回值里；调用方负责写文件或设环境变量，
/// **不得**把它拼进命令行。
pub fn render_credential_file(credential: &ProxyCredential) -> String {
    let mut out = String::from("{\"username\":");
    out.push_str(&json_string(credential.username()));
    out.push_str(",\"password\":");
    out.push_str(&json_string(credential.password()));
    out.push('}');
    out
}

/// 自检：命令行里若出现凭据明文，拒绝启动。
///
/// 这是**最后一道闸**：即便将来有人给 `--proxy-server` 加了 userinfo，
/// 也会在这里被拦住而不是悄悄泄露。
pub fn assert_no_credential_leak(
    command_line: &str,
    credential: &ProxyCredential,
) -> Result<(), LaunchError> {
    let user = credential.username();
    let password = credential.password();
    if (!user.is_empty() && command_line.contains(user))
        || (!password.is_empty() && command_line.contains(password))
    {
        return Err(LaunchError::CredentialLeak);
    }
    Ok(())
}

/// 环境变量名形状：ASCII 字母数字与下划线。
fn is_safe_env_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// 文件名形状：不含路径分隔符、不含 `..`、不是隐藏文件。
fn is_safe_file_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains(['/', '\\', '\0'])
        && !name.contains("..")
        && !name.starts_with('.')
}

/// 最小 JSON 字符串转义（侧车只需要 ASCII 常规字符）。
fn json_string(value: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::{
        assert_no_credential_leak, render_credential_file, CredentialInjection, CredentialPlan,
        CREDENTIAL_FILE_NAME, SIDE_CAR_ENV_PREFIX,
    };
    use crate::error::LaunchError;
    use crate::proxy::ProxyCredential;
    use std::path::Path;

    fn credential() -> ProxyCredential {
        ProxyCredential::new("alice", "s3cr3t-pw").unwrap()
    }

    #[test]
    fn an_env_plan_gets_the_namespace_prefix() {
        let plan = CredentialPlan::plan(
            &credential(),
            CredentialInjection::EnvironmentVariable {
                variable: "SIDECAR_AUTH".into(),
            },
            Path::new("/tmp/env-a"),
        )
        .unwrap();
        assert_eq!(plan.variable(), "LENGSUO_PROXY_SIDECAR_AUTH");
    }

    #[test]
    fn an_env_plan_keeps_an_explicit_namespace() {
        let plan = CredentialPlan::plan(
            &credential(),
            CredentialInjection::EnvironmentVariable {
                variable: format!("{SIDE_CAR_ENV_PREFIX}X"),
            },
            Path::new("/tmp/env-a"),
        )
        .unwrap();
        assert_eq!(plan.variable(), "LENGSUO_PROXY_X");
    }

    #[test]
    fn a_file_plan_lands_inside_the_environment_data_dir() {
        let plan = CredentialPlan::plan(
            &credential(),
            CredentialInjection::File { file_name: None },
            Path::new("/tmp/env-a"),
        )
        .unwrap();
        assert_eq!(
            plan.file_path(),
            Path::new("/tmp/env-a").join(CREDENTIAL_FILE_NAME)
        );
    }

    #[test]
    fn two_environments_get_two_different_credential_files() {
        let a = CredentialPlan::plan(
            &credential(),
            CredentialInjection::File { file_name: None },
            Path::new("/tmp/env-a"),
        )
        .unwrap();
        let b = CredentialPlan::plan(
            &credential(),
            CredentialInjection::File { file_name: None },
            Path::new("/tmp/env-b"),
        )
        .unwrap();
        assert_ne!(a.file_path(), b.file_path());
    }

    #[test]
    fn an_unsafe_file_name_is_refused() {
        let err = CredentialPlan::plan(
            &credential(),
            CredentialInjection::File {
                file_name: Some("../escape.json".into()),
            },
            Path::new("/tmp/env-a"),
        )
        .unwrap_err();
        assert_eq!(err, LaunchError::Argument("凭据文件名非法"));
    }

    #[test]
    fn the_credential_file_carries_the_plain_values() {
        let rendered = render_credential_file(&credential());
        assert!(rendered.contains("alice"));
        assert!(rendered.contains("s3cr3t-pw"));
    }

    #[test]
    fn a_command_line_with_the_password_is_refused() {
        let err = assert_no_credential_leak(
            "chrome --proxy-server=http://alice:s3cr3t-pw@127.0.0.1:8080",
            &credential(),
        )
        .unwrap_err();
        assert_eq!(err, LaunchError::CredentialLeak);
    }

    #[test]
    fn a_command_line_without_the_password_is_accepted() {
        assert!(assert_no_credential_leak(
            "chrome --proxy-server=http=127.0.0.1:8080",
            &credential()
        )
        .is_ok());
    }
}
