//! 规格 §1 数据模型分片：`action`。
//!
//! 统一从 [`crate::model`] 再导出，字段名/数值契约见本目录各文件。
//! 七项被管控操作及其开关（规格 §1 `actions`、§2.6）。

use serde::{Deserialize, Serialize};

/// 七个被管控的操作（规格 §1 `actions` 的键，也是 `EvaluateRequest::action`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    /// 访问页面本身。
    Access,
    /// 复制/读取剪贴板。
    Clipboard,
    /// 上传文件。
    FileUpload,
    /// 下载文件。
    FileDownload,
    /// 打印。
    Print,
    /// 打开控制台/开发者工具。
    Console,
    /// 点击 DOM 元素（需要选择器粒度）。
    ClickDom,
}

impl Action {
    /// 与 `actions` 对象键一致的规范名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Clipboard => "clipboard",
            Self::FileUpload => "file_upload",
            Self::FileDownload => "file_download",
            Self::Print => "print",
            Self::Console => "console",
            Self::ClickDom => "click_dom",
        }
    }

    /// 由规范名解析；未知名字返回 `None`（不猜测意图）。
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "access" => Self::Access,
            "clipboard" => Self::Clipboard,
            "file_upload" => Self::FileUpload,
            "file_download" => Self::FileDownload,
            "print" => Self::Print,
            "console" => Self::Console,
            "click_dom" => Self::ClickDom,
            _ => return None,
        })
    }
}

/// 单条规则的操作开关集合。
///
/// 缺省（`#[serde(default)]`）= 全 `false`，即「未显式授权的操作一律拒绝」。
/// 这是 deny-by-default 的唯一宽松点：字段可省略，省略的解释权是拒绝而非放行。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actions {
    /// 访问。
    #[serde(default)]
    pub access: bool,
    /// 剪贴板。
    #[serde(default)]
    pub clipboard: bool,
    /// 文件上传。
    #[serde(default)]
    pub file_upload: bool,
    /// 文件下载。
    #[serde(default)]
    pub file_download: bool,
    /// 打印。
    #[serde(default)]
    pub print: bool,
    /// 控制台。
    #[serde(default)]
    pub console: bool,
    /// 点击 DOM。
    #[serde(default)]
    pub click_dom: bool,
}

impl Actions {
    /// 全部拒绝。
    #[must_use]
    pub const fn none() -> Self {
        Self {
            access: false,
            clipboard: false,
            file_upload: false,
            file_download: false,
            print: false,
            console: false,
            click_dom: false,
        }
    }

    /// 全部允许（只用于测试与显式「全操作」规则）。
    #[must_use]
    pub const fn all() -> Self {
        Self {
            access: true,
            clipboard: true,
            file_upload: true,
            file_download: true,
            print: true,
            console: true,
            click_dom: true,
        }
    }

    /// 只开放访问操作，其余全拒。
    #[must_use]
    pub const fn access_only() -> Self {
        Self {
            access: true,
            ..Self::none()
        }
    }

    /// 查询某个操作的开关。
    #[must_use]
    pub const fn enabled(&self, action: Action) -> bool {
        match action {
            Action::Access => self.access,
            Action::Clipboard => self.clipboard,
            Action::FileUpload => self.file_upload,
            Action::FileDownload => self.file_download,
            Action::Print => self.print,
            Action::Console => self.console,
            Action::ClickDom => self.click_dom,
        }
    }
}
