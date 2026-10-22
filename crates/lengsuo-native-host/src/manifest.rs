//! Host manifest 渲染（Chromium `native_messaging_host_manifest.cc` 读取的形状）。
//!
//! # 输出（冻结）
//!
//! ```json
//! {"name":"lengsuo.credential","allowed_origins":["chrome-extension://ejlmmjamfpkoopjachjhcbdjlddknhok/"]}
//! ```
//!
//! - `name` 取契约 §6 的 host 名 `lengsuo.credential`（与
//!   `lengsuo_browser_extension::HOST_NAME` 同值，但本 crate 不依赖它，故本地常量）；
//! - `allowed_origins` **只有一项**：本扩展的 origin，带尾斜杠、无通配 `*`；
//! - 字段顺序固定 `name` 在前、`allowed_origins` 在后，无空白、无尾换行。
//!
//! # 为什么不带 `key`
//!
//! 契约 §5.0 要求安装清单带 `key`（公钥 PEM），否则 Chromium 退回按路径派生、ID 会漂。
//! ⛔ 公钥是部署期材料，**不在源码里**；本模块只渲染 `name` + `allowed_origins`，
//! 上层的安装器负责把 `key` 合进最终文件（见报告「待外部补」）。
//!
//! ⛔ **纯函数、不写文件**：落盘属于安装 / 注册层。

use crate::extension::EXTENSION_ORIGIN;

/// Host 名（契约 §6）。
pub const HOST_NAME: &str = "lengsuo.credential";

/// 渲染 host manifest 的 JSON 文本（无尾换行）。
#[must_use]
pub fn render_host_manifest() -> String {
    format!("{{\"name\":\"{HOST_NAME}\",\"allowed_origins\":[\"{EXTENSION_ORIGIN}\"]}}")
}
