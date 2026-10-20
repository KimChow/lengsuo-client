//! 浏览器进程启动与就绪探测（占位骨架，由对应开发卡填充实现）。
//!
//! 见 crate 级文档的契约边界说明。

/// 浏览器可执行文件的定位结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserBinary {
    /// 已定位到的可执行文件路径。
    Found(std::path::PathBuf),
    /// 未找到可执行文件（**fail-closed**，不得降级为裸连）。
    Missing,
}
