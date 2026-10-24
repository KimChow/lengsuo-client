//! 进程入口接线（lib 侧**纯逻辑**，IO 可注入、不碰全局状态）：
//! argv 解析 → 来源严格校验 → 管道帧主循环。
//!
//! bin 目标（`src/main.rs`）只负责取真实 stdio 锁并把结果映射成退出码；
//! 所有可测逻辑都在本模块。
//!
//! # argv 形状（两平台一致的真相，`launch_context.cc:201-213`）
//!
//! | 平台 | `argv[0]` | `argv[1]` | `argv[2..]` |
//! |---|---|---|---|
//! | POSIX | 程序名 | origin（必须第一个参数，`:204-206`） | 无 |
//! | Windows | 程序名 | origin | `--parent-window=<句柄>`（`:210-213`） |
//!
//! ⇒ origin 恒为 `argv[1]`；`argv[2..]` **一律忽略**（不识别、也不拒绝）——
//! 若「未知参数即失败」，Windows 上宿主永远起不来。
//!
//! # fail-closed 顺序
//!
//! [`run_host`] 先做来源严格校验（[`require_our_extension`]），**通过之前一个字节
//! 都不读、不写**；校验失败 ⇒ 以具名错误立即终止（退出码见 [`HostError::exit_code`]）。

use std::ffi::OsString;
use std::io::{Read, Write};

use crate::error::{LoopError, OriginError};
use crate::extension::require_our_extension;
use crate::io_loop::{self, LoopOutcome, UnwiredDispatch};

/// 宿主进程启动 / 运行失败（变体之间互相可区分 ⇒ 各自的退出码）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostError {
    /// 没有 `argv[1]`：Chromium 必传 origin（`launch_context.cc:206`），
    /// 缺失说明宿主不是被浏览器正常拉起的。
    #[error("缺少 origin 参数：argv[1] 必须是扩展 origin")]
    MissingOrigin,

    /// `argv[1]` 不是合法 UTF-8。
    #[error("origin 参数不是合法 UTF-8")]
    NonUtf8Origin,

    /// 来源校验失败（形状 / 格式 / 值，见 [`OriginError`]）。
    #[error("来源校验失败：{0}")]
    Origin(
        #[from]
        #[source]
        OriginError,
    ),

    /// 主循环失败（见 [`LoopError`]；其 Display 保证不含载荷字节）。
    #[error("主循环失败：{0}")]
    Loop(
        #[from]
        #[source]
        LoopError,
    ),
}

impl HostError {
    /// 进程退出码（自设工程决定，失败类别互相可区分）：
    ///
    /// | 取值 | 含义 |
    /// |---|---|
    /// | 0 | 主循环在帧边界正常关闭（`LoopOutcome::Closed`） |
    /// | 2 | 缺 `argv[1]`（[`HostError::MissingOrigin`]） |
    /// | 3 | `argv[1]` 非 UTF-8（[`HostError::NonUtf8Origin`]） |
    /// | 4 | 来源校验失败（[`HostError::Origin`]） |
    /// | 5 | 主循环失败（[`HostError::Loop`]） |
    ///
    /// ⛔ 失败绝不映射成 0：Chromium 只看通道是否关闭，但排障必须能分辨失败类别。
    /// 1 留给「未分类失败」（shell / 运行时的通用约定），本宿主不主动使用。
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::MissingOrigin => 2,
            Self::NonUtf8Origin => 3,
            Self::Origin(_) => 4,
            Self::Loop(_) => 5,
        }
    }
}

/// 解析启动参数：`argv[1]` 是 origin，`argv[2..]` 一律忽略。
///
/// 参数以迭代器注入（bin 入口传 [`std::env::args_os`]，单测可传任意序列）。
/// ⛔ 不用 `std::env::args()`：非 UTF-8 参数会让它 panic；这里对 `argv[1]`
/// 显式转 UTF-8，失败即具名错误。
///
/// # Errors
/// - 迭代器不足两个元素（无 `argv[1]`）⇒ [`HostError::MissingOrigin`]。
/// - `argv[1]` 非 UTF-8 ⇒ [`HostError::NonUtf8Origin`]。
pub fn parse_launch_args<I>(mut args: I) -> Result<String, HostError>
where
    I: Iterator<Item = OsString>,
{
    let _ = args.next(); // argv[0] 是程序名，不是 origin。
    let Some(raw) = args.next() else {
        return Err(HostError::MissingOrigin);
    };
    let origin = raw.to_str().ok_or(HostError::NonUtf8Origin)?;
    // argv[2..] 一律忽略（Windows 的 --parent-window=<句柄>，launch_context.cc:210-213）；
    // ⛔ 不做「未知参数即失败」，也不把 argv[2] 当 origin。
    Ok(origin.to_owned())
}

/// 跑宿主进程主体：来源严格校验 → 管道帧主循环（生产编解码器 + [`UnwiredDispatch`]）。
///
/// 业务分派保持「未接线」：所有业务消息一律 [`crate::io_loop::Dispatch::NoReply`]，
/// **不伪造成功响应**（payload 契约未定，那是另一张卡的阻塞点）。
///
/// # Errors
/// - 来源不是本扩展 ⇒ [`HostError::Origin`]（**此时尚未读写任何字节**）。
/// - 主循环失败 ⇒ [`HostError::Loop`]。
pub fn run_host<R: Read, W: Write>(
    origin: &str,
    input: &mut R,
    output: &mut W,
) -> Result<LoopOutcome, HostError> {
    require_our_extension(origin)?;
    Ok(io_loop::run(input, output, &mut UnwiredDispatch)?)
}
