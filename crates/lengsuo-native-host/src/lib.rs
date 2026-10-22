//! 凭据体系的 Native Messaging **宿主进程接线层**（管道帧、来源校验、扩展 ID 严格校验、
//! manifest 渲染、stdin/stdout 主循环框架）。
//!
//! 本 crate 实现的是 **宿主进程与 Chromium 之间的管道帧**，
//! 与凭据线契约 §5.2 的「扩展 ⇄ 宿主消息帧」是**两层不同的东西**。
//!
//! | 层 | 谁定字节 | 本 crate |
//! |---|---|---|
//! | 管道帧（宿主 ⇄ Chromium） | **Chromium 自身的实现** | ✅ 本 crate |
//! | 业务消息帧（扩展 ⇄ 宿主） | 凭据线契约 §5.2 | ⛔ 不是本 crate |
//!
//! 一条管道帧的 JSON 载荷里装着一条业务消息帧。
//!
//! | 模块 | 内容 |
//! |---|---|
//! | [`frame`] | 管道帧编解码（4 字节本机字节序长度前缀 + JSON 载荷） |
//! | [`origin`] | 来源解析（从 `argv[1]` 取出扩展 ID + 格式校验） |
//! | [`extension`] | 扩展 ID **严格值校验** + 本扩展 ID / origin 常量（契约 §5.0） |
//! | [`manifest`] | host manifest 渲染（`allowed_origins` 只含本扩展，纯函数） |
//! | [`io_loop`] | stdin/stdout 主循环框架（管道帧 → 信封 → 业务帧 → 分派接口） |
//! | [`error`] | 类型化错误（每类失败一个具名变体） |
//!
//! # 字节真相
//!
//! Chromium 155 的 `chrome/browser/extensions/api/messaging/`：
//! - 写侧 `native_message_process_host.cc` `OnMessage`（`memcpy` 本机字节序 `uint32_t`）；
//! - 读侧同文件 `ProcessIncomingData`（裸解 `uint32_t`，攒够一整帧才交付）。
//!
//! # 信封层未接线（⚠️ 本卡开箱状态）
//!
//! [`io_loop`] 负责「管道帧 → 信封文本 → 业务帧 → 分派」的搬运与边界校验；
//! 信封文本的编解码属于 W3b-2a（`lengsuo-browser-extension` 的
//! `decode_frame_b64` / `encode_frame_b64`），⛔ 本 crate 不复制 base64 / JSON 解析。
//! 本卡路径边界不含 `Cargo.toml` ⇒ 生产用编解码器以一个接口
//! [`io_loop::EnvelopeCodec`] 留口，目前是 [`io_loop::UnwiredEnvelope`]（显式拒绝）；
//! 接线见报告「待基建卡」。主循环因此**尚不能端到端跑通**，单测用测试夹具编解码器
//! 走通除信封层外的全部路径。
//!
//! # 业务分派目标待 W4/W5
//!
//! [`io_loop::run`] 只定义分派接口 [`io_loop::MessageDispatch`]；
//! 本卡提供 [`io_loop::UnwiredDispatch`]（一律「未接线」、不回包）。
//! W4 的页面劫持 / 11 种消息业务落地后替换分派器即可，主循环字节语义不变。
//!
//! # IO 纪律
//!
//! ⛔ 本 crate 不碰进程真实 stdin/stdout、不起进程、不开线程、不写文件：
//! stdin/stdout 主循环对 `Read` / `Write` 泛型，单测走内存 `Cursor`。
//! 不读环境变量；进程启动与 manifest 落盘属于后续的接线层。
//!
//! # 许可
//!
//! 纯手写实现（只按字节语义重写，不复制参考实现源码），只依赖 `thiserror`
//! （MIT/Apache-2.0）⇒ **可商用闭源**。⛔ 不含任何 GPL-3.0 实现的代码。

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
pub mod extension;
pub mod frame;
pub mod io_loop;
pub mod manifest;
pub mod origin;

pub use error::{FrameError, IdFormatError, LoopError, OriginError};
pub use extension::{
    require_our_extension, require_our_id, strict_eq, EXTENSION_ID, EXTENSION_ORIGIN,
};
pub use frame::{
    decode_frame, encode_frame, FrameDecoder, FRAME_HEADER_LEN, MAX_FRAME_PAYLOAD_LEN,
};
pub use io_loop::{
    run, run_with, Dispatch, EnvelopeCodec, LoopOutcome, MessageDispatch, UnwiredDispatch,
    UnwiredEnvelope,
};
pub use manifest::{render_host_manifest, HOST_NAME};
pub use origin::{parse_extension_id, EXTENSION_ID_LEN, EXTENSION_SCHEME_PREFIX};
