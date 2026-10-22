//! 凭据体系的 Native Messaging **宿主进程传输层**（管道帧编解码 + 来源解析）。
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
//! | [`error`] | 类型化错误（每类失败一个具名变体） |
//!
//! # 字节真相
//!
//! Chromium 155 的 `chrome/browser/extensions/api/messaging/`：
//! - 写侧 `native_message_process_host.cc` `OnMessage`（`memcpy` 本机字节序 `uint32_t`）；
//! - 读侧同文件 `ProcessIncomingData`（裸解 `uint32_t`，攒够一整帧才交付）。
//!
//! # 纯函数层
//!
//! ⛔ 本 crate **不做 IO**：不碰 socket、不读写 stdin/stdout、不启动进程、
//! 不写宿主清单、不读环境变量。进程启动与注册属于后续的接线层。
//!
//! # 许可
//!
//! 纯手写实现（只按字节语义重写，不复制参考实现源码），只依赖 `thiserror`
//! （MIT/Apache-2.0）⇒ **可商用闭源**。⛔ 不含任何 GPL-3.0 实现的代码。

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
pub mod frame;
pub mod origin;

pub use error::{FrameError, IdFormatError, OriginError};
pub use frame::{
    decode_frame, encode_frame, FrameDecoder, FRAME_HEADER_LEN, MAX_FRAME_PAYLOAD_LEN,
};
pub use origin::{parse_extension_id, EXTENSION_ID_LEN, EXTENSION_SCHEME_PREFIX};
