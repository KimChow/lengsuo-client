//! 凭据体系的 Native Messaging **宿主进程传输层**。
//!
//! 本 crate 实现的是 **宿主进程与 Chromium 之间的管道帧**，
//! 与凭据线契约 §5.2 的「扩展 ⇄ 宿主消息帧」是**两层不同的东西**。
//!
//! 本 crate 的字节布局以 Chromium 155 自身实现为唯一真相
//! （`chrome/browser/extensions/api/messaging/`），
//! 派卡方已逐行核实并写入任务书。
#![forbid(unsafe_code)]
#![deny(missing_docs)]
