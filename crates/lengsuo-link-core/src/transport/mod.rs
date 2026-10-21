//! L1 传输抽象：**字节搬运**的 trait + L1↔L2 的接线层。
//!
//! 本模块是「跨端 P2P 方案 B（T2）」的**最底层**：在 L2 会话（密钥、世代号）
//! 与 L3 密文帧之下，定义「怎么把**已经封好**的字节搬到对端」。
//!
//! # 分层位置
//!
//! ```text
//! L1 传输（本模块）        crates/lengsuo-link-core/src/transport  ← 本卡
//! L2 会话                 crates/lengsuo-link-core/src/session
//! L3 密文帧               crates/lengsuo-link-core/src/frame
//! L4 通道协商             crates/lengsuo-link-core/src/negotiate
//! L5 ACP 语义             lengsuo-agent            ← 一行不改
//! ```
//!
//! # 一句话
//!
//! 把「怎么把密文帧的字节搬到对端」抽象成一个 trait，
//! 并提供**把 L2 会话接到该 trait 上的胶水层**
//! （`seal_frame` → 搬出去；搬回来 → `open_frame`）。
//!
//! # 三条纪律
//!
//! 1. **搬运层只认字节**：⛔ trait **不要求**实现方提供明文语义；
//!    搬运层永远拿不到明文。
//! 2. **明文旁路不存在**：⛔ 任何「明文直接上链路」的通道都不许有。
//!    明文只在 [`Link::send_frame`] 里变成密文（见 [`link`] 模块文档）。
//! 3. **fail-closed**：认证失败 / 会话失效 / 超长字节 ⇒ **明确错误**，
//!    ⛔ 不回退明文、⛔ 不截断、⛔ 不吞错当成功。
//!
//! # 无 IO
//!
//! 本 crate 仍然**无 IO**：⛔ 无 tokio、⛔ 无 socket、⛔ 无文件、⛔ 无线程、
//! ⛔ 无计时器。**同步/阻塞语义由调用方决定**——trait 本身不约束实现方
//! 用同步 socket 还是别的什么。
//!
//! ⚠️ **L1 的「实现」（UDP socket）不在本卡**：
//! `crates/lengsuo-tunnel` 负责 UDP / 打洞 / endpoint 漫游 / keepalive 定时器。
//! 本卡只交付**抽象 + 接线 + 可测的内存环回**。
//!
//! # 子模块
//!
//! | 模块 | 内容 |
//! |---|---|
//! | [`trait_def`] | [`Transport`] trait（发送 / 接收 / 长度上限）与契约 |
//! | [`link`] | [`Link`] 接线层：`Session` + `Transport` ⇒ 收发明文帧 |
//! | [`loopback`] | [`Loopback`]：内存环回实现（测试与自检用） |
//! | [`error`] | [`TransportError`] 与**稳定错误码目录** [`ErrorCode`] |

pub mod error;
pub mod link;
pub mod loopback;
pub mod trait_def;

pub use error::{ErrorCode, TransportError};
pub use link::Link;
pub use loopback::Loopback;
pub use trait_def::Transport;
