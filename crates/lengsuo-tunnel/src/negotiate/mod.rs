//! L4 通道协商的**装配侧接线**。
//!
//! # 这一层补的是什么
//!
//! `lengsuo-link-core::negotiate` 是 L4 的**协议真相**（状态机 + 载荷格式 +
//! 稳定错误码），但它**无 IO** ⇒ 生产路径上从不被调用。
//! 本模块是 PC 端隧道装配层的接线：把协商驱动器挂进 [`crate::assembly`]，
//! 让控制帧真的能驱动一次 L4 协商。
//!
//! | 谁 | 类型 | 干什么 |
//! |---|---|---|
//! | 协议真相 | `lengsuo_link_core::negotiate::Negotiator` | L4 语义（状态机 / 选模式 / 算交集） |
//! | 装配侧 | [`NegotiateDriver`] | 接线（角色、帧类型纪律、把结果交给上层） |
//!
//! ⛔ **本模块不重写任何 L4 语义**：状态机、载荷编解码、能力集交集、
//! 错误码目录**全部**来自 `lengsuo-link-core`。这里只做三件事：
//!
//! 1. 把「请求哪个通道模式」从配置里带进来；
//! 2. 保证协商载荷**只**走控制帧（[`decode_control`] 是唯一入口）；
//! 3. 把协商的每一步以**可判定**的形式交回上层。
//!
//! # 帧类型纪律
//!
//! 协商载荷**只能**封进控制帧：走别的帧类型 ⇒
//! [`NegotiateError::WrongFrameType`]（fail-closed，⛔ **不解析**载荷、
//! ⛔ 没有明文旁路）。
//!
//! # 失败语义（全部 fail-closed）
//!
//! | 场景 | 错误码 | ⛔ 不得 |
//! |---|---|---|
//! | 协商载荷走错帧类型 | `WRONG_FRAME_TYPE` | 解析载荷 |
//! | 双方无共同通道模式 | `NO_COMMON_CHANNEL_MODE` | 回退到某个默认模式 |
//! | 世代号不匹配 | `GENERATION_MISMATCH` | 继续用旧连接 |
//! | 重复发起 | `INVALID_STATE` | 复用半成品协商器 |
//! | 角色不匹配 | `ROLE_MISMATCH` | 换角色硬来 |
//! | 对端选中的模式本端不支持 | `CHANNEL_MODE_NOT_ACCEPTED` | 接受该结果 |
//!
//! # 证据边界
//!
//! ⚠️ 本模块的验证只到 **Rust ↔ Rust 的字节级一致**
//! （见 `tests/negotiate_wire.rs`）。移动端仓**尚不存在**
//! ⇒ ⛔ 不得声称「已与移动端互通」。

pub mod config;
pub mod driver;

pub use self::config::NegotiateConfig;
pub use self::driver::{NegotiateDriver, NegotiationStep};

pub use lengsuo_link_core::negotiate::{
    Capability, CapabilitySet, ChannelMode, ErrorCode, ModeSet, NegotiateError, NegotiateState,
    NegotiationResult, NegotiatorRole,
};
pub use lengsuo_link_core::session::Generation;
