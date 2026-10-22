//! 出口方向接线：包 → 环境归因 → 选协议出口 → 交给出口运行时。
//!
//! 本模块**不碰真实网卡、不自己拨号**：它只做决策层——把「已归因的包」映射到
//! 「一条具体的协议出口」，并把决策过程变成可审计的结构（`reason` 枚举 + 命中的
//! 绑定 id）。真实协议栈的建连由注入的 [`OutboundRuntime`] 承担。
//!
//! ## 依赖方向（重要，已实测）
//!
//! `lengsuo-environment` **依赖**本 crate（它复用 [`crate::packet::PacketInfo`]），
//! 因此本 crate 若反向依赖它会构成 **cargo 依赖环**、cargo 直接拒绝构建（本卡已
//! 用最小复现工程实测复现）。本模块因此只定义两个 trait（[`BindingAuthority`] /
//! [`OutboundRuntime`]）并由上层注入实现；真实 `lengsuo_environment::Router` 的
//! 适配见 `tests/egress_wiring.rs`。
//!
//! ## 安全语义（全部 fail-closed，**没有第三种「直连」出口**）
//!
//! - 归因不到环境 ⇒ [`DenyReason::NoAttribution`]，**不回落默认直连**。
//! - 环境无绑定 ⇒ [`DenyReason::UnknownEnvironment`]。
//! - 绑定设备离线 ⇒ [`DenyReason::DeviceOffline`]。
//! - 归因的设备/代次落后于权威绑定 ⇒ [`DenyReason::StaleAttribution`]。
//! - 会话持有的租约不再有效（`validate` 失败）⇒ [`DenyReason::StaleLease`]。
//! - 该设备配置的协议出口不可用 ⇒ [`DenyReason::ProtocolUnavailable`]，
//!   **不静默改用别的协议**。
//! - 查不到出接口 ⇒ [`DenyReason::NoRoute`]（出接口由路由表选定）。
//! - 会话表满 ⇒ [`DenyReason::Capacity`]（不驱逐既有会话，且释放刚建的出口）。
//!
//! 决策结果与绑定 id 只含环境号、设备号、代次、协议名与出接口索引，**不含**口令、
//! 密钥或完整配置。
//!
//! ## 与既有路径的分工
//!
//! - `crate::tcp::connector::route` 选的是**出接口**（哪块网卡）；本模块选的是
//!   **协议出口**（trojan/anytls/… 的哪一条）。两者职责不重叠、不重复实现路由表。
//! - `crate::ingress` 的 `Ingress<D, C, E>` 是既有的三段式管道；本模块的
//!   [`EgressSelector`] 通过 `crate::ingress::SelectorSink` 接进它的 sink 侧，
//!   **不重写** ingress 的事件循环。

mod authority;
mod node_runtime;
mod runtime;
mod selector;

pub use authority::{
    Attribution, AuthorityError, BindingAuthority, BindingId, DeviceId, EnvironmentId, Lease,
};
pub use node_runtime::NodeOutboundRuntime;
pub use runtime::{
    OutboundExchange, OutboundProtocol, OutboundRuntime, OutboundSession, RuntimeError,
};
pub use selector::{
    DenyReason, EgressDecision, EgressError, EgressHandle, EgressSelector, SelectionReason,
};
