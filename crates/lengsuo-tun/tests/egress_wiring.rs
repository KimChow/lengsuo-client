//! 出口方向接线测试：包 → 归因 → 选协议出口 → 交给出口运行时。
//!
//! # 性质（重要，勿误读）
//!
//! 本用例**不碰真实网卡、不建真实 socket、不做协议互通**：出口运行时是内存假实现。
//! 因此本套件证明的是**接线层的决策语义**（归因 → 选出口 → 复用 → 释放 →
//! fail-closed），**不是**与任何外部实现的互通。
//!
//! # 依赖方向的实测证据
//!
//! `lengsuo-environment` **依赖** `lengsuo-tun`（它复用 `PacketInfo`），故
//! `lengsuo-tun` 反向依赖它会构成 **cargo 依赖环**、cargo 直接拒绝构建（本卡已用
//! 最小复现工程实测复现）。生产侧因此只定义两个 trait 由上层注入；测试侧
//! `lengsuo-environment` 是本 crate 的 **dev-dependency**，本文件因此用**真实的
//! `lengsuo_environment::Router`** 做权威来源，验证 trait 与真实路由核心一致。
//!
//! 全部用例带总超时，不使用主机绝对路径、不含真实凭据。
//!
//! # 组织方式
//!
//! 原单文件 697 行（离 700 硬上限只差 3 行），按**主题**拆成本目录下的三个子模块：
//! - [`support`]：共享夹具（真实权威来源适配、内存假运行时、报文与路由构造）。
//! - [`routing`]：选路与归属（归因命中 / 无归属 / 设备离线 / 协议不可用 / 换绑）。
//! - [`session`]：会话与租约（复用 / 释放 / 过期 GC / 无路由）。
//! - [`pipeline`]：ingress 管道接入（整链跑通、拒绝计入出口错误）。

#[path = "egress_wiring/pipeline.rs"]
mod pipeline;
#[path = "egress_wiring/routing.rs"]
mod routing;
#[path = "egress_wiring/session.rs"]
mod session;
#[path = "egress_wiring/support.rs"]
mod support;
