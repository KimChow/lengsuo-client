//! L4 通道协商：**通道选择 / 能力集 / 世代号确认 / 错误码**。
//!
//! 本模块是「握手完成之后，双方用**控制帧**交换一份协商结果」的那一步：
//! 走 `p2p` 直连还是 `relay` 中继、各自支持哪些能力、确认世代号；
//! 协商失败时给出**明确的错误码**——**全程 fail-closed**。
//!
//! # 分层位置
//!
//! ```text
//! L1 传输（UDP / 打洞）  crates/lengsuo-tunnel      ← 不在本卡
//! L2 会话（密钥 / 世代号） crates/lengsuo-link-core/src/session
//! L3 密文帧               crates/lengsuo-link-core/src/frame
//! L4 通道协商（本模块）    crates/lengsuo-link-core/src/negotiate   ← 本卡
//! L5 ACP 语义             lengsuo-agent            ← 一行不改
//! ```
//!
//! # 两条轴：通道模式 vs 能力集
//!
//! | 轴 | 类型 | 回答的问题 | 交集为空的后果 |
//! |---|---|---|---|
//! | **通道模式** | [`ModeSet`]（2 位） | 「这条链路走 `p2p` 还是 `relay`？」 | **协商失败**（`NO_COMMON_CHANNEL_MODE`） |
//! | **能力集** | [`CapabilitySet`]（`u64`） | 「双方共同支持哪些可选特性？」 | 只表示「没有共同特性」，**协商仍可成功** |
//!
//! 详见 [`capabilities`] 的模块文档。
//!
//! # 协商流程
//!
//! ```text
//!  发起方                                        响应方
//!  ──────                                        ──────
//!  propose(mode)                                  │
//!      │  提案（控制帧 / 密文）                    │
//!      └─────────────────────────────────────────▶│
//!                                               accept_proposal()
//!                                                  │ 校验世代号
//!                                                  │ 求模式集交集 / 能力集交集
//!                                                  │ 选通道模式
//!      │  应答（控制帧 / 密文，带交集与选中模式）    │
//!      ◀─────────────────────────────────────────┘
//!  accept_response()
//!      │ 校验世代号 / 校验选中模式本端支持
//!      ▼
//!  Completed（结果：模式 + 能力集 + 世代号）
//! ```
//!
//! - **谁发起**：由 [`NegotiatorRole`] 固定（一次协商里角色不变）；
//! - **谁应答**：对侧角色相反的一端；
//! - **超时**：⛔ 本 crate **不起计时器**。调用方传入时间戳，
//!   用 [`Negotiator::is_timed_out`] 判定。
//!
//! # fail-closed 纪律
//!
//! - 协商失败 ⇒ **明确错误码**，⛔ **绝不**「协商不上就默认走 `p2p`」；
//! - 世代号不匹配 ⇒ **明确错误**，⛔ **不得**继续用旧连接；
//! - 能力集是**交集**（⛔ 不是并集）；未知位**忽略并记录**（单项 fail-open）；
//! - 载荷超限 ⇒ **明确错误**，⛔ **不截断**。
//!
//! # 无 IO
//!
//! 本模块**不碰** socket、文件、线程、计时器：时间由调用方显式传入
//! （`Instant`）。协商载荷走**同一条密文通道**（L3 控制帧），
//! ⛔ **没有明文旁路**。
//!
//! # 子模块
//!
//! | 模块 | 内容 |
//! |---|---|
//! | [`channel`] | 通道模式（`p2p` / `relay`）与模式集、模式选择规则 |
//! | [`capabilities`] | 能力位定义、能力集、**交集**规则与未知位纪律 |
//! | [`message`] | 协商消息的载荷格式与编解码（40 字节定长头 + TLV 扩展块） |
//! | [`error`] | 错误类型与**稳定错误码目录** |
//! | [`state`] | 角色 / 状态 / 协商结果类型 |
//! | [`negotiator`] | 协商状态机的编排（提案 / 应答 / 结果 / 超时判定） |

pub mod capabilities;
pub mod channel;
pub mod error;
pub mod message;
pub mod negotiator;
pub mod state;

pub use capabilities::{Capability, CapabilitySet};
pub use channel::{select_channel_mode, ChannelMode, ModeSet};
pub use error::{ErrorCode, NegotiateError};
pub use message::{
    decode_control, MessageKind, NegotiationExtension, NegotiationMessage, NEGOTIATE_HEADER_LEN,
    NEGOTIATE_MAGIC, NEGOTIATE_VERSION,
};
pub use negotiator::Negotiator;
pub use state::{NegotiateState, NegotiationResult, NegotiatorRole};
