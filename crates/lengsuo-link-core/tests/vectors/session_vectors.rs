//! L2 会话向量：握手报文 / 收发帧 / 重连的**字节级**跨端向量。
//!
//! # 覆盖什么
//!
//! - **发起方铸出的 initiation 报文**（148B）；
//! - **响应方铸出的 response 报文**（92B）；
//! - 握手成功后**双方**的世代号取值；
//! - 握手成功后**双向**封帧的**整帧期望字节**；
//! - **重连**（第二轮握手）后的世代号与新的期望字节。
//!
//! # ⛔ 关键约束：握手报文**不是**整份逐字节可复现的
//!
//! `lengsuo-wireguard` 的握手时间戳取自**系统墙钟**
//! （`tai64n_now()`，纳秒掩到 ~16.78ms 刻度），且
//! `create_initiation` / `consume_initiation` 都**不接受注入时间**
//! ⇒ 报文里有一段**依赖墙钟**的字节，跨进程跑必然不同。
//!
//! 实测确认的**确定性边界**（本卡用探针在两个独立进程里逐字节比对过）：
//!
//! | 报文 | 依赖墙钟的字节区间 | 含义 |
//! |---|---|---|
//! | initiation (148B) | `[88,132)` | TAI64N 时间戳密文(28B) + 其 MAC1(16B) |
//! | response (92B) | `[44,76)` | empty 密文(16B) + 其 MAC1(16B) |
//!
//! 其余字节（类型/index/临时公钥/静态公钥密文/MAC2）**逐字节可复现**。
//!
//! ⇒ 本卡的做法：**同时**给出
//! - `canonical_hex`：整份报文，把墙钟区段**清零**后的字节；
//! - `volatile_ranges` / `volatile_layout`：**声明**哪一段是墙钟依赖（移动端
//!   对这段**不做**逐字节比对，只做结构/长度检查）。
//!
//! 而**传输密钥**与**密文帧**（transport 层的 nonce 由计数器派生、不含随机数）
//! 是**整份逐字节可复现**的 ⇒ 那些向量给**完整的期望字节**。
//!
//! # 密钥纪律
//!
//! 全部是**测试专用假密钥**（`0x11` / `0x22` / `0x33` / `0x44` 模式字节），
//! **不得**用于任何真实会话。对端公钥由仓外独立实现（Python `cryptography`
//! 的 X25519）算出后写死 ⇒ 不依赖本仓的 X25519 代码自证。

use lengsuo_link_core::frame::FrameType;

pub use super::session_data::SESSION_VECTORS_JSON;
use super::{from_hex, key32, num_field, object_item, str_field};

/// 向量 JSON 的**格式标识**（移动端按它识别这是哪一版向量）。
pub const FORMAT: &str = "lengsuo-link-session-vectors";
/// 向量 JSON 的**版本号**。
pub const VERSION: u64 = 1;
/// 向量 JSON 指向的规范文档。
pub const SPEC: &str = "docs/link-vectors-spec.md";

/// initiation 里**依赖墙钟**的字节区间（半开区间）。
pub const INITIATION_VOLATILE: &str = "88-132";
/// response 里**依赖墙钟**的字节区间（半开区间）。
pub const RESPONSE_VOLATILE: &str = "44-76";

/// initiation 墙钟区段的布局说明。
pub const INITIATION_VOLATILE_LAYOUT: &str =
    "bytes[88..116]=TAI64N 时间戳密文(28B), bytes[116..132]=覆盖前者的 MAC1(16B)";
/// response 墙钟区段的布局说明。
pub const RESPONSE_VOLATILE_LAYOUT: &str =
    "bytes[44..60]=empty 密文(16B, AAD=当前 hash 链), bytes[60..76]=覆盖前者的 MAC1(16B)";

/// 一条链路的**密钥材料**（测试专用假密钥）。
#[derive(Debug, Clone)]
pub struct LinkMaterial {
    /// 发起方静态私钥。
    pub initiator_static_private: [u8; 32],
    /// 发起方静态公钥。
    pub initiator_static_public: [u8; 32],
    /// 响应方静态私钥。
    pub responder_static_private: [u8; 32],
    /// 响应方静态公钥。
    pub responder_static_public: [u8; 32],
}

/// 一份握手报文的向量（**墙钟区段已清零**的 canonical 形式）。
#[derive(Debug, Clone)]
pub struct MessageVector {
    /// 依赖墙钟的字节区间（半开区间）。
    pub volatile_ranges: Vec<(usize, usize)>,
    /// 墙钟区段的布局说明。
    pub volatile_layout: String,
    /// canonical 字节（墙钟区段清零）。
    pub canonical: Vec<u8>,
}

/// 传输密钥向量（双方各两把）。
#[derive(Debug, Clone)]
pub struct TransportKeys {
    /// 发起方发送密钥。
    pub initiator_send: [u8; 32],
    /// 发起方接收密钥。
    pub initiator_receive: [u8; 32],
    /// 响应方发送密钥。
    pub responder_send: [u8; 32],
    /// 响应方接收密钥。
    pub responder_receive: [u8; 32],
}

/// 一条密文帧向量（**整帧期望字节**）。
#[derive(Debug, Clone)]
pub struct FrameVector {
    /// 帧名（链路内唯一）。
    pub name: String,
    /// 帧方向。
    pub direction: String,
    /// 帧类型。
    pub frame_type: FrameType,
    /// 帧序号。
    pub seq: u64,
    /// 传输层计数器（决定 nonce；**每个方向各自**从 0 开始）。
    pub counter: u64,
    /// 明文。
    pub plaintext: Vec<u8>,
    /// 期望的整帧字节。
    pub frame: Vec<u8>,
}

/// 一轮握手的向量。
#[derive(Debug, Clone)]
pub struct RoundVector {
    /// 轮次（从 1 开始）。
    pub round: u64,
    /// 发起方本轮 index。
    pub initiator_index: u32,
    /// 响应方本轮 index。
    pub responder_index: u32,
    /// 发起方本轮临时私钥种子。
    pub initiator_seed: [u8; 32],
    /// 响应方本轮临时私钥种子。
    pub responder_seed: [u8; 32],
    /// 握手成功后的世代号（双方一致）。
    pub generation: u64,
    /// initiation 报文向量。
    pub initiation: MessageVector,
    /// response 报文向量。
    pub response: MessageVector,
    /// 传输密钥向量。
    pub transport_keys: TransportKeys,
    /// 帧向量（按发送顺序）。
    pub frames: Vec<FrameVector>,
}

/// 一条链路的向量。
#[derive(Debug, Clone)]
pub struct LinkVector {
    /// 链路名。
    pub name: String,
    /// 密钥材料。
    pub material: LinkMaterial,
    /// 各轮握手。
    pub rounds: Vec<RoundVector>,
}

/// 解析一条握手报文向量。
fn message_vector(item: &str) -> MessageVector {
    MessageVector {
        volatile_ranges: super::parse_ranges(&str_field(item, "volatile_ranges")),
        volatile_layout: str_field(item, "volatile_layout"),
        canonical: from_hex(&str_field(item, "canonical_hex")),
    }
}

/// 解析传输密钥向量。
fn transport_keys(item: &str) -> TransportKeys {
    TransportKeys {
        initiator_send: key32(&str_field(item, "initiator_send_hex")),
        initiator_receive: key32(&str_field(item, "initiator_receive_hex")),
        responder_send: key32(&str_field(item, "responder_send_hex")),
        responder_receive: key32(&str_field(item, "responder_receive_hex")),
    }
}

/// 解析一条帧向量。
fn frame_vector(item: &str) -> FrameVector {
    FrameVector {
        name: str_field(item, "name"),
        direction: str_field(item, "direction"),
        frame_type: super::frame_type_from_name(&str_field(item, "frame_type")),
        seq: num_field(item, "seq"),
        counter: num_field(item, "counter"),
        plaintext: from_hex(&str_field(item, "plaintext_hex")),
        frame: from_hex(&str_field(item, "frame_hex")),
    }
}

/// 解析一条链路的向量。
fn link_vector(item: &str) -> LinkVector {
    let material = LinkMaterial {
        initiator_static_private: key32(&str_field(item, "initiator_static_private_hex")),
        initiator_static_public: key32(&str_field(item, "initiator_static_public_hex")),
        responder_static_private: key32(&str_field(item, "responder_static_private_hex")),
        responder_static_public: key32(&str_field(item, "responder_static_public_hex")),
    };
    let rounds = super::array_items(item, "rounds")
        .iter()
        .map(|round| RoundVector {
            round: num_field(round, "round"),
            initiator_index: num_field(round, "initiator_index") as u32,
            responder_index: num_field(round, "responder_index") as u32,
            initiator_seed: key32(&str_field(round, "initiator_ephemeral_seed_hex")),
            responder_seed: key32(&str_field(round, "responder_ephemeral_seed_hex")),
            generation: num_field(round, "generation"),
            initiation: message_vector(&object_item(round, "initiation")),
            response: message_vector(&object_item(round, "response")),
            transport_keys: transport_keys(&object_item(round, "transport_keys")),
            frames: super::array_items(round, "frames")
                .iter()
                .map(|frame| frame_vector(frame))
                .collect(),
        })
        .collect();
    LinkVector {
        name: str_field(item, "name"),
        material,
        rounds,
    }
}

/// 解析整份会话向量 JSON。
pub fn parse_session_vectors() -> Vec<LinkVector> {
    assert_eq!(
        str_field(SESSION_VECTORS_JSON, "format"),
        FORMAT,
        "向量格式标识不符"
    );
    assert_eq!(
        num_field(SESSION_VECTORS_JSON, "version"),
        VERSION,
        "向量版本号不符"
    );
    assert_eq!(
        str_field(SESSION_VECTORS_JSON, "spec"),
        SPEC,
        "向量规范文档路径不符"
    );
    super::array_items(SESSION_VECTORS_JSON, "links")
        .iter()
        .map(|item| link_vector(item))
        .collect()
}
