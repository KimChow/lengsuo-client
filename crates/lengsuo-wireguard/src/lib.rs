#![forbid(unsafe_code)]
//! lengsuo-wireguard — WireGuard 协议栈的 Rust 实现（对齐 wireguard-go
//! commit 2631ce99）。
//!
//! 已有：
//! - `wire::parse` 对四类报文做 fail-closed 的类型字段与长度检查；
//! - `handshake`：Noise IK 握手（X25519/blake2s/HKDF）、MAC1/MAC2、CookieReply
//!   签发与消费；
//! - `transport`：类型 4 运输数据消息的 AEAD 封装（seal）与认证解封（open）；
//! - `replay::Window`：每个 peer/key epoch 独占的 8192 位接收重放窗口；
//! - `keypair`：`Keypair` 生命周期（Reject/Rekey 阈值）与 `KeypairSet` 三槽位轮换；
//! - `timers`：keepalive/重试/握手发起/会话派生的定时器状态机（调用方驱动的
//!   `tick(now)`，见偏离清单）；
//! - `allowedips`：最长前缀匹配路由表；
//! - `index_table`：全局 index 表（随机分配 + 冲突重试 + 容量 fail-closed）；
//! - `peers`：多 peer 配置装载与按公钥/id 定向；
//! - `packet_pad`：IP 包填充（16 字节倍数）与按 MTU 的分片/重组判据；
//! - `device`：把上述部件组合成会话的调用序。
//!
//! 与 wireguard-go 参考进程的 UDP 双向互通已实跑（`tests/wireguard_go.rs`，
//! `--ignored`）。
//!
//! **本 crate 仍不是完整可用的 WireGuard 设备。** 尚未实现：TUN/系统路由读写、
//! Windows 设备接口。`wire::parse`
//! 只检查类型字段与长度，绝不声称载荷已通过 MAC 或解密；
//! `transport::Receiver::open` 已完成认证解密，重放窗口检查只在认证成功后进行。
//! 状态、偏离清单与验证记录见 `docs/wireguard-status.md`。

pub mod allowedips;
pub mod device;
pub mod handshake;
pub mod index_table;
pub mod keypair;
pub mod packet_pad;
pub mod peers;
pub mod replay;
pub mod timers;
pub mod transport;
pub mod wire;

pub use allowedips::AllowedIps;
pub use index_table::{IndexEntry, IndexError, IndexTable};
pub use keypair::{Keypair, KeypairSet, KeypairStatus};
pub use packet_pad::{
    calculate_padding_size, fragment, pad, reassemble, unpad, PadError, PADDING_MULTIPLE,
};
pub use peers::{Peer, PeerConfig, PeerError, PeerSet, MAX_PEERS};
pub use replay::{Error as ReplayError, Window, WINDOW_BITS};
pub use timers::{constants as timer_constants, TimerAction, TimerState};
pub use transport::{
    Decrypted, Error as TransportError, Receiver, Sender, TransportKey, DEFAULT_MAX_COUNTER,
    MAX_PACKET_LEN, MAX_PAYLOAD_LEN,
};
pub use wire::{
    parse, Error as WireError, HandshakeKind, HandshakeMessage, Message, TransportMessage,
    COOKIE_LEN, INIT_LEN, RESPONSE_LEN, TRANSPORT_MIN_LEN,
};
