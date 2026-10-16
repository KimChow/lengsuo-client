#![forbid(unsafe_code)]
//! lengsuo-wireguard — WireGuard **报文头解析** 与 **接收重放窗口**（部分实现）。
//!
//! 已有：`wire::parse` 对四类报文做 fail-closed 的类型字段与长度检查；
//! `replay::Window` 提供每个 peer/key epoch 独占的 8192 位接收重放窗口；
//! `transport` 提供类型 4 运输数据消息的 AEAD 封装（seal）与认证解封（open），
//! 会话密钥由调用方提供，本 crate 不生成密钥。
//! 格式依据 WireGuard 官方公开协议说明自主实现，未读取或复制 GPL 内核代码。
//!
//! **本 crate 不是 WireGuard，也不构成可用的 WireGuard 连接。** 尚未实现：
//! Noise 握手状态机与密钥协商（X25519、blake2s、HKDF）——参考目录内没有
//! wireguard-go 源，握手消息构造无法在此实现，因此 `transport` 的密钥只能由
//! 调用方注入，**与任何真实 WireGuard 对端的双向互通均未验证**；
//! COOKIE 消息的生成与校验、MAC 验证、密钥轮换与重试计时、
//! TUN/内核设备接口同样未实现。
//! `wire::parse` 只检查类型字段与长度，绝不声称载荷已通过 MAC 或解密；
//! `transport::Receiver::open` 已完成认证解密，重放窗口检查只在认证成功后进行。
//! 状态与验证记录见 `docs/wireguard-status.md`。

pub mod handshake;
pub mod replay;
pub mod transport;
pub mod wire;

pub use replay::{Error as ReplayError, Window, WINDOW_BITS};
pub use transport::{
    Decrypted, Error as TransportError, Receiver, Sender, TransportKey, DEFAULT_MAX_COUNTER,
    MAX_PACKET_LEN, MAX_PAYLOAD_LEN,
};
pub use wire::{
    parse, Error as WireError, HandshakeKind, HandshakeMessage, Message, TransportMessage,
    COOKIE_LEN, INIT_LEN, RESPONSE_LEN, TRANSPORT_MIN_LEN,
};
