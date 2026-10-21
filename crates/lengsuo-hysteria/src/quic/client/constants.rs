//! 客户端侧常量：QUIC datagram 会话 ID 长度、通道容量、首个会话 ID。

/// QUIC datagram 上的会话 ID 长度（字节），对齐 `InterUdpConn.Write` 的前缀。
pub const UDP_SESSION_ID_LEN: usize = 4;
/// 会话分发通道容量，对齐 `config.go` `udpMessageChanSize`。
pub const UDP_MESSAGE_CHAN_SIZE: usize = 1024;
/// 客户端首个 UDP 会话 ID 从 1 开始（dialer.go `next: 1`）。
pub const FIRST_UDP_SESSION_ID: u32 = 1;
